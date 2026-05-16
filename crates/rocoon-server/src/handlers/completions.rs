use std::time::Instant;

use anyhow::{Context, Result};
use serde_json::{Map, Value};

use crate::http::{Error as HttpError, ServerResponse, upstream_response};
use crate::stats::{CompletionFailure, CompletionSuccess};
use crate::{Defaults, ServerState};

/// Sanitized completion request plus Cocoon-specific execution limits.
struct CompletionRequest {
    model: String,
    body: Vec<u8>,
    max_coefficient: i32,
    max_tokens: i32,
    timeout: f64,
}

/// Handles `POST /v1/chat/completions` and `POST /v1/completions`.
pub fn handle(
    state: &ServerState,
    defaults: Defaults,
    path: &str,
    body: &[u8],
) -> std::result::Result<ServerResponse, HttpError> {
    let completion = parse_request(body, defaults).map_err(|error| HttpError::new(400, &error))?;
    state
        .stats
        .lock()
        .map_err(|_| HttpError::message(500, "stats mutex poisoned"))?
        .record_completion_started();
    let started_at = Instant::now();
    let response = state
        .client
        .lock()
        .map_err(|_| HttpError::message(500, "Cocoon client mutex poisoned"))?
        .run_chat_completion(
            &completion.model,
            path,
            &completion.body,
            completion.max_coefficient,
            completion.max_tokens,
            completion.timeout,
        );
    let duration = started_at.elapsed();
    let response = match response {
        Ok(response) => {
            state
                .stats
                .lock()
                .map_err(|_| HttpError::message(500, "stats mutex poisoned"))?
                .record_completion_success(CompletionSuccess {
                    model: &completion.model,
                    path,
                    request_bytes: completion.body.len(),
                    duration,
                    response: &response,
                });
            response
        }
        Err(error) => {
            let message = format!("{error:#}");
            state
                .stats
                .lock()
                .map_err(|_| HttpError::message(500, "stats mutex poisoned"))?
                .record_completion_failure(CompletionFailure {
                    model: &completion.model,
                    path,
                    request_bytes: completion.body.len(),
                    duration,
                    error: &message,
                });
            return Err(HttpError::new(502, &error));
        }
    };
    upstream_response(response).map_err(|error| HttpError::new(500, &error))
}

/// Parses and sanitizes `OpenAI` completion JSON.
///
/// The model name is extracted for Cocoon routing. `Cocoon`-specific knobs
/// (`max_coefficient`, `timeout`) are removed from the forwarded JSON body,
/// while token limits are normalized for worker compatibility.
fn parse_request(body: &[u8], defaults: Defaults) -> Result<CompletionRequest> {
    let mut value: Value = serde_json::from_slice(body).context("parse OpenAI request JSON")?;
    let object = value
        .as_object_mut()
        .context("OpenAI request JSON must be an object")?;

    let model = object
        .get("model")
        .and_then(Value::as_str)
        .context("OpenAI request requires string field 'model'")?
        .to_string();

    let max_tokens = object
        .get("max_completion_tokens")
        .or_else(|| object.get("max_tokens"))
        .and_then(Value::as_i64)
        .map(i32::try_from)
        .transpose()
        .context("max_tokens is out of range")?
        .unwrap_or(defaults.max_tokens);
    let max_coefficient = object
        .remove("max_coefficient")
        .and_then(|value| value.as_i64())
        .map(i32::try_from)
        .transpose()
        .context("max_coefficient is out of range")?
        .unwrap_or(defaults.max_coefficient);
    let timeout = object
        .remove("timeout")
        .and_then(|value| value.as_f64())
        .unwrap_or(defaults.timeout);
    if max_tokens < 0 {
        anyhow::bail!("max_tokens must not be negative");
    }
    if max_coefficient < 0 {
        anyhow::bail!("max_coefficient must not be negative");
    }
    if timeout <= 0.0 {
        anyhow::bail!("timeout must be greater than zero");
    }

    if max_tokens > 0 {
        object.insert("max_tokens".to_string(), Value::from(max_tokens));
        object.insert("max_completion_tokens".to_string(), Value::from(max_tokens));
    }
    if object
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let stream_options = object
            .entry("stream_options")
            .or_insert_with(|| Value::Object(Map::default()));
        if let Some(stream_options) = stream_options.as_object_mut() {
            stream_options.insert("include_usage".to_string(), Value::from(true));
        }
    } else {
        object.remove("stream_options");
    }

    Ok(CompletionRequest {
        model,
        body: serde_json::to_vec(&value).context("serialize sanitized OpenAI request JSON")?,
        max_coefficient,
        max_tokens,
        timeout,
    })
}
