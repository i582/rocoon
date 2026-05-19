use std::time::Instant;

use anyhow::Context;
use rocoon_openai::completions::{CompletionRequest, CompletionResponse, parse_response};

use crate::http::{HandlerResult, Json, bad_gateway, bad_request};
use crate::stats::{CompletionFailure, CompletionSuccess};
use crate::{Defaults, ServerState};

/// Handles `POST /v2/completions`.
pub fn handle(
    state: &ServerState,
    defaults: Defaults,
    body: &[u8],
) -> HandlerResult<Json<CompletionResponse>> {
    let request = parse_request(body).map_err(bad_request)?;

    state.stats()?.record_completion_started();

    let path = "/v1/completions";
    let body = convert_body(&request).map_err(bad_request)?;

    let max_coefficient = request
        .non_standard
        .max_coefficient
        .unwrap_or(defaults.max_coefficient);

    let max_tokens: i32 = request
        .openai
        .max_tokens
        .map_or(defaults.max_tokens, |value| {
            i32::try_from(value).unwrap_or(defaults.max_tokens)
        });

    let timeout = request.non_standard.timeout.unwrap_or(defaults.timeout);

    let started_at = Instant::now();
    let response = state.client()?.run_chat_completion(
        &request.openai.model,
        path,
        &body,
        max_coefficient,
        max_tokens,
        timeout,
    );

    let duration = started_at.elapsed();
    let response = match response {
        Ok(response) => {
            state.stats()?.record_completion_success(CompletionSuccess {
                model: &request.openai.model,
                path,
                request_bytes: body.len(),
                duration,
                response: &response,
            });
            response
        }
        Err(error) => {
            let message = format!("{error:#}");
            state.stats()?.record_completion_failure(CompletionFailure {
                model: &request.openai.model,
                path,
                request_bytes: body.len(),
                duration,
                error: &message,
            });
            return Err(bad_gateway(error));
        }
    };

    let response = parse_response(&response.payload)
        .context("parse OpenAI completion response JSON")
        .map_err(bad_gateway)?;
    Ok(Json::ok(response))
}

fn parse_request(body: &[u8]) -> anyhow::Result<CompletionRequest> {
    serde_json::from_slice(body).context("parse OpenAI completion request JSON")
}

fn convert_body(request: &CompletionRequest) -> anyhow::Result<Vec<u8>> {
    serde_json::to_vec(request).context("serialize sanitized OpenAI completion request JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_reads_typed_model() {
        let request = parse_request(br#"{"model":"test-model","prompt":"hello"}"#)
            .expect("completion request should parse");

        assert_eq!(request.model(), "test-model");
    }

    #[test]
    fn convert_body_strips_disabled_openai_fields() {
        let request = parse_request(
            br#"{
                "model":"test-model",
                "prompt":"hello",
                "logit_bias":{"1":100},
                "max_coefficient":10,
                "timeout":30.0
            }"#,
        )
        .expect("completion request should parse");
        let forwarded: serde_json::Value = serde_json::from_slice(
            &convert_body(&request).expect("completion request should serialize"),
        )
        .expect("forwarded body should be JSON");

        assert!(forwarded.get("logit_bias").is_none());
        assert_eq!(forwarded["max_coefficient"], serde_json::Value::from(10));
        assert_eq!(forwarded["timeout"], serde_json::Value::from(30.0));
    }
}
