use anyhow::Context;
use rocoon_openai::chat_completions::{
    ChatCompletionRequest, ChatCompletionResponse, parse_response,
};
use std::time::Instant;

use super::fake_stream;
use crate::http::{
    HandlerResult, IntoServerResponse, Json, ServerResponse, bad_gateway, bad_request,
};
use crate::stats::{CompletionFailure, CompletionSuccess};
use crate::{Defaults, ServerState};

pub enum HandlerResponse {
    Json(Json<ChatCompletionResponse>),
    EventStream(fake_stream::Response),
}

impl IntoServerResponse for HandlerResponse {
    fn into_server_response(self) -> anyhow::Result<ServerResponse> {
        match self {
            Self::Json(response) => response.into_server_response(),
            Self::EventStream(response) => response.into_server_response(),
        }
    }
}

/// Handles `POST /v2/chat/completions`.
pub fn handle(
    state: &ServerState,
    defaults: Defaults,
    body: &[u8],
) -> HandlerResult<HandlerResponse> {
    let request = parse_request(body).map_err(bad_request)?;

    state.stats()?.record_completion_started();

    let path = "/v1/chat/completions";
    let body = convert_body(&request).map_err(bad_request)?;
    let fake_stream_requested = fake_stream::is_requested(&request);
    let stream_include_usage = fake_stream::include_usage(&request);

    let max_coefficient = request
        .non_standard
        .max_coefficient
        .unwrap_or(defaults.max_coefficient);

    #[allow(deprecated)]
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

    if fake_stream_requested && (200..300).contains(&response.status_code) {
        let response = fake_stream::Response::from_payload(
            response.status_code,
            &response.payload,
            stream_include_usage,
        )
        .context("build OpenAI chat completion stream response")
        .map_err(bad_gateway)?;
        return Ok(HandlerResponse::EventStream(response));
    }

    let response = parse_response(&response.payload)
        .context("parse OpenAI chat completion response JSON")
        .map_err(bad_gateway)?;
    Ok(HandlerResponse::Json(Json::ok(response)))
}

fn parse_request(body: &[u8]) -> anyhow::Result<ChatCompletionRequest> {
    serde_json::from_slice(body).context("parse OpenAI chat completion request JSON")
}

fn convert_body(request: &ChatCompletionRequest) -> anyhow::Result<Vec<u8>> {
    let mut request = request.clone();
    fake_stream::disable_upstream_request(&mut request);

    serde_json::to_vec(&request).context("serialize sanitized OpenAI chat completion request JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_reads_typed_model() {
        let request = parse_request(br#"{"model":"test-model","messages":[]}"#)
            .expect("chat completion request should parse");

        assert_eq!(request.openai.model.as_str(), "test-model");
    }

    #[test]
    fn convert_body_strips_disabled_openai_fields() {
        let request = parse_request(
            br#"{
                "model":"test-model",
                "messages":[],
                "tools":"not-forwarded",
                "tool_choice":"not-forwarded",
                "stream":true,
                "stream_options":{"include_usage":true}
            }"#,
        )
        .expect("chat completion request should parse");
        let forwarded: serde_json::Value = serde_json::from_slice(
            &convert_body(&request).expect("chat completion request should serialize"),
        )
        .expect("forwarded body should be JSON");

        assert!(forwarded.get("tools").is_none());
        assert!(forwarded.get("tool_choice").is_none());
        assert_eq!(forwarded["stream"], serde_json::Value::from(false));
        assert_eq!(
            forwarded["stream_options"]["include_usage"],
            serde_json::Value::from(false)
        );
    }
}
