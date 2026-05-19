//! Types for `/v1/completions`.

use async_openai::types::completions::{CreateCompletionRequest, CreateCompletionResponse};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::request::{deserialize_flat_request, serialize_flat_request};
pub use crate::request_non_standard::CompletionRequestNonStandardFields as RequestNonStandardFields;

const DISABLED_OPENAI_FIELDS: &[&str] = &["logit_bias"];

#[derive(Debug, Clone, PartialEq)]
pub struct CompletionRequest {
    pub openai: CreateCompletionRequest,
    pub non_standard: RequestNonStandardFields,
}

impl<'de> Deserialize<'de> for CompletionRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (openai, non_standard) =
            deserialize_flat_request(deserializer, DISABLED_OPENAI_FIELDS)?;
        Ok(Self {
            openai,
            non_standard,
        })
    }
}

impl Serialize for CompletionRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_flat_request(
            &self.openai,
            &self.non_standard,
            DISABLED_OPENAI_FIELDS,
            serializer,
        )
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct CompletionResponse(CreateCompletionResponse);

/// Parses an `OpenAI` completion response JSON body.
///
/// # Errors
///
/// Returns a `serde_json` error when the body is not a valid
/// `CreateCompletionResponse` payload.
pub fn parse_response(body: &[u8]) -> serde_json::Result<CompletionResponse> {
    serde_json::from_slice(body)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use async_openai::types::chat::{Choice, CompletionFinishReason};

    use super::*;

    #[test]
    fn make_response_uses_request_model() {
        let request: CompletionRequest =
            serde_json::from_str(r#"{"model":"test-model","prompt":"hello"}"#)
                .expect("completion request JSON should parse");

        let response = make_response(&request, "done");
        let response =
            serde_json::to_value(response).expect("completion response should serialize");

        assert_eq!(request.openai.model, "test-model");
        assert_eq!(response["model"], "test-model");
        assert_eq!(response["object"], "text_completion");
        assert_eq!(response["choices"][0]["text"], "done");
    }

    #[test]
    fn completion_request_splits_standard_and_non_standard_fields() {
        let request: CompletionRequest = serde_json::from_str(
            r#"{
                "model": "test-model",
                "prompt": "hello",
                "stream": true,
                "skip_special_tokens": true,
                "max_coefficient": 10
            }"#,
        )
        .expect("completion request JSON should parse");

        assert_eq!(request.openai.model, "test-model");
        assert_eq!(request.openai.stream, Some(true));
        assert_eq!(request.non_standard.skip_special_tokens, Some(true));
        assert_eq!(request.non_standard.max_coefficient, Some(10));
    }

    #[test]
    fn completion_request_strips_disabled_openai_fields() {
        let request = serde_json::from_str::<CompletionRequest>(
            r#"{
                "model": "test-model",
                "prompt": "hello",
                "logit_bias": { "1": 100 }
            }"#,
        )
        .expect("disabled OpenAI fields should be stripped");
        let forwarded = serde_json::to_value(request).expect("completion request should serialize");

        assert!(forwarded.get("logit_bias").is_none());
    }

    #[test]
    fn parse_response_reads_openai_completion_payload() {
        let response = parse_response(
            br#"{
                "id": "cmpl-test",
                "object": "text_completion",
                "created": 123,
                "model": "test-model",
                "choices": [{
                    "index": 0,
                    "text": "hello",
                    "finish_reason": "stop"
                }]
            }"#,
        )
        .expect("OpenAI completion response should parse");
        let response =
            serde_json::to_value(response).expect("completion response should serialize");

        assert_eq!(response["model"], "test-model");
        assert_eq!(response["choices"][0]["text"], "hello");
    }

    #[must_use]
    fn make_response(
        request: &CompletionRequest,
        content: impl Into<String>,
    ) -> CompletionResponse {
        let created = unix_timestamp();

        CompletionResponse(CreateCompletionResponse {
            id: default_response_id(created),
            choices: vec![Choice {
                text: content.into(),
                index: 0,
                logprobs: None,
                finish_reason: Some(CompletionFinishReason::Stop),
            }],
            created,
            model: request.openai.model.clone(),
            system_fingerprint: None,
            object: "text_completion".to_string(),
            usage: None,
        })
    }

    #[must_use]
    fn unix_timestamp() -> u32 {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        u32::try_from(seconds).unwrap_or(u32::MAX)
    }

    #[must_use]
    fn default_response_id(created: u32) -> String {
        format!("cmpl-rocoon-{created}")
    }
}
