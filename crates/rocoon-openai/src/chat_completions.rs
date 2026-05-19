//! Types for `/v1/chat/completions`.

use std::time::{SystemTime, UNIX_EPOCH};

use async_openai::types::chat::{
    ChatChoice, ChatCompletionResponseMessage, CreateChatCompletionRequest,
    CreateChatCompletionResponse, FinishReason, Role,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::request::{deserialize_flat_request, serialize_flat_request};

const DISABLED_OPENAI_FIELDS: &[&str] = &[
    "function",
    "function_call",
    "functions",
    "logit_bias",
    "metadata",
    "tool_choice",
    "tools",
    "web_search_options",
];

#[derive(Debug, Clone, PartialEq)]
pub struct ChatCompletionRequest {
    pub openai: CreateChatCompletionRequest,
    pub non_standard: RequestNonStandardFields,
}

impl ChatCompletionRequest {}

impl<'de> Deserialize<'de> for ChatCompletionRequest {
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

impl Serialize for ChatCompletionRequest {
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

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct RequestNonStandardFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_special_tokens: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_template_kwargs: Option<ChatTemplateKwargs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_coefficient: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_debug: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_guid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChatTemplateKwargs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_thinking: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionResponse(CreateChatCompletionResponse);

impl ChatCompletionResponse {
    #[must_use]
    pub(crate) const fn inner(&self) -> &CreateChatCompletionResponse {
        &self.0
    }
}

#[must_use]
#[allow(deprecated)]
pub fn make_response(
    request: &ChatCompletionRequest,
    content: impl Into<String>,
) -> ChatCompletionResponse {
    let created = unix_timestamp();

    ChatCompletionResponse(CreateChatCompletionResponse {
        id: default_response_id(created),
        choices: vec![ChatChoice {
            index: 0,
            message: ChatCompletionResponseMessage {
                content: Some(content.into()),
                refusal: None,
                tool_calls: None,
                annotations: None,
                role: Role::Assistant,
                function_call: None,
                audio: None,
            },
            finish_reason: Some(FinishReason::Stop),
            logprobs: None,
        }],
        created,
        model: request.openai.model.to_string(),
        service_tier: request.openai.service_tier.clone(),
        system_fingerprint: None,
        object: "chat.completion".to_string(),
        usage: None,
    })
}

/// Parses an `OpenAI` chat completion response JSON body.
///
/// # Errors
///
/// Returns a `serde_json` error when the body is not a valid
/// `CreateChatCompletionResponse` payload.
pub fn parse_response(body: &[u8]) -> serde_json::Result<ChatCompletionResponse> {
    serde_json::from_slice(body)
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
    format!("chatcmpl-rocoon-{created}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_response_uses_request_model() {
        let request: ChatCompletionRequest =
            serde_json::from_str(r#"{"model":"test-model","messages":[]}"#)
                .expect("chat completion request JSON should parse");

        let response = make_response(&request, "done");
        let response =
            serde_json::to_value(response).expect("chat completion response should serialize");

        assert_eq!(request.openai.model.to_string(), "test-model");
        assert_eq!(response["model"], "test-model");
        assert_eq!(response["object"], "chat.completion");
        assert_eq!(response["choices"][0]["message"]["role"], "assistant");
        assert_eq!(response["choices"][0]["message"]["content"], "done");
    }

    #[test]
    fn chat_completion_request_splits_standard_and_non_standard_fields() {
        let request: ChatCompletionRequest = serde_json::from_str(
            r#"{
                "model": "test-model",
                "messages": [{ "role": "user", "content": "hello" }],
                "stream": true,
                "skip_special_tokens": true,
                "chat_template_kwargs": { "enable_thinking": false },
                "max_coefficient": 10
            }"#,
        )
        .expect("chat completion request JSON should parse");

        assert_eq!(request.openai.model.to_string(), "test-model");
        assert_eq!(request.openai.stream, Some(true));
        assert_eq!(request.non_standard.skip_special_tokens, Some(true));
        assert_eq!(request.non_standard.max_coefficient, Some(10));
        assert_eq!(
            request
                .non_standard
                .chat_template_kwargs
                .and_then(|kwargs| kwargs.enable_thinking),
            Some(false)
        );
    }

    #[test]
    fn chat_completion_request_strips_disabled_openai_fields() {
        let request = serde_json::from_str::<ChatCompletionRequest>(
            r#"{
                "model": "test-model",
                "messages": [],
                "tools": "not-forwarded",
                "tool_choice": "not-forwarded"
            }"#,
        )
        .expect("disabled OpenAI fields should be stripped");
        let forwarded =
            serde_json::to_value(request).expect("chat completion request should serialize");

        assert!(forwarded.get("tools").is_none());
        assert!(forwarded.get("tool_choice").is_none());
    }

    #[test]
    fn parse_response_reads_openai_chat_completion_payload() {
        let response = parse_response(
            br#"{
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 123,
                "model": "test-model",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "hello"
                    },
                    "finish_reason": "stop"
                }]
            }"#,
        )
        .expect("OpenAI chat completion response should parse");
        let response =
            serde_json::to_value(response).expect("chat completion response should serialize");

        assert_eq!(response["model"], "test-model");
        assert_eq!(response["choices"][0]["message"]["content"], "hello");
    }
}
