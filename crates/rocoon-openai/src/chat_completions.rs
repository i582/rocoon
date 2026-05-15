//! Types for `/v1/chat/completions`.

use std::time::{SystemTime, UNIX_EPOCH};

use async_openai::types::chat::{
    ChatChoice, ChatCompletionResponseMessage, CreateChatCompletionRequest,
    CreateChatCompletionResponse, FinishReason, Role,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionRequest(CreateChatCompletionRequest);

impl ChatCompletionRequest {
    #[must_use]
    pub fn model(&self) -> &str {
        &self.0.model
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionResponse(CreateChatCompletionResponse);

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
        model: request.model().to_string(),
        service_tier: request.0.service_tier.clone(),
        system_fingerprint: None,
        object: "chat.completion".to_string(),
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

        assert_eq!(request.model(), "test-model");
        assert_eq!(response["model"], "test-model");
        assert_eq!(response["object"], "chat.completion");
        assert_eq!(response["choices"][0]["message"]["role"], "assistant");
        assert_eq!(response["choices"][0]["message"]["content"], "done");
    }
}
