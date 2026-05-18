//! Types for streaming `/v1/chat/completions` responses.

use async_openai::types::chat::{
    ChatChoice as AsyncChatChoice, ChatChoiceStream as AsyncChatChoiceStream,
    ChatCompletionStreamResponseDelta as AsyncChatCompletionStreamResponseDelta,
    CompletionUsage as AsyncCompletionUsage,
    CreateChatCompletionStreamResponse as AsyncCreateChatCompletionStreamResponse,
    FinishReason as AsyncFinishReason, Role as AsyncRole,
};
use serde::{Deserialize, Serialize};

use crate::chat_completions::ChatCompletionResponse;

pub fn response_choices(
    response: &ChatCompletionResponse,
) -> impl Iterator<Item = ChatCompletionResponseChoice<'_>> + '_ {
    response
        .inner()
        .choices
        .iter()
        .map(ChatCompletionResponseChoice)
}

#[must_use]
pub fn response_usage(response: &ChatCompletionResponse) -> Option<ChatCompletionUsage> {
    response.inner().usage.clone().map(ChatCompletionUsage)
}

#[derive(Debug, Clone, Copy)]
pub struct ChatCompletionResponseChoice<'a>(&'a AsyncChatChoice);

impl ChatCompletionResponseChoice<'_> {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.0.index
    }

    #[must_use]
    pub const fn role(&self) -> ChatCompletionRole {
        ChatCompletionRole(self.0.message.role)
    }

    #[must_use]
    pub fn content(&self) -> Option<&str> {
        self.0.message.content.as_deref()
    }

    #[must_use]
    pub fn refusal(&self) -> Option<&str> {
        self.0.message.refusal.as_deref()
    }

    #[must_use]
    pub const fn finish_reason(&self) -> Option<ChatCompletionFinishReason> {
        match self.0.finish_reason {
            Some(finish_reason) => Some(ChatCompletionFinishReason(finish_reason)),
            None => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionRole(AsyncRole);

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionFinishReason(AsyncFinishReason);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionUsage(AsyncCompletionUsage);

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionStreamResponse(AsyncCreateChatCompletionStreamResponse);

impl ChatCompletionStreamResponse {
    #[must_use]
    #[allow(deprecated)]
    pub fn from_response(
        response: &ChatCompletionResponse,
        choices: Vec<ChatCompletionStreamChoice>,
        usage: Option<ChatCompletionUsage>,
    ) -> Self {
        let response = response.inner();
        Self(AsyncCreateChatCompletionStreamResponse {
            id: response.id.clone(),
            choices: choices.into_iter().map(|choice| choice.0).collect(),
            created: response.created,
            model: response.model.clone(),
            service_tier: response.service_tier.clone(),
            system_fingerprint: response.system_fingerprint.clone(),
            object: "chat.completion.chunk".to_string(),
            usage: usage.map(|usage| usage.0),
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionStreamChoice(AsyncChatChoiceStream);

impl ChatCompletionStreamChoice {
    #[must_use]
    pub fn new(
        index: u32,
        delta: ChatCompletionStreamDelta,
        finish_reason: Option<ChatCompletionFinishReason>,
    ) -> Self {
        Self(AsyncChatChoiceStream {
            index,
            delta: delta.0,
            finish_reason: finish_reason.map(|finish_reason| finish_reason.0),
            logprobs: None,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(transparent)]
pub struct ChatCompletionStreamDelta(AsyncChatCompletionStreamResponseDelta);

impl ChatCompletionStreamDelta {
    #[must_use]
    #[allow(deprecated)]
    pub const fn empty() -> Self {
        Self(AsyncChatCompletionStreamResponseDelta {
            content: None,
            function_call: None,
            tool_calls: None,
            role: None,
            refusal: None,
        })
    }

    #[must_use]
    pub const fn with_role(role: ChatCompletionRole) -> Self {
        let mut delta = Self::empty();
        delta.0.role = Some(role.0);
        delta
    }

    #[must_use]
    pub fn with_content(content: String) -> Self {
        let mut delta = Self::empty();
        delta.0.content = Some(content);
        delta
    }

    #[must_use]
    pub fn with_refusal(refusal: String) -> Self {
        let mut delta = Self::empty();
        delta.0.refusal = Some(refusal);
        delta
    }
}
