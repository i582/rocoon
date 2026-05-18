use anyhow::Context;
use rocoon_openai::chat_completion_stream::{
    ChatCompletionFinishReason, ChatCompletionResponseChoice, ChatCompletionStreamChoice,
    ChatCompletionStreamDelta, ChatCompletionStreamResponse, ChatCompletionUsage, response_choices,
    response_usage,
};
use rocoon_openai::chat_completions::{
    ChatCompletionRequest, ChatCompletionResponse, parse_response,
};
use tiny_http::StatusCode;

use crate::http::{IntoServerResponse, ServerResponse, response_with_body};

pub struct Response {
    status_code: i32,
    body: Vec<u8>,
}

impl Response {
    pub fn from_payload(
        status_code: i32,
        payload: &[u8],
        include_usage: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            status_code,
            body: stream_body(payload, include_usage)?,
        })
    }
}

impl IntoServerResponse for Response {
    fn into_server_response(self) -> anyhow::Result<ServerResponse> {
        let status_code =
            StatusCode(u16::try_from(self.status_code).context("HTTP status code out of range")?);
        response_with_body(
            status_code,
            vec![
                ("Content-Type".to_string(), "text/event-stream".to_string()),
                ("Cache-Control".to_string(), "no-cache".to_string()),
            ],
            self.body,
        )
    }
}

pub fn is_requested(request: &ChatCompletionRequest) -> bool {
    request.openai.stream.unwrap_or(false)
}

pub fn include_usage(request: &ChatCompletionRequest) -> bool {
    request
        .openai
        .stream_options
        .as_ref()
        .and_then(|stream_options| stream_options.include_usage)
        .unwrap_or(false)
}

pub fn disable_upstream_request(request: &mut ChatCompletionRequest) {
    if !is_requested(request) {
        return;
    }

    request.openai.stream = Some(false);
    if let Some(stream_options) = &mut request.openai.stream_options {
        if stream_options.include_usage.is_some() {
            stream_options.include_usage = Some(false);
        }
        if stream_options.include_obfuscation.is_some() {
            stream_options.include_obfuscation = Some(false);
        }
    }
}

fn stream_body(payload: &[u8], include_usage: bool) -> anyhow::Result<Vec<u8>> {
    let response = parse_response(payload).context("parse chat completion response JSON")?;

    let mut body = Vec::new();
    for choice in response_choices(&response) {
        write_chat_choice_stream_chunks(&mut body, &response, choice)?;
    }

    if include_usage {
        write_stream_chunk(&mut body, &response, Vec::new(), response_usage(&response))?;
    }

    body.extend_from_slice(b"data: [DONE]\n\n");
    Ok(body)
}

fn write_chat_choice_stream_chunks(
    body: &mut Vec<u8>,
    response: &ChatCompletionResponse,
    choice: ChatCompletionResponseChoice<'_>,
) -> anyhow::Result<()> {
    let index = choice.index();

    write_stream_chunk(
        body,
        response,
        vec![stream_choice(
            index,
            ChatCompletionStreamDelta::with_role(choice.role()),
            None,
        )],
        None,
    )?;
    if let Some(content) = choice.content() {
        for content in split_content(content) {
            write_stream_chunk(
                body,
                response,
                vec![stream_choice(
                    index,
                    ChatCompletionStreamDelta::with_content(content),
                    None,
                )],
                None,
            )?;
        }
    }
    if let Some(refusal) = choice.refusal() {
        write_stream_chunk(
            body,
            response,
            vec![stream_choice(
                index,
                ChatCompletionStreamDelta::with_refusal(refusal.to_string()),
                None,
            )],
            None,
        )?;
    }
    write_stream_chunk(
        body,
        response,
        vec![stream_choice(
            index,
            ChatCompletionStreamDelta::empty(),
            choice.finish_reason(),
        )],
        None,
    )
}

#[allow(deprecated)]
fn write_stream_chunk(
    body: &mut Vec<u8>,
    response: &ChatCompletionResponse,
    choices: Vec<ChatCompletionStreamChoice>,
    usage: Option<ChatCompletionUsage>,
) -> anyhow::Result<()> {
    let chunk = ChatCompletionStreamResponse::from_response(response, choices, usage);
    write_sse_json(body, &chunk)
}

fn stream_choice(
    index: u32,
    delta: ChatCompletionStreamDelta,
    finish_reason: Option<ChatCompletionFinishReason>,
) -> ChatCompletionStreamChoice {
    ChatCompletionStreamChoice::new(index, delta, finish_reason)
}

fn split_content(content: &str) -> Vec<String> {
    const CHUNK_CHARS: usize = 256;

    let mut chunks = Vec::new();
    let mut start = 0;
    let mut chunk_len = 0;
    for (index, _) in content.char_indices() {
        if chunk_len == CHUNK_CHARS {
            chunks.push(content[start..index].to_string());
            start = index;
            chunk_len = 0;
        }
        chunk_len += 1;
    }
    if start < content.len() {
        chunks.push(content[start..].to_string());
    }
    chunks
}

fn write_sse_json(body: &mut Vec<u8>, value: &ChatCompletionStreamResponse) -> anyhow::Result<()> {
    body.extend_from_slice(b"data: ");
    serde_json::to_writer(&mut *body, value).context("serialize chat completion stream chunk")?;
    body.extend_from_slice(b"\n\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disable_upstream_request_turns_stream_fields_false() {
        let mut request: ChatCompletionRequest = serde_json::from_str(
            r#"{
                "model": "test-model",
                "messages": [],
                "stream": true,
                "stream_options": {
                    "include_usage": true,
                    "include_obfuscation": true
                }
            }"#,
        )
        .expect("chat completion request should parse");

        assert!(is_requested(&request));
        assert!(include_usage(&request));

        disable_upstream_request(&mut request);

        assert_eq!(request.openai.stream, Some(false));
        let stream_options = request
            .openai
            .stream_options
            .expect("stream options should be preserved");
        assert_eq!(stream_options.include_usage, Some(false));
        assert_eq!(stream_options.include_obfuscation, Some(false));
    }

    #[test]
    fn stream_body_converts_json_response_to_sse() {
        let body = stream_body(
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
                }],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2
                }
            }"#,
            true,
        )
        .expect("chat completion response should convert to SSE");
        let body = String::from_utf8(body).expect("SSE body should be UTF-8");

        assert!(body.contains("data: {"));
        assert!(body.contains(r#""object":"chat.completion.chunk""#));
        assert!(body.contains(r#""role":"assistant""#));
        assert!(body.contains(r#""content":"hello""#));
        assert!(body.contains(r#""finish_reason":"stop""#));
        assert!(body.contains(r#""choices":[]"#));
        assert!(body.contains(r#""usage":{"#));
        assert!(body.ends_with("data: [DONE]\n\n"));
    }
}
