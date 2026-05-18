use std::time::Instant;

use anyhow::Context;
use serde_json::{Map, Value};
use tiny_http::StatusCode;

use crate::http::{
    HandlerResult, IntoServerResponse, ServerResponse, Upstream, bad_gateway, bad_request,
    response_with_body,
};
use crate::stats::{CompletionFailure, CompletionSuccess};
use crate::{Defaults, ServerState};

/// Sanitized completion request plus Cocoon-specific execution limits.
struct CompletionRequest {
    model: String,
    body: Vec<u8>,
    stream: bool,
    stream_include_usage: bool,
    max_coefficient: i32,
    max_tokens: i32,
    timeout: f64,
}

pub enum CompletionResponse {
    Upstream(Upstream),
    Stream {
        response: rocoon_client::HttpExchange,
        include_usage: bool,
    },
}

impl IntoServerResponse for CompletionResponse {
    fn into_server_response(self) -> anyhow::Result<ServerResponse> {
        match self {
            Self::Upstream(response) => response.into_server_response(),
            Self::Stream {
                response,
                include_usage,
            } => completion_stream_response(&response, include_usage),
        }
    }
}

/// Handles `POST /v1/chat/completions` and `POST /v1/completions`.
pub fn handle(
    state: &ServerState,
    defaults: Defaults,
    path: &str,
    body: &[u8],
) -> HandlerResult<CompletionResponse> {
    let completion = parse_request(body, defaults).map_err(bad_request)?;
    state.stats()?.record_completion_started();
    let started_at = Instant::now();
    let response = state.client()?.run_chat_completion(
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
            state.stats()?.record_completion_success(CompletionSuccess {
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
            state.stats()?.record_completion_failure(CompletionFailure {
                model: &completion.model,
                path,
                request_bytes: completion.body.len(),
                duration,
                error: &message,
            });
            return Err(bad_gateway(error));
        }
    };

    if completion.stream && (200..300).contains(&response.status_code) {
        Ok(CompletionResponse::Stream {
            response,
            include_usage: completion.stream_include_usage,
        })
    } else {
        Ok(CompletionResponse::Upstream(Upstream(response)))
    }
}

/// Parses and sanitizes `OpenAI` completion JSON.
///
/// The model name is extracted for Cocoon routing. `Cocoon`-specific knobs
/// (`max_coefficient`, `timeout`) are removed from the forwarded JSON body,
/// while token limits are normalized for worker compatibility.
fn parse_request(body: &[u8], defaults: Defaults) -> anyhow::Result<CompletionRequest> {
    let mut value: Value = serde_json::from_slice(body).context("parse OpenAI request JSON")?;
    let object = value
        .as_object_mut()
        .context("OpenAI request JSON must be an object")?;

    let model = object
        .get("model")
        .and_then(Value::as_str)
        .context("OpenAI request requires string field 'model'")?
        .to_string();
    let stream = object
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let stream_include_usage = object
        .get("stream_options")
        .and_then(|stream_options| stream_options.get("include_usage"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

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
    if stream {
        object.insert("stream".to_string(), Value::from(false));
    }
    object.remove("stream_options");

    Ok(CompletionRequest {
        model,
        body: serde_json::to_vec(&value).context("serialize sanitized OpenAI request JSON")?,
        stream,
        stream_include_usage,
        max_coefficient,
        max_tokens,
        timeout,
    })
}

fn completion_stream_response(
    response: &rocoon_client::HttpExchange,
    include_usage: bool,
) -> anyhow::Result<ServerResponse> {
    let body = completion_stream_body(&response.payload, include_usage)?;
    sse_response(response.status_code, body)
}

fn sse_response(status_code: i32, body: Vec<u8>) -> anyhow::Result<ServerResponse> {
    let status_code =
        StatusCode(u16::try_from(status_code).context("HTTP status code out of range")?);
    response_with_body(
        status_code,
        vec![
            ("Content-Type".to_string(), "text/event-stream".to_string()),
            ("Cache-Control".to_string(), "no-cache".to_string()),
        ],
        body,
    )
}

fn completion_stream_body(payload: &[u8], include_usage: bool) -> anyhow::Result<Vec<u8>> {
    let response: Value =
        serde_json::from_slice(payload).context("parse completion response JSON")?;
    let object = response
        .as_object()
        .context("completion response JSON must be an object")?;
    let choices = object
        .get("choices")
        .and_then(Value::as_array)
        .context("completion response requires array field 'choices'")?;
    let metadata = stream_metadata(object);
    let uses_delta_chunks = uses_delta_chunks(object, choices);

    let mut body = Vec::new();
    for (position, choice) in choices.iter().enumerate() {
        write_completion_choice_stream_chunks(&mut body, &metadata, position, choice)?;
    }

    if include_usage
        && let Some(usage) = object
            .get("usage")
            .filter(|value| !value.is_null())
            .cloned()
    {
        if uses_delta_chunks {
            write_delta_stream_chunk(&mut body, &metadata, Value::Array(Vec::new()), Some(usage))?;
        } else {
            write_text_stream_chunk(&mut body, &metadata, Value::Array(Vec::new()), Some(usage))?;
        }
    }

    body.extend_from_slice(b"data: [DONE]\n\n");
    Ok(body)
}

struct StreamMetadata {
    id: Value,
    created: Value,
    model: Value,
    system_fingerprint: Option<Value>,
    service_tier: Option<Value>,
}

fn stream_metadata(object: &Map<String, Value>) -> StreamMetadata {
    StreamMetadata {
        id: object.get("id").cloned().unwrap_or(Value::Null),
        created: object
            .get("created")
            .cloned()
            .unwrap_or_else(|| Value::from(0)),
        model: object.get("model").cloned().unwrap_or(Value::Null),
        system_fingerprint: object.get("system_fingerprint").cloned(),
        service_tier: object.get("service_tier").cloned(),
    }
}

fn uses_delta_chunks(object: &Map<String, Value>, choices: &[Value]) -> bool {
    object
        .get("object")
        .and_then(Value::as_str)
        .is_some_and(|object| object == "chat.completion")
        || choices.iter().any(|choice| {
            choice
                .as_object()
                .is_some_and(|choice| choice.contains_key("message"))
        })
}

fn write_completion_choice_stream_chunks(
    body: &mut Vec<u8>,
    metadata: &StreamMetadata,
    position: usize,
    choice: &Value,
) -> anyhow::Result<()> {
    let choice_object = choice
        .as_object()
        .context("completion choice must be an object")?;
    if choice_object.contains_key("message") {
        write_delta_choice_stream_chunks(body, metadata, position, choice)
    } else {
        write_text_choice_stream_chunks(body, metadata, position, choice)
    }
}

fn write_delta_choice_stream_chunks(
    body: &mut Vec<u8>,
    metadata: &StreamMetadata,
    position: usize,
    choice: &Value,
) -> anyhow::Result<()> {
    let choice_object = choice
        .as_object()
        .context("completion choice must be an object")?;
    let index = choice_object
        .get("index")
        .cloned()
        .unwrap_or_else(|| Value::from(position));
    let message = choice_object
        .get("message")
        .and_then(Value::as_object)
        .context("completion choice requires object field 'message'")?;

    if let Some(role) = message.get("role").cloned() {
        write_delta_stream_chunk(
            body,
            metadata,
            delta_stream_choice(index.clone(), map_with_field("role", role), None),
            None,
        )?;
    }
    write_content_chunks(body, metadata, &index, message)?;
    write_extra_message_field_chunks(body, metadata, &index, message)?;
    write_finish_chunk(body, metadata, index, choice_object)
}

fn write_content_chunks(
    body: &mut Vec<u8>,
    metadata: &StreamMetadata,
    index: &Value,
    message: &Map<String, Value>,
) -> anyhow::Result<()> {
    let Some(content) = message.get("content").and_then(Value::as_str) else {
        return Ok(());
    };
    for content in split_content(content) {
        write_delta_stream_chunk(
            body,
            metadata,
            delta_stream_choice(
                index.clone(),
                map_with_field("content", Value::from(content)),
                None,
            ),
            None,
        )?;
    }
    Ok(())
}

fn write_extra_message_field_chunks(
    body: &mut Vec<u8>,
    metadata: &StreamMetadata,
    index: &Value,
    message: &Map<String, Value>,
) -> anyhow::Result<()> {
    for field in ["refusal", "tool_calls", "function_call"] {
        if let Some(value) = message.get(field).filter(|value| !value.is_null()).cloned() {
            write_delta_stream_chunk(
                body,
                metadata,
                delta_stream_choice(index.clone(), map_with_field(field, value), None),
                None,
            )?;
        }
    }
    Ok(())
}

fn write_finish_chunk(
    body: &mut Vec<u8>,
    metadata: &StreamMetadata,
    index: Value,
    choice_object: &Map<String, Value>,
) -> anyhow::Result<()> {
    let finish_reason = choice_object
        .get("finish_reason")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| Value::from("stop"));
    write_delta_stream_chunk(
        body,
        metadata,
        delta_stream_choice(index, Map::default(), Some(finish_reason)),
        None,
    )
}

fn write_delta_stream_chunk(
    body: &mut Vec<u8>,
    metadata: &StreamMetadata,
    choice: Value,
    usage: Option<Value>,
) -> anyhow::Result<()> {
    let chunk = delta_stream_chunk(DeltaStreamChunkInput {
        id: &metadata.id,
        created: &metadata.created,
        model: &metadata.model,
        system_fingerprint: metadata.system_fingerprint.as_ref(),
        service_tier: metadata.service_tier.as_ref(),
        choice,
        usage,
    });
    write_sse_json(body, &chunk)
}

fn write_text_choice_stream_chunks(
    body: &mut Vec<u8>,
    metadata: &StreamMetadata,
    position: usize,
    choice: &Value,
) -> anyhow::Result<()> {
    let choice_object = choice
        .as_object()
        .context("completion choice must be an object")?;
    let index = choice_object
        .get("index")
        .cloned()
        .unwrap_or_else(|| Value::from(position));
    let logprobs = choice_object
        .get("logprobs")
        .cloned()
        .unwrap_or(Value::Null);

    if let Some(text) = choice_object.get("text").and_then(Value::as_str) {
        for text in split_content(text) {
            write_text_stream_chunk(
                body,
                metadata,
                text_stream_choice(index.clone(), text, logprobs.clone(), None),
                None,
            )?;
        }
    }

    let finish_reason = choice_object
        .get("finish_reason")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| Value::from("stop"));
    write_text_stream_chunk(
        body,
        metadata,
        text_stream_choice(index, String::new(), logprobs, Some(finish_reason)),
        None,
    )
}

fn write_text_stream_chunk(
    body: &mut Vec<u8>,
    metadata: &StreamMetadata,
    choice: Value,
    usage: Option<Value>,
) -> anyhow::Result<()> {
    let chunk = text_stream_chunk(TextStreamChunkInput {
        id: &metadata.id,
        created: &metadata.created,
        model: &metadata.model,
        choice,
        usage,
    });
    write_sse_json(body, &chunk)
}

struct DeltaStreamChunkInput<'a> {
    id: &'a Value,
    created: &'a Value,
    model: &'a Value,
    system_fingerprint: Option<&'a Value>,
    service_tier: Option<&'a Value>,
    choice: Value,
    usage: Option<Value>,
}

struct TextStreamChunkInput<'a> {
    id: &'a Value,
    created: &'a Value,
    model: &'a Value,
    choice: Value,
    usage: Option<Value>,
}

fn delta_stream_chunk(input: DeltaStreamChunkInput<'_>) -> Value {
    let mut chunk = Map::new();
    chunk.insert("id".to_string(), input.id.clone());
    chunk.insert("object".to_string(), Value::from("chat.completion.chunk"));
    chunk.insert("created".to_string(), input.created.clone());
    chunk.insert("model".to_string(), input.model.clone());
    if let Some(system_fingerprint) = input.system_fingerprint {
        chunk.insert("system_fingerprint".to_string(), system_fingerprint.clone());
    }
    if let Some(service_tier) = input.service_tier {
        chunk.insert("service_tier".to_string(), service_tier.clone());
    }
    chunk.insert(
        "choices".to_string(),
        match input.choice {
            Value::Array(choices) => Value::Array(choices),
            choice => Value::Array(vec![choice]),
        },
    );
    if let Some(usage) = input.usage {
        chunk.insert("usage".to_string(), usage);
    }
    Value::Object(chunk)
}

fn text_stream_chunk(input: TextStreamChunkInput<'_>) -> Value {
    let mut chunk = Map::new();
    chunk.insert("id".to_string(), input.id.clone());
    chunk.insert("object".to_string(), Value::from("text_completion"));
    chunk.insert("created".to_string(), input.created.clone());
    chunk.insert("model".to_string(), input.model.clone());
    chunk.insert(
        "choices".to_string(),
        match input.choice {
            Value::Array(choices) => Value::Array(choices),
            choice => Value::Array(vec![choice]),
        },
    );
    if let Some(usage) = input.usage {
        chunk.insert("usage".to_string(), usage);
    }
    Value::Object(chunk)
}

fn delta_stream_choice(
    index: Value,
    delta: Map<String, Value>,
    finish_reason: Option<Value>,
) -> Value {
    let mut choice = Map::new();
    choice.insert("index".to_string(), index);
    choice.insert("delta".to_string(), Value::Object(delta));
    choice.insert(
        "finish_reason".to_string(),
        finish_reason.unwrap_or(Value::Null),
    );
    Value::Object(choice)
}

fn text_stream_choice(
    index: Value,
    text: String,
    logprobs: Value,
    finish_reason: Option<Value>,
) -> Value {
    let mut choice = Map::new();
    choice.insert("text".to_string(), Value::from(text));
    choice.insert("index".to_string(), index);
    choice.insert("logprobs".to_string(), logprobs);
    choice.insert(
        "finish_reason".to_string(),
        finish_reason.unwrap_or(Value::Null),
    );
    Value::Object(choice)
}

fn map_with_field(name: &str, value: Value) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(name.to_string(), value);
    map
}

fn split_content(content: &str) -> Vec<String> {
    const CHUNK_CHARS: usize = 256;

    let mut chunks = Vec::new();
    let mut chunk = String::new();
    let mut chunk_len = 0;
    for character in content.chars() {
        chunk.push(character);
        chunk_len += 1;
        if chunk_len >= CHUNK_CHARS {
            chunks.push(std::mem::take(&mut chunk));
            chunk_len = 0;
        }
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    chunks
}

fn write_sse_json(body: &mut Vec<u8>, value: &Value) -> anyhow::Result<()> {
    body.extend_from_slice(b"data: ");
    serde_json::to_writer(&mut *body, value).context("serialize completion stream chunk")?;
    body.extend_from_slice(b"\n\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> Defaults {
        Defaults {
            max_coefficient: 100,
            max_tokens: 42,
            timeout: 30.0,
        }
    }

    #[test]
    fn parse_request_disables_upstream_streaming() {
        let completion = parse_request(
            br#"{
                "model": "test-model",
                "messages": [],
                "stream": true,
                "stream_options": { "include_usage": true },
                "max_tokens": 8
            }"#,
            defaults(),
        )
        .expect("streaming request should parse");

        let forwarded: Value =
            serde_json::from_slice(&completion.body).expect("forwarded body should be JSON");
        assert!(completion.stream);
        assert!(completion.stream_include_usage);
        assert_eq!(forwarded["stream"], Value::from(false));
        assert_eq!(forwarded["max_tokens"], Value::from(8));
        assert!(forwarded.get("stream_options").is_none());
    }

    #[test]
    fn completion_stream_body_converts_message_choices_to_sse() {
        let body = completion_stream_body(
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
        .expect("message choices should convert to SSE");
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

    #[test]
    fn completion_stream_body_converts_text_choices_to_sse() {
        let body = completion_stream_body(
            br#"{
                "id": "cmpl-test",
                "object": "text_completion",
                "created": 123,
                "model": "test-model",
                "choices": [{
                    "text": "hello",
                    "index": 0,
                    "logprobs": null,
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
        .expect("text choices should convert to SSE");
        let body = String::from_utf8(body).expect("SSE body should be UTF-8");

        assert!(body.contains("data: {"));
        assert!(body.contains(r#""object":"text_completion""#));
        assert!(body.contains(r#""text":"hello""#));
        assert!(body.contains(r#""logprobs":null"#));
        assert!(body.contains(r#""finish_reason":"stop""#));
        assert!(body.contains(r#""choices":[]"#));
        assert!(body.contains(r#""usage":{"#));
        assert!(body.ends_with("data: [DONE]\n\n"));
    }
}
