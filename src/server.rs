//! Local OpenAI-compatible HTTP server.
//!
//! The server is deliberately small and synchronous: it accepts localhost HTTP
//! requests, translates the supported endpoints into `CocoonClient` calls, and
//! writes OpenAI-compatible responses. A single Cocoon session is protected by
//! a mutex so requests do not interleave bytes on the proxy connection.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::client::{CocoonClient, HttpExchange};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Default per-request limits used when an HTTP request omits them.
#[derive(Clone, Copy)]
pub struct Defaults {
    /// Default maximum accepted Cocoon worker price coefficient.
    pub max_coefficient: i32,
    /// Default maximum token count.
    pub max_tokens: i32,
    /// Default Cocoon request timeout in seconds.
    pub timeout: f64,
}

/// Minimal parsed HTTP request shape needed by this server.
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

/// Sanitized completion request plus Cocoon-specific execution limits.
struct CompletionRequest {
    model: String,
    body: Vec<u8>,
    max_coefficient: i32,
    max_tokens: i32,
    timeout: f64,
}

/// Serves the local OpenAI-compatible API forever.
///
/// Supported endpoints are `/health`, `/v1/models`, `/v1/chat/completions`,
/// and `/v1/completions`. Each accepted TCP connection is handled on a separate
/// thread while access to the underlying Cocoon client remains serialized.
pub fn serve(listen_addr: &str, client: CocoonClient, defaults: Defaults) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).with_context(|| format!("bind {listen_addr}"))?;
    println!("OpenAI-compatible HTTP server listening on http://{listen_addr}");

    let client = Arc::new(Mutex::new(client));
    for stream in listener.incoming() {
        let stream = stream.context("accept HTTP connection")?;
        let client = Arc::clone(&client);
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, client, defaults) {
                eprintln!("HTTP request failed: {error:#}");
                if let Some(mut stream) = error.stream {
                    let _ = write_json(
                        &mut stream,
                        error.status_code,
                        json!({"error": {"message": error.message, "type": "rocoon_error"}}),
                        Vec::new(),
                    );
                }
            }
        });
    }
    Ok(())
}

/// Handles one accepted HTTP connection.
///
/// Errors are represented as `HttpError` so the caller can still write a JSON
/// error response if the socket is usable.
fn handle_connection(
    mut stream: TcpStream,
    client: Arc<Mutex<CocoonClient>>,
    defaults: Defaults,
) -> std::result::Result<(), HttpError> {
    let request = read_http_request(&mut stream)
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 400, error))?;
    let path = request.path.split('?').next().unwrap_or(&request.path);

    match (request.method.as_str(), path) {
        ("GET", "/health") => write_json(&mut stream, 200, json!({"status": "ok"}), Vec::new())
            .map_err(|error| HttpError::new(None, 500, error)),
        ("GET", "/v1/models") => {
            let models = client
                .lock()
                .map_err(|_| {
                    HttpError::message(stream.try_clone().ok(), 500, "Cocoon client mutex poisoned")
                })?
                .get_worker_types_v2()
                .map_err(|error| HttpError::new(stream.try_clone().ok(), 502, error))?;
            let data: Vec<_> = models
                .into_iter()
                .map(|model| {
                    json!({
                        "id": model.id,
                        "object": "model",
                        "created": 0,
                        "owned_by": "?",
                        "workers": model.workers.into_iter().map(|worker| {
                            json!({
                                "coefficient": worker.coefficient,
                                "running_requests": worker.active_requests,
                                "max_running_requests": worker.max_active_requests,
                            })
                        }).collect::<Vec<_>>(),
                    })
                })
                .collect();
            write_json(
                &mut stream,
                200,
                json!({"object": "list", "data": data}),
                Vec::new(),
            )
            .map_err(|error| HttpError::new(None, 500, error))
        }
        ("POST", "/v1/chat/completions") | ("POST", "/v1/completions") => {
            let completion = parse_completion_request(&request.body, defaults)
                .map_err(|error| HttpError::new(stream.try_clone().ok(), 400, error))?;
            let response = client
                .lock()
                .map_err(|_| {
                    HttpError::message(stream.try_clone().ok(), 500, "Cocoon client mutex poisoned")
                })?
                .run_chat_completion(
                    &completion.model,
                    path,
                    &completion.body,
                    completion.max_coefficient,
                    completion.max_tokens,
                    completion.timeout,
                )
                .map_err(|error| HttpError::new(stream.try_clone().ok(), 502, error))?;
            write_cocoon_http_response(&mut stream, response)
                .map_err(|error| HttpError::new(None, 500, error))
        }
        _ => write_json(
            &mut stream,
            404,
            json!({"error": {"message": "not found", "type": "invalid_request_error"}}),
            Vec::new(),
        )
        .map_err(|error| HttpError::new(None, 500, error)),
    }
}

/// HTTP error carrying enough context to respond on the original stream.
struct HttpError {
    stream: Option<TcpStream>,
    status_code: i32,
    message: String,
}

impl HttpError {
    /// Builds an error from an `anyhow::Error`.
    fn new(stream: Option<TcpStream>, status_code: i32, error: anyhow::Error) -> Self {
        Self {
            stream,
            status_code,
            message: format!("{error:#}"),
        }
    }

    /// Builds an error from a static message.
    fn message(stream: Option<TcpStream>, status_code: i32, message: &str) -> Self {
        Self {
            stream,
            status_code,
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Reads and parses one HTTP/1.x request from a stream.
///
/// This parser intentionally supports only what the local bridge needs:
/// request line, headers, `Content-Length`, and a bounded body.
fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut data = Vec::new();
    let header_end = loop {
        if data.len() > MAX_HEADER_BYTES {
            anyhow::bail!("HTTP headers too large");
        }

        if let Some(pos) = find_header_end(&data) {
            break pos;
        }

        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).context("read HTTP request")?;
        if n == 0 {
            anyhow::bail!("connection closed before HTTP headers");
        }
        data.extend_from_slice(&buf[..n]);
    };

    let header_bytes = &data[..header_end];
    let header_text = std::str::from_utf8(header_bytes).context("HTTP headers are not UTF-8")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().context("missing HTTP request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .context("missing HTTP method")?
        .to_string();
    let path = request_parts
        .next()
        .context("missing HTTP path")?
        .to_string();

    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect();

    let content_length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.parse::<usize>())
        .transpose()
        .context("parse Content-Length")?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        anyhow::bail!("HTTP body too large");
    }

    let body_start = header_end + 4;
    let mut body = data[body_start..].to_vec();
    while body.len() < content_length {
        let mut buf = [0u8; 8192];
        let n = stream.read(&mut buf).context("read HTTP body")?;
        if n == 0 {
            anyhow::bail!("connection closed before HTTP body");
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_length);

    Ok(HttpRequest { method, path, body })
}

/// Parses and sanitizes OpenAI completion JSON.
///
/// The model name is extracted for Cocoon routing. Cocoon-specific knobs
/// (`max_coefficient`, `timeout`) are removed from the forwarded JSON body,
/// while token limits are normalized for worker compatibility.
fn parse_completion_request(body: &[u8], defaults: Defaults) -> Result<CompletionRequest> {
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
            .or_insert_with(|| Value::Object(Default::default()));
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

/// Writes a Cocoon worker HTTP response back to the local client.
fn write_cocoon_http_response(stream: &mut TcpStream, response: HttpExchange) -> Result<()> {
    let headers = sanitized_response_headers(response.headers);
    write_response(
        stream,
        response.status_code,
        &response.reason,
        headers,
        &response.payload,
    )
}

/// Writes a JSON response with a generated HTTP status line and length.
fn write_json(
    stream: &mut TcpStream,
    status_code: i32,
    value: Value,
    headers: Vec<(String, String)>,
) -> Result<()> {
    let mut headers = headers;
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    let body = serde_json::to_vec(&value).context("serialize JSON response")?;
    write_response(
        stream,
        status_code,
        reason_phrase(status_code),
        headers,
        &body,
    )
}

/// Writes a complete HTTP/1.1 response.
///
/// Header names are normalized through a map so generated `Content-Length` and
/// `Connection` values reliably override upstream values.
fn write_response(
    stream: &mut TcpStream,
    status_code: i32,
    reason: &str,
    headers: Vec<(String, String)>,
    body: &[u8],
) -> Result<()> {
    let mut normalized = HashMap::<String, String>::new();
    for (name, value) in headers {
        normalized.insert(name.to_ascii_lowercase(), value);
    }
    normalized
        .entry("content-type".to_string())
        .or_insert_with(|| "application/json".to_string());
    normalized.insert("content-length".to_string(), body.len().to_string());
    normalized.insert("connection".to_string(), "close".to_string());

    write!(stream, "HTTP/1.1 {} {}\r\n", status_code, reason).context("write status line")?;
    for (name, value) in normalized {
        write!(stream, "{}: {}\r\n", canonical_header_name(&name), value)
            .context("write response header")?;
    }
    write!(stream, "\r\n").context("write response header terminator")?;
    stream.write_all(body).context("write response body")?;
    stream.flush().context("flush response")
}

/// Removes hop-by-hop and Cocoon-internal response headers.
fn sanitized_response_headers(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter(|(name, _)| {
            !name.eq_ignore_ascii_case("content-length")
                && !name.eq_ignore_ascii_case("connection")
                && !name.eq_ignore_ascii_case("transfer-encoding")
                && !name.to_ascii_lowercase().starts_with("x-cocoon-")
        })
        .collect()
}

/// Finds the end of an HTTP header block.
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Returns a small reason phrase set for generated responses.
fn reason_phrase(status_code: i32) -> &'static str {
    match status_code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

/// Converts a lowercase header name into conventional HTTP casing.
fn canonical_header_name(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_ascii_uppercase(), chars.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}
