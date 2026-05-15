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
use std::time::Instant;

use anyhow::{Context, Result};
use serde_json::{Map, Value, json};

use rocoon_client::{COCOON_WALLET_RESERVE_NANOTONS, CocoonClient, HttpExchange, TonControlAction};

mod stats;
use stats::{CompletionFailure, CompletionSuccess, ServerStats};

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

/// Shared state for all local HTTP request handler threads.
struct ServerState {
    client: Mutex<CocoonClient>,
    stats: Mutex<ServerStats>,
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

/// Request shape for sweeping the Cocoon wallet after contract close.
struct WalletSweepRequest {
    destination_address: Option<String>,
    reserve_nanotons: u64,
}

/// Serves the local OpenAI-compatible API forever.
///
/// Supported endpoints are `/health`, `/stats`, `/jsonstats`, `/v1/stats`,
/// `/v1/models`, `/v1/chat/completions`, and `/v1/completions`. Each accepted
/// TCP connection is handled on a separate thread while access to the
/// underlying Cocoon client remains serialized.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or an incoming TCP connection
/// cannot be accepted. Per-request failures are converted to JSON HTTP errors
/// and do not stop the listener.
pub fn serve(listen_addr: &str, client: CocoonClient, defaults: Defaults) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).with_context(|| format!("bind {listen_addr}"))?;
    println!("OpenAI-compatible HTTP server listening on http://{listen_addr}");

    let state = Arc::new(ServerState {
        client: Mutex::new(client),
        stats: Mutex::new(ServerStats::default()),
    });
    for stream in listener.incoming() {
        let stream = stream.context("accept HTTP connection")?;
        let state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, &state, defaults) {
                eprintln!("HTTP request failed: {error:#}");
                if let Some(mut stream) = error.stream {
                    let body = json!({"error": {"message": error.message, "type": "rocoon_error"}});
                    let _ = write_json(&mut stream, error.status_code, &body, Vec::new());
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
    state: &ServerState,
    defaults: Defaults,
) -> std::result::Result<(), HttpError> {
    let request = read_http_request(&mut stream)
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 400, &error))?;
    let (path, query) = split_path_query(&request.path);

    match (request.method.as_str(), path) {
        ("GET", "/health") => write_json(&mut stream, 200, &json!({"status": "ok"}), Vec::new())
            .map_err(|error| HttpError::new(None, 500, &error)),
        ("GET", "/stats" | "/jsonstats" | "/v1/stats") => handle_stats(&mut stream, state),
        ("GET", "/v1/models") => handle_models(&mut stream, state),
        ("GET" | "POST", "/request/withdraw") => {
            handle_control(&mut stream, state, TonControlAction::Withdraw, query)
        }
        ("GET" | "POST", "/request/close") => {
            handle_control(&mut stream, state, TonControlAction::RequestRefund, query)
        }
        ("GET" | "POST", "/wallet/withdraw" | "/wallet/sweep") => {
            handle_wallet_sweep(&mut stream, state, query, &request.body)
        }
        ("POST", "/v1/chat/completions" | "/v1/completions") => {
            handle_completion(&mut stream, state, defaults, path, &request.body)
        }
        _ => write_json(
            &mut stream,
            404,
            &json!({"error": {"message": "not found", "type": "invalid_request_error"}}),
            Vec::new(),
        )
        .map_err(|error| HttpError::new(None, 500, &error)),
    }
}

/// Writes the local runtime statistics response.
fn handle_stats(stream: &mut TcpStream, state: &ServerState) -> std::result::Result<(), HttpError> {
    let client_status = state
        .client
        .lock()
        .map_err(|_| {
            HttpError::message(stream.try_clone().ok(), 500, "Cocoon client mutex poisoned")
        })?
        .status();
    let stats_json = state
        .stats
        .lock()
        .map_err(|_| HttpError::message(stream.try_clone().ok(), 500, "stats mutex poisoned"))?
        .to_json(&client_status);
    write_json(stream, 200, &stats_json, Vec::new())
        .map_err(|error| HttpError::new(None, 500, &error))
}

/// Writes `/v1/models` from Cocoon worker metadata.
fn handle_models(
    stream: &mut TcpStream,
    state: &ServerState,
) -> std::result::Result<(), HttpError> {
    let models = state
        .client
        .lock()
        .map_err(|_| {
            HttpError::message(stream.try_clone().ok(), 500, "Cocoon client mutex poisoned")
        })?
        .get_worker_types_v2()
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 502, &error))?;
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
        stream,
        200,
        &json!({"object": "list", "data": data}),
        Vec::new(),
    )
    .map_err(|error| HttpError::new(None, 500, &error))
}

/// Sends a Cocoon client-contract control message via the local wallet.
fn handle_control(
    stream: &mut TcpStream,
    state: &ServerState,
    action: TonControlAction,
    query: &str,
) -> std::result::Result<(), HttpError> {
    let proxy = query_param(query, "proxy");
    let result = state
        .client
        .lock()
        .map_err(|_| {
            HttpError::message(stream.try_clone().ok(), 500, "Cocoon client mutex poisoned")
        })?
        .request_control(action, proxy.as_deref())
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 502, &error))?;
    write_json(
        stream,
        200,
        &json!({
            "object": "rocoon.control",
            "status": "sent",
            "action": result.action.as_str(),
            "query_id": result.query_id,
            "wallet_seqno": result.wallet_seqno,
            "attached_value": result.attached_value,
            "send_status": result.send_status,
            "client_sc_address": result.client_contract_address,
            "wallet_address": result.wallet_address
        }),
        Vec::new(),
    )
    .map_err(|error| HttpError::new(None, 500, &error))
}

/// Sends sweepable Cocoon wallet funds back to the owner wallet.
fn handle_wallet_sweep(
    stream: &mut TcpStream,
    state: &ServerState,
    query: &str,
    body: &[u8],
) -> std::result::Result<(), HttpError> {
    let request = parse_wallet_sweep_request(query, body)
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 400, &error))?;
    let result = state
        .client
        .lock()
        .map_err(|_| {
            HttpError::message(stream.try_clone().ok(), 500, "Cocoon client mutex poisoned")
        })?
        .sweep_cocoon_wallet(
            request.destination_address.as_deref(),
            request.reserve_nanotons,
        )
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 502, &error))?;
    write_json(
        stream,
        200,
        &json!({
            "object": "rocoon.wallet_withdraw",
            "status": "sent",
            "wallet_seqno": result.wallet_seqno,
            "amount": result.amount,
            "amount_ton": format_nanotons_u64_as_ton(result.amount),
            "reserve": request.reserve_nanotons,
            "reserve_ton": format_nanotons_u64_as_ton(request.reserve_nanotons),
            "send_status": result.send_status,
            "destination_address": result.destination_address,
            "wallet_address": result.wallet_address
        }),
        Vec::new(),
    )
    .map_err(|error| HttpError::new(None, 500, &error))
}

/// Runs a completion request and records local usage statistics.
fn handle_completion(
    stream: &mut TcpStream,
    state: &ServerState,
    defaults: Defaults,
    path: &str,
    body: &[u8],
) -> std::result::Result<(), HttpError> {
    let completion = parse_completion_request(body, defaults)
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 400, &error))?;
    state
        .stats
        .lock()
        .map_err(|_| HttpError::message(stream.try_clone().ok(), 500, "stats mutex poisoned"))?
        .record_completion_started();
    let started_at = Instant::now();
    let response = state
        .client
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
        );
    let duration = started_at.elapsed();
    let response = match response {
        Ok(response) => {
            state
                .stats
                .lock()
                .map_err(|_| {
                    HttpError::message(stream.try_clone().ok(), 500, "stats mutex poisoned")
                })?
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
                .map_err(|_| {
                    HttpError::message(stream.try_clone().ok(), 500, "stats mutex poisoned")
                })?
                .record_completion_failure(CompletionFailure {
                    model: &completion.model,
                    path,
                    request_bytes: completion.body.len(),
                    duration,
                    error: &message,
                });
            return Err(HttpError::new(stream.try_clone().ok(), 502, &error));
        }
    };
    write_cocoon_http_response(stream, response).map_err(|error| HttpError::new(None, 500, &error))
}

/// HTTP error carrying enough context to respond on the original stream.
struct HttpError {
    stream: Option<TcpStream>,
    status_code: i32,
    message: String,
}

impl HttpError {
    /// Builds an error from an `anyhow::Error`.
    fn new(stream: Option<TcpStream>, status_code: i32, error: &anyhow::Error) -> Self {
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

/// Splits an HTTP request target into path and raw query string.
fn split_path_query(path: &str) -> (&str, &str) {
    path.split_once('?')
        .map_or((path, ""), |(path, query)| (path, query))
}

/// Reads and URL-decodes a query parameter.
fn query_param(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .find_map(|part| {
            let (raw_key, raw_value) = part.split_once('=').unwrap_or((part, ""));
            let key = url_decode_query_component(raw_key)?;
            (key == name)
                .then(|| url_decode_query_component(raw_value))
                .flatten()
        })
}

fn url_decode_query_component(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        match byte {
            b'+' => decoded.push(b' '),
            b'%' => {
                let high = bytes.next()?;
                let low = bytes.next()?;
                decoded.push((hex_value(high)? << 4) | hex_value(low)?);
            }
            _ => decoded.push(byte),
        }
    }
    String::from_utf8(decoded).ok()
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parses and sanitizes `OpenAI` completion JSON.
///
/// The model name is extracted for Cocoon routing. `Cocoon`-specific knobs
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

/// Parses `/wallet/withdraw` query parameters and optional JSON body.
fn parse_wallet_sweep_request(query: &str, body: &[u8]) -> Result<WalletSweepRequest> {
    let mut destination_address = query_param(query, "to")
        .or_else(|| query_param(query, "destination_address"))
        .filter(|address| !address.is_empty());
    let mut reserve_nanotons = query_param(query, "reserve_nanotons")
        .or_else(|| query_param(query, "reserve"))
        .map(|value| parse_u64_string("reserve_nanotons", &value))
        .transpose()?
        .unwrap_or(COCOON_WALLET_RESERVE_NANOTONS);
    if let Some(amount) = query_param(query, "amount")
        && amount != "all"
    {
        anyhow::bail!("wallet withdraw supports only amount=all");
    }

    if body.is_empty() {
        return Ok(WalletSweepRequest {
            destination_address,
            reserve_nanotons,
        });
    }

    let value: Value = serde_json::from_slice(body).context("parse wallet withdraw JSON")?;
    let object = value
        .as_object()
        .context("wallet withdraw JSON must be an object")?;
    if let Some(value) = object
        .get("to")
        .or_else(|| object.get("destination_address"))
    {
        destination_address =
            json_optional_string(value, "to")?.filter(|address| !address.is_empty());
    }
    if let Some(value) = object
        .get("reserve_nanotons")
        .or_else(|| object.get("reserve"))
    {
        reserve_nanotons = parse_u64_json("reserve_nanotons", value)?;
    }
    if let Some(value) = object.get("amount")
        && !value.is_null()
        && value.as_str().is_none_or(|amount| amount != "all")
    {
        anyhow::bail!("wallet withdraw supports only amount=\"all\"");
    }

    Ok(WalletSweepRequest {
        destination_address,
        reserve_nanotons,
    })
}

/// Parses a non-negative integer stored as a query string.
fn parse_u64_string(field: &str, value: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .with_context(|| format!("parse {field} as u64"))
}

/// Parses a non-negative integer stored either as JSON number or string.
fn parse_u64_json(field: &str, value: &Value) -> Result<u64> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }
    if let Some(string) = value.as_str() {
        return parse_u64_string(field, string);
    }
    anyhow::bail!("{field} must be a non-negative integer")
}

/// Reads an optional string field from JSON.
fn json_optional_string(value: &Value, field: &str) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .map(|value| Some(value.to_string()))
        .with_context(|| format!("{field} must be a string or null"))
}

/// Formats a nanoton amount as a fixed 9-decimal TON string.
fn format_nanotons_u64_as_ton(value: u64) -> String {
    let whole = value / 1_000_000_000;
    let frac = value % 1_000_000_000;
    format!("{whole}.{frac:09}")
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
    value: &Value,
    headers: Vec<(String, String)>,
) -> Result<()> {
    let mut headers = headers;
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    let body = serde_json::to_vec(value).context("serialize JSON response")?;
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

    write!(stream, "HTTP/1.1 {status_code} {reason}\r\n").context("write status line")?;
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
const fn reason_phrase(status_code: i32) -> &'static str {
    match status_code {
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
            chars.next().map_or_else(String::new, |first| {
                format!("{}{}", first.to_ascii_uppercase(), chars.as_str())
            })
        })
        .collect::<Vec<_>>()
        .join("-")
}
