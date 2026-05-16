//! HTTP response helpers for the local server.

use std::io::{Cursor, Read};

use anyhow::{Context, Result};
use rocoon_client::HttpExchange;
use tiny_http::{Header, Request, Response, StatusCode};

const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_BODY_READ_LIMIT: u64 = 32 * 1024 * 1024 + 1;

pub type ServerResponse = Response<Cursor<Vec<u8>>>;
pub type HandlerError = (StatusCode, anyhow::Error);
pub type HandlerResult<T> = std::result::Result<T, HandlerError>;

pub struct Json<T> {
    status_code: StatusCode,
    value: T,
}

impl<T> Json<T> {
    pub const fn new(status_code: StatusCode, value: T) -> Self {
        Self { status_code, value }
    }

    pub const fn ok(value: T) -> Self {
        Self::new(StatusCode(200), value)
    }
}

pub struct Upstream(pub HttpExchange);

pub trait IntoServerResponse {
    fn into_server_response(self) -> Result<ServerResponse>;
}

impl<T> IntoServerResponse for Json<T>
where
    T: serde::Serialize,
{
    fn into_server_response(self) -> Result<ServerResponse> {
        json_response(self.status_code, &self.value)
    }
}

impl IntoServerResponse for Upstream {
    fn into_server_response(self) -> Result<ServerResponse> {
        upstream_response(self.0)
    }
}

pub fn finalize<T>(result: HandlerResult<T>) -> HandlerResult<ServerResponse>
where
    T: IntoServerResponse,
{
    result.and_then(|response| response.into_server_response().map_err(internal))
}

pub const fn bad_request(error: anyhow::Error) -> HandlerError {
    (StatusCode(400), error)
}

pub const fn bad_gateway(error: anyhow::Error) -> HandlerError {
    (StatusCode(502), error)
}

pub const fn internal(error: anyhow::Error) -> HandlerError {
    (StatusCode(500), error)
}

pub fn internal_message(message: &'static str) -> HandlerError {
    (StatusCode(500), anyhow::anyhow!(message))
}

pub fn read_body(request: &mut Request) -> Result<Vec<u8>> {
    if request
        .body_length()
        .is_some_and(|body_len| body_len > MAX_BODY_BYTES)
    {
        anyhow::bail!("HTTP body too large");
    }

    let mut body = Vec::new();
    request
        .as_reader()
        .take(MAX_BODY_READ_LIMIT)
        .read_to_end(&mut body)
        .context("read HTTP body")?;
    if body.len() > MAX_BODY_BYTES {
        anyhow::bail!("HTTP body too large");
    }
    Ok(body)
}

/// Splits an HTTP request target into path and raw query string.
pub fn split_path_query(path: &str) -> (&str, &str) {
    path.split_once('?')
        .map_or((path, ""), |(path, query)| (path, query))
}

/// Converts a Cocoon worker HTTP response into a local response.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn upstream_response(response: HttpExchange) -> Result<ServerResponse> {
    let headers = sanitized_response_headers(response.headers);
    let status_code = StatusCode(response.status_code as u16);
    response_with_body(status_code, headers, response.payload)
}

/// Builds a JSON response with a generated HTTP status line and length.
pub fn json_response(
    status_code: StatusCode,
    value: &(impl serde::Serialize + ?Sized),
) -> Result<ServerResponse> {
    let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    let body = serde_json::to_vec(value).context("serialize JSON response")?;
    response_with_body(status_code, headers, body)
}

pub fn response_with_body(
    status_code: StatusCode,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<ServerResponse> {
    let mut response = Response::from_data(body)
        .with_status_code(status_code)
        .with_chunked_threshold(usize::MAX);
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    {
        response.add_header(header("Content-Type", "application/json")?);
    }
    for (name, value) in headers {
        response.add_header(header(&name, &value)?);
    }
    Ok(response)
}

fn header(name: &str, value: &str) -> Result<Header> {
    Header::from_bytes(name.as_bytes(), value.as_bytes())
        .map_err(|()| anyhow::anyhow!("invalid HTTP response header {name}: {value}"))
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
