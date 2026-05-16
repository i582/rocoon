//! HTTP response helpers for the local server.

use std::io::{Cursor, Read};

use anyhow::{Context, Result};
use rocoon_client::HttpExchange;
use tiny_http::{Header, Request, Response, StatusCode};

const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_BODY_READ_LIMIT: u64 = 32 * 1024 * 1024 + 1;

pub type ServerResponse = Response<Cursor<Vec<u8>>>;

/// HTTP error carrying enough context to build an OpenAI-compatible response.
pub struct Error {
    pub status_code: i32,
    pub message: String,
}

impl Error {
    /// Builds an error from an `anyhow::Error`.
    pub fn new(status_code: i32, error: &anyhow::Error) -> Self {
        Self {
            status_code,
            message: format!("{error:#}"),
        }
    }

    /// Builds an error from a static message.
    pub fn message(status_code: i32, message: &str) -> Self {
        Self {
            status_code,
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
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
pub fn upstream_response(response: HttpExchange) -> Result<ServerResponse> {
    let headers = sanitized_response_headers(response.headers);
    response_with_body(response.status_code, headers, response.payload)
}

/// Builds a JSON response with a generated HTTP status line and length.
pub fn json_response(
    status_code: i32,
    value: &(impl serde::Serialize + ?Sized),
    headers: Vec<(String, String)>,
) -> Result<ServerResponse> {
    let mut headers = headers;
    headers.push(("Content-Type".to_string(), "application/json".to_string()));
    let body = serde_json::to_vec(value).context("serialize JSON response")?;
    response_with_body(status_code, headers, body)
}

fn response_with_body(
    status_code: i32,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<ServerResponse> {
    let status_code = u16::try_from(status_code).context("HTTP status code out of range")?;
    let mut response = Response::from_data(body)
        .with_status_code(StatusCode(status_code))
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
