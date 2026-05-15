//! Minimal HTTP/1.x parsing and response writing used by the local server.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;

use anyhow::{Context, Result};
use rocoon_client::HttpExchange;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Minimal parsed HTTP request shape needed by this server.
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// HTTP error carrying enough context to respond on the original stream.
pub struct Error {
    pub stream: Option<TcpStream>,
    pub status_code: i32,
    pub message: String,
}

impl Error {
    /// Builds an error from an `anyhow::Error`.
    pub fn new(stream: Option<TcpStream>, status_code: i32, error: &anyhow::Error) -> Self {
        Self {
            stream,
            status_code,
            message: format!("{error:#}"),
        }
    }

    /// Builds an error from a static message.
    pub fn message(stream: Option<TcpStream>, status_code: i32, message: &str) -> Self {
        Self {
            stream,
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

/// Reads and parses one HTTP/1.x request from a stream.
///
/// This parser intentionally supports only what the local bridge needs:
/// request line, headers, `Content-Length`, and a bounded body.
pub fn read_request(stream: &mut TcpStream) -> Result<Request> {
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

    Ok(Request { method, path, body })
}

/// Splits an HTTP request target into path and raw query string.
pub fn split_path_query(path: &str) -> (&str, &str) {
    path.split_once('?')
        .map_or((path, ""), |(path, query)| (path, query))
}

/// Writes a Cocoon worker HTTP response back to the local client.
pub fn write_upstream_response(stream: &mut TcpStream, response: HttpExchange) -> Result<()> {
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
pub fn write_json(
    stream: &mut TcpStream,
    status_code: i32,
    value: &(impl serde::Serialize + ?Sized),
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
