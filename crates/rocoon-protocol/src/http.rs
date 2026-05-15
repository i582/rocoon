//! TL objects in the `http.*` namespace.

use anyhow::{Context, Result};
use tl_proto::{TlRead, TlWrite};

/// HTTP header encoded inside Cocoon's TL `http.request`/`http.response`.
///
/// Source TL:
///
/// ```tl
/// http.header
///     name:string
///     value:string
///     = http.Header;
/// ```
#[derive(Debug, TlWrite, TlRead)]
pub struct HttpHeader<'tl> {
    /// Header name as raw bytes.
    pub name: &'tl [u8],
    /// Header value as raw bytes.
    pub value: &'tl [u8],
}

/// TL representation of an HTTP request forwarded to a Cocoon worker.
///
/// Source TL:
///
/// ```tl
/// http.request
///     method:string
///     url:string
///     http_version:string
///     headers:(vector http.header)
///     payload:bytes
///     = http.Response;
/// ```
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0x47492de5)]
struct HttpRequest<'a> {
    method: &'a [u8],
    url: &'a [u8],
    http_version: &'a [u8],
    headers: Vec<HttpHeader<'a>>,
    payload: &'a [u8],
}

/// TL representation of an HTTP response returned by a Cocoon worker.
///
/// Source TL:
///
/// ```tl
/// http.response
///     http_version:string
///     status_code:int
///     reason:string
///     headers:(vector http.header)
///     payload:bytes
///     = http.Response;
/// ```
#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x1cd0c42b)]
pub struct HttpResponse<'tl> {
    /// Worker-provided HTTP version string.
    pub http_version: &'tl [u8],
    /// Worker-provided HTTP status code.
    pub status_code: i32,
    /// Worker-provided HTTP reason phrase.
    pub reason: &'tl [u8],
    /// Worker-provided response headers.
    pub headers: Vec<HttpHeader<'tl>>,
    /// First response body chunk.
    pub payload: &'tl [u8],
}

/// Encodes Cocoon's internal `http.request` object.
///
/// This is the request that Cocoon workers receive through `client.runQueryEx`.
#[must_use]
pub fn encode_http_request(
    method: &str,
    url: &str,
    headers: &[(&str, String)],
    payload: &[u8],
) -> Vec<u8> {
    let headers = headers
        .iter()
        .map(|(name, value)| HttpHeader {
            name: name.as_bytes(),
            value: value.as_bytes(),
        })
        .collect();
    tl_proto::serialize(HttpRequest {
        method: method.as_bytes(),
        url: url.as_bytes(),
        http_version: b"HTTP/1.0",
        headers,
        payload,
    })
}

/// Decodes Cocoon's internal `http.response` object.
///
/// # Errors
///
/// Returns an error when `raw` is not a valid boxed `http.response` TL object.
pub fn decode_http_response(raw: &[u8]) -> Result<HttpResponse<'_>> {
    tl_proto::deserialize::<HttpResponse>(raw).context("decode http.response")
}
