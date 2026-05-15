//! Cocoon TL schema bindings and encoding helpers.
//!
//! The Cocoon proxy speaks a TL-based protocol. Most message types in this
//! file are thin Rust representations of those wire objects and are used only
//! for serialization/deserialization. `tl-proto` handles most objects, but
//! `client.runQueryEx` is encoded manually because this prototype needs exact
//! compatibility with Cocoon's current double/flag layout.

use anyhow::{Context, Result};
use tl_proto::{TlRead, TlWrite};

/// Request limits and protocol options for `client.runQueryEx`.
#[derive(Debug, Clone, Copy)]
pub struct RunQueryOptions {
    /// Maximum worker price coefficient the client accepts.
    pub max_coefficient: i32,
    /// Maximum tokens the worker may spend for this request.
    pub max_tokens: i32,
    /// Worker timeout in seconds.
    pub timeout: f64,
    /// Minimum accepted on-chain Cocoon config version.
    pub min_config_version: i32,
    /// Optional receiver public key for encrypted requests in proto >= 3.
    ///
    /// The C++ client passes the parsed `receiver_public_key` field here. A
    /// zero key is accepted by the proxy and means the request is unencrypted.
    pub public_key: Option<[u8; 32]>,
}

/// Parameters embedded into `client.connectToProxy`.
#[derive(Debug, TlWrite)]
#[allow(dead_code)]
struct ClientParams<'a> {
    #[tl(flags)]
    flags: (),
    client_owner_address: &'a [u8],
    #[tl(flags_bit = 0)]
    is_test: Option<bool>,
    #[tl(flags_bit = 1)]
    min_proto_version: Option<i32>,
    #[tl(flags_bit = 1)]
    max_proto_version: Option<i32>,
}

/// TL request that starts Cocoon proxy authorization.
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0xff5fa0f4)]
struct ClientConnectToProxy<'a> {
    params: ClientParams<'a>,
    min_config_version: i32,
}

/// TL request for short authorization using a shared secret.
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0x6c276723)]
struct ClientAuthorizeWithProxyShort<'a> {
    data: &'a [u8],
}

/// TL request for model and worker discovery.
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0xb2133d72)]
struct ClientGetWorkerTypesV2;

/// HTTP header encoded inside Cocoon's TL `http.request`/`http.response`.
#[derive(Debug, TlWrite, TlRead)]
pub struct HttpHeader<'tl> {
    /// Header name as raw bytes.
    pub name: &'tl [u8],
    /// Header value as raw bytes.
    pub value: &'tl [u8],
}

/// TL representation of an HTTP request forwarded to a Cocoon worker.
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
#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x1cd0c42b)]
#[allow(dead_code)]
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

/// Successful `client.connectToProxy` response.
///
/// This carries proxy parameters, the derived client contract address, and the
/// authorization mode the client must use next.
#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x95317ad1)]
#[allow(dead_code)]
pub struct ConnectedToProxy<'tl> {
    pub params: ProxyParams<'tl>,
    pub client_sc_address: &'tl [u8],
    pub auth: ProxyAuth<'tl>,
    pub signed_payment: SignedPayment<'tl>,
}

/// Proxy metadata returned during connection setup.
#[derive(Debug, TlRead)]
#[allow(dead_code)]
pub struct ProxyParams<'tl> {
    #[tl(flags)]
    flags: (),
    pub proxy_public_key: &'tl [u8; 32],
    pub proxy_owner_address: &'tl [u8],
    pub proxy_sc_address: &'tl [u8],
    #[tl(flags_bit = 0)]
    pub is_test: Option<bool>,
    #[tl(flags_bit = 1)]
    pub proto_version: Option<i32>,
}

/// Authorization mode selected by the proxy.
#[derive(Debug, TlRead)]
#[tl(boxed)]
#[allow(dead_code)]
pub enum ProxyAuth<'tl> {
    /// Existing registered client can authorize with a shared secret.
    #[tl(id = 0xd6ffc5af)]
    Short {
        secret_hash: &'tl [u8; 32],
        nonce: i64,
    },
    /// Client must perform on-chain registration before requests can run.
    #[tl(id = 0x417bf016)]
    Long { nonce: i64 },
}

/// Optional signed payment data returned by authorization.
#[derive(Debug, TlRead)]
#[tl(boxed)]
#[allow(dead_code)]
pub enum SignedPayment<'tl> {
    #[tl(id = 0x02998182)]
    Data { data: &'tl [u8] },
    #[tl(id = 0xb347ce64)]
    Empty,
}

/// Result of `client.authorizeWithProxyShort`.
#[derive(Debug, TlRead)]
#[tl(boxed)]
#[allow(dead_code)]
pub enum AuthorizationWithProxy<'tl> {
    /// Authorization succeeded and the proxy returned current token limits.
    #[tl(id = 0x75d5ac34)]
    Success {
        signed_payment: SignedPayment<'tl>,
        tokens_committed_to_db: i64,
        max_tokens: i64,
    },
    /// Authorization failed with a proxy-provided error.
    #[tl(id = 0x60551c96)]
    Failed { error_code: i32, error: &'tl [u8] },
}

/// Response object for `client.getWorkerTypesV2`.
#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x0cf0dc67)]
pub struct WorkerTypesV2<'tl> {
    /// All known model types returned by the proxy.
    pub types: Vec<WorkerTypeV2<'tl>>,
}

/// One model type and its currently available workers.
#[derive(Debug, TlRead)]
pub struct WorkerTypeV2<'tl> {
    /// Model name, for example `Qwen/Qwen3-32B`.
    pub name: &'tl [u8],
    /// Worker instances currently advertising this model.
    pub workers: Vec<WorkerInstanceV2>,
}

/// Worker capacity and price metadata returned by the proxy.
#[derive(Debug, TlRead)]
#[allow(dead_code)]
pub struct WorkerInstanceV2 {
    #[tl(flags)]
    flags: (),
    pub coefficient: i32,
    pub active_requests: i32,
    pub max_active_requests: i32,
}

/// Final metadata optionally attached to the last query answer packet.
///
/// The current HTTP bridge does not expose this object directly, but it is part
/// of the TL schema and marks the end of a streamed Cocoon answer.
#[derive(Debug, TlRead)]
#[allow(dead_code)]
pub struct QueryFinalInfo<'tl> {
    #[tl(flags)]
    flags: (),
    pub tokens_used: TokensUsedTl,
    #[tl(flags_bit = 0)]
    pub worker_debug: Option<&'tl [u8]>,
    #[tl(flags_bit = 0)]
    pub proxy_debug: Option<&'tl [u8]>,
    #[tl(flags_bit = 1)]
    pub proxy_start_time: Option<f64>,
    #[tl(flags_bit = 1)]
    pub proxy_end_time: Option<f64>,
    #[tl(flags_bit = 1)]
    pub worker_start_time: Option<f64>,
    #[tl(flags_bit = 1)]
    pub worker_end_time: Option<f64>,
}

/// Token usage counters inside `QueryFinalInfo`.
#[derive(Debug, Clone, Copy, TlRead)]
#[allow(clippy::struct_field_names, dead_code)]
pub struct TokensUsedTl {
    pub prompt_tokens_used: i64,
    pub cached_tokens_used: i64,
    pub completion_tokens_used: i64,
    pub reasoning_tokens_used: i64,
    pub total_tokens_used: i64,
}

/// Streamed answer variants for `client.runQueryEx`.
#[derive(Debug, TlRead)]
#[tl(boxed)]
#[allow(dead_code)]
pub enum QueryAnswerEx<'tl> {
    /// First packet containing the encoded HTTP response head.
    #[tl(id = 0xcd524720)]
    Answer {
        request_id: &'tl [u8; 32],
        answer: &'tl [u8],
        #[tl(flags)]
        flags: (),
        #[tl(flags_bit = 0)]
        final_info: Option<QueryFinalInfo<'tl>>,
    },
    /// Error packet for the matching request id.
    #[tl(id = 0x072562a8)]
    Error {
        request_id: &'tl [u8; 32],
        error_code: i32,
        error: &'tl [u8],
        #[tl(flags)]
        flags: (),
        #[tl(flags_bit = 0)]
        final_info: Option<QueryFinalInfo<'tl>>,
    },
    /// Additional response body bytes after the first answer packet.
    #[tl(id = 0xc07bfaec)]
    Part {
        request_id: &'tl [u8; 32],
        answer: &'tl [u8],
        #[tl(flags)]
        flags: (),
        #[tl(flags_bit = 0)]
        final_info: Option<QueryFinalInfo<'tl>>,
    },
}

/// Encodes `client.connectToProxy`.
pub fn encode_connect_to_proxy(owner_address: &str, min_config_version: i32) -> Vec<u8> {
    tl_proto::serialize(ClientConnectToProxy {
        params: ClientParams {
            flags: (),
            client_owner_address: owner_address.as_bytes(),
            is_test: Some(false),
            min_proto_version: Some(1),
            max_proto_version: Some(4),
        },
        min_config_version,
    })
}

/// Encodes `client.authorizeWithProxyShort`.
pub fn encode_authorize_with_proxy_short(secret: &str) -> Vec<u8> {
    tl_proto::serialize(ClientAuthorizeWithProxyShort {
        data: secret.as_bytes(),
    })
}

/// Encodes `client.getWorkerTypesV2`.
pub fn encode_get_worker_types_v2() -> Vec<u8> {
    tl_proto::serialize(ClientGetWorkerTypesV2)
}

/// Encodes Cocoon's internal `http.request` object.
///
/// This is the request that Cocoon workers receive through `client.runQueryEx`.
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

/// Encodes `client.runQueryEx`.
///
/// This is intentionally manual rather than `TlWrite`-derived because exact
/// field order and primitive encoding are critical for proxy compatibility.
pub fn encode_run_query_ex(
    model: &str,
    query: &[u8],
    request_id: &[u8; 32],
    options: RunQueryOptions,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xf54c_b74b_u32.to_le_bytes());
    write_tl_bytes(&mut out, model.as_bytes());
    write_tl_bytes(&mut out, query);
    out.extend_from_slice(&options.max_coefficient.to_le_bytes());
    out.extend_from_slice(&options.max_tokens.to_le_bytes());
    out.extend_from_slice(&options.timeout.to_bits().to_le_bytes());
    out.extend_from_slice(request_id);
    out.extend_from_slice(&options.min_config_version.to_le_bytes());

    let mut flags = 1u32;
    if options.public_key.is_some() {
        flags |= 2;
    }
    out.extend_from_slice(&flags.to_le_bytes());
    write_tl_bool(&mut out, false);
    if let Some(public_key) = options.public_key {
        out.extend_from_slice(&public_key);
    }
    out
}

/// Decodes `client.connectedToProxy`.
pub fn decode_connected_to_proxy(raw: &[u8]) -> Result<ConnectedToProxy<'_>> {
    tl_proto::deserialize::<ConnectedToProxy>(raw).context("decode client.connectedToProxy")
}

/// Decodes `client.authorizationWithProxy`.
pub fn decode_authorization_with_proxy(raw: &[u8]) -> Result<AuthorizationWithProxy<'_>> {
    tl_proto::deserialize::<AuthorizationWithProxy>(raw)
        .context("decode client.authorizationWithProxy")
}

/// Decodes `client.workerTypesV2`.
pub fn decode_worker_types_v2(raw: &[u8]) -> Result<WorkerTypesV2<'_>> {
    tl_proto::deserialize::<WorkerTypesV2>(raw).context("decode client.workerTypesV2")
}

/// Decodes any `client.queryAnswer*Ex` packet.
pub fn decode_query_answer_ex(raw: &[u8]) -> Result<QueryAnswerEx<'_>> {
    tl_proto::deserialize::<QueryAnswerEx>(raw).context("decode client.QueryAnswerEx")
}

/// Decodes Cocoon's internal `http.response` object.
pub fn decode_http_response(raw: &[u8]) -> Result<HttpResponse<'_>> {
    tl_proto::deserialize::<HttpResponse>(raw).context("decode http.response")
}

/// Writes a TL byte string with the required four-byte alignment.
#[allow(clippy::branches_sharing_code, clippy::cast_possible_truncation)]
fn write_tl_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = bytes.len();
    if len < 254 {
        out.push(len as u8);
        out.extend_from_slice(bytes);
        pad_to_four(out);
    } else {
        out.push(254);
        out.push((len & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        out.extend_from_slice(bytes);
        pad_to_four(out);
    }
}

/// Writes the boxed TL boolean constructor used by Cocoon.
fn write_tl_bool(out: &mut Vec<u8>, value: bool) {
    let magic = if value {
        0x9972_75b5_u32
    } else {
        0xbc79_9737_u32
    };
    out.extend_from_slice(&magic.to_le_bytes());
}

/// Pads the current buffer to the next TL four-byte boundary.
fn pad_to_four(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}
