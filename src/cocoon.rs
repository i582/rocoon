use anyhow::{Context, Result};
use tl_proto::{TlRead, TlWrite};

#[derive(Debug, Clone, Copy)]
pub struct RunQueryOptions {
    pub max_coefficient: i32,
    pub max_tokens: i32,
    pub timeout: f64,
    pub min_config_version: i32,
    pub public_key: Option<[u8; 32]>,
}

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

#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0xff5fa0f4)]
struct ClientConnectToProxy<'a> {
    params: ClientParams<'a>,
    min_config_version: i32,
}

#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0x6c276723)]
struct ClientAuthorizeWithProxyShort<'a> {
    data: &'a [u8],
}

#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0xb2133d72)]
struct ClientGetWorkerTypesV2;

#[derive(Debug, TlWrite, TlRead)]
pub struct HttpHeader<'tl> {
    pub name: &'tl [u8],
    pub value: &'tl [u8],
}

#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0x47492de5)]
struct HttpRequest<'a> {
    method: &'a [u8],
    url: &'a [u8],
    http_version: &'a [u8],
    headers: Vec<HttpHeader<'a>>,
    payload: &'a [u8],
}

#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x1cd0c42b)]
#[allow(dead_code)]
pub struct HttpResponse<'tl> {
    pub http_version: &'tl [u8],
    pub status_code: i32,
    pub reason: &'tl [u8],
    pub headers: Vec<HttpHeader<'tl>>,
    pub payload: &'tl [u8],
}

#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x95317ad1)]
#[allow(dead_code)]
pub struct ConnectedToProxy<'tl> {
    pub params: ProxyParams<'tl>,
    pub client_sc_address: &'tl [u8],
    pub auth: ProxyAuth<'tl>,
    pub signed_payment: SignedPayment<'tl>,
}

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

#[derive(Debug, TlRead)]
#[tl(boxed)]
#[allow(dead_code)]
pub enum ProxyAuth<'tl> {
    #[tl(id = 0xd6ffc5af)]
    Short {
        secret_hash: &'tl [u8; 32],
        nonce: i64,
    },
    #[tl(id = 0x417bf016)]
    Long { nonce: i64 },
}

#[derive(Debug, TlRead)]
#[tl(boxed)]
#[allow(dead_code)]
pub enum SignedPayment<'tl> {
    #[tl(id = 0x02998182)]
    Data { data: &'tl [u8] },
    #[tl(id = 0xb347ce64)]
    Empty,
}

#[derive(Debug, TlRead)]
#[tl(boxed)]
#[allow(dead_code)]
pub enum AuthorizationWithProxy<'tl> {
    #[tl(id = 0x75d5ac34)]
    Success {
        signed_payment: SignedPayment<'tl>,
        tokens_committed_to_db: i64,
        max_tokens: i64,
    },
    #[tl(id = 0x60551c96)]
    Failed { error_code: i32, error: &'tl [u8] },
}

#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x0cf0dc67)]
pub struct WorkerTypesV2<'tl> {
    pub types: Vec<WorkerTypeV2<'tl>>,
}

#[derive(Debug, TlRead)]
pub struct WorkerTypeV2<'tl> {
    pub name: &'tl [u8],
    pub workers: Vec<WorkerInstanceV2>,
}

#[derive(Debug, TlRead)]
#[allow(dead_code)]
pub struct WorkerInstanceV2 {
    #[tl(flags)]
    flags: (),
    pub coefficient: i32,
    pub active_requests: i32,
    pub max_active_requests: i32,
}

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

#[derive(Debug, Clone, Copy, TlRead)]
#[allow(dead_code)]
pub struct TokensUsedTl {
    pub prompt_tokens_used: i64,
    pub cached_tokens_used: i64,
    pub completion_tokens_used: i64,
    pub reasoning_tokens_used: i64,
    pub total_tokens_used: i64,
}

#[derive(Debug, TlRead)]
#[tl(boxed)]
#[allow(dead_code)]
pub enum QueryAnswerEx<'tl> {
    #[tl(id = 0xcd524720)]
    Answer {
        request_id: &'tl [u8; 32],
        answer: &'tl [u8],
        #[tl(flags)]
        flags: (),
        #[tl(flags_bit = 0)]
        final_info: Option<QueryFinalInfo<'tl>>,
    },
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

pub fn encode_authorize_with_proxy_short(secret: &str) -> Vec<u8> {
    tl_proto::serialize(ClientAuthorizeWithProxyShort {
        data: secret.as_bytes(),
    })
}

pub fn encode_get_worker_types_v2() -> Vec<u8> {
    tl_proto::serialize(ClientGetWorkerTypesV2)
}

pub fn encode_http_request(
    method: &str,
    url: &str,
    headers: Vec<(&str, String)>,
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

pub fn encode_run_query_ex(
    model: &str,
    query: &[u8],
    request_id: &[u8; 32],
    options: RunQueryOptions,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xf54cb74bu32.to_le_bytes());
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

pub fn decode_connected_to_proxy(raw: &[u8]) -> Result<ConnectedToProxy<'_>> {
    tl_proto::deserialize::<ConnectedToProxy>(raw).context("decode client.connectedToProxy")
}

pub fn decode_authorization_with_proxy(raw: &[u8]) -> Result<AuthorizationWithProxy<'_>> {
    tl_proto::deserialize::<AuthorizationWithProxy>(raw)
        .context("decode client.authorizationWithProxy")
}

pub fn decode_worker_types_v2(raw: &[u8]) -> Result<WorkerTypesV2<'_>> {
    tl_proto::deserialize::<WorkerTypesV2>(raw).context("decode client.workerTypesV2")
}

pub fn decode_query_answer_ex(raw: &[u8]) -> Result<QueryAnswerEx<'_>> {
    tl_proto::deserialize::<QueryAnswerEx>(raw).context("decode client.QueryAnswerEx")
}

pub fn decode_http_response(raw: &[u8]) -> Result<HttpResponse<'_>> {
    tl_proto::deserialize::<HttpResponse>(raw).context("decode http.response")
}

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

fn write_tl_bool(out: &mut Vec<u8>, value: bool) {
    let magic = if value { 0x997275b5u32 } else { 0xbc799737u32 };
    out.extend_from_slice(&magic.to_le_bytes());
}

fn pad_to_four(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}
