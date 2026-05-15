//! TL objects in the `client.*` namespace.

use anyhow::{Context, Result};
use tl_proto::{TlRead, TlWrite};

use crate::proxy::{ProxyParams, SignedPayment};
use crate::tokens_used::TokensUsed;

/// Request limits and protocol options for `client.runQueryEx`.
///
/// Source TL:
///
/// ```tl
/// client.runQueryEx#f54cb74b
///     model_name:string
///     query:bytes
///     max_coefficient:int
///     max_tokens:int
///     timeout:double
///     request_id:int256
///     min_config_version:int
///     flags:#
///     enable_debug:flags.0?Bool
///     public_key:flags.1?int256
///     = client.QueryAnswerEx;
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RunQueryOptions {
    /// Maximum worker price coefficient the client accepts.
    pub max_coefficient: i32,
    /// Maximum tokens the worker may spend for this request.
    pub max_tokens: i32,
    /// Worker timeout in seconds.
    pub timeout: f64,
    /// Whether the proxy should attach debug fields to final query info.
    pub enable_debug: bool,
    /// Minimum accepted on-chain Cocoon config version.
    pub min_config_version: i32,
    /// Optional receiver public key for encrypted requests in proto >= 3.
    ///
    /// The C++ client passes the parsed `receiver_public_key` field here. A
    /// zero key is accepted by the proxy and means the request is unencrypted.
    pub public_key: Option<[u8; 32]>,
}

/// Parameters embedded into `client.connectToProxy`.
///
/// Source TL:
///
/// ```tl
/// client.params#40fdca64
///     flags:#
///     client_owner_address:string
///     is_test:flags.0?Bool
///     min_proto_version:flags.1?int
///     max_proto_version:flags.1?int
///     = client.Params;
/// ```
#[derive(Debug, TlWrite)]
struct ClientParams<'a> {
    #[tl(flags)]
    _flags: (),
    client_owner_address: &'a [u8],
    #[tl(flags_bit = 0)]
    is_test: Option<bool>,
    #[tl(flags_bit = 1)]
    min_proto_version: Option<i32>,
    #[tl(flags_bit = 1)]
    max_proto_version: Option<i32>,
}

/// TL request that starts Cocoon proxy authorization.
///
/// Source TL:
///
/// ```tl
/// client.connectToProxy
///     params:client.params
///     min_config_version:int
///     = client.ConnectedToProxy;
/// ```
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0xff5fa0f4)]
struct ClientConnectToProxy<'a> {
    params: ClientParams<'a>,
    min_config_version: i32,
}

/// TL request for short authorization using a shared secret.
///
/// Source TL:
///
/// ```tl
/// client.authorizeWithProxyShort
///     data:bytes
///     = client.AuthorizationWithProxy;
/// ```
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0x6c276723)]
struct ClientAuthorizeWithProxyShort<'a> {
    data: &'a [u8],
}

/// TL request sent after on-chain long authorization registration.
///
/// Source TL:
///
/// ```tl
/// client.authorizeWithProxyLong
///     = client.AuthorizationWithProxy;
/// ```
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0xd3474303)]
struct ClientAuthorizeWithProxyLong;

/// TL request for the latest proxy-side client payment status.
///
/// Source TL:
///
/// ```tl
/// client.updatePaymentStatus = client.PaymentStatus;
/// ```
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0x9ed1c697)]
struct ClientUpdatePaymentStatus;

/// TL request for model and worker discovery.
///
/// Source TL:
///
/// ```tl
/// client.getWorkerTypesV2 = client.WorkerTypesV2;
/// ```
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0xb2133d72)]
struct ClientGetWorkerTypesV2;

/// TL request that runs an HTTP query on a Cocoon worker.
///
/// Source TL:
///
/// ```tl
/// client.runQueryEx#f54cb74b
///     model_name:string
///     query:bytes
///     max_coefficient:int
///     max_tokens:int
///     timeout:double
///     request_id:int256
///     min_config_version:int
///     flags:#
///     enable_debug:flags.0?Bool
///     public_key:flags.1?int256
///     = client.QueryAnswerEx;
/// ```
#[derive(Debug, TlWrite)]
#[tl(boxed, id = 0xf54c_b74b)]
struct ClientRunQueryEx<'a> {
    model_name: &'a [u8],
    query: &'a [u8],
    max_coefficient: i32,
    max_tokens: i32,
    #[tl(write_with = "write_raw_f64", size_hint = 8)]
    timeout: f64,
    request_id: &'a [u8; 32],
    min_config_version: i32,
    #[tl(flags)]
    _flags: (),
    #[tl(flags_bit = 0)]
    enable_debug: Option<bool>,
    #[tl(flags_bit = 1)]
    public_key: Option<&'a [u8; 32]>,
}

/// Successful `client.connectToProxy` response.
///
/// This carries proxy parameters, the derived client contract address, and the
/// authorization mode the client must use next.
///
/// Source TL:
///
/// ```tl
/// client.connectedToProxy
///     params:proxy.params
///     client_sc_address:string
///     auth:client.ProxyConnectionAuth
///     signed_payment:proxy.SignedPayment
///     = client.ConnectedToProxy;
/// ```
#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x95317ad1)]
pub struct ConnectedToProxy<'tl> {
    pub params: ProxyParams<'tl>,
    pub client_sc_address: &'tl [u8],
    pub auth: ProxyConnectionAuth<'tl>,
    pub signed_payment: SignedPayment<'tl>,
}

/// Authorization mode selected by the proxy.
///
/// Source TL:
///
/// ```tl
/// client.proxyConnectionAuthShort
///     secret_hash:int256
///     nonce:long
///     = client.ProxyConnectionAuth;
/// client.proxyConnectionAuthLong
///     nonce:long
///     = client.ProxyConnectionAuth;
/// ```
#[derive(Debug, TlRead)]
#[tl(boxed)]
pub enum ProxyConnectionAuth<'tl> {
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

/// Result of `client.authorizeWithProxyShort`.
///
/// Source TL:
///
/// ```tl
/// client.authorizationWithProxySuccess
///     signed_payment:proxy.SignedPayment
///     tokens_committed_to_db:long
///     max_tokens:long
///     = client.AuthorizationWithProxy;
/// client.authorizationWithProxyFailed
///     error_code:int
///     error:string
///     = client.AuthorizationWithProxy;
/// ```
#[derive(Debug, TlRead)]
#[tl(boxed)]
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

/// Response object for `client.updatePaymentStatus`.
///
/// Source TL:
///
/// ```tl
/// client.paymentStatus
///     signed_payment:proxy.SignedPayment
///     db_tokens:long
///     max_tokens:long
///     = client.PaymentStatus;
/// ```
#[derive(Debug, TlRead)]
#[tl(boxed, id = 0xaa8a0ecc)]
pub struct PaymentStatus<'tl> {
    pub signed_payment: SignedPayment<'tl>,
    pub db_tokens: i64,
    pub max_tokens: i64,
}

/// Response object for `client.getWorkerTypesV2`.
///
/// Source TL:
///
/// ```tl
/// client.workerTypesV2
///     types:(vector client.workerTypeV2)
///     = client.WorkerTypesV2;
/// ```
#[derive(Debug, TlRead)]
#[tl(boxed, id = 0x0cf0dc67)]
pub struct WorkerTypesV2<'tl> {
    /// All known model types returned by the proxy.
    pub types: Vec<WorkerTypeV2<'tl>>,
}

/// One model type and its currently available workers.
///
/// Source TL:
///
/// ```tl
/// client.workerTypeV2
///     name:string
///     workers:(vector client.workerInstanceV2)
///     = client.WorkerTypeV2;
/// ```
#[derive(Debug, TlRead)]
pub struct WorkerTypeV2<'tl> {
    /// Model name, for example `Qwen/Qwen3-32B`.
    pub name: &'tl [u8],
    /// Worker instances currently advertising this model.
    pub workers: Vec<WorkerInstanceV2>,
}

/// Worker capacity and price metadata returned by the proxy.
///
/// Source TL:
///
/// ```tl
/// client.workerInstanceV2#3ea93d00
///     flags:#
///     coefficient:int
///     active_requests:int
///     max_active_requests:int
///     = client.WorkerInstanceV2;
/// ```
#[derive(Debug, TlRead)]
#[non_exhaustive]
pub struct WorkerInstanceV2 {
    #[tl(flags)]
    #[doc(hidden)]
    pub flags: (),
    pub coefficient: i32,
    pub active_requests: i32,
    pub max_active_requests: i32,
}

/// Final metadata optionally attached to the last query answer packet.
///
/// The current HTTP bridge does not expose this object directly, but it is part
/// of the TL schema and marks the end of a streamed Cocoon answer.
///
/// Source TL:
///
/// ```tl
/// client.queryFinalInfo flags:#
///     tokens_used:tokensUsed
///     worker_debug:flags.0?string
///     proxy_debug:flags.0?string
///     proxy_start_time:flags.1?double
///     proxy_end_time:flags.1?double
///     worker_start_time:flags.1?double
///     worker_end_time:flags.1?double
///     = client.QueryFinalInfo;
/// ```
#[derive(Debug, TlRead)]
#[non_exhaustive]
pub struct QueryFinalInfo<'tl> {
    #[tl(flags)]
    #[doc(hidden)]
    pub flags: (),
    pub tokens_used: TokensUsed,
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

/// Streamed answer variants for `client.runQueryEx`.
///
/// Source TL:
///
/// ```tl
/// client.queryAnswerEx
///     request_id:int256
///     answer:bytes
///     flags:#
///     final_info:flags.0?client.queryFinalInfo
///     = client.QueryAnswerEx;
/// client.queryAnswerErrorEx
///     request_id:int256
///     error_code:int
///     error:string
///     flags:#
///     final_info:flags.0?client.queryFinalInfo
///     = client.QueryAnswerEx;
/// client.queryAnswerPartEx
///     request_id:int256
///     answer:bytes
///     flags:#
///     final_info:flags.0?client.queryFinalInfo
///     = client.QueryAnswerEx;
/// ```
#[derive(Debug, TlRead)]
#[tl(boxed)]
pub enum QueryAnswerEx<'tl> {
    /// First packet containing the encoded HTTP response head.
    #[tl(id = 0xcd524720)]
    Answer {
        request_id: &'tl [u8; 32],
        answer: &'tl [u8],
        #[tl(flags)]
        _flags: (),
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
        _flags: (),
        #[tl(flags_bit = 0)]
        final_info: Option<QueryFinalInfo<'tl>>,
    },
    /// Additional response body bytes after the first answer packet.
    #[tl(id = 0xc07bfaec)]
    Part {
        request_id: &'tl [u8; 32],
        answer: &'tl [u8],
        #[tl(flags)]
        _flags: (),
        #[tl(flags_bit = 0)]
        final_info: Option<QueryFinalInfo<'tl>>,
    },
}

/// Encodes `client.connectToProxy`.
#[must_use]
pub fn encode_connect_to_proxy(client_owner_address: &str, min_config_version: i32) -> Vec<u8> {
    tl_proto::serialize(ClientConnectToProxy {
        params: ClientParams {
            _flags: (),
            client_owner_address: client_owner_address.as_bytes(),
            is_test: Some(false),
            min_proto_version: Some(1),
            max_proto_version: Some(4),
        },
        min_config_version,
    })
}

/// Encodes `client.authorizeWithProxyShort`.
#[must_use]
pub fn encode_authorize_with_proxy_short(secret: &str) -> Vec<u8> {
    tl_proto::serialize(ClientAuthorizeWithProxyShort {
        data: secret.as_bytes(),
    })
}

/// Encodes `client.authorizeWithProxyLong`.
#[must_use]
pub fn encode_authorize_with_proxy_long() -> Vec<u8> {
    tl_proto::serialize(ClientAuthorizeWithProxyLong)
}

/// Encodes `client.updatePaymentStatus`.
#[must_use]
pub fn encode_update_payment_status() -> Vec<u8> {
    tl_proto::serialize(ClientUpdatePaymentStatus)
}

/// Encodes `client.getWorkerTypesV2`.
#[must_use]
pub fn encode_get_worker_types_v2() -> Vec<u8> {
    tl_proto::serialize(ClientGetWorkerTypesV2)
}

/// Encodes `client.runQueryEx`.
///
/// The `timeout` field uses a custom writer because `tl-proto`'s native `f64`
/// serializer does not write the raw IEEE-754 representation expected by the
/// Cocoon C++ implementation.
#[must_use]
pub fn encode_run_query_ex(
    model: &str,
    query: &[u8],
    request_id: &[u8; 32],
    options: RunQueryOptions,
) -> Vec<u8> {
    tl_proto::serialize(ClientRunQueryEx {
        model_name: model.as_bytes(),
        query,
        max_coefficient: options.max_coefficient,
        max_tokens: options.max_tokens,
        timeout: options.timeout,
        request_id,
        min_config_version: options.min_config_version,
        _flags: (),
        enable_debug: Some(options.enable_debug),
        public_key: options.public_key.as_ref(),
    })
}

/// Decodes `client.connectedToProxy`.
///
/// # Errors
///
/// Returns an error when `raw` is not a valid boxed `client.connectedToProxy`
/// TL object.
pub fn decode_connected_to_proxy(raw: &[u8]) -> Result<ConnectedToProxy<'_>> {
    tl_proto::deserialize::<ConnectedToProxy>(raw).context("decode client.connectedToProxy")
}

/// Decodes `client.authorizationWithProxy`.
///
/// # Errors
///
/// Returns an error when `raw` is not a valid boxed
/// `client.authorizationWithProxy` TL object.
pub fn decode_authorization_with_proxy(raw: &[u8]) -> Result<AuthorizationWithProxy<'_>> {
    tl_proto::deserialize::<AuthorizationWithProxy>(raw)
        .context("decode client.authorizationWithProxy")
}

/// Decodes `client.PaymentStatus`.
///
/// # Errors
///
/// Returns an error when `raw` is not a valid boxed `client.paymentStatus` TL
/// object.
pub fn decode_payment_status(raw: &[u8]) -> Result<PaymentStatus<'_>> {
    tl_proto::deserialize::<PaymentStatus>(raw).context("decode client.paymentStatus")
}

/// Decodes `client.workerTypesV2`.
///
/// # Errors
///
/// Returns an error when `raw` is not a valid boxed `client.workerTypesV2` TL
/// object.
pub fn decode_worker_types_v2(raw: &[u8]) -> Result<WorkerTypesV2<'_>> {
    tl_proto::deserialize::<WorkerTypesV2>(raw).context("decode client.workerTypesV2")
}

/// Decodes any `client.queryAnswer*Ex` packet.
///
/// # Errors
///
/// Returns an error when `raw` is not one of Cocoon's boxed query answer TL
/// variants.
pub fn decode_query_answer_ex(raw: &[u8]) -> Result<QueryAnswerEx<'_>> {
    tl_proto::deserialize::<QueryAnswerEx>(raw).context("decode client.QueryAnswerEx")
}

/// Writes a Cocoon-compatible raw TL `double`.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn write_raw_f64<P: tl_proto::TlPacket>(value: &f64, packet: &mut P) {
    packet.write_u64(value.to_bits());
}

#[cfg(test)]
mod tests {
    use super::{encode_authorize_with_proxy_long, encode_update_payment_status};

    #[test]
    fn authorize_with_proxy_long_uses_cocoon_constructor_id() {
        let payload = encode_authorize_with_proxy_long();

        assert_eq!(&payload[..4], &0xd347_4303_u32.to_le_bytes());
    }

    #[test]
    fn update_payment_status_uses_cocoon_constructor_id() {
        let payload = encode_update_payment_status();

        assert_eq!(&payload[..4], &0x9ed1_c697_u32.to_le_bytes());
    }
}
