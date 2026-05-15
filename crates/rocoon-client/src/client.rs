//! High-level Cocoon client orchestration.
//!
//! This module ties the lower protocol and transport crates together: TCP
//! connect, `PoW`, RA-TLS, Cocoon session framing, proxy authorization, model
//! discovery, and inference requests. It exposes domain-level methods used by
//! the local HTTP server instead of leaking TL objects or frame handling into
//! the API layer.

use std::net::{TcpStream, ToSocketAddrs};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::config::RuntimeConfig;
use crate::ton_readonly::{TonReadonlyClient, TonReadonlySnapshot};
use rocoon_protocol::{self as cocoon, RunQueryOptions, WorkerInstanceV2, WorkerTypeV2};
use rocoon_transport::{QueryFinalInfo, RunQueryOutput, Session, pow, ratls};

/// Authenticated Cocoon proxy client.
///
/// A `CocoonClient` owns one live session to a selected proxy. If selected
/// calls fail, it can reconnect using the stored `RuntimeConfig`.
pub struct CocoonClient {
    session: Session<ratls::RatlsStream>,
    request_options: RunQueryOptions,
    proto_version: i32,
    proxy_owner_address: String,
    proxy_sc_address: String,
    payment_status: AuthPaymentStatus,
    ton_readonly: TonReadonlyState,
    config: RuntimeConfig,
}

/// Snapshot of local client state that can be exposed through `/stats`.
#[derive(Clone, Debug)]
pub struct ClientStatus {
    /// Cocoon proxy TCP address used by this session.
    pub proxy_addr: String,
    /// External TON owner wallet address from config.
    pub owner_address: String,
    /// Derived Cocoon wallet contract address used for proxy auth.
    pub cocoon_wallet_address: String,
    /// Protocol version negotiated with the proxy.
    pub proto_version: i32,
    /// Number of live proxy sessions owned by this prototype client.
    pub active_proxy_connections: usize,
    /// Proxy owner address returned by `client.connectedToProxy`.
    pub proxy_owner_address: String,
    /// Proxy smart-contract address returned by `client.connectedToProxy`.
    pub proxy_sc_address: String,
    /// Short-auth payment metadata returned by the proxy.
    pub payment_status: AuthPaymentStatus,
    /// Whether read-only TON liteserver polling is enabled.
    pub ton_readonly_enabled: bool,
    /// Whether the latest read-only TON query succeeded.
    pub ton_readonly_ok: bool,
    /// Last read-only TON query/init error.
    pub ton_readonly_error: Option<String>,
    /// Masterchain seqno used for the latest wallet account read.
    pub masterchain_seqno: Option<u32>,
    /// Optional root contract address from config.
    pub root_contract_address: Option<String>,
    /// On-chain Cocoon wallet balance in nanotons.
    pub wallet_balance: Option<u64>,
    /// Cocoon wallet seqno parsed from the first 32 bits of the data cell.
    pub wallet_seqno: Option<u32>,
    /// TON account state for the Cocoon wallet.
    pub wallet_state: Option<String>,
    /// Last transaction logical time for the Cocoon wallet account.
    pub wallet_last_tx_lt: Option<u64>,
}

/// Payment counters returned by `client.authorizeWithProxyShort`.
#[derive(Clone, Debug)]
pub struct AuthPaymentStatus {
    /// Whether the proxy returned non-empty signed payment data.
    pub signed_payment_available: bool,
    /// Tokens already committed to proxy DB state.
    pub tokens_committed_to_db: i64,
    /// Maximum tokens the proxy currently allows for this client.
    pub max_tokens: i64,
}

/// OpenAI-style model metadata derived from `client.getWorkerTypesV2`.
pub struct ModelInfo {
    /// Model identifier, for example `Qwen/Qwen3-32B`.
    pub id: String,
    /// Available workers currently advertising this model.
    pub workers: Vec<WorkerInfo>,
}

/// Worker capacity and price metadata for one model.
pub struct WorkerInfo {
    /// Cocoon price coefficient advertised by the worker.
    pub coefficient: i32,
    /// Number of requests the worker reports as currently active.
    pub active_requests: i32,
    /// Worker-side concurrency limit.
    pub max_active_requests: i32,
}

/// HTTP response returned by Cocoon after an inference request.
///
/// Cocoon wraps the model API as an HTTP request/response transported inside
/// TL messages. This struct is the decoded response that the local server can
/// write back to OpenAI-compatible clients.
pub struct HttpExchange {
    /// Upstream HTTP status code.
    pub status_code: i32,
    /// Upstream HTTP reason phrase.
    pub reason: String,
    /// Upstream headers after TL decoding.
    pub headers: Vec<(String, String)>,
    /// Full response body assembled from head and streamed parts.
    pub payload: Vec<u8>,
    /// Terminal Cocoon query metadata, when the proxy supplied it.
    pub final_info: Option<QueryFinalInfo>,
}

impl CocoonClient {
    /// Opens and authorizes a full Cocoon proxy connection.
    ///
    /// The handshake sequence is:
    /// TCP connect -> Cocoon `PoW` -> RA-TLS -> `tcp.connect` session ->
    /// `client.connectToProxy` -> `client.authorizeWithProxyShort`.
    ///
    /// # Errors
    ///
    /// Returns an error if DNS/TCP connection, `PoW`, RA-TLS, session framing,
    /// proxy authorization, or config-derived short authentication fails.
    pub fn connect(config: &RuntimeConfig) -> Result<Self> {
        let addr = &config.proxy_addr;
        println!("connecting to Cocoon proxy at {addr}");
        let socket_addr = addr
            .to_socket_addrs()
            .with_context(|| format!("resolve {addr}"))?
            .next()
            .with_context(|| format!("no socket addresses for {addr}"))?;

        let mut tcp = TcpStream::connect_timeout(&socket_addr, config.connect_timeout)
            .with_context(|| format!("connect TCP to {socket_addr} (from {addr})"))?;
        tcp.set_nodelay(true).context("set TCP_NODELAY")?;

        let pow = pow::handshake(&mut tcp).context("Cocoon TCP PoW handshake")?;
        println!(
            "pow solved: difficulty={} nonce={} elapsed_ms={}",
            pow.difficulty,
            pow.nonce,
            pow.elapsed.as_millis()
        );

        let tls = ratls::connect(tcp).context("Cocoon RA-TLS handshake")?;
        println!(
            "tls connected: server_cert_der_len={}",
            tls.server_cert_der_len()
        );

        let (mut session, connected) =
            Session::connect(tls).context("Cocoon tcp.connect session handshake")?;
        println!("session connected: id={}", connected.id);

        let authorization = authorize(&mut session, config)?;
        let ton_readonly = TonReadonlyState::new(config);

        Ok(Self {
            session,
            request_options: RunQueryOptions {
                max_coefficient: config.max_coefficient,
                max_tokens: config.max_tokens,
                timeout: config.request_timeout * 0.95,
                min_config_version: config.min_config_version,
                public_key: None,
            },
            proto_version: authorization.proto_version,
            proxy_owner_address: authorization.proxy_owner_address,
            proxy_sc_address: authorization.proxy_sc_address,
            payment_status: authorization.payment_status,
            ton_readonly,
            config: config.clone(),
        })
    }

    /// Returns the locally known connection, wallet, and payment status.
    #[must_use]
    pub fn status(&self) -> ClientStatus {
        let ton = self
            .ton_readonly
            .snapshot(&self.config.cocoon_wallet_address);
        let wallet = ton.wallet.as_ref();
        ClientStatus {
            proxy_addr: self.config.proxy_addr.clone(),
            owner_address: self.config.owner_address.clone(),
            cocoon_wallet_address: self.config.cocoon_wallet_address.clone(),
            proto_version: self.proto_version,
            active_proxy_connections: 1,
            proxy_owner_address: self.proxy_owner_address.clone(),
            proxy_sc_address: self.proxy_sc_address.clone(),
            payment_status: self.payment_status.clone(),
            ton_readonly_enabled: ton.enabled,
            ton_readonly_ok: ton.ok,
            ton_readonly_error: ton.last_error,
            masterchain_seqno: ton.masterchain_seqno,
            root_contract_address: self.config.ton.root_contract_address.clone(),
            wallet_balance: wallet.and_then(|wallet| wallet.balance),
            wallet_seqno: wallet.and_then(|wallet| wallet.seqno),
            wallet_state: wallet.map(|wallet| wallet.state.as_str().to_string()),
            wallet_last_tx_lt: wallet.and_then(|wallet| wallet.last_tx_lt),
        }
    }

    /// Returns the current model/worker list from the proxy.
    ///
    /// This powers `/v1/models`. A reconnect is attempted once because metadata
    /// calls are cheap and stale sessions are common after proxy-side closes.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be sent, the reconnect attempt
    /// fails, or the proxy response is not a valid `client.workerTypesV2`.
    pub fn get_worker_types_v2(&mut self) -> Result<Vec<ModelInfo>> {
        let request = cocoon::encode_get_worker_types_v2();
        let response = match self.session.make_request(&request) {
            Ok(response) => response,
            Err(error) => {
                eprintln!("client.getWorkerTypesV2 failed, reconnecting: {error:#}");
                self.reconnect()
                    .context("reconnect after getWorkerTypesV2 failure")?;
                self.session
                    .make_request(&request)
                    .context("client.getWorkerTypesV2 after reconnect")?
            }
        };
        let response = cocoon::decode_worker_types_v2(&response)?;
        Ok(response.types.iter().map(model_info_from_tl).collect())
    }

    /// Runs an OpenAI-compatible completion request through Cocoon.
    ///
    /// `body` is already sanitized JSON from the local HTTP layer. The method
    /// wraps it into Cocoon's internal `http.request`, sends `client.runQueryEx`,
    /// gathers all answer parts, and decodes Cocoon's `http.response`.
    ///
    /// # Errors
    ///
    /// Returns an error if the request cannot be sent, the proxy returns a query
    /// error, the response stream is malformed, or the worker response cannot be
    /// decoded as Cocoon's internal `http.response`.
    pub fn run_chat_completion(
        &mut self,
        model: &str,
        path: &str,
        body: &[u8],
        max_coefficient: i32,
        max_tokens: i32,
        timeout: f64,
    ) -> Result<HttpExchange> {
        let mut options = self.request_options;
        options.max_coefficient = max_coefficient;
        options.max_tokens = max_tokens;
        options.timeout = timeout * 0.95;
        // C++ sets flag bit 1 for proto >= 3 even when the request is not
        // encrypted. The zero key preserves that wire shape.
        options.public_key = (self.proto_version >= 3).then_some([0u8; 32]);

        let headers = json_request_headers(body.len());
        let http_request = cocoon::encode_http_request("POST", path, &headers, body);
        let output = match self
            .session
            .run_client_query_ex(model, &http_request, options)
        {
            Ok(output) => output,
            Err(error) => {
                eprintln!("client.runQueryEx failed, reconnecting for next request: {error:#}");
                if let Err(reconnect_error) = self.reconnect() {
                    eprintln!("reconnect after runQueryEx failure failed: {reconnect_error:#}");
                }
                return Err(error).context("client.runQueryEx");
            }
        };
        http_exchange_from_output(output)
    }

    /// Replaces the current live session with a fresh authorized connection.
    fn reconnect(&mut self) -> Result<()> {
        let replacement = Self::connect(&self.config)?;
        *self = replacement;
        Ok(())
    }
}

/// Initialization state for optional read-only TON diagnostics.
enum TonReadonlyState {
    Disabled,
    Ready(TonReadonlyClient),
    Failed(String),
}

impl TonReadonlyState {
    fn new(config: &RuntimeConfig) -> Self {
        if !config.ton.readonly_enabled {
            return Self::Disabled;
        }
        match TonReadonlyClient::connect(&config.ton) {
            Ok(client) => Self::Ready(client),
            Err(error) => Self::Failed(format!("{error:#}")),
        }
    }

    fn snapshot(&self, wallet_address: &str) -> TonReadonlySnapshot {
        match self {
            Self::Disabled => TonReadonlySnapshot::disabled(),
            Self::Failed(error) => TonReadonlySnapshot::failed(error.clone()),
            Self::Ready(client) => client
                .wallet_snapshot(wallet_address)
                .unwrap_or_else(|error| TonReadonlySnapshot::failed(format!("{error:#}"))),
        }
    }
}

/// Minimal HTTP headers required by Cocoon's internal HTTP request wrapper.
///
/// User-agent, auth, and other local UI headers are intentionally not forwarded
/// because the Cocoon worker only needs the JSON payload and its length.
fn json_request_headers(body_len: usize) -> Vec<(&'static str, String)> {
    vec![
        ("Content-Type", "application/json".to_string()),
        ("Content-Length", body_len.to_string()),
    ]
}

/// Data collected while authenticating a Cocoon proxy session.
struct AuthorizationInfo {
    proto_version: i32,
    proxy_owner_address: String,
    proxy_sc_address: String,
    payment_status: AuthPaymentStatus,
}

/// Performs Cocoon proxy authorization and returns the negotiated protocol version.
///
/// The current prototype supports short authorization with a local secret. Long
/// authorization requires on-chain registration/top-up and is intentionally not
/// implemented here.
fn authorize(
    session: &mut Session<ratls::RatlsStream>,
    config: &RuntimeConfig,
) -> Result<AuthorizationInfo> {
    println!(
        "authenticating owner {} via Cocoon wallet {}",
        config.owner_address, config.cocoon_wallet_address
    );
    let request =
        cocoon::encode_connect_to_proxy(&config.cocoon_wallet_address, config.min_config_version);
    let response = session
        .make_request(&request)
        .context("client.connectToProxy")?;
    let connected_to_proxy = cocoon::decode_connected_to_proxy(&response)?;
    let proto_version = connected_to_proxy.params.proto_version.unwrap_or(0);
    let proxy_owner_address =
        String::from_utf8_lossy(connected_to_proxy.params.proxy_owner_address).into_owned();
    let proxy_sc_address =
        String::from_utf8_lossy(connected_to_proxy.params.proxy_sc_address).into_owned();

    let payment_status = match connected_to_proxy.auth {
        cocoon::ProxyAuth::Short { secret_hash, .. } => {
            let Some(secret) = config.client_secret.as_deref() else {
                anyhow::bail!("short auth requires client.secret in TOML or COCOON_CLIENT_SECRET");
            };
            verify_secret_hash(secret, secret_hash)?;

            let request = cocoon::encode_authorize_with_proxy_short(secret);
            let response = session
                .make_request(&request)
                .context("client.authorizeWithProxyShort")?;
            let auth = cocoon::decode_authorization_with_proxy(&response)?;
            payment_status_from_auth(&auth)?
        }
        cocoon::ProxyAuth::Long { nonce } => {
            anyhow::bail!(
                "auth: long nonce={nonce}; on-chain register is required before Rust can serve requests"
            );
        }
    };

    Ok(AuthorizationInfo {
        proto_version,
        proxy_owner_address,
        proxy_sc_address,
        payment_status,
    })
}

/// Checks that the configured secret matches the proxy-provided challenge hash.
fn verify_secret_hash(secret: &str, expected: &[u8; 32]) -> Result<()> {
    let digest = Sha256::digest(secret.as_bytes());
    if digest.as_slice() != expected {
        anyhow::bail!("client secret hash does not match proxy challenge");
    }
    Ok(())
}

/// Converts the proxy authorization result into local payment status.
fn payment_status_from_auth(
    auth: &cocoon::AuthorizationWithProxy<'_>,
) -> Result<AuthPaymentStatus> {
    match auth {
        cocoon::AuthorizationWithProxy::Success {
            signed_payment,
            tokens_committed_to_db,
            max_tokens,
        } => {
            println!(
                "auth success: tokens_committed_to_db={tokens_committed_to_db} max_tokens={max_tokens}"
            );
            Ok(AuthPaymentStatus {
                signed_payment_available: matches!(
                    signed_payment,
                    cocoon::SignedPayment::Data { .. }
                ),
                tokens_committed_to_db: *tokens_committed_to_db,
                max_tokens: *max_tokens,
            })
        }
        cocoon::AuthorizationWithProxy::Failed { error_code, error } => {
            anyhow::bail!("auth failed: code={error_code} error={}", utf8(error)?)
        }
    }
}

/// Converts Cocoon's framed response into a local HTTP exchange.
///
/// The first `client.queryAnswerEx` carries the HTTP response head. Subsequent
/// `client.queryAnswerPartEx` packets carry additional response body bytes.
fn http_exchange_from_output(output: RunQueryOutput) -> Result<HttpExchange> {
    let RunQueryOutput {
        response_head,
        payload_parts,
        final_info,
    } = output;
    let response = cocoon::decode_http_response(&response_head)?;
    let mut payload = response.payload.to_vec();
    for part in payload_parts {
        payload.extend(part);
    }

    Ok(HttpExchange {
        status_code: response.status_code,
        reason: utf8(response.reason)?.to_string(),
        headers: response
            .headers
            .iter()
            .map(|header| {
                Ok((
                    utf8(header.name)?.to_string(),
                    utf8(header.value)?.to_string(),
                ))
            })
            .collect::<Result<_>>()?,
        payload,
        final_info,
    })
}

/// Converts one TL worker type entry into API-facing model metadata.
fn model_info_from_tl(value: &WorkerTypeV2<'_>) -> ModelInfo {
    ModelInfo {
        id: String::from_utf8_lossy(value.name).into_owned(),
        workers: value.workers.iter().map(worker_info_from_tl).collect(),
    }
}

/// Converts one TL worker entry into API-facing worker metadata.
const fn worker_info_from_tl(value: &WorkerInstanceV2) -> WorkerInfo {
    WorkerInfo {
        coefficient: value.coefficient,
        active_requests: value.active_requests,
        max_active_requests: value.max_active_requests,
    }
}

/// Decodes a TL byte string that must contain UTF-8 text.
fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).context("decode TL string as UTF-8")
}
