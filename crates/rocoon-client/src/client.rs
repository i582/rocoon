//! High-level Cocoon client orchestration.
//!
//! This module ties the lower protocol and transport crates together: TCP
//! connect, `PoW`, RA-TLS, Cocoon session framing, proxy authorization, model
//! discovery, and inference requests. It exposes domain-level methods used by
//! the local HTTP server instead of leaking TL objects or frame handling into
//! the API layer.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::config::{RuntimeConfig, TonRuntimeConfig};
use crate::ton_readonly::{
    COCOON_WALLET_RESERVE_NANOTONS, CONTROL_MESSAGE_VALUE_NANOTONS, ClientContractSnapshot,
    TonAccountState, TonControlAction, TonControlPreparedMessage, TonControlRequest,
    TonControlResult, TonReadonlyClient, TonReadonlySnapshot, TonWalletSnapshot,
    TonWalletTransferPreparedMessage, TonWalletTransferRequest, TonWalletTransferResult,
};
use rocoon_protocol::{self as cocoon, RunQueryOptions, WorkerInstanceV2, WorkerTypeV2};
use rocoon_transport::{QueryFinalInfo, RunQueryOutput, Session, pow, ratls};

const CONTROL_RESEND_INTERVAL: Duration = Duration::from_secs(30);
const COCOON_CLIENT_CONTRACT_STATE_CLOSED: u8 = 2;

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
    client_sc_address: String,
    payment_status: AuthPaymentStatus,
    ton_readonly: TonReadonlyState,
    config: RuntimeConfig,
    control_request: Option<PendingControlRequest>,
    wallet_transfer_request: Option<PendingWalletTransferRequest>,
    client_contract_close_confirmed: bool,
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
    /// Client smart-contract address returned by `client.connectedToProxy`.
    pub client_sc_address: String,
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
    /// Number of queued wallet transactions waiting to be signed/sent.
    pub wallet_pending_transactions: usize,
    /// Number of wallet transactions sent and waiting for chain confirmation.
    pub wallet_active_transactions: usize,
    /// Running plain wallet transfer, if any.
    pub wallet_transfer: Option<WalletTransferStatus>,
    /// Whether a client-contract smart-contract request is still running.
    pub sc_request_running: bool,
    /// Running client-contract request, if any.
    pub sc_request: Option<ControlRequestStatus>,
    /// Connected client contract account and data-cell state.
    pub client_contract: Option<ClientContractSnapshot>,
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

/// Running smart-contract control request shown in `/stats`.
#[derive(Clone, Debug)]
pub struct ControlRequestStatus {
    /// Action sent to the client contract.
    pub action: TonControlAction,
    /// Query id embedded into the client-contract message.
    pub query_id: u64,
    /// Cocoon wallet seqno used for the external message.
    pub wallet_seqno: u32,
}

/// Running plain Cocoon wallet transfer shown in `/stats`.
#[derive(Clone, Debug)]
pub struct WalletTransferStatus {
    /// Destination TON address.
    pub destination_address: String,
    /// Value sent from the Cocoon wallet, in nanotons.
    pub amount: u64,
    /// Cocoon wallet seqno used for the external message.
    pub wallet_seqno: u32,
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
            client_sc_address: authorization.client_sc_address,
            payment_status: authorization.payment_status,
            ton_readonly,
            config: config.clone(),
            control_request: None,
            wallet_transfer_request: None,
            client_contract_close_confirmed: false,
        })
    }

    /// Returns the locally known connection, wallet, and payment status.
    pub fn status(&mut self) -> ClientStatus {
        let ton = self
            .ton_readonly
            .snapshot(&self.config.cocoon_wallet_address, &self.client_sc_address);
        if let Some(client_contract) = &ton.client_contract {
            self.refresh_control_request(client_contract);
        }
        if let Some(wallet) = &ton.wallet {
            self.refresh_wallet_transfer_request(wallet);
        }
        self.resend_pending_wallet_messages_if_due();
        let wallet = ton.wallet.as_ref();
        let control_request = self
            .control_request
            .as_ref()
            .map(PendingControlRequest::status);
        let wallet_transfer = self
            .wallet_transfer_request
            .as_ref()
            .map(PendingWalletTransferRequest::status);
        let wallet_active_transactions = usize::from(self.control_request.is_some())
            .saturating_add(usize::from(self.wallet_transfer_request.is_some()));
        ClientStatus {
            proxy_addr: self.config.proxy_addr.clone(),
            owner_address: self.config.owner_address.clone(),
            cocoon_wallet_address: self.config.cocoon_wallet_address.clone(),
            proto_version: self.proto_version,
            active_proxy_connections: 1,
            proxy_owner_address: self.proxy_owner_address.clone(),
            proxy_sc_address: self.proxy_sc_address.clone(),
            client_sc_address: self.client_sc_address.clone(),
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
            wallet_pending_transactions: 0,
            wallet_active_transactions,
            wallet_transfer,
            sc_request_running: self.control_request.is_some(),
            sc_request: control_request,
            client_contract: ton.client_contract,
        }
    }

    /// Sends a local control request to the connected Cocoon client contract.
    ///
    /// This currently supports only already-registered client contracts. The
    /// long-auth registration path from Go is intentionally not implemented.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested proxy does not match this session,
    /// TON polling/signing is unavailable, the client contract is not active,
    /// or the liteserver rejects the external message.
    pub fn request_control(
        &mut self,
        action: TonControlAction,
        proxy_sc_address: Option<&str>,
    ) -> Result<TonControlResult> {
        if let Some(proxy_sc_address) = proxy_sc_address
            && !proxy_sc_address.is_empty()
            && proxy_sc_address != self.proxy_sc_address
        {
            anyhow::bail!("proxy not found");
        }

        let ton = self
            .ton_readonly
            .snapshot(&self.config.cocoon_wallet_address, &self.client_sc_address);
        if !ton.ok {
            anyhow::bail!(
                "TON state is unavailable: {}",
                ton.last_error.as_deref().unwrap_or("unknown error")
            );
        }
        let client_contract = ton
            .client_contract
            .as_ref()
            .context("client contract state is unavailable")?;
        self.refresh_control_request(client_contract);
        if let Some(wallet) = &ton.wallet {
            self.refresh_wallet_transfer_request(wallet);
        }
        if self.control_request.is_some() || self.wallet_transfer_request.is_some() {
            self.resend_pending_wallet_messages_if_due();
            anyhow::bail!("wallet transaction is already running");
        }
        validate_client_contract_control(client_contract)?;
        let wallet = ton
            .wallet
            .as_ref()
            .context("Cocoon wallet state is unavailable")?;
        let wallet_seqno =
            validate_cocoon_wallet_can_send_control(&self.config.cocoon_wallet_address, wallet)?;

        let request = TonControlRequest {
            action,
            wallet_owner_address: &self.config.owner_address,
            wallet_address: &self.config.cocoon_wallet_address,
            wallet_seqno,
            client_contract_address: &self.client_sc_address,
            wallet_seed: self.config.node_wallet_key.seed(),
        };
        let prepared = self.ton_readonly.prepare_client_control(&request)?;
        let result = self.ton_readonly.send_prepared_control(&prepared)?;
        self.control_request = Some(PendingControlRequest::new(&prepared, client_contract));
        Ok(result)
    }

    /// Sends all sweepable Cocoon wallet funds to the owner wallet.
    ///
    /// The transfer is intentionally allowed only after the connected client
    /// contract is in Cocoon state `closed`. This keeps the wallet funded while
    /// `/request/close` may still need another on-chain message.
    ///
    /// # Errors
    ///
    /// Returns an error when TON polling/signing is unavailable, the client
    /// contract is not closed, another wallet transaction is pending, the
    /// Cocoon wallet is not active, no funds remain above `reserve_nanotons`,
    /// or the liteserver rejects the external message.
    pub fn sweep_cocoon_wallet(
        &mut self,
        destination_address: Option<&str>,
        reserve_nanotons: u64,
        allow_untracked_closed: bool,
    ) -> Result<TonWalletTransferResult> {
        let ton = self
            .ton_readonly
            .snapshot(&self.config.cocoon_wallet_address, &self.client_sc_address);
        if !ton.ok {
            anyhow::bail!(
                "TON state is unavailable: {}",
                ton.last_error.as_deref().unwrap_or("unknown error")
            );
        }
        let client_contract = ton
            .client_contract
            .as_ref()
            .context("client contract state is unavailable")?;
        self.refresh_control_request(client_contract);
        if let Some(wallet) = &ton.wallet {
            self.refresh_wallet_transfer_request(wallet);
        }
        if self.control_request.is_some() || self.wallet_transfer_request.is_some() {
            self.resend_pending_wallet_messages_if_due();
            anyhow::bail!("wallet transaction is already running");
        }
        validate_client_contract_closed_for_sweep(client_contract)?;
        if !allow_untracked_closed && !self.client_contract_close_confirmed {
            anyhow::bail!(
                "client contract close was not confirmed by this rocoon process; call /request/close first or pass force=true for an already closed contract"
            );
        }

        let wallet = ton
            .wallet
            .as_ref()
            .context("Cocoon wallet state is unavailable")?;
        let (wallet_seqno, amount) = validate_cocoon_wallet_can_sweep(
            &self.config.cocoon_wallet_address,
            wallet,
            reserve_nanotons,
        )?;
        let destination_address = destination_address
            .filter(|address| !address.is_empty())
            .unwrap_or(&self.config.owner_address);

        let request = TonWalletTransferRequest {
            wallet_owner_address: &self.config.owner_address,
            wallet_address: &self.config.cocoon_wallet_address,
            wallet_seqno,
            wallet_seed: self.config.node_wallet_key.seed(),
            destination_address,
            amount,
        };
        let prepared = self.ton_readonly.prepare_wallet_transfer(&request)?;
        let result = self.ton_readonly.send_prepared_wallet_transfer(&prepared)?;
        self.wallet_transfer_request = Some(PendingWalletTransferRequest::new(&prepared, wallet));
        Ok(result)
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
        let control_request = self.control_request.clone();
        let wallet_transfer_request = self.wallet_transfer_request.clone();
        let client_contract_close_confirmed = self.client_contract_close_confirmed;
        let mut replacement = Self::connect(&self.config)?;
        replacement.control_request = control_request;
        replacement.wallet_transfer_request = wallet_transfer_request;
        replacement.client_contract_close_confirmed = client_contract_close_confirmed;
        *self = replacement;
        Ok(())
    }

    fn refresh_control_request(&mut self, client_contract: &ClientContractSnapshot) {
        let Some(request) = self.control_request.as_ref() else {
            return;
        };
        if !request.is_completed_by(client_contract) {
            return;
        }
        if request.action == TonControlAction::RequestRefund
            && client_contract.state_raw == Some(COCOON_CLIENT_CONTRACT_STATE_CLOSED)
        {
            self.client_contract_close_confirmed = true;
        }
        self.control_request = None;
    }

    fn refresh_wallet_transfer_request(&mut self, wallet: &TonWalletSnapshot) {
        if self
            .wallet_transfer_request
            .as_ref()
            .is_some_and(|request| request.is_completed_by(wallet))
        {
            self.wallet_transfer_request = None;
        }
    }

    fn resend_pending_wallet_messages_if_due(&mut self) {
        self.resend_control_request_if_due();
        self.resend_wallet_transfer_if_due();
    }

    fn resend_control_request_if_due(&mut self) {
        let Some(request) = self.control_request.as_mut() else {
            return;
        };
        if !request.is_resend_due() {
            return;
        }

        let external_message = request.external_message.clone();
        request.mark_resend_attempted();
        match self.ton_readonly.resend_external_message(&external_message) {
            Ok(send_status) => {
                eprintln!(
                    "resent Cocoon wallet control message: action={} query_id={} send_status={send_status}",
                    request.action.as_str(),
                    request.query_id
                );
            }
            Err(error) => {
                eprintln!(
                    "failed to resend Cocoon wallet control message: action={} query_id={} error={error:#}",
                    request.action.as_str(),
                    request.query_id
                );
            }
        }
    }

    fn resend_wallet_transfer_if_due(&mut self) {
        let Some(request) = self.wallet_transfer_request.as_mut() else {
            return;
        };
        if !request.is_resend_due() {
            return;
        }

        let external_message = request.external_message.clone();
        request.mark_resend_attempted();
        match self.ton_readonly.resend_external_message(&external_message) {
            Ok(send_status) => {
                eprintln!(
                    "resent Cocoon wallet transfer: destination={} amount={} send_status={send_status}",
                    request.destination_address, request.amount
                );
            }
            Err(error) => {
                eprintln!(
                    "failed to resend Cocoon wallet transfer: destination={} amount={} error={error:#}",
                    request.destination_address, request.amount
                );
            }
        }
    }
}

#[derive(Clone, Debug)]
struct PendingControlRequest {
    action: TonControlAction,
    query_id: u64,
    wallet_seqno: u32,
    expected_state_raw: Option<u8>,
    withdrawable_balance: Option<u64>,
    external_message: Vec<u8>,
    next_resend_at: Instant,
}

impl PendingControlRequest {
    fn new(message: &TonControlPreparedMessage, snapshot: &ClientContractSnapshot) -> Self {
        Self {
            action: message.action,
            query_id: message.query_id,
            wallet_seqno: message.wallet_seqno,
            expected_state_raw: expected_state_after_request(message.action, snapshot.state_raw),
            withdrawable_balance: snapshot.withdrawable_balance,
            external_message: message.external_message.clone(),
            next_resend_at: Instant::now() + CONTROL_RESEND_INTERVAL,
        }
    }

    const fn status(&self) -> ControlRequestStatus {
        ControlRequestStatus {
            action: self.action,
            query_id: self.query_id,
            wallet_seqno: self.wallet_seqno,
        }
    }

    fn is_completed_by(&self, snapshot: &ClientContractSnapshot) -> bool {
        if let Some(expected_state_raw) = self.expected_state_raw
            && snapshot
                .state_raw
                .is_some_and(|state_raw| state_raw >= expected_state_raw)
        {
            return true;
        }
        if self.action == TonControlAction::Withdraw
            && let Some(before) = self.withdrawable_balance
            && snapshot
                .withdrawable_balance
                .is_some_and(|current| current < before)
        {
            return true;
        }
        false
    }

    fn is_resend_due(&self) -> bool {
        Instant::now() >= self.next_resend_at
    }

    fn mark_resend_attempted(&mut self) {
        self.next_resend_at = Instant::now() + CONTROL_RESEND_INTERVAL;
    }
}

#[derive(Clone, Debug)]
struct PendingWalletTransferRequest {
    destination_address: String,
    amount: u64,
    wallet_seqno: u32,
    wallet_balance_before: Option<u64>,
    external_message: Vec<u8>,
    next_resend_at: Instant,
}

impl PendingWalletTransferRequest {
    fn new(message: &TonWalletTransferPreparedMessage, snapshot: &TonWalletSnapshot) -> Self {
        Self {
            destination_address: message.destination_address.clone(),
            amount: message.amount,
            wallet_seqno: message.wallet_seqno,
            wallet_balance_before: snapshot.balance,
            external_message: message.external_message.clone(),
            next_resend_at: Instant::now() + CONTROL_RESEND_INTERVAL,
        }
    }

    fn status(&self) -> WalletTransferStatus {
        WalletTransferStatus {
            destination_address: self.destination_address.clone(),
            amount: self.amount,
            wallet_seqno: self.wallet_seqno,
        }
    }

    fn is_completed_by(&self, snapshot: &TonWalletSnapshot) -> bool {
        if snapshot
            .seqno
            .is_some_and(|current_seqno| current_seqno > self.wallet_seqno)
        {
            return true;
        }
        if let Some(before) = self.wallet_balance_before
            && snapshot.balance.is_some_and(|current| current < before)
        {
            return true;
        }
        false
    }

    fn is_resend_due(&self) -> bool {
        Instant::now() >= self.next_resend_at
    }

    fn mark_resend_attempted(&mut self) {
        self.next_resend_at = Instant::now() + CONTROL_RESEND_INTERVAL;
    }
}

/// Initialization state for optional read-only TON diagnostics.
enum TonReadonlyState {
    Disabled,
    Ready {
        config: TonRuntimeConfig,
        client: TonReadonlyClient,
    },
    Failed {
        config: TonRuntimeConfig,
        error: String,
    },
}

impl TonReadonlyState {
    fn new(config: &RuntimeConfig) -> Self {
        if !config.ton.readonly_enabled {
            return Self::Disabled;
        }
        match TonReadonlyClient::connect(&config.ton) {
            Ok(client) => Self::Ready {
                config: config.ton.clone(),
                client,
            },
            Err(error) => Self::Failed {
                config: config.ton.clone(),
                error: format!("{error:#}"),
            },
        }
    }

    fn snapshot(
        &mut self,
        wallet_address: &str,
        client_contract_address: &str,
    ) -> TonReadonlySnapshot {
        match self {
            Self::Disabled => TonReadonlySnapshot::disabled(),
            Self::Failed { config, error } => {
                eprintln!("TON liteclient is unavailable, reconnecting: {error}");
                let config = config.clone();
                match TonReadonlyClient::connect(&config) {
                    Ok(client) => {
                        *self = Self::Ready { config, client };
                        self.snapshot(wallet_address, client_contract_address)
                    }
                    Err(reconnect_error) => TonReadonlySnapshot::failed(format!(
                        "{error}; reconnect failed: {reconnect_error:#}"
                    )),
                }
            }
            Self::Ready { config, client } => {
                match client.accounts_snapshot(wallet_address, Some(client_contract_address)) {
                    Ok(snapshot) => snapshot,
                    Err(first_error) => {
                        eprintln!("TON snapshot failed, reconnecting liteclient: {first_error:#}");
                        match TonReadonlyClient::connect(config) {
                            Ok(replacement) => {
                                *client = replacement;
                                client
                                    .accounts_snapshot(wallet_address, Some(client_contract_address))
                                    .unwrap_or_else(|second_error| {
                                        TonReadonlySnapshot::failed(format!(
                                            "{first_error:#}; retry after reconnect failed: {second_error:#}"
                                        ))
                                    })
                            }
                            Err(reconnect_error) => TonReadonlySnapshot::failed(format!(
                                "{first_error:#}; reconnect failed: {reconnect_error:#}"
                            )),
                        }
                    }
                }
            }
        }
    }

    fn prepare_client_control(
        &self,
        request: &TonControlRequest<'_>,
    ) -> Result<TonControlPreparedMessage> {
        match self {
            Self::Disabled => anyhow::bail!("TON liteclient is disabled"),
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { .. } => TonReadonlyClient::prepare_client_control_message(request),
        }
    }

    fn send_prepared_control(
        &self,
        message: &TonControlPreparedMessage,
    ) -> Result<TonControlResult> {
        match self {
            Self::Disabled => anyhow::bail!("TON liteclient is disabled"),
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { client, .. } => client.send_prepared_control_message(message),
        }
    }

    fn prepare_wallet_transfer(
        &self,
        request: &TonWalletTransferRequest<'_>,
    ) -> Result<TonWalletTransferPreparedMessage> {
        match self {
            Self::Disabled => anyhow::bail!("TON liteclient is disabled"),
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { .. } => TonReadonlyClient::prepare_wallet_transfer_message(request),
        }
    }

    fn send_prepared_wallet_transfer(
        &self,
        message: &TonWalletTransferPreparedMessage,
    ) -> Result<TonWalletTransferResult> {
        match self {
            Self::Disabled => anyhow::bail!("TON liteclient is disabled"),
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { client, .. } => client.send_prepared_wallet_transfer_message(message),
        }
    }

    fn resend_external_message(&self, message: &[u8]) -> Result<u32> {
        match self {
            Self::Disabled => anyhow::bail!("TON liteclient is disabled"),
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { client, .. } => client.send_raw_message(message),
        }
    }
}

fn validate_client_contract_closed_for_sweep(snapshot: &ClientContractSnapshot) -> Result<()> {
    if snapshot.account_state != TonAccountState::Active {
        anyhow::bail!(
            "client contract account is not active: {}",
            snapshot.account_state.as_str()
        );
    }
    match snapshot.state_raw {
        Some(COCOON_CLIENT_CONTRACT_STATE_CLOSED) => Ok(()),
        Some(state_raw) => {
            anyhow::bail!(
                "client contract is not closed yet: {}",
                client_contract_state_name_for_error(state_raw)
            )
        }
        None => anyhow::bail!("client contract is not initialized"),
    }
}

fn validate_client_contract_control(snapshot: &ClientContractSnapshot) -> Result<()> {
    if snapshot.account_state != TonAccountState::Active {
        anyhow::bail!(
            "client contract account is not active: {}",
            snapshot.account_state.as_str()
        );
    }
    let Some(state_raw) = snapshot.state_raw else {
        anyhow::bail!("client contract is not initialized");
    };
    if state_raw >= 2 {
        anyhow::bail!("client contract is closed");
    }
    Ok(())
}

fn validate_cocoon_wallet_can_send_control(
    wallet_address: &str,
    snapshot: &TonWalletSnapshot,
) -> Result<u32> {
    let wallet_seqno = match snapshot.state {
        TonAccountState::Active => snapshot
            .seqno
            .context("Cocoon wallet seqno is unavailable in active account")?,
        TonAccountState::Uninit => 0,
        TonAccountState::None | TonAccountState::Frozen => {
            anyhow::bail!(
                "Cocoon wallet account cannot send control messages: {}",
                snapshot.state.as_str()
            );
        }
    };
    let balance = snapshot
        .balance
        .context("Cocoon wallet balance is unavailable")?;
    let required_balance =
        CONTROL_MESSAGE_VALUE_NANOTONS.saturating_add(COCOON_WALLET_RESERVE_NANOTONS);
    if balance < required_balance {
        anyhow::bail!(
            "ACTION REQUIRED: BALANCE ON CONTRACT {wallet_address} IS TOO LOW: SENDING MESSAGE OF VALUE {CONTROL_MESSAGE_VALUE_NANOTONS} CURRENT {balance}"
        );
    }
    Ok(wallet_seqno)
}

fn validate_cocoon_wallet_can_sweep(
    wallet_address: &str,
    snapshot: &TonWalletSnapshot,
    reserve_nanotons: u64,
) -> Result<(u32, u64)> {
    if snapshot.state != TonAccountState::Active {
        anyhow::bail!(
            "Cocoon wallet account cannot be swept: {}",
            snapshot.state.as_str()
        );
    }
    let wallet_seqno = snapshot
        .seqno
        .context("Cocoon wallet seqno is unavailable in active account")?;
    let balance = snapshot
        .balance
        .context("Cocoon wallet balance is unavailable")?;
    if balance <= reserve_nanotons {
        anyhow::bail!(
            "Cocoon wallet {wallet_address} has no sweepable balance: reserve={reserve_nanotons} current={balance}"
        );
    }
    Ok((wallet_seqno, balance - reserve_nanotons))
}

const fn expected_state_after_request(
    action: TonControlAction,
    current_state_raw: Option<u8>,
) -> Option<u8> {
    match (action, current_state_raw) {
        (TonControlAction::RequestRefund, Some(0)) => Some(1),
        (TonControlAction::RequestRefund, Some(1)) => Some(2),
        _ => None,
    }
}

const fn client_contract_state_name_for_error(state: u8) -> &'static str {
    match state {
        0 => "running",
        1 => "closing",
        2 => "closed",
        _ => "unknown",
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
    client_sc_address: String,
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
    let client_sc_address =
        String::from_utf8_lossy(connected_to_proxy.client_sc_address).into_owned();

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
        client_sc_address,
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

#[cfg(test)]
mod tests {
    use super::*;

    const fn active_wallet(balance: u64) -> TonWalletSnapshot {
        TonWalletSnapshot {
            balance: Some(balance),
            seqno: Some(7),
            state: TonAccountState::Active,
            last_tx_lt: Some(10),
        }
    }

    const fn uninit_wallet(balance: u64) -> TonWalletSnapshot {
        TonWalletSnapshot {
            balance: Some(balance),
            seqno: None,
            state: TonAccountState::Uninit,
            last_tx_lt: Some(0),
        }
    }

    const fn active_client_contract(
        state_raw: u8,
        last_tx_lt: u64,
        withdrawable_balance: u64,
    ) -> ClientContractSnapshot {
        const STAKE: u64 = 15_000_000_000;
        ClientContractSnapshot {
            account_balance: Some(STAKE),
            account_state: TonAccountState::Active,
            last_tx_lt: Some(last_tx_lt),
            state_raw: Some(state_raw),
            state: Some(client_contract_state_name_for_error(state_raw)),
            balance: Some(STAKE + withdrawable_balance),
            stake: Some(STAKE),
            tokens_used: Some(0),
            unlock_ts: Some(0),
            withdrawable_balance: Some(withdrawable_balance),
        }
    }

    fn prepared_wallet_transfer_message() -> TonWalletTransferPreparedMessage {
        TonWalletTransferPreparedMessage {
            wallet_seqno: 7,
            amount: 1_000_000_000,
            destination_address: "owner".to_string(),
            wallet_address: "wallet".to_string(),
            external_message: vec![1, 2, 3],
        }
    }

    fn prepared_control_message(action: TonControlAction) -> TonControlPreparedMessage {
        TonControlPreparedMessage {
            action,
            query_id: 42,
            wallet_seqno: 7,
            attached_value: CONTROL_MESSAGE_VALUE_NANOTONS,
            client_contract_address: String::new(),
            wallet_address: String::new(),
            external_message: vec![1, 2, 3],
        }
    }

    #[test]
    fn control_send_requires_wallet_balance_plus_cocoon_reserve() -> Result<()> {
        let required_balance = CONTROL_MESSAGE_VALUE_NANOTONS + COCOON_WALLET_RESERVE_NANOTONS;
        let low_wallet = active_wallet(required_balance - 1);
        assert!(validate_cocoon_wallet_can_send_control("wallet", &low_wallet).is_err());

        let funded_wallet = active_wallet(required_balance);
        assert_eq!(
            validate_cocoon_wallet_can_send_control("wallet", &funded_wallet)?,
            7
        );
        Ok(())
    }

    #[test]
    fn control_send_can_deploy_uninit_wallet_with_seqno_zero() -> Result<()> {
        let required_balance = CONTROL_MESSAGE_VALUE_NANOTONS + COCOON_WALLET_RESERVE_NANOTONS;
        let wallet = uninit_wallet(required_balance);

        assert_eq!(
            validate_cocoon_wallet_can_send_control("wallet", &wallet)?,
            0
        );
        Ok(())
    }

    #[test]
    fn wallet_sweep_requires_active_wallet_and_balance_above_reserve() -> Result<()> {
        let reserve = COCOON_WALLET_RESERVE_NANOTONS;
        let low_wallet = active_wallet(reserve);
        assert!(validate_cocoon_wallet_can_sweep("wallet", &low_wallet, reserve).is_err());

        let funded_wallet = active_wallet(reserve + 42);
        assert_eq!(
            validate_cocoon_wallet_can_sweep("wallet", &funded_wallet, reserve)?,
            (7, 42)
        );
        assert!(
            validate_cocoon_wallet_can_sweep("wallet", &uninit_wallet(reserve + 42), reserve)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn wallet_sweep_requires_closed_client_contract() {
        assert!(
            validate_client_contract_closed_for_sweep(&active_client_contract(0, 10, 0)).is_err()
        );
        assert!(
            validate_client_contract_closed_for_sweep(&active_client_contract(1, 10, 0)).is_err()
        );
        assert!(
            validate_client_contract_closed_for_sweep(&active_client_contract(2, 10, 0)).is_ok()
        );
    }

    #[test]
    fn pending_control_does_not_clear_when_only_client_contract_tx_advances() {
        let before = active_client_contract(0, 10, 1_000_000_000);
        let pending = PendingControlRequest::new(
            &prepared_control_message(TonControlAction::Withdraw),
            &before,
        );

        assert!(!pending.is_completed_by(&before));
        assert!(!pending.is_completed_by(&active_client_contract(0, 11, 1_000_000_000)));
    }

    #[test]
    fn pending_close_clears_when_expected_contract_state_is_reached() {
        let before = active_client_contract(0, 10, 1_000_000_000);
        let pending = PendingControlRequest::new(
            &prepared_control_message(TonControlAction::RequestRefund),
            &before,
        );

        assert!(!pending.is_completed_by(&before));
        assert!(pending.is_completed_by(&active_client_contract(1, 11, 1_000_000_000)));
    }

    #[test]
    fn pending_withdraw_clears_when_withdrawable_balance_decreases() {
        let before = active_client_contract(0, 10, 1_000_000_000);
        let pending = PendingControlRequest::new(
            &prepared_control_message(TonControlAction::Withdraw),
            &before,
        );

        assert!(!pending.is_completed_by(&before));
        assert!(pending.is_completed_by(&active_client_contract(0, 11, 900_000_000)));
    }

    #[test]
    fn pending_wallet_transfer_clears_when_wallet_seqno_advances() {
        let before = active_wallet(2_000_000_000);
        let pending =
            PendingWalletTransferRequest::new(&prepared_wallet_transfer_message(), &before);
        let after = TonWalletSnapshot {
            balance: before.balance,
            seqno: Some(8),
            state: TonAccountState::Active,
            last_tx_lt: Some(11),
        };

        assert!(!pending.is_completed_by(&before));
        assert!(pending.is_completed_by(&after));
    }
}
