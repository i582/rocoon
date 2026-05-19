//! High-level Cocoon client orchestration.
//!
//! This module ties the lower protocol and transport crates together: TCP
//! connect, `PoW`, RA-TLS, Cocoon session framing, proxy authorization, model
//! discovery, and inference requests. It exposes domain-level methods used by
//! the local HTTP server instead of leaking TL objects or frame handling into
//! the API layer.

use std::error::Error;
use std::fmt;
use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use inquire::Text;
use rand::Rng;
use sha2::{Digest, Sha256};

use crate::ton_readonly::{
    COCOON_WALLET_MIN_BALANCE_NANOTONS, COCOON_WALLET_RESERVE_NANOTONS,
    CONTROL_MESSAGE_VALUE_NANOTONS, ClientContractSnapshot, RegisteredProxySnapshot,
    RootContractSnapshot, TonAccountState, TonClientRegisterPreparedMessage,
    TonClientRegisterRequest, TonClientRegisterResult, TonClientSecretHashPreparedMessage,
    TonClientSecretHashRequest, TonClientSecretHashResult, TonClientTopUpPreparedMessage,
    TonClientTopUpRequest, TonClientTopUpResult, TonControlAction, TonControlPreparedMessage,
    TonControlRequest, TonControlResult, TonReadonlyClient, TonReadonlySnapshot, TonWalletSnapshot,
    TonWalletTransferPreparedMessage, TonWalletTransferRequest, TonWalletTransferResult,
};
use rocoon_config::{RuntimeConfig, TonRuntimeConfig, color::OwoColorize};
use rocoon_protocol::{self as cocoon, RunQueryOptions, WorkerInstanceV2, WorkerTypeV2};
use rocoon_transport::{QueryError, QueryFinalInfo, RunQueryOutput, Session, pow, ratls};

const CONTROL_RESEND_INTERVAL: Duration = Duration::from_secs(30);
const AUTH_REQUEST_TIMEOUT: Duration = Duration::from_mins(5);
const BALANCE_CHECK_MIN_SECS: f64 = 1.0;
const BALANCE_CHECK_MAX_SECS: f64 = 2.0;
const PAYMENT_COMPARE_MIN_SECS: f64 = 10.0;
const PAYMENT_COMPARE_MAX_SECS: f64 = 20.0;
const COCOON_CLIENT_CONTRACT_STATE_CLOSED: u8 = 2;
const PROXY_CLIENT_CLOSING_QUERY_ERROR_CODE: i32 = 602;
const PROXY_CLIENT_CLOSING_QUERY_ERROR_MESSAGE: &str = "client is closing";
const INTERACTIVE_REQUIRED_WALLET_BALANCE_NANOTONS: u64 = 20_000_000_000;
const NANOTONS_PER_TON: u64 = 1_000_000_000;
const SECRET_HASH_CONFIRM_ATTEMPTS: usize = 30;
const SECRET_HASH_CONFIRM_INTERVAL: Duration = Duration::from_secs(1);
const AUTO_PROXY_ADDR: &str = "auto";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectVerbosity {
    Quiet,
    Interactive,
    InteractiveVerbose,
}

impl ConnectVerbosity {
    const fn is_verbose(self) -> bool {
        matches!(self, Self::InteractiveVerbose)
    }

    const fn is_interactive(self) -> bool {
        matches!(self, Self::Interactive | Self::InteractiveVerbose)
    }

    const fn interactive(verbose: bool) -> Self {
        if verbose {
            Self::InteractiveVerbose
        } else {
            Self::Interactive
        }
    }
}

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
    client_top_up_request: Option<PendingClientTopUpRequest>,
    next_balance_check_at: Instant,
    next_payment_compare_at: Instant,
    verbosity: ConnectVerbosity,
}

/// Proxy rejection that means the configured Cocoon wallet cannot start again.
#[derive(Debug)]
pub struct ClientContractClosedOrClosing;

impl fmt::Display for ClientContractClosedOrClosing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("client contract is closing or closed")
    }
}

impl Error for ClientContractClosedOrClosing {}

/// Returns true when a failure chain contains a closed/closing contract proxy rejection.
#[must_use]
pub fn is_client_contract_closed_or_closing_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<ClientContractClosedOrClosing>()
            .is_some()
    })
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
    /// Whether a client-contract top-up request is still waiting for confirmation.
    pub client_top_up_running: bool,
    /// Connected client contract account and data-cell state.
    pub client_contract: Option<ClientContractSnapshot>,
    /// Root contract state and registered proxies, when configured.
    pub root_contract: Option<RootContractSnapshot>,
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

/// Metadata returned by a lightweight `client.connectToProxy` probe.
pub struct ProxyHandshakeInfo {
    /// TCP address used for the probe.
    pub proxy_addr: String,
    /// Proxy public key returned by `client.connectedToProxy`.
    pub proxy_public_key: [u8; 32],
    /// Protocol version negotiated with the proxy.
    pub proto_version: i32,
    /// Whether the proxy reports a testnet configuration.
    pub is_test: Option<bool>,
    /// Proxy owner address returned by `client.connectedToProxy`.
    pub proxy_owner_address: String,
    /// Proxy smart-contract address returned by `client.connectedToProxy`.
    pub proxy_sc_address: String,
    /// Client smart-contract address returned by `client.connectedToProxy`.
    pub client_sc_address: String,
    /// Authorization mode selected by the proxy.
    pub auth: ProxyHandshakeAuth,
    /// Whether the proxy attached signed payment data to the connection reply.
    pub signed_payment_available: bool,
}

/// Authorization mode returned by a lightweight proxy probe.
pub enum ProxyHandshakeAuth {
    /// Existing registered client can authorize with a shared secret.
    Short { nonce: i64 },
    /// Client must perform on-chain registration before requests can run.
    Long { nonce: i64 },
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
    /// `client.connectToProxy` -> short auth, or on-chain long auth register
    /// followed by `client.authorizeWithProxyLong`.
    ///
    /// # Errors
    ///
    /// Returns an error if DNS/TCP connection, `PoW`, RA-TLS, session framing,
    /// proxy authorization, or TON long-auth registration fails.
    pub fn connect(config: &RuntimeConfig) -> Result<Self> {
        Self::connect_with_verbosity(config, ConnectVerbosity::Quiet)
    }

    /// Connected client contract address returned by `client.connectToProxy`.
    #[must_use]
    pub fn client_contract_address(&self) -> &str {
        &self.client_sc_address
    }

    /// Opens and authorizes a full Cocoon proxy connection for CLI use.
    ///
    /// When long authorization is required, this variant shows the derived
    /// Cocoon wallet address, waits until the user confirms funding, and turns
    /// low-balance TON errors into concise retry prompts.
    ///
    /// # Errors
    ///
    /// Returns non-actionable connection, transport, protocol, and TON errors.
    pub fn connect_interactive(config: &RuntimeConfig) -> Result<Self> {
        let verbosity = ConnectVerbosity::interactive(config.verbose);
        let config = resolve_proxy_config(config, verbosity.is_interactive())?;
        loop {
            println!(
                "{} Connecting to Cocoon proxy {}",
                ">".cyan().bold(),
                config.proxy_addr
            );
            match Self::connect_with_verbosity(&config, verbosity) {
                Ok(client) => {
                    println!("{} Cocoon proxy connected", "✓".green().bold());
                    return Ok(client);
                }
                Err(error) => {
                    let Some(action) = wallet_funding_required_from_error(&error) else {
                        return Err(error);
                    };

                    println!();
                    println!("{} Cocoon wallet needs funding", "!".yellow().bold());
                    println!("Address: {}", action.wallet_address);
                    println!("Current: {} TON", format_nanotons(action.current_balance));
                    println!("Required: {} TON", format_nanotons(action.required_balance));
                    println!("Missing: {} TON", format_nanotons(action.missing_balance));

                    wait_for_enter("Fund the wallet and press Enter to retry...")?;
                }
            }
        }
    }

    /// Sends one client-contract withdraw request and exits without running HTTP.
    ///
    /// This withdraws the balance above stake from the client contract back to
    /// the Cocoon wallet. It does not sweep the Cocoon wallet to the owner
    /// address; use `sweep_cocoon_wallet_interactive` for that second step.
    ///
    /// # Errors
    ///
    /// Returns an error if proxy discovery, TON state reads, wallet signing, or
    /// liteserver message submission fails.
    pub fn request_withdraw_interactive(
        config: &RuntimeConfig,
        client_contract_address: Option<&str>,
    ) -> Result<TonControlResult> {
        Self::request_control_interactive(
            config,
            client_contract_address,
            TonControlAction::Withdraw,
        )
    }

    /// Sends one client-contract close request and exits without running HTTP.
    ///
    /// If `client_contract_address` is omitted, this performs only lightweight
    /// proxy discovery (`client.connectToProxy`) to learn the client contract
    /// address, then sends the TON control message directly through the Cocoon
    /// wallet.
    ///
    /// # Errors
    ///
    /// Returns an error if proxy discovery, TON state reads, wallet signing, or
    /// liteserver message submission fails.
    pub fn request_close_interactive(
        config: &RuntimeConfig,
        client_contract_address: Option<&str>,
    ) -> Result<TonControlResult> {
        Self::request_control_interactive(
            config,
            client_contract_address,
            TonControlAction::RequestRefund,
        )
    }

    fn request_control_interactive(
        config: &RuntimeConfig,
        client_contract_address: Option<&str>,
        action: TonControlAction,
    ) -> Result<TonControlResult> {
        let action_name = match action {
            TonControlAction::Withdraw => "withdraw",
            TonControlAction::RequestRefund => "close",
        };
        let client_contract_address =
            resolve_client_contract_address(config, client_contract_address, config.verbose)?;
        println!(
            "{} Sending {action_name} request to {}",
            ">".cyan().bold(),
            client_contract_address
        );
        send_client_control_from_config(config, &client_contract_address, action)
    }

    /// Sends all sweepable Cocoon wallet funds and exits without running HTTP.
    ///
    /// If `client_contract_address` is omitted, this tries lightweight proxy
    /// discovery. For an already closed contract the proxy may reject discovery,
    /// so CLI callers should pass the address printed by `--close`.
    ///
    /// # Errors
    ///
    /// Returns an error if the client contract address cannot be discovered,
    /// the contract is not closed, or the wallet transfer cannot be sent.
    pub fn sweep_cocoon_wallet_interactive(
        config: &RuntimeConfig,
        client_contract_address: Option<&str>,
        destination_address: Option<&str>,
        reserve_nanotons: u64,
    ) -> Result<TonWalletTransferResult> {
        let client_contract_address =
            resolve_client_contract_address(config, client_contract_address, config.verbose)?;
        println!(
            "{} Sweeping Cocoon wallet via client contract {}",
            ">".cyan().bold(),
            client_contract_address
        );
        sweep_cocoon_wallet_from_config(
            config,
            &client_contract_address,
            destination_address,
            reserve_nanotons,
        )
    }

    /// Reads the Cocoon root contract and returns the registered proxy list.
    ///
    /// # Errors
    ///
    /// Returns an error when no root contract address is configured, TON
    /// liteclient initialization fails, or the root contract data cannot be read.
    pub fn root_contract_snapshot(
        config: &RuntimeConfig,
        root_contract_address: Option<&str>,
    ) -> Result<RootContractSnapshot> {
        let root_contract_address = root_contract_address
            .or(config.ton.root_contract_address.as_deref())
            .context(
                "ton.root_contract_address is required; pass --root-contract or set [ton].root_contract_address",
            )?;
        let client = TonReadonlyClient::connect(&config.ton)
            .context("connect TON liteclient for Cocoon root contract")?;
        client.root_contract_snapshot(root_contract_address)
    }

    /// Performs a lightweight proxy handshake and returns public proxy metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the proxy TCP/RA-TLS/session handshake fails or
    /// `client.connectToProxy` does not return a valid response.
    pub fn proxy_handshake_info(
        config: &RuntimeConfig,
        proxy_addr: &str,
    ) -> Result<ProxyHandshakeInfo> {
        let mut config = config.clone();
        config.proxy_addr = proxy_addr.to_string();
        let info = discover_proxy_info(&config, config.verbose)?;
        Ok(ProxyHandshakeInfo {
            proxy_addr: config.proxy_addr,
            proxy_public_key: info.proxy_public_key,
            proto_version: info.proto_version,
            is_test: info.is_test,
            proxy_owner_address: info.proxy_owner_address,
            proxy_sc_address: info.proxy_sc_address,
            client_sc_address: info.client_sc_address,
            auth: proxy_handshake_auth(&info.auth),
            signed_payment_available: info.signed_payment_available,
        })
    }

    fn connect_with_verbosity(config: &RuntimeConfig, verbosity: ConnectVerbosity) -> Result<Self> {
        let config = resolve_proxy_config(config, verbosity.is_interactive())?;
        let mut session = open_session(&config, verbosity.is_verbose())?;
        let mut ton_readonly = TonReadonlyState::new(&config);
        let authorization = authorize(&mut session, &config, &mut ton_readonly, verbosity)?;

        Ok(Self {
            session,
            request_options: RunQueryOptions {
                max_coefficient: config.max_coefficient,
                max_tokens: config.max_tokens,
                timeout: config.request_timeout * 0.95,
                enable_debug: false,
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
            client_top_up_request: None,
            next_balance_check_at: Instant::now(),
            next_payment_compare_at: Instant::now(),
            verbosity,
        })
    }

    /// Runs the C++ client-runner style periodic maintenance.
    ///
    /// C++ does not top up during authorization. Its actor alarm periodically
    /// refreshes client-contract state, decides whether a top-up is needed, and
    /// separately asks the proxy for payment status. This method performs the
    /// same checks for the synchronous Rust bridge.
    pub fn maintenance_tick(&mut self) {
        let now = Instant::now();
        if now >= self.next_balance_check_at {
            self.next_balance_check_at =
                now + random_interval(BALANCE_CHECK_MIN_SECS, BALANCE_CHECK_MAX_SECS);
            if let Err(error) = self.update_balances_and_check()
                && self.verbosity.is_verbose()
            {
                eprintln!("balance check failed: {error:#}");
            }
        }
        if now >= self.next_payment_compare_at {
            self.next_payment_compare_at =
                now + random_interval(PAYMENT_COMPARE_MIN_SECS, PAYMENT_COMPARE_MAX_SECS);
            if let Err(error) = self.refresh_payment_status()
                && self.verbosity.is_verbose()
            {
                eprintln!("payment compare failed: {error:#}");
            }
        }
    }

    /// Returns the locally known connection, wallet, and payment status.
    pub fn status(&mut self) -> ClientStatus {
        let ton = self.ton_readonly.snapshot(
            &self.config.cocoon_wallet_address,
            &self.client_sc_address,
            self.config.ton.root_contract_address.as_deref(),
        );
        if let Some(client_contract) = &ton.client_contract {
            self.refresh_client_top_up_request(client_contract);
        }
        self.resend_pending_wallet_messages_if_due();
        let wallet = ton.wallet.as_ref();
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
            ton_readonly_ok: ton.ok,
            ton_readonly_error: ton.last_error,
            masterchain_seqno: ton.masterchain_seqno,
            root_contract_address: self.config.ton.root_contract_address.clone(),
            wallet_balance: wallet.and_then(|wallet| wallet.balance),
            wallet_seqno: wallet.and_then(|wallet| wallet.seqno),
            wallet_state: wallet.map(|wallet| wallet.state.as_str().to_string()),
            wallet_last_tx_lt: wallet.and_then(|wallet| wallet.last_tx_lt),
            client_top_up_running: self.client_top_up_request.is_some(),
            client_contract: ton.client_contract,
            root_contract: ton.root_contract,
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

        let headers = vec![
            ("Content-Type", "application/json".to_string()),
            ("Content-Length", body.len().to_string()),
        ];
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
        let client_top_up_request = self.client_top_up_request.clone();
        let next_balance_check_at = self.next_balance_check_at;
        let next_payment_compare_at = self.next_payment_compare_at;
        let verbosity = self.verbosity;
        let mut replacement = Self::connect_with_verbosity(&self.config, verbosity)?;
        replacement.client_top_up_request = client_top_up_request;
        replacement.next_balance_check_at = next_balance_check_at;
        replacement.next_payment_compare_at = next_payment_compare_at;
        replacement.verbosity = verbosity;
        *self = replacement;
        Ok(())
    }

    fn update_balances_and_check(&mut self) -> Result<()> {
        let ton = self.ton_readonly.snapshot(
            &self.config.cocoon_wallet_address,
            &self.client_sc_address,
            None,
        );
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
        self.refresh_client_top_up_request(client_contract);
        self.resend_pending_wallet_messages_if_due();
        self.maybe_run_client_top_up(client_contract)
    }

    fn maybe_run_client_top_up(&mut self, client_contract: &ClientContractSnapshot) -> Result<()> {
        if self.client_top_up_request.is_some()
            || client_contract.account_state != TonAccountState::Active
            || client_contract.state_raw.is_none()
            || client_contract
                .state_raw
                .is_some_and(|state| state >= COCOON_CLIENT_CONTRACT_STATE_CLOSED)
        {
            return Ok(());
        }
        let Some(root_contract_address) = self.config.ton.root_contract_address.clone() else {
            return Ok(());
        };

        let request = TonClientTopUpRequest {
            wallet_owner_address: &self.config.owner_address,
            wallet_address: &self.config.cocoon_wallet_address,
            root_contract_address: &root_contract_address,
            client_contract_address: &self.client_sc_address,
            wallet_seed: self.config.node_wallet_key.seed(),
        };
        let Some(prepared) = self.ton_readonly.prepare_client_top_up(&request)? else {
            return Ok(());
        };
        let result = self
            .ton_readonly
            .send_prepared_client_top_up(&prepared)
            .context("send client top-up transaction")?;
        if self.verbosity.is_verbose() {
            println!(
                "client top-up sent: wallet={} client_contract={} top_up={} value={} wallet_seqno={} query_id={} send_status={}",
                result.wallet_address,
                result.client_contract_address,
                result.top_up_amount,
                result.attached_value,
                result.wallet_seqno,
                result.query_id,
                result.send_status
            );
        }
        self.client_top_up_request =
            Some(PendingClientTopUpRequest::new(&prepared, client_contract));
        Ok(())
    }

    fn refresh_payment_status(&mut self) -> Result<()> {
        self.payment_status = update_payment_status(&mut self.session)?;
        Ok(())
    }

    fn refresh_client_top_up_request(&mut self, client_contract: &ClientContractSnapshot) {
        if self
            .client_top_up_request
            .as_ref()
            .is_some_and(|request| request.is_completed_by(client_contract))
        {
            self.client_top_up_request = None;
        }
    }

    fn resend_pending_wallet_messages_if_due(&mut self) {
        self.resend_client_top_up_if_due();
    }

    fn resend_client_top_up_if_due(&mut self) {
        let Some(request) = self.client_top_up_request.as_mut() else {
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
                    "resent Cocoon wallet client top-up: query_id={} wallet_seqno={} top_up={} send_status={send_status}",
                    request.query_id, request.wallet_seqno, request.top_up_amount
                );
            }
            Err(error) => {
                eprintln!(
                    "failed to resend Cocoon wallet client top-up: query_id={} wallet_seqno={} top_up={} error={error:#}",
                    request.query_id, request.wallet_seqno, request.top_up_amount
                );
            }
        }
    }
}

#[derive(Clone, Debug)]
struct PendingClientTopUpRequest {
    query_id: u64,
    wallet_seqno: u32,
    top_up_amount: u64,
    request_balance_before: Option<u64>,
    last_tx_lt_before: Option<u64>,
    external_message: Vec<u8>,
    next_resend_at: Instant,
}

impl PendingClientTopUpRequest {
    fn new(message: &TonClientTopUpPreparedMessage, snapshot: &ClientContractSnapshot) -> Self {
        Self {
            query_id: message.query_id,
            wallet_seqno: message.wallet_seqno,
            top_up_amount: message.top_up_amount,
            request_balance_before: snapshot.balance,
            last_tx_lt_before: snapshot.last_tx_lt,
            external_message: message.external_message.clone(),
            next_resend_at: Instant::now() + CONTROL_RESEND_INTERVAL,
        }
    }

    fn is_completed_by(&self, snapshot: &ClientContractSnapshot) -> bool {
        if let Some(before) = self.last_tx_lt_before
            && snapshot.last_tx_lt.is_some_and(|current| current > before)
        {
            return true;
        }
        if let Some(before) = self.request_balance_before
            && snapshot.balance.is_some_and(|current| current > before)
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

/// Initialization state for TON liteclient diagnostics and wallet messages.
enum TonReadonlyState {
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
        root_contract_address: Option<&str>,
    ) -> TonReadonlySnapshot {
        match self {
            Self::Failed { config, error } => {
                let config = config.clone();
                match TonReadonlyClient::connect(&config) {
                    Ok(client) => {
                        *self = Self::Ready { config, client };
                        self.snapshot(
                            wallet_address,
                            client_contract_address,
                            root_contract_address,
                        )
                    }
                    Err(reconnect_error) => TonReadonlySnapshot::failed(format!(
                        "{error}; reconnect failed: {reconnect_error:#}"
                    )),
                }
            }
            Self::Ready { config, client } => {
                match client.accounts_snapshot(
                    wallet_address,
                    Some(client_contract_address),
                    root_contract_address,
                ) {
                    Ok(snapshot) => snapshot,
                    Err(first_error) => {
                        eprintln!("TON snapshot failed, reconnecting liteclient: {first_error:#}");
                        match TonReadonlyClient::connect(config) {
                            Ok(replacement) => {
                                *client = replacement;
                                client
                                    .accounts_snapshot(
                                        wallet_address,
                                        Some(client_contract_address),
                                        root_contract_address,
                                    )
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
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { .. } => TonReadonlyClient::prepare_client_control_message(request),
        }
    }

    fn prepare_client_register(
        &mut self,
        request: &TonClientRegisterRequest<'_>,
    ) -> Result<TonClientRegisterPreparedMessage> {
        match self {
            Self::Failed { config, error } => {
                let config = config.clone();
                match TonReadonlyClient::connect(&config) {
                    Ok(client) => {
                        *self = Self::Ready { config, client };
                        self.prepare_client_register(request)
                    }
                    Err(reconnect_error) => {
                        anyhow::bail!(
                            "TON liteclient is unavailable: {error}; reconnect failed: {reconnect_error:#}"
                        );
                    }
                }
            }
            Self::Ready { config, client } => match client.prepare_client_register_message(request)
            {
                Ok(message) => Ok(message),
                Err(first_error) => match TonReadonlyClient::connect(config) {
                    Ok(replacement) => {
                        *client = replacement;
                        client
                            .prepare_client_register_message(request)
                            .with_context(|| {
                                format!("{first_error:#}; retry after reconnect also failed")
                            })
                    }
                    Err(reconnect_error) => {
                        anyhow::bail!("{first_error:#}; reconnect failed: {reconnect_error:#}");
                    }
                },
            },
        }
    }

    fn prepare_client_secret_hash(
        &self,
        request: &TonClientSecretHashRequest<'_>,
    ) -> Result<TonClientSecretHashPreparedMessage> {
        match self {
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { .. } => TonReadonlyClient::prepare_client_secret_hash_message(request),
        }
    }

    fn prepare_client_top_up(
        &mut self,
        request: &TonClientTopUpRequest<'_>,
    ) -> Result<Option<TonClientTopUpPreparedMessage>> {
        match self {
            Self::Failed { config, error } => {
                let config = config.clone();
                match TonReadonlyClient::connect(&config) {
                    Ok(client) => {
                        *self = Self::Ready { config, client };
                        self.prepare_client_top_up(request)
                    }
                    Err(reconnect_error) => {
                        anyhow::bail!(
                            "TON liteclient is unavailable: {error}; reconnect failed: {reconnect_error:#}"
                        );
                    }
                }
            }
            Self::Ready { config, client } => match client.prepare_client_top_up_message(request) {
                Ok(message) => Ok(message),
                Err(first_error) => match TonReadonlyClient::connect(config) {
                    Ok(replacement) => {
                        *client = replacement;
                        client
                            .prepare_client_top_up_message(request)
                            .with_context(|| {
                                format!("{first_error:#}; retry after reconnect also failed")
                            })
                    }
                    Err(reconnect_error) => {
                        anyhow::bail!("{first_error:#}; reconnect failed: {reconnect_error:#}");
                    }
                },
            },
        }
    }

    fn send_prepared_client_register(
        &mut self,
        message: &TonClientRegisterPreparedMessage,
    ) -> Result<TonClientRegisterResult> {
        match self {
            Self::Failed { config, error } => {
                let config = config.clone();
                match TonReadonlyClient::connect(&config) {
                    Ok(client) => {
                        *self = Self::Ready { config, client };
                        self.send_prepared_client_register(message)
                    }
                    Err(reconnect_error) => {
                        anyhow::bail!(
                            "TON liteclient is unavailable: {error}; reconnect failed: {reconnect_error:#}"
                        );
                    }
                }
            }
            Self::Ready { config, client } => {
                match client.send_prepared_client_register_message(message) {
                    Ok(result) => Ok(result),
                    Err(first_error) => match TonReadonlyClient::connect(config) {
                        Ok(replacement) => {
                            *client = replacement;
                            client
                                .send_prepared_client_register_message(message)
                                .with_context(|| {
                                    format!("{first_error:#}; retry after reconnect also failed")
                                })
                        }
                        Err(reconnect_error) => {
                            anyhow::bail!("{first_error:#}; reconnect failed: {reconnect_error:#}");
                        }
                    },
                }
            }
        }
    }

    fn send_prepared_client_top_up(
        &mut self,
        message: &TonClientTopUpPreparedMessage,
    ) -> Result<TonClientTopUpResult> {
        match self {
            Self::Failed { config, error } => {
                let config = config.clone();
                match TonReadonlyClient::connect(&config) {
                    Ok(client) => {
                        *self = Self::Ready { config, client };
                        self.send_prepared_client_top_up(message)
                    }
                    Err(reconnect_error) => {
                        anyhow::bail!(
                            "TON liteclient is unavailable: {error}; reconnect failed: {reconnect_error:#}"
                        );
                    }
                }
            }
            Self::Ready { config, client } => {
                match client.send_prepared_client_top_up_message(message) {
                    Ok(result) => Ok(result),
                    Err(first_error) => match TonReadonlyClient::connect(config) {
                        Ok(replacement) => {
                            *client = replacement;
                            client
                                .send_prepared_client_top_up_message(message)
                                .with_context(|| {
                                    format!("{first_error:#}; retry after reconnect also failed")
                                })
                        }
                        Err(reconnect_error) => {
                            anyhow::bail!("{first_error:#}; reconnect failed: {reconnect_error:#}");
                        }
                    },
                }
            }
        }
    }

    fn send_prepared_client_secret_hash(
        &mut self,
        message: &TonClientSecretHashPreparedMessage,
    ) -> Result<TonClientSecretHashResult> {
        match self {
            Self::Failed { config, error } => {
                let config = config.clone();
                match TonReadonlyClient::connect(&config) {
                    Ok(client) => {
                        *self = Self::Ready { config, client };
                        self.send_prepared_client_secret_hash(message)
                    }
                    Err(reconnect_error) => {
                        anyhow::bail!(
                            "TON liteclient is unavailable: {error}; reconnect failed: {reconnect_error:#}"
                        );
                    }
                }
            }
            Self::Ready { config, client } => {
                match client.send_prepared_client_secret_hash_message(message) {
                    Ok(result) => Ok(result),
                    Err(first_error) => match TonReadonlyClient::connect(config) {
                        Ok(replacement) => {
                            *client = replacement;
                            client
                                .send_prepared_client_secret_hash_message(message)
                                .with_context(|| {
                                    format!("{first_error:#}; retry after reconnect also failed")
                                })
                        }
                        Err(reconnect_error) => {
                            anyhow::bail!("{first_error:#}; reconnect failed: {reconnect_error:#}");
                        }
                    },
                }
            }
        }
    }

    fn send_prepared_control(
        &self,
        message: &TonControlPreparedMessage,
    ) -> Result<TonControlResult> {
        match self {
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { client, .. } => client.send_prepared_control_message(message),
        }
    }

    fn prepare_wallet_transfer(
        &self,
        request: &TonWalletTransferRequest<'_>,
    ) -> Result<TonWalletTransferPreparedMessage> {
        match self {
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { .. } => TonReadonlyClient::prepare_wallet_transfer_message(request),
        }
    }

    fn send_prepared_wallet_transfer(
        &self,
        message: &TonWalletTransferPreparedMessage,
    ) -> Result<TonWalletTransferResult> {
        match self {
            Self::Failed { error, .. } => anyhow::bail!("TON liteclient is unavailable: {error}"),
            Self::Ready { client, .. } => client.send_prepared_wallet_transfer_message(message),
        }
    }

    fn resend_external_message(&self, message: &[u8]) -> Result<u32> {
        match self {
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

#[derive(Debug)]
struct CocoonWalletFundingRequired {
    wallet_address: String,
    current_balance: u64,
    required_balance: u64,
    missing_balance: u64,
    message_value: u64,
}

impl fmt::Display for CocoonWalletFundingRequired {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Cocoon wallet {} balance is too low: current={} nanotons, required={} nanotons, missing={} nanotons, message_value={} nanotons",
            self.wallet_address,
            self.current_balance,
            self.required_balance,
            self.missing_balance,
            self.message_value
        )
    }
}

impl Error for CocoonWalletFundingRequired {}

fn validate_cocoon_wallet_can_send_control(
    wallet_address: &str,
    snapshot: &TonWalletSnapshot,
) -> Result<u32> {
    validate_cocoon_wallet_can_send_value(wallet_address, snapshot, CONTROL_MESSAGE_VALUE_NANOTONS)
}

fn validate_cocoon_wallet_can_send_value(
    wallet_address: &str,
    snapshot: &TonWalletSnapshot,
    value_nanotons: u64,
) -> Result<u32> {
    let wallet_seqno = match snapshot.state {
        TonAccountState::Active => snapshot
            .seqno
            .context("Cocoon wallet seqno is unavailable in active account")?,
        TonAccountState::None | TonAccountState::Uninit => 0,
        TonAccountState::Frozen => {
            anyhow::bail!(
                "Cocoon wallet account cannot send control messages: {}",
                snapshot.state.as_str()
            );
        }
    };
    let balance = snapshot
        .balance
        .context("Cocoon wallet balance is unavailable")?;
    let required_for_message = value_nanotons.saturating_add(COCOON_WALLET_RESERVE_NANOTONS);
    let required_balance = required_for_message.max(COCOON_WALLET_MIN_BALANCE_NANOTONS);
    if balance < required_balance {
        let missing_balance = required_balance - balance;
        return Err(CocoonWalletFundingRequired {
            wallet_address: wallet_address.to_string(),
            current_balance: balance,
            required_balance,
            missing_balance,
            message_value: value_nanotons,
        }
        .into());
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

const fn client_contract_state_name_for_error(state: u8) -> &'static str {
    match state {
        0 => "running",
        1 => "closing",
        2 => "closed",
        _ => "unknown",
    }
}

fn random_interval(min_secs: f64, max_secs: f64) -> Duration {
    Duration::from_secs_f64(rand::thread_rng().gen_range(min_secs..max_secs))
}

/// Data collected while authenticating a Cocoon proxy session.
struct AuthorizationInfo {
    proto_version: i32,
    proxy_owner_address: String,
    proxy_sc_address: String,
    client_sc_address: String,
    payment_status: AuthPaymentStatus,
}

struct ConnectedProxyInfo {
    proto_version: i32,
    is_test: Option<bool>,
    proxy_owner_address: String,
    proxy_sc_address: String,
    client_sc_address: String,
    proxy_public_key: [u8; 32],
    auth: ProxyAuthInfo,
    signed_payment_available: bool,
}

enum ProxyAuthInfo {
    Short { secret_hash: [u8; 32], nonce: i64 },
    Long { nonce: i64 },
}

#[derive(Clone, Copy)]
struct LongAuthParams<'a> {
    nonce: u64,
    client_sc_address: &'a str,
    proxy_sc_address: &'a str,
    proxy_public_key: &'a [u8; 32],
    prompt_for_funding: bool,
}

fn open_session(config: &RuntimeConfig, verbose: bool) -> Result<Session<ratls::RatlsStream>> {
    let addr = &config.proxy_addr;
    if verbose {
        println!("connecting to Cocoon proxy at {addr}");
    }
    let socket_addr = addr
        .to_socket_addrs()
        .with_context(|| format!("resolve {addr}"))?
        .next()
        .with_context(|| format!("no socket addresses for {addr}"))?;

    let mut tcp = TcpStream::connect_timeout(&socket_addr, config.connect_timeout)
        .with_context(|| format!("connect TCP to {socket_addr} (from {addr})"))?;
    tcp.set_nodelay(true).context("set TCP_NODELAY")?;

    let pow = pow::handshake(&mut tcp).context("Cocoon TCP PoW handshake")?;
    if verbose {
        println!(
            "pow solved: difficulty={} nonce={} elapsed_ms={}",
            pow.difficulty,
            pow.nonce,
            pow.elapsed.as_millis()
        );
    }

    let tls = ratls::connect(tcp).context("Cocoon RA-TLS handshake")?;
    if verbose {
        println!(
            "tls connected: server_cert_der_len={}",
            tls.server_cert_der_len()
        );
    }

    let (session, connected) =
        Session::connect(tls).context("Cocoon tcp.connect session handshake")?;
    if verbose {
        println!("session connected: id={}", connected.id);
    }
    Ok(session)
}

fn discover_proxy_info(config: &RuntimeConfig, verbose: bool) -> Result<ConnectedProxyInfo> {
    let config = resolve_proxy_config(config, verbose)?;
    let mut session = open_session(&config, verbose)?;
    connect_to_proxy(&mut session, &config)
}

fn resolve_proxy_config(config: &RuntimeConfig, announce: bool) -> Result<RuntimeConfig> {
    if !is_auto_proxy_addr(&config.proxy_addr) {
        return Ok(config.clone());
    }

    let root_contract_address = config.ton.root_contract_address.as_deref().context(
        "network.proxy_addr = \"auto\" requires [ton].root_contract_address or ton.mainnet = true",
    )?;
    if announce {
        println!(
            "{} Resolving Cocoon proxy from root contract {}",
            ">".cyan().bold(),
            root_contract_address.cyan().bold()
        );
    }

    let snapshot = CocoonClient::root_contract_snapshot(config, Some(root_contract_address))
        .context("resolve network.proxy_addr = \"auto\"")?;
    let proxy = select_auto_proxy(&snapshot.registered_proxies).with_context(|| {
        format!("no registered proxies found in Cocoon root contract {root_contract_address}")
    })?;
    let proxy_seqno = proxy.seqno;
    let proxy_addr = proxy.address_for_clients.clone();
    if announce {
        println!(
            "{} Selected Cocoon proxy {} (seqno {})",
            "✓".green().bold(),
            proxy_addr.cyan().bold(),
            proxy_seqno
        );
    }

    let mut config = config.clone();
    config.proxy_addr = proxy_addr;
    Ok(config)
}

fn is_auto_proxy_addr(proxy_addr: &str) -> bool {
    proxy_addr.trim().eq_ignore_ascii_case(AUTO_PROXY_ADDR)
}

fn select_auto_proxy(proxies: &[RegisteredProxySnapshot]) -> Option<&RegisteredProxySnapshot> {
    let candidate_count = proxies
        .iter()
        .filter(|proxy| proxy_has_client_address(proxy))
        .count();
    if candidate_count == 0 {
        return None;
    }
    let selected_index = rand::thread_rng().gen_range(0..candidate_count);
    select_auto_proxy_at(proxies, selected_index)
}

fn select_auto_proxy_at(
    proxies: &[RegisteredProxySnapshot],
    selected_index: usize,
) -> Option<&RegisteredProxySnapshot> {
    proxies
        .iter()
        .filter(|proxy| proxy_has_client_address(proxy))
        .nth(selected_index)
}

fn proxy_has_client_address(proxy: &RegisteredProxySnapshot) -> bool {
    !proxy.address_for_clients.trim().is_empty()
}

fn resolve_client_contract_address(
    config: &RuntimeConfig,
    client_contract_address: Option<&str>,
    verbose: bool,
) -> Result<String> {
    if let Some(address) = client_contract_address.filter(|address| !address.is_empty()) {
        return Ok(address.to_string());
    }
    println!("{} Resolving Cocoon client contract", ">".cyan().bold());
    Ok(discover_proxy_info(config, verbose)
        .context("discover client contract; pass --client-contract if the proxy cannot resolve it")?
        .client_sc_address)
}

fn connect_to_proxy(
    session: &mut Session<ratls::RatlsStream>,
    config: &RuntimeConfig,
) -> Result<ConnectedProxyInfo> {
    let request =
        cocoon::encode_connect_to_proxy(&config.cocoon_wallet_address, config.min_config_version);
    let response = match session.make_request(&request) {
        Ok(response) => response,
        Err(error) if proxy_query_error_is_client_closing(&error) => {
            return Err(anyhow::Error::new(ClientContractClosedOrClosing))
                .context("client.connectToProxy");
        }
        Err(error) => return Err(error).context("client.connectToProxy"),
    };
    let connected_to_proxy = cocoon::decode_connected_to_proxy(&response)?;
    let auth = match connected_to_proxy.auth {
        cocoon::ProxyConnectionAuth::Short { secret_hash, nonce } => ProxyAuthInfo::Short {
            secret_hash: *secret_hash,
            nonce,
        },
        cocoon::ProxyConnectionAuth::Long { nonce } => ProxyAuthInfo::Long { nonce },
    };
    Ok(ConnectedProxyInfo {
        proto_version: connected_to_proxy.params.proto_version.unwrap_or(0),
        is_test: connected_to_proxy.params.is_test,
        proxy_owner_address: String::from_utf8_lossy(connected_to_proxy.params.proxy_owner_address)
            .into_owned(),
        proxy_sc_address: String::from_utf8_lossy(connected_to_proxy.params.proxy_sc_address)
            .into_owned(),
        client_sc_address: String::from_utf8_lossy(connected_to_proxy.client_sc_address)
            .into_owned(),
        proxy_public_key: *connected_to_proxy.params.proxy_public_key,
        auth,
        signed_payment_available: matches!(
            connected_to_proxy.signed_payment,
            cocoon::SignedPayment::Data { .. }
        ),
    })
}

const fn proxy_handshake_auth(auth: &ProxyAuthInfo) -> ProxyHandshakeAuth {
    match auth {
        ProxyAuthInfo::Short { nonce, .. } => ProxyHandshakeAuth::Short { nonce: *nonce },
        ProxyAuthInfo::Long { nonce } => ProxyHandshakeAuth::Long { nonce: *nonce },
    }
}

fn proxy_query_error_is_client_closing(error: &anyhow::Error) -> bool {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<QueryError>())
        .is_some_and(|error| {
            error.code() == PROXY_CLIENT_CLOSING_QUERY_ERROR_CODE
                && error
                    .message()
                    .contains(PROXY_CLIENT_CLOSING_QUERY_ERROR_MESSAGE)
        })
}

/// Performs Cocoon proxy authorization and returns the negotiated protocol version.
fn authorize(
    session: &mut Session<ratls::RatlsStream>,
    config: &RuntimeConfig,
    ton_readonly: &mut TonReadonlyState,
    verbosity: ConnectVerbosity,
) -> Result<AuthorizationInfo> {
    let verbose = verbosity.is_verbose();
    if verbose {
        println!(
            "authenticating owner {} via Cocoon wallet {}",
            config.owner_address, config.cocoon_wallet_address
        );
    }
    let connected_to_proxy = connect_to_proxy(session, config)?;

    let payment_status = match connected_to_proxy.auth {
        ProxyAuthInfo::Short { secret_hash, nonce } => {
            if let Some(secret) = config.client_secret.as_deref()
                && (secret_hash_bytes(secret) == secret_hash)
            {
                authorize_short(session, secret, verbose)?
            } else {
                if verbose {
                    eprintln!(
                        "short auth secret is unavailable or stale; falling back to long auth"
                    );
                }
                authorize_long(
                    session,
                    config,
                    ton_readonly,
                    LongAuthParams {
                        nonce: tl_long_to_u64(nonce),
                        client_sc_address: &connected_to_proxy.client_sc_address,
                        proxy_sc_address: &connected_to_proxy.proxy_sc_address,
                        proxy_public_key: &connected_to_proxy.proxy_public_key,
                        prompt_for_funding: false,
                    },
                    verbosity,
                )?
            }
        }
        ProxyAuthInfo::Long { nonce } => authorize_long(
            session,
            config,
            ton_readonly,
            LongAuthParams {
                nonce: tl_long_to_u64(nonce),
                client_sc_address: &connected_to_proxy.client_sc_address,
                proxy_sc_address: &connected_to_proxy.proxy_sc_address,
                proxy_public_key: &connected_to_proxy.proxy_public_key,
                prompt_for_funding: true,
            },
            verbosity,
        )?,
    };

    Ok(AuthorizationInfo {
        proto_version: connected_to_proxy.proto_version,
        proxy_owner_address: connected_to_proxy.proxy_owner_address,
        proxy_sc_address: connected_to_proxy.proxy_sc_address,
        client_sc_address: connected_to_proxy.client_sc_address,
        payment_status,
    })
}

fn authorize_short(
    session: &mut Session<ratls::RatlsStream>,
    secret: &str,
    verbose: bool,
) -> Result<AuthPaymentStatus> {
    let request = cocoon::encode_authorize_with_proxy_short(secret);
    let response = session
        .make_request_with_timeout(&request, AUTH_REQUEST_TIMEOUT)
        .context("client.authorizeWithProxyShort")?;
    let auth = cocoon::decode_authorization_with_proxy(&response)?;
    payment_status_from_auth(&auth, verbose)
}

fn authorize_long(
    session: &mut Session<ratls::RatlsStream>,
    config: &RuntimeConfig,
    ton_readonly: &mut TonReadonlyState,
    params: LongAuthParams<'_>,
    verbosity: ConnectVerbosity,
) -> Result<AuthPaymentStatus> {
    let root_contract_address = config
        .ton
        .root_contract_address
        .as_deref()
        .context("ton.root_contract_address is required for long auth")?;
    if verbosity.is_interactive() && params.prompt_for_funding {
        wait_for_long_auth_funding(config)?;
    } else if verbosity.is_verbose() {
        println!(
            "running long auth: client_contract={} proxy_contract={} nonce={}",
            params.client_sc_address, params.proxy_sc_address, params.nonce
        );
    }
    let request = TonClientRegisterRequest {
        wallet_owner_address: &config.owner_address,
        wallet_address: &config.cocoon_wallet_address,
        root_contract_address,
        client_contract_address: params.client_sc_address,
        proxy_contract_address: params.proxy_sc_address,
        proxy_public_key: params.proxy_public_key,
        nonce: params.nonce,
        wallet_seed: config.node_wallet_key.seed(),
    };
    let prepared = ton_readonly
        .prepare_client_register(&request)
        .context("prepare long auth register transaction")?;
    let result = ton_readonly
        .send_prepared_client_register(&prepared)
        .context("send long auth register transaction")?;
    if verbosity.is_interactive() {
        println!(
            "{} Long auth transaction sent, waiting for proxy confirmation",
            "✓".green().bold()
        );
    } else if verbosity.is_verbose() {
        println!(
            "long auth register sent: wallet={} client_contract={} value={} wallet_seqno={} query_id={} nonce={} send_status={}",
            result.wallet_address,
            result.client_contract_address,
            result.attached_value,
            result.wallet_seqno,
            result.query_id,
            result.nonce,
            result.send_status
        );
    }

    let request = cocoon::encode_authorize_with_proxy_long();
    let response = session
        .make_request_with_timeout(&request, AUTH_REQUEST_TIMEOUT)
        .context("client.authorizeWithProxyLong")?;
    let auth = cocoon::decode_authorization_with_proxy(&response)?;
    let payment_status = payment_status_from_auth(&auth, verbosity.is_verbose())?;
    ensure_short_auth_secret_hash(config, ton_readonly, params.client_sc_address, verbosity)?;
    Ok(payment_status)
}

fn update_payment_status(session: &mut Session<ratls::RatlsStream>) -> Result<AuthPaymentStatus> {
    let request = cocoon::encode_update_payment_status();
    let response = session
        .make_request(&request)
        .context("client.updatePaymentStatus")?;
    let status = cocoon::decode_payment_status(&response)?;
    Ok(payment_status_from_fields(
        &status.signed_payment,
        status.db_tokens,
        status.max_tokens,
    ))
}

fn send_client_control_from_config(
    config: &RuntimeConfig,
    client_sc_address: &str,
    action: TonControlAction,
) -> Result<TonControlResult> {
    let mut ton_readonly = TonReadonlyState::new(config);
    let ton = ton_readonly.snapshot(&config.cocoon_wallet_address, client_sc_address, None);
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
    validate_client_contract_control(client_contract)?;
    let wallet = ton
        .wallet
        .as_ref()
        .context("Cocoon wallet state is unavailable")?;
    let wallet_seqno =
        validate_cocoon_wallet_can_send_control(&config.cocoon_wallet_address, wallet)?;
    let request = TonControlRequest {
        action,
        wallet_owner_address: &config.owner_address,
        wallet_address: &config.cocoon_wallet_address,
        wallet_seqno,
        client_contract_address: client_sc_address,
        wallet_seed: config.node_wallet_key.seed(),
    };
    let prepared = ton_readonly.prepare_client_control(&request)?;
    ton_readonly.send_prepared_control(&prepared)
}

fn sweep_cocoon_wallet_from_config(
    config: &RuntimeConfig,
    client_sc_address: &str,
    destination_address: Option<&str>,
    reserve_nanotons: u64,
) -> Result<TonWalletTransferResult> {
    let mut ton_readonly = TonReadonlyState::new(config);
    let ton = ton_readonly.snapshot(&config.cocoon_wallet_address, client_sc_address, None);
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
    validate_client_contract_closed_for_sweep(client_contract)?;
    let wallet = ton
        .wallet
        .as_ref()
        .context("Cocoon wallet state is unavailable")?;
    let (wallet_seqno, amount) =
        validate_cocoon_wallet_can_sweep(&config.cocoon_wallet_address, wallet, reserve_nanotons)?;
    let destination_address = destination_address
        .filter(|address| !address.is_empty())
        .unwrap_or(&config.owner_address);
    let request = TonWalletTransferRequest {
        wallet_owner_address: &config.owner_address,
        wallet_address: &config.cocoon_wallet_address,
        wallet_seqno,
        wallet_seed: config.node_wallet_key.seed(),
        destination_address,
        amount,
    };
    let prepared = ton_readonly.prepare_wallet_transfer(&request)?;
    ton_readonly.send_prepared_wallet_transfer(&prepared)
}

fn ensure_short_auth_secret_hash(
    config: &RuntimeConfig,
    ton_readonly: &mut TonReadonlyState,
    client_sc_address: &str,
    verbosity: ConnectVerbosity,
) -> Result<()> {
    let Some(secret) = config.client_secret.as_deref() else {
        return Ok(());
    };
    let desired_secret_hash = secret_hash_bytes(secret);
    let mut sent_update = false;

    for attempt in 1..=SECRET_HASH_CONFIRM_ATTEMPTS {
        let snapshot =
            ton_readonly.snapshot(&config.cocoon_wallet_address, client_sc_address, None);
        if !snapshot.ok {
            if attempt == SECRET_HASH_CONFIRM_ATTEMPTS {
                anyhow::bail!(
                    "short-auth secret hash check failed: {}",
                    snapshot.last_error.as_deref().unwrap_or("unknown error")
                );
            }
            thread::sleep(SECRET_HASH_CONFIRM_INTERVAL);
            continue;
        }

        let client_contract = snapshot
            .client_contract
            .as_ref()
            .context("client contract state is unavailable for short-auth secret update")?;
        if client_contract.secret_hash == Some(desired_secret_hash) {
            if sent_update && verbosity.is_interactive() {
                println!("{} Short auth token installed", "✓".green().bold());
            }
            return Ok(());
        }

        if !sent_update {
            let wallet = snapshot
                .wallet
                .as_ref()
                .context("Cocoon wallet state is unavailable for short-auth secret update")?;
            validate_client_contract_control(client_contract)?;
            let wallet_seqno =
                validate_cocoon_wallet_can_send_control(&config.cocoon_wallet_address, wallet)?;
            let request = TonClientSecretHashRequest {
                wallet_owner_address: &config.owner_address,
                wallet_address: &config.cocoon_wallet_address,
                wallet_seqno,
                client_contract_address: client_sc_address,
                secret_hash: &desired_secret_hash,
                wallet_seed: config.node_wallet_key.seed(),
            };
            let prepared = ton_readonly.prepare_client_secret_hash(&request)?;
            let result = ton_readonly.send_prepared_client_secret_hash(&prepared)?;
            if verbosity.is_verbose() {
                println!(
                    "client secret hash update sent: wallet={} client_contract={} value={} wallet_seqno={} query_id={} send_status={}",
                    result.wallet_address,
                    result.client_contract_address,
                    result.attached_value,
                    result.wallet_seqno,
                    result.query_id,
                    result.send_status
                );
            }
            sent_update = true;
        }

        thread::sleep(SECRET_HASH_CONFIRM_INTERVAL);
    }

    anyhow::bail!("short-auth secret hash update was not confirmed")
}

fn wait_for_long_auth_funding(config: &RuntimeConfig) -> Result<()> {
    println!(
        "{} Long auth requires a funded Cocoon wallet",
        ">".cyan().bold()
    );
    println!("Address: {}", config.cocoon_wallet_address);
    println!(
        "Deposit {} to this address, then continue.",
        "20 TON".yellow().bold()
    );
    wait_for_enter("Press Enter after funding...")?;

    loop {
        match read_interactive_wallet_balance(config) {
            Ok(balance) if balance < INTERACTIVE_REQUIRED_WALLET_BALANCE_NANOTONS => {
                let wallet_address = &config.cocoon_wallet_address;
                let missing = INTERACTIVE_REQUIRED_WALLET_BALANCE_NANOTONS.saturating_sub(balance);

                println!();
                println!("{} Cocoon wallet needs funding", "!".yellow().bold());
                println!("Address: {wallet_address}");
                println!("Current: {} TON", format_nanotons(balance));
                println!(
                    "Required: {} TON",
                    format_nanotons(INTERACTIVE_REQUIRED_WALLET_BALANCE_NANOTONS)
                );
                println!("Missing: {} TON", format_nanotons(missing));
                wait_for_enter("Fund the wallet and press Enter...")?;
            }
            Ok(balance) => {
                println!(
                    "{} Cocoon wallet balance: {} TON",
                    "✓".green().bold(),
                    format_nanotons(balance)
                );
                return Ok(());
            }
            Err(error) => {
                println!(
                    "{} Could not check Cocoon wallet balance: {error:#}",
                    "!".yellow().bold()
                );
                println!("Continuing; TON will return a clear error if the wallet is underfunded.");
                return Ok(());
            }
        }
    }
}

fn read_interactive_wallet_balance(config: &RuntimeConfig) -> Result<u64> {
    let client = TonReadonlyClient::connect(&config.ton)
        .context("connect TON liteclient to check Cocoon wallet balance")?;
    let snapshot = client
        .accounts_snapshot(&config.cocoon_wallet_address, None, None)
        .context("read Cocoon wallet balance")?;
    snapshot
        .wallet
        .and_then(|wallet| wallet.balance)
        .context("Cocoon wallet balance is unavailable")
}

fn wait_for_enter(prompt: &str) -> Result<()> {
    Text::new(prompt)
        .prompt()
        .context("read prompt confirmation")?;
    Ok(())
}

fn wallet_funding_required_from_error(
    error: &anyhow::Error,
) -> Option<&CocoonWalletFundingRequired> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<CocoonWalletFundingRequired>())
}

fn format_nanotons(value: u64) -> String {
    let whole = value / NANOTONS_PER_TON;
    let fraction = value % NANOTONS_PER_TON;
    format!("{whole}.{fraction:09}")
}

fn secret_hash_bytes(secret: &str) -> [u8; 32] {
    let digest = Sha256::digest(secret.as_bytes());
    digest.into()
}

const fn tl_long_to_u64(value: i64) -> u64 {
    u64::from_le_bytes(value.to_le_bytes())
}

/// Converts the proxy authorization result into local payment status.
fn payment_status_from_auth(
    auth: &cocoon::AuthorizationWithProxy<'_>,
    verbose: bool,
) -> Result<AuthPaymentStatus> {
    match auth {
        cocoon::AuthorizationWithProxy::Success {
            signed_payment,
            tokens_committed_to_db,
            max_tokens,
        } => {
            if verbose {
                println!(
                    "auth success: tokens_committed_to_db={tokens_committed_to_db} max_tokens={max_tokens}"
                );
            }
            Ok(payment_status_from_fields(
                signed_payment,
                *tokens_committed_to_db,
                *max_tokens,
            ))
        }
        cocoon::AuthorizationWithProxy::Failed { error_code, error } => {
            anyhow::bail!("auth failed: code={error_code} error={}", utf8(error)?)
        }
    }
}

const fn payment_status_from_fields(
    signed_payment: &cocoon::SignedPayment<'_>,
    tokens_committed_to_db: i64,
    max_tokens: i64,
) -> AuthPaymentStatus {
    AuthPaymentStatus {
        signed_payment_available: matches!(signed_payment, cocoon::SignedPayment::Data { .. }),
        tokens_committed_to_db,
        max_tokens,
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

    const fn none_wallet(balance: u64) -> TonWalletSnapshot {
        TonWalletSnapshot {
            balance: Some(balance),
            seqno: None,
            state: TonAccountState::None,
            last_tx_lt: None,
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
            secret_hash: Some([0; 32]),
            withdrawable_balance: Some(withdrawable_balance),
        }
    }

    fn registered_proxy(seqno: u32, address_for_clients: &str) -> RegisteredProxySnapshot {
        RegisteredProxySnapshot {
            seqno,
            address: address_for_clients.to_string(),
            address_for_workers: format!("workers-{seqno}:8888"),
            address_for_clients: address_for_clients.to_string(),
        }
    }

    #[test]
    fn proxy_client_closing_query_error_is_actionable() {
        let error = anyhow::Error::new(QueryError::new(602, "client is closing"));

        assert!(proxy_query_error_is_client_closing(&error));
    }

    #[test]
    fn client_contract_closed_error_is_detected_through_context() {
        let error =
            anyhow::Error::new(ClientContractClosedOrClosing).context("client.connectToProxy");

        assert!(is_client_contract_closed_or_closing_error(&error));
    }

    #[test]
    fn auto_proxy_selects_index_from_available_client_addresses() {
        let proxies = [
            registered_proxy(1, "proxy-1:8888"),
            registered_proxy(2, "proxy-2:8888"),
        ];

        let proxy = select_auto_proxy_at(&proxies, 1).expect("proxy should be selected");

        assert_eq!(proxy.address_for_clients, "proxy-2:8888");
    }

    #[test]
    fn auto_proxy_random_selection_returns_a_candidate() {
        let proxies = [
            registered_proxy(3, "proxy-3:8888"),
            registered_proxy(7, "proxy-7:8888"),
        ];

        let proxy = select_auto_proxy(&proxies).expect("proxy should be selected");

        assert!(["proxy-3:8888", "proxy-7:8888"].contains(&proxy.address_for_clients.as_str()));
    }

    #[test]
    fn auto_proxy_ignores_empty_client_addresses() {
        let proxies = [
            registered_proxy(10, ""),
            registered_proxy(9, "proxy-9:8888"),
        ];

        let proxy = select_auto_proxy_at(&proxies, 0).expect("proxy should be selected");

        assert_eq!(proxy.address_for_clients, "proxy-9:8888");
    }

    #[test]
    fn control_send_requires_cocoon_wallet_min_balance() -> Result<()> {
        let required_balance = COCOON_WALLET_MIN_BALANCE_NANOTONS;
        let low_wallet = active_wallet(required_balance - 1);
        let error = validate_cocoon_wallet_can_send_control("wallet", &low_wallet)
            .expect_err("wallet below the Cocoon minimum must be rejected");
        let funding_error = wallet_funding_required_from_error(&error)
            .expect("low wallet balance must be reported as a structured funding error");
        assert_eq!(funding_error.wallet_address, "wallet");
        assert_eq!(funding_error.current_balance, required_balance - 1);
        assert_eq!(funding_error.required_balance, required_balance);
        assert_eq!(funding_error.missing_balance, 1);

        let funded_wallet = active_wallet(required_balance);
        assert_eq!(
            validate_cocoon_wallet_can_send_control("wallet", &funded_wallet)?,
            7
        );
        Ok(())
    }

    #[test]
    fn control_send_can_deploy_uninit_wallet_with_seqno_zero() -> Result<()> {
        let required_balance = COCOON_WALLET_MIN_BALANCE_NANOTONS;
        let wallet = uninit_wallet(required_balance);

        assert_eq!(
            validate_cocoon_wallet_can_send_control("wallet", &wallet)?,
            0
        );
        Ok(())
    }

    #[test]
    fn control_send_reports_low_balance_for_missing_wallet_account() {
        let wallet = none_wallet(0);

        let error = validate_cocoon_wallet_can_send_control("wallet", &wallet)
            .expect_err("missing wallet account with zero balance must be rejected as underfunded");

        let funding_error = wallet_funding_required_from_error(&error)
            .expect("missing wallet account must be reported as a structured funding error");
        assert_eq!(funding_error.wallet_address, "wallet");
        assert_eq!(funding_error.current_balance, 0);
        assert_eq!(
            funding_error.required_balance,
            COCOON_WALLET_MIN_BALANCE_NANOTONS
        );
        assert_eq!(
            funding_error.missing_balance,
            COCOON_WALLET_MIN_BALANCE_NANOTONS
        );
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
}
