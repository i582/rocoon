//! Runtime statistics exposed by the local HTTP bridge.
//!
//! C++ Cocoon exposes `/stats` and `/jsonstats` from a runner that also owns
//! TON wallet state. `rocoon` now reads wallet state through a read-only TON
//! liteclient and combines it with local proxy/session counters.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rocoon_client::{ClientStatus, HttpExchange, QueryFinalInfo, TokenUsage};
use serde::Serialize;
use serde_json::Value;

const NANOTONS_PER_TON: u64 = 1_000_000_000;

/// Accumulated local bridge counters.
#[derive(Default)]
pub struct ServerStats {
    completion_requests_started: u64,
    completion_requests_succeeded: u64,
    completion_requests_failed: u64,
    completion_requests_in_flight: u64,
    request_bytes_received: u64,
    response_bytes_sent: u64,
    total_request_duration_ms: u64,
    cocoon_tokens_used: TokenUsage,
    openai_usage: OpenAiUsage,
    last_request: Option<LastRequestStats>,
    last_error: Option<String>,
}

/// Success data captured after Cocoon returns a worker response.
#[derive(Clone, Copy)]
pub struct CompletionSuccess<'a> {
    pub model: &'a str,
    pub path: &'a str,
    pub request_bytes: usize,
    pub duration: Duration,
    pub response: &'a HttpExchange,
}

/// Failure data captured when a completion request cannot be served.
#[derive(Clone, Copy)]
pub struct CompletionFailure<'a> {
    pub model: &'a str,
    pub path: &'a str,
    pub request_bytes: usize,
    pub duration: Duration,
    pub error: &'a str,
}

impl ServerStats {
    /// Marks a completion request as in-flight.
    pub const fn record_completion_started(&mut self) {
        self.completion_requests_started = self.completion_requests_started.saturating_add(1);
        self.completion_requests_in_flight = self.completion_requests_in_flight.saturating_add(1);
    }

    /// Records a completed inference response.
    pub fn record_completion_success(&mut self, success: CompletionSuccess<'_>) {
        let openai_usage = parse_openai_usage(&success.response.payload);
        self.completion_requests_in_flight = self.completion_requests_in_flight.saturating_sub(1);
        self.completion_requests_succeeded = self.completion_requests_succeeded.saturating_add(1);
        self.request_bytes_received = self
            .request_bytes_received
            .saturating_add(usize_to_u64(success.request_bytes));
        self.response_bytes_sent = self
            .response_bytes_sent
            .saturating_add(usize_to_u64(success.response.payload.len()));
        self.total_request_duration_ms = self
            .total_request_duration_ms
            .saturating_add(duration_ms(success.duration));

        if let Some(final_info) = &success.response.final_info {
            add_token_usage(&mut self.cocoon_tokens_used, final_info.tokens_used);
        }
        if let Some(usage) = openai_usage {
            self.openai_usage.add(usage);
        }

        self.last_error = None;
        self.last_request = Some(LastRequestStats {
            completed_at_unix: unix_now(),
            model: success.model.to_string(),
            path: success.path.to_string(),
            success: true,
            status_code: Some(success.response.status_code),
            error: None,
            request_bytes: usize_to_u64(success.request_bytes),
            response_bytes: usize_to_u64(success.response.payload.len()),
            duration_ms: duration_ms(success.duration),
            openai_usage,
            final_info: success.response.final_info.clone(),
        });
    }

    /// Records a failed inference request.
    pub fn record_completion_failure(&mut self, failure: CompletionFailure<'_>) {
        let error = failure.error.to_string();
        self.completion_requests_in_flight = self.completion_requests_in_flight.saturating_sub(1);
        self.completion_requests_failed = self.completion_requests_failed.saturating_add(1);
        self.request_bytes_received = self
            .request_bytes_received
            .saturating_add(usize_to_u64(failure.request_bytes));
        self.total_request_duration_ms = self
            .total_request_duration_ms
            .saturating_add(duration_ms(failure.duration));
        self.last_error = Some(error.clone());
        self.last_request = Some(LastRequestStats {
            completed_at_unix: unix_now(),
            model: failure.model.to_string(),
            path: failure.path.to_string(),
            success: false,
            status_code: None,
            error: Some(error),
            request_bytes: usize_to_u64(failure.request_bytes),
            response_bytes: 0,
            duration_ms: duration_ms(failure.duration),
            openai_usage: None,
            final_info: None,
        });
    }

    /// Builds the response body for `/stats`, `/jsonstats`, and `/v1/stats`.
    pub fn to_response(&self, client: &ClientStatus) -> StatsResponse {
        StatsResponse {
            object: "rocoon.stats",
            status: StatusResponse {
                ton_wallet_polling_ok: client.ton_readonly_ok,
                ton_readonly_error: client.ton_readonly_error.clone(),
            },
            client: ClientResponse {
                proxy_addr: client.proxy_addr.clone(),
                owner_address: client.owner_address.clone(),
                cocoon_wallet_address: client.cocoon_wallet_address.clone(),
                root_contract_address: client.root_contract_address.clone(),
                proto_version: client.proto_version,
                active_proxy_connections: client.active_proxy_connections,
                proxy_owner_address: client.proxy_owner_address.clone(),
                proxy_sc_address: client.proxy_sc_address.clone(),
                client_sc_address: client.client_sc_address.clone(),
            },
            blockchain: BlockchainResponse {
                network: "ton",
                masterchain_seqno: client.masterchain_seqno,
            },
            client_contract: client_contract_response(client),
            wallet: WalletResponse {
                address: client.cocoon_wallet_address.clone(),
                balance: client.wallet_balance,
                balance_ton: client.wallet_balance.map(format_nanotons_u64_as_ton),
                seqno: client.wallet_seqno,
                state: client.wallet_state.clone(),
                last_tx_lt: client.wallet_last_tx_lt,
            },
            payment: PaymentResponse {
                signed_payment_available: client.payment_status.signed_payment_available,
                tokens_committed_to_db: client.payment_status.tokens_committed_to_db,
                max_tokens: client.payment_status.max_tokens,
            },
            requests: RequestsResponse {
                completion_started: self.completion_requests_started,
                completion_success: self.completion_requests_succeeded,
                completion_failed: self.completion_requests_failed,
                completion_in_flight: self.completion_requests_in_flight,
                bytes_received: self.request_bytes_received,
                bytes_sent: self.response_bytes_sent,
                total_time_ms: self.total_request_duration_ms,
            },
            usage: UsageResponse {
                cocoon_final_info_tokens: TokenUsageResponse::from(self.cocoon_tokens_used),
                openai_response_usage: OpenAiUsageResponse::from(self.openai_usage),
                cost: CostResponse {
                    total_cost: self.openai_usage.total_cost,
                    total_cost_ton_estimate: format_nanotons_as_ton(self.openai_usage.total_cost),
                    note: "total_cost is forwarded from worker response usage; TON charges are not independently verified yet",
                },
            },
            debug: DebugResponse {
                last_error: self.last_error.clone(),
            },
            last_request: self.last_request.as_ref().map(LastRequestResponse::from),
        }
    }
}

/// Serialized `/stats` response.
#[derive(Serialize)]
pub struct StatsResponse {
    object: &'static str,
    status: StatusResponse,
    client: ClientResponse,
    blockchain: BlockchainResponse,
    client_contract: Option<ClientContractResponse>,
    wallet: WalletResponse,
    payment: PaymentResponse,
    requests: RequestsResponse,
    usage: UsageResponse,
    debug: DebugResponse,
    last_request: Option<LastRequestResponse>,
}

#[derive(Serialize)]
struct StatusResponse {
    ton_wallet_polling_ok: bool,
    ton_readonly_error: Option<String>,
}

#[derive(Serialize)]
struct ClientResponse {
    proxy_addr: String,
    owner_address: String,
    cocoon_wallet_address: String,
    root_contract_address: Option<String>,
    proto_version: i32,
    active_proxy_connections: usize,
    proxy_owner_address: String,
    proxy_sc_address: String,
    client_sc_address: String,
}

#[derive(Serialize)]
struct BlockchainResponse {
    network: &'static str,
    masterchain_seqno: Option<u32>,
}

#[derive(Serialize)]
struct ClientContractResponse {
    address: String,
    account_state: &'static str,
    account_balance: Option<u64>,
    account_balance_ton: Option<String>,
    last_tx_lt: Option<u64>,
    state: Option<&'static str>,
    state_raw: Option<u8>,
    balance: Option<u64>,
    balance_ton: Option<String>,
    stake: Option<u64>,
    stake_ton: Option<String>,
    tokens_used: Option<u64>,
    unlock_ts: Option<u32>,
    withdrawable_balance: Option<u64>,
    withdrawable_balance_ton: Option<String>,
    client_top_up_running: bool,
}

#[derive(Serialize)]
struct WalletResponse {
    address: String,
    balance: Option<u64>,
    balance_ton: Option<String>,
    seqno: Option<u32>,
    state: Option<String>,
    last_tx_lt: Option<u64>,
}

#[derive(Serialize)]
struct PaymentResponse {
    signed_payment_available: bool,
    tokens_committed_to_db: i64,
    max_tokens: i64,
}

#[derive(Serialize)]
struct RequestsResponse {
    completion_started: u64,
    completion_success: u64,
    completion_failed: u64,
    completion_in_flight: u64,
    bytes_received: u64,
    bytes_sent: u64,
    total_time_ms: u64,
}

#[derive(Serialize)]
struct UsageResponse {
    cocoon_final_info_tokens: TokenUsageResponse,
    openai_response_usage: OpenAiUsageResponse,
    cost: CostResponse,
}

#[derive(Serialize)]
struct CostResponse {
    total_cost: i64,
    total_cost_ton_estimate: String,
    note: &'static str,
}

#[derive(Serialize)]
struct DebugResponse {
    last_error: Option<String>,
}

/// Last completed completion request.
#[derive(Clone)]
struct LastRequestStats {
    completed_at_unix: u64,
    model: String,
    path: String,
    success: bool,
    status_code: Option<i32>,
    error: Option<String>,
    request_bytes: u64,
    response_bytes: u64,
    duration_ms: u64,
    openai_usage: Option<OpenAiUsage>,
    final_info: Option<QueryFinalInfo>,
}

impl LastRequestStats {
    fn as_response(&self) -> LastRequestResponse {
        LastRequestResponse {
            completed_at_unix: self.completed_at_unix,
            model: self.model.clone(),
            path: self.path.clone(),
            success: self.success,
            status_code: self.status_code,
            error: self.error.clone(),
            request_bytes: self.request_bytes,
            response_bytes: self.response_bytes,
            duration_ms: self.duration_ms,
            openai_usage: self.openai_usage.map(OpenAiUsageResponse::from),
            final_info: self.final_info.as_ref().map(FinalInfoResponse::from),
        }
    }
}

#[derive(Serialize)]
struct LastRequestResponse {
    completed_at_unix: u64,
    model: String,
    path: String,
    success: bool,
    status_code: Option<i32>,
    error: Option<String>,
    request_bytes: u64,
    response_bytes: u64,
    duration_ms: u64,
    openai_usage: Option<OpenAiUsageResponse>,
    final_info: Option<FinalInfoResponse>,
}

impl From<&LastRequestStats> for LastRequestResponse {
    fn from(value: &LastRequestStats) -> Self {
        value.as_response()
    }
}

/// Usage object parsed from the worker's OpenAI-compatible JSON response.
#[derive(Clone, Copy, Debug, Default)]
struct OpenAiUsage {
    prompt_tokens: i64,
    cached_tokens: i64,
    completion_tokens: i64,
    reasoning_tokens: i64,
    total_tokens: i64,
    prompt_total_cost: i64,
    completion_total_cost: i64,
    total_cost: i64,
}

impl OpenAiUsage {
    /// Adds another response usage object to this total.
    const fn add(&mut self, other: Self) {
        self.prompt_tokens = self.prompt_tokens.saturating_add(other.prompt_tokens);
        self.cached_tokens = self.cached_tokens.saturating_add(other.cached_tokens);
        self.completion_tokens = self
            .completion_tokens
            .saturating_add(other.completion_tokens);
        self.reasoning_tokens = self.reasoning_tokens.saturating_add(other.reasoning_tokens);
        self.total_tokens = self.total_tokens.saturating_add(other.total_tokens);
        self.prompt_total_cost = self
            .prompt_total_cost
            .saturating_add(other.prompt_total_cost);
        self.completion_total_cost = self
            .completion_total_cost
            .saturating_add(other.completion_total_cost);
        self.total_cost = self.total_cost.saturating_add(other.total_cost);
    }
}

/// Parses the `usage` field returned by Cocoon's OpenAI-compatible worker.
fn parse_openai_usage(payload: &[u8]) -> Option<OpenAiUsage> {
    let value: Value = serde_json::from_slice(payload).ok()?;
    let usage = value.get("usage")?;
    let cached_tokens = usage
        .get("prompt_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_i64)
        .unwrap_or(0);

    Some(OpenAiUsage {
        prompt_tokens: read_i64(usage, "prompt_tokens"),
        cached_tokens,
        completion_tokens: read_i64(usage, "completion_tokens"),
        reasoning_tokens: read_i64(usage, "reasoning_tokens"),
        total_tokens: read_i64(usage, "total_tokens"),
        prompt_total_cost: read_i64(usage, "prompt_total_cost"),
        completion_total_cost: read_i64(usage, "completion_total_cost"),
        total_cost: read_i64(usage, "total_cost"),
    })
}

/// Reads an integer field from a JSON object, defaulting to zero when absent.
fn read_i64(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// Adds terminal Cocoon token counters to the cumulative total.
const fn add_token_usage(total: &mut TokenUsage, value: TokenUsage) {
    total.prompt_tokens_used = total
        .prompt_tokens_used
        .saturating_add(value.prompt_tokens_used);
    total.cached_tokens_used = total
        .cached_tokens_used
        .saturating_add(value.cached_tokens_used);
    total.completion_tokens_used = total
        .completion_tokens_used
        .saturating_add(value.completion_tokens_used);
    total.reasoning_tokens_used = total
        .reasoning_tokens_used
        .saturating_add(value.reasoning_tokens_used);
    total.total_tokens_used = total
        .total_tokens_used
        .saturating_add(value.total_tokens_used);
}

/// Serialized Cocoon token counters.
#[derive(Serialize)]
#[allow(clippy::struct_field_names)]
struct TokenUsageResponse {
    prompt_tokens_used: i64,
    cached_tokens_used: i64,
    completion_tokens_used: i64,
    reasoning_tokens_used: i64,
    total_tokens_used: i64,
}

impl From<TokenUsage> for TokenUsageResponse {
    fn from(value: TokenUsage) -> Self {
        Self {
            prompt_tokens_used: value.prompt_tokens_used,
            cached_tokens_used: value.cached_tokens_used,
            completion_tokens_used: value.completion_tokens_used,
            reasoning_tokens_used: value.reasoning_tokens_used,
            total_tokens_used: value.total_tokens_used,
        }
    }
}

/// Serialized OpenAI-compatible usage counters.
#[derive(Serialize)]
struct OpenAiUsageResponse {
    prompt_tokens: i64,
    cached_tokens: i64,
    completion_tokens: i64,
    reasoning_tokens: i64,
    total_tokens: i64,
    prompt_total_cost: i64,
    completion_total_cost: i64,
    total_cost: i64,
    total_cost_ton_estimate: String,
}

impl From<OpenAiUsage> for OpenAiUsageResponse {
    fn from(value: OpenAiUsage) -> Self {
        Self {
            prompt_tokens: value.prompt_tokens,
            cached_tokens: value.cached_tokens,
            completion_tokens: value.completion_tokens,
            reasoning_tokens: value.reasoning_tokens,
            total_tokens: value.total_tokens,
            prompt_total_cost: value.prompt_total_cost,
            completion_total_cost: value.completion_total_cost,
            total_cost: value.total_cost,
            total_cost_ton_estimate: format_nanotons_as_ton(value.total_cost),
        }
    }
}

/// Serialized terminal Cocoon query metadata.
#[derive(Serialize)]
struct FinalInfoResponse {
    tokens_used: TokenUsageResponse,
    worker_debug: Option<String>,
    proxy_debug: Option<String>,
    proxy_start_time: Option<f64>,
    proxy_end_time: Option<f64>,
    worker_start_time: Option<f64>,
    worker_end_time: Option<f64>,
}

impl From<&QueryFinalInfo> for FinalInfoResponse {
    fn from(value: &QueryFinalInfo) -> Self {
        Self {
            tokens_used: TokenUsageResponse::from(value.tokens_used),
            worker_debug: value.worker_debug.clone(),
            proxy_debug: value.proxy_debug.clone(),
            proxy_start_time: value.proxy_start_time,
            proxy_end_time: value.proxy_end_time,
            worker_start_time: value.worker_start_time,
            worker_end_time: value.worker_end_time,
        }
    }
}

/// Formats a nanoton amount as a fixed 9-decimal TON string.
fn format_nanotons_as_ton(value: i64) -> String {
    let sign = if value.is_negative() { "-" } else { "" };
    let abs = value.unsigned_abs();
    let whole = abs / NANOTONS_PER_TON;
    let fraction = abs % NANOTONS_PER_TON;
    format!("{sign}{whole}.{fraction:09}")
}

fn format_nanotons_u64_as_ton(value: u64) -> String {
    let whole = value / NANOTONS_PER_TON;
    let frac = value % NANOTONS_PER_TON;
    format!("{whole}.{frac:09}")
}

fn client_contract_response(client: &ClientStatus) -> Option<ClientContractResponse> {
    let contract = client.client_contract.as_ref()?;
    Some(ClientContractResponse {
        address: client.client_sc_address.clone(),
        account_state: contract.account_state.as_str(),
        account_balance: contract.account_balance,
        account_balance_ton: contract.account_balance.map(format_nanotons_u64_as_ton),
        last_tx_lt: contract.last_tx_lt,
        state: contract.state,
        state_raw: contract.state_raw,
        balance: contract.balance,
        balance_ton: contract.balance.map(format_nanotons_u64_as_ton),
        stake: contract.stake,
        stake_ton: contract.stake.map(format_nanotons_u64_as_ton),
        tokens_used: contract.tokens_used,
        unlock_ts: contract.unlock_ts,
        withdrawable_balance: contract.withdrawable_balance,
        withdrawable_balance_ton: contract
            .withdrawable_balance
            .map(format_nanotons_u64_as_ton),
        client_top_up_running: client.client_top_up_running,
    })
}

/// Converts a byte length to `u64` without panicking on unusual platforms.
fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Converts a duration to milliseconds without overflowing `u64`.
fn duration_ms(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

/// Current Unix timestamp in seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
