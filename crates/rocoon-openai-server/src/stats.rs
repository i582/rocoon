//! Runtime statistics exposed by the local HTTP bridge.
//!
//! C++ Cocoon exposes `/stats` and `/jsonstats` from a runner that also owns
//! TON wallet state. `rocoon` now reads wallet state through a read-only TON
//! liteclient and combines it with local proxy/session counters.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rocoon_client::{ClientStatus, HttpExchange, QueryFinalInfo, TokenUsage};
use serde_json::{Value, json};

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

    /// Builds the JSON body for `/stats`, `/jsonstats`, and `/v1/stats`.
    pub fn to_json(&self, client: &ClientStatus) -> Value {
        json!({
            "object": "rocoon.stats",
            "status": {
                "enabled": true,
                "connected": true,
                "ton_wallet_polling": client.ton_readonly_enabled,
                "ton_wallet_polling_ok": client.ton_readonly_ok,
                "root_contract_polling": false,
                "ton_readonly_error": &client.ton_readonly_error
            },
            "client": {
                "proxy_addr": &client.proxy_addr,
                "owner_address": &client.owner_address,
                "cocoon_wallet_address": &client.cocoon_wallet_address,
                "root_contract_address": &client.root_contract_address,
                "proto_version": client.proto_version,
                "active_proxy_connections": client.active_proxy_connections,
                "proxy_owner_address": &client.proxy_owner_address,
                "proxy_sc_address": &client.proxy_sc_address,
                "client_sc_address": &client.client_sc_address
            },
            "blockchain": {
                "network": "ton",
                "readonly_enabled": client.ton_readonly_enabled,
                "masterchain_seqno": client.masterchain_seqno,
                "root_contract_polling": false
            },
            "client_contract": client_contract_json(client),
            "wallet": {
                "address": &client.cocoon_wallet_address,
                "balance": client.wallet_balance,
                "balance_ton": client.wallet_balance.map(format_nanotons_u64_as_ton),
                "seqno": client.wallet_seqno,
                "state": &client.wallet_state,
                "last_tx_lt": client.wallet_last_tx_lt,
                "pending_transactions_cnt": client.wallet_pending_transactions,
                "active_transactions_cnt": client.wallet_active_transactions,
                "wallet_transfer_running": client.wallet_transfer.is_some(),
                "wallet_transfer": wallet_transfer_json(client),
                "source": wallet_source(client)
            },
            "payment": {
                "signed_payment_available": client.payment_status.signed_payment_available,
                "tokens_committed_to_db": client.payment_status.tokens_committed_to_db,
                "max_tokens": client.payment_status.max_tokens,
                "payment_status_endpoint_supported": false
            },
            "requests": {
                "completion_started": self.completion_requests_started,
                "completion_success": self.completion_requests_succeeded,
                "completion_failed": self.completion_requests_failed,
                "completion_in_flight": self.completion_requests_in_flight,
                "bytes_received": self.request_bytes_received,
                "bytes_sent": self.response_bytes_sent,
                "total_time_ms": self.total_request_duration_ms
            },
            "usage": {
                "cocoon_final_info_tokens": token_usage_json(self.cocoon_tokens_used),
                "openai_response_usage": openai_usage_json(self.openai_usage),
                "cost": {
                    "total_cost": self.openai_usage.total_cost,
                    "total_cost_ton_estimate": format_nanotons_as_ton(self.openai_usage.total_cost),
                    "note": "total_cost is forwarded from worker response usage; TON charges are not independently verified yet"
                }
            },
            "debug": {
                "last_error": &self.last_error
            },
            "last_request": self.last_request.as_ref().map_or(Value::Null, LastRequestStats::to_json)
        })
    }
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
    /// Converts the request snapshot into JSON.
    fn to_json(&self) -> Value {
        json!({
            "completed_at_unix": self.completed_at_unix,
            "model": &self.model,
            "path": &self.path,
            "success": self.success,
            "status_code": self.status_code,
            "error": &self.error,
            "request_bytes": self.request_bytes,
            "response_bytes": self.response_bytes,
            "duration_ms": self.duration_ms,
            "openai_usage": self.openai_usage.map_or(Value::Null, openai_usage_json),
            "final_info": self.final_info.as_ref().map_or(Value::Null, final_info_json)
        })
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

/// Converts Cocoon final token counters into JSON.
fn token_usage_json(usage: TokenUsage) -> Value {
    json!({
        "prompt_tokens_used": usage.prompt_tokens_used,
        "cached_tokens_used": usage.cached_tokens_used,
        "completion_tokens_used": usage.completion_tokens_used,
        "reasoning_tokens_used": usage.reasoning_tokens_used,
        "total_tokens_used": usage.total_tokens_used
    })
}

/// Converts OpenAI-compatible usage counters into JSON.
fn openai_usage_json(usage: OpenAiUsage) -> Value {
    json!({
        "prompt_tokens": usage.prompt_tokens,
        "cached_tokens": usage.cached_tokens,
        "completion_tokens": usage.completion_tokens,
        "reasoning_tokens": usage.reasoning_tokens,
        "total_tokens": usage.total_tokens,
        "prompt_total_cost": usage.prompt_total_cost,
        "completion_total_cost": usage.completion_total_cost,
        "total_cost": usage.total_cost,
        "total_cost_ton_estimate": format_nanotons_as_ton(usage.total_cost)
    })
}

/// Converts terminal Cocoon query metadata into JSON.
fn final_info_json(info: &QueryFinalInfo) -> Value {
    json!({
        "tokens_used": token_usage_json(info.tokens_used),
        "worker_debug": info.worker_debug.as_deref(),
        "proxy_debug": info.proxy_debug.as_deref(),
        "proxy_start_time": info.proxy_start_time,
        "proxy_end_time": info.proxy_end_time,
        "worker_start_time": info.worker_start_time,
        "worker_end_time": info.worker_end_time
    })
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

const fn wallet_source(client: &ClientStatus) -> &'static str {
    match (client.ton_readonly_enabled, client.ton_readonly_ok) {
        (false, _) => "disabled_ton_wallet_polling",
        (true, true) => "ton_liteclient",
        (true, false) => "ton_liteclient_error",
    }
}

fn client_contract_json(client: &ClientStatus) -> Value {
    let Some(contract) = &client.client_contract else {
        return Value::Null;
    };
    json!({
        "address": &client.client_sc_address,
        "account_state": contract.account_state.as_str(),
        "account_balance": contract.account_balance,
        "account_balance_ton": contract.account_balance.map(format_nanotons_u64_as_ton),
        "last_tx_lt": contract.last_tx_lt,
        "state": contract.state,
        "state_raw": contract.state_raw,
        "balance": contract.balance,
        "balance_ton": contract.balance.map(format_nanotons_u64_as_ton),
        "stake": contract.stake,
        "stake_ton": contract.stake.map(format_nanotons_u64_as_ton),
        "tokens_used": contract.tokens_used,
        "unlock_ts": contract.unlock_ts,
        "withdrawable_balance": contract.withdrawable_balance,
        "withdrawable_balance_ton": contract.withdrawable_balance.map(format_nanotons_u64_as_ton),
        "sc_request_running": client.sc_request_running,
        "sc_request": control_request_json(client)
    })
}

fn control_request_json(client: &ClientStatus) -> Value {
    let Some(request) = &client.sc_request else {
        return Value::Null;
    };
    json!({
        "action": request.action.as_str(),
        "query_id": request.query_id,
        "wallet_seqno": request.wallet_seqno
    })
}

fn wallet_transfer_json(client: &ClientStatus) -> Value {
    let Some(request) = &client.wallet_transfer else {
        return Value::Null;
    };
    json!({
        "destination_address": &request.destination_address,
        "amount": request.amount,
        "amount_ton": format_nanotons_u64_as_ton(request.amount),
        "wallet_seqno": request.wallet_seqno
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
