use anyhow::{Context, Result};
use rocoon_config::color::OwoColorize;
use serde_json::Value;

use super::local_http;

const LABEL_WIDTH: usize = 16;

pub fn run(listen_addr: &str, api_token: Option<&str>, verbose: bool) -> Result<()> {
    let url = local_http::url(listen_addr, "/stats");
    println!("{} Fetching {}", ">".cyan().bold(), url.cyan().bold());
    let response = local_http::get(listen_addr, "/stats", api_token)?;
    if response.status_code != 200 {
        anyhow::bail!(
            "rocoon server at {} returned HTTP {}; expected 200",
            url.cyan().bold(),
            response.status_code
        );
    }
    let value: Value = serde_json::from_str(&response.body).context("parse /stats JSON")?;
    if verbose {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).context("format /stats JSON")?
        );
    } else {
        print_summary(&value);
    }
    Ok(())
}

fn print_summary(value: &Value) {
    println!("{} rocoon server stats", "✓".green().bold());
    print_field(
        "proxy",
        pointer_str(value, "/client/proxy_addr"),
        ValueStyle::Addr,
    );
    print_field(
        "wallet",
        pointer_str(value, "/client/cocoon_wallet_address"),
        ValueStyle::Addr,
    );
    print_field(
        "client contract",
        pointer_str(value, "/client/client_sc_address"),
        ValueStyle::Addr,
    );
    print_field(
        "contract state",
        pointer_str(value, "/client_contract/state"),
        ValueStyle::State,
    );
    print_field(
        "wallet balance",
        ton_value(value, "/wallet/balance_ton").as_deref(),
        ValueStyle::Amount,
    );
    print_field(
        "request balance",
        ton_value(value, "/client_contract/balance_ton").as_deref(),
        ValueStyle::Amount,
    );
    print_field(
        "withdrawable",
        ton_value(value, "/client_contract/withdrawable_balance_ton").as_deref(),
        ValueStyle::Amount,
    );
    print_field(
        "TON state",
        if pointer_bool(value, "/status/ton_wallet_polling_ok") == Some(true) {
            Some("ok")
        } else {
            pointer_str(value, "/status/ton_readonly_error")
        },
        ValueStyle::State,
    );
    print_field(
        "requests",
        Some(&format!(
            "{} ok / {} failed / {} in flight",
            pointer_u64(value, "/requests/completion_success").unwrap_or(0),
            pointer_u64(value, "/requests/completion_failed").unwrap_or(0),
            pointer_u64(value, "/requests/completion_in_flight").unwrap_or(0)
        )),
        ValueStyle::Text,
    );
    print_field(
        "tokens",
        Some(&format!(
            "{} prompt / {} completion / {} total",
            pointer_u64(value, "/usage/openai_response_usage/prompt_tokens").unwrap_or(0),
            pointer_u64(value, "/usage/openai_response_usage/completion_tokens").unwrap_or(0),
            pointer_u64(value, "/usage/openai_response_usage/total_tokens").unwrap_or(0)
        )),
        ValueStyle::Text,
    );
    print_field(
        "cost",
        ton_value(value, "/usage/cost/total_cost_ton_estimate").as_deref(),
        ValueStyle::Amount,
    );
}

#[derive(Clone, Copy)]
enum ValueStyle {
    Addr,
    Amount,
    State,
    Text,
}

fn print_field(label: &str, value: Option<&str>, style: ValueStyle) {
    let label = format!("{label}:");
    let value = value.unwrap_or("-");
    println!(
        "{label:<LABEL_WIDTH$} {}",
        color_value(value, style),
        label = label.cyan().bold()
    );
}

fn color_value(value: &str, style: ValueStyle) -> String {
    match style {
        ValueStyle::Addr => value.cyan().bold().to_string(),
        ValueStyle::Amount => value.yellow().bold().to_string(),
        ValueStyle::State => match value {
            "ok" | "running" | "active" => value.green().bold().to_string(),
            "closing" | "close_requested" => value.yellow().bold().to_string(),
            _ => value.red().bold().to_string(),
        },
        ValueStyle::Text => value.bold().to_string(),
    }
}

fn pointer_str<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer)?.as_str()
}

fn ton_value(value: &Value, pointer: &str) -> Option<String> {
    pointer_str(value, pointer).map(|value| format!("{value} TON"))
}

fn pointer_bool(value: &Value, pointer: &str) -> Option<bool> {
    value.pointer(pointer)?.as_bool()
}

fn pointer_u64(value: &Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer)?.as_u64()
}
