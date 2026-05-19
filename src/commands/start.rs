use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};
use rocoon_config::{RuntimeConfig, color::OwoColorize};
use rocoon_server::{Defaults, SessionSummary, bind, serve_bound};
use signal_hook::consts::SIGINT;

pub fn run(config: &RuntimeConfig) -> Result<()> {
    let listener = bind(&config.listen_addr)?;
    println!(
        "{} Reserved HTTP listener {}",
        ">".cyan().bold(),
        format!("http://{}", config.listen_addr).cyan().bold()
    );
    let client = crate::connect_cocoon_interactive(config)?;
    let defaults = Defaults {
        max_coefficient: config.max_coefficient,
        max_tokens: config.max_tokens,
        timeout: config.request_timeout,
    };
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let _default_signal_id =
        signal_hook::flag::register_conditional_default(SIGINT, Arc::clone(&shutdown_requested))
            .context("install second Ctrl+C handler")?;
    let _interrupt_signal_id = signal_hook::flag::register(SIGINT, Arc::clone(&shutdown_requested))
        .context("install Ctrl+C handler")?;

    let summary = serve_bound(
        listener,
        client,
        defaults,
        config.api_token.clone(),
        &shutdown_requested,
    )?;
    if shutdown_requested.load(Ordering::SeqCst) {
        print_session_summary(&summary);
    }
    Ok(())
}

const SESSION_LABEL_WIDTH: usize = 10;

fn print_session_summary(summary: &SessionSummary) {
    println!();
    println!("{} rocoon stopped", "✓".green().bold());

    let uptime = format_duration(summary.elapsed);
    print_session_field("uptime", uptime.cyan().bold());
    print_session_field("requests", format_session_requests(summary));
    print_session_field("tokens", format_session_tokens(summary));
    print_session_field(
        "cost",
        format!(
            "{} {}",
            summary.total_cost_ton_estimate.yellow().bold(),
            "TON".yellow().bold()
        ),
    );
    print_session_field("traffic", format_session_traffic(summary));
}

fn print_session_field(label: &str, value: impl fmt::Display) {
    let label = format!("{label}:");
    let label = format!("{label:<SESSION_LABEL_WIDTH$}");
    println!("{} {value}", label.cyan().bold());
}

fn format_session_requests(summary: &SessionSummary) -> String {
    format!(
        "{} started / {} ok / {} failed / {} in flight",
        summary.completion_started.cyan().bold(),
        summary.completion_success.green().bold(),
        summary.completion_failed.red().bold(),
        summary.completion_in_flight.yellow().bold()
    )
}

fn format_session_tokens(summary: &SessionSummary) -> String {
    let tokens = summary.tokens;
    let mut parts = vec![
        format!("{} prompt", tokens.prompt.cyan().bold()),
        format!("{} completion", tokens.completion.cyan().bold()),
    ];
    if tokens.cached != 0 {
        parts.push(format!("{} cached", tokens.cached.cyan().bold()));
    }
    if tokens.reasoning != 0 {
        parts.push(format!("{} reasoning", tokens.reasoning.cyan().bold()));
    }
    parts.push(format!("{} total", tokens.total.cyan().bold()));
    parts.join(" / ")
}

fn format_session_traffic(summary: &SessionSummary) -> String {
    let received = format_bytes(summary.bytes_received);
    let sent = format_bytes(summary.bytes_sent);
    format!("{} in / {} out", received.cyan().bold(), sent.cyan().bold())
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let minutes = seconds / 60;
    let seconds = seconds % 60;
    if minutes == 0 {
        format!("{seconds}s")
    } else {
        format!("{minutes}m {seconds}s")
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes < KIB {
        format!("{bytes} B")
    } else if bytes < MIB {
        format_scaled_bytes(bytes, KIB, "KiB")
    } else if bytes < GIB {
        format_scaled_bytes(bytes, MIB, "MiB")
    } else {
        format_scaled_bytes(bytes, GIB, "GiB")
    }
}

fn format_scaled_bytes(bytes: u64, unit: u64, suffix: &str) -> String {
    let whole = bytes / unit;
    let mut tenth = ((bytes % unit) * 10 + unit / 2) / unit;
    let mut whole = whole;
    if tenth == 10 {
        whole += 1;
        tenth = 0;
    }
    format!("{whole}.{tenth} {suffix}")
}
