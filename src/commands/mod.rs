use crate::NANOTONS_PER_TON;

pub mod close;
pub mod health;
pub mod local_http;
pub mod models;
pub mod proxies;
pub mod request_withdraw;
pub mod start;
pub mod stats;
pub mod withdraw;

fn format_nanotons_as_ton(amount: u64) -> String {
    let whole = amount / NANOTONS_PER_TON;
    let fractional = amount % NANOTONS_PER_TON;
    if fractional == 0 {
        return whole.to_string();
    }
    let fractional = format!("{fractional:09}");
    let fractional = fractional.trim_end_matches('0');
    format!("{whole}.{fractional}")
}
