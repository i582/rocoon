use anyhow::{Context, Result};
use rocoon_client::{
    CocoonClient, ProxyHandshakeAuth, ProxyHandshakeInfo, RegisteredProxySnapshot,
    RootContractSnapshot,
};
use rocoon_config::{RuntimeConfig, color::OwoColorize};

const LABEL_WIDTH: usize = 20;

pub fn list(config: &RuntimeConfig, root_contract: Option<&str>) -> Result<()> {
    let (_, snapshot) = fetch(config, root_contract)?;

    if let Some(last_proxy_seqno) = snapshot.last_proxy_seqno {
        print_summary_line("Last proxy seqno", last_proxy_seqno);
    }
    if snapshot.registered_proxies.is_empty() {
        println!("{} No proxies available", "✓".green().bold());
    } else {
        print_summary_line("Available proxies", snapshot.registered_proxies.len());
    }
    if snapshot.registered_proxies.is_empty() {
        return Ok(());
    }

    println!();
    let header = format!("{:<8} {:<24} CLIENTS", "SEQNO", "WORKERS");
    println!("{}", header.cyan().bold());
    for proxy in &snapshot.registered_proxies {
        println!(
            "{:<8} {:<24} {}",
            proxy.seqno, proxy.address_for_workers, proxy.address_for_clients
        );
    }
    Ok(())
}

pub fn inspect(
    config: &RuntimeConfig,
    proxy_selector: &str,
    root_contract: Option<&str>,
) -> Result<()> {
    let (_, snapshot) = fetch(config, root_contract)?;
    let proxy = find_proxy(&snapshot, proxy_selector)?;
    let info = CocoonClient::proxy_handshake_info(config, &proxy.address_for_clients)
        .with_context(|| format!("probe proxy {}", proxy.address_for_clients))?;
    print_inspect(proxy, &info);
    Ok(())
}

fn fetch(
    config: &RuntimeConfig,
    root_contract: Option<&str>,
) -> Result<(String, RootContractSnapshot)> {
    let root_contract_address = root_contract
        .or(config.ton.root_contract_address.as_deref())
        .context(
            "ton.root_contract_address is required; pass --root-contract or set [ton].root_contract_address",
        )?;
    print_summary_line("Root contract", root_contract_address);
    println!("{} Fetching proxies", ">".cyan().bold());
    let snapshot = CocoonClient::root_contract_snapshot(config, Some(root_contract_address))?;
    Ok((root_contract_address.to_string(), snapshot))
}

fn find_proxy<'a>(
    snapshot: &'a RootContractSnapshot,
    proxy_selector: &str,
) -> Result<&'a RegisteredProxySnapshot> {
    if let Ok(seqno) = proxy_selector.parse::<u32>()
        && let Some(proxy) = snapshot
            .registered_proxies
            .iter()
            .find(|proxy| proxy.seqno == seqno)
    {
        return Ok(proxy);
    }

    snapshot
        .registered_proxies
        .iter()
        .find(|proxy| {
            proxy.address == proxy_selector
                || proxy.address_for_workers == proxy_selector
                || proxy.address_for_clients == proxy_selector
        })
        .with_context(|| {
            format!(
                "proxy {} was not found. Run {} to see available proxies.",
                proxy_selector.cyan().bold(),
                "rocoon proxies list".cyan().bold()
            )
        })
}

fn print_inspect(proxy: &RegisteredProxySnapshot, info: &ProxyHandshakeInfo) {
    println!("{} Proxy {}", "✓".green().bold(), proxy.seqno);
    print_field("workers", &proxy.address_for_workers);
    print_field("clients", &proxy.address_for_clients);
    print_field("raw address", &proxy.address);
    print_field("proxy addr", &info.proxy_addr);
    print_field("proxy contract", &info.proxy_sc_address);
    print_field("owner", &info.proxy_owner_address);
    print_field("public key", hex(&info.proxy_public_key));
    print_field("proto", info.proto_version);
    print_field("testnet", option_bool(info.is_test));
    print_field("client contract", &info.client_sc_address);
    let (auth_mode, nonce) = auth_info(&info.auth);
    print_field("auth", auth_mode);
    print_field("nonce", nonce);
    print_field("signed payment", yes_no(info.signed_payment_available));
}

fn print_field(label: &str, value: impl std::fmt::Display) {
    let label = format!("{label}:");
    let label = format!("{label:<LABEL_WIDTH$}");
    println!("{} {value}", label.cyan().bold());
}

fn print_summary_line(label: &str, value: impl std::fmt::Display) {
    println!(
        "{} {label}: {}",
        "✓".green().bold(),
        value.to_string().cyan().bold()
    );
}

const fn auth_info(auth: &ProxyHandshakeAuth) -> (&'static str, i64) {
    match auth {
        ProxyHandshakeAuth::Short { nonce } => ("short", *nonce),
        ProxyHandshakeAuth::Long { nonce } => ("long", *nonce),
    }
}

const fn option_bool(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}
