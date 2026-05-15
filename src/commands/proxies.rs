use anyhow::{Context, Result};
use rocoon_client::CocoonClient;
use rocoon_config::RuntimeConfig;

pub fn run(config: &RuntimeConfig, root_contract: Option<&str>) -> Result<()> {
    let root_contract_address = root_contract
        .or(config.ton.root_contract_address.as_deref())
        .context(
            "ton.root_contract_address is required; pass --root-contract or set [ton].root_contract_address",
        )?;
    let snapshot = CocoonClient::root_contract_snapshot(config, Some(root_contract_address))?;

    println!("Root contract: {root_contract_address}");
    println!("State: {}", snapshot.account_state.as_str());
    if let Some(version) = snapshot.version {
        println!("Version: {version}");
    }
    if let Some(last_proxy_seqno) = snapshot.last_proxy_seqno {
        println!("Last proxy seqno: {last_proxy_seqno}");
    }
    println!("Registered proxies: {}", snapshot.registered_proxies.len());
    if snapshot.registered_proxies.is_empty() {
        return Ok(());
    }

    println!();
    println!(
        "{:<8} {:<24} {:<24} PROXY_CONTRACT",
        "SEQNO", "WORKERS", "CLIENTS"
    );
    for proxy in snapshot.registered_proxies {
        let proxy_contract =
            match CocoonClient::proxy_handshake_info(config, &proxy.address_for_clients) {
                Ok(info) => info.proxy_sc_address,
                Err(error) => format!("unavailable: {error:#}"),
            };
        println!(
            "{:<8} {:<24} {:<24} {}",
            proxy.seqno, proxy.address_for_workers, proxy.address_for_clients, proxy_contract
        );
    }
    Ok(())
}
