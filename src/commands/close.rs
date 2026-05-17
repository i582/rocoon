use crate::commands::format_nanotons_as_ton;
use crate::{ClientContractStatus, remember_client_contract};
use rocoon_client::CocoonClient;
use rocoon_config::RuntimeConfig;
use rocoon_config::color::OwoColorize;

pub fn run(config: &RuntimeConfig, client_contract: Option<&str>) -> anyhow::Result<()> {
    let result = CocoonClient::request_close_interactive(config, client_contract)?;
    remember_client_contract(
        config,
        &result.client_contract_address,
        ClientContractStatus::CloseRequested,
    );
    println!("{} Close request sent", "✓".green().bold());
    println!("Client contract: {}", result.client_contract_address);
    println!("Wallet seqno: {}", result.wallet_seqno);
    println!(
        "Attached: {} TON",
        format_nanotons_as_ton(result.attached_value)
    );
    println!("Send status: {}", result.send_status);
    Ok(())
}
