use crate::commands::format_nanotons_as_ton;
use crate::{ClientContractStatus, remember_client_contract};
use rocoon_client::CocoonClient;
use rocoon_config::RuntimeConfig;
use rocoon_config::color::OwoColorize;

pub fn run(
    config: &RuntimeConfig,
    client_contract: Option<&str>,
    destination_address: Option<&str>,
    reserve_nanotons: u64,
) -> anyhow::Result<()> {
    let result = CocoonClient::sweep_cocoon_wallet_interactive(
        config,
        client_contract,
        destination_address,
        reserve_nanotons,
    )?;
    if let Some(client_contract) = client_contract {
        remember_client_contract(config, client_contract, ClientContractStatus::Closed);
    }
    println!("{} Wallet withdraw sent", "✓".green().bold());
    println!("Wallet: {}", result.wallet_address);
    println!("Destination: {}", result.destination_address);
    println!("Amount: {} TON", format_nanotons_as_ton(result.amount));
    println!("Reserve: {} TON", format_nanotons_as_ton(reserve_nanotons));
    println!("Wallet seqno: {}", result.wallet_seqno);
    println!("Send status: {}", result.send_status);
    Ok(())
}
