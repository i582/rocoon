use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use rocoon_client::{COCOON_WALLET_RESERVE_NANOTONS, CocoonClient, RuntimeConfig};
use rocoon_openai_server::{Defaults, serve};

const NANOTONS_PER_TON: u64 = 1_000_000_000;
const STATE_FILE_NAME: &str = ".rocoon-state";

#[derive(Debug, Parser)]
#[command(
    name = "rocoon",
    version,
    about = "Rust bridge for the Cocoon proxy protocol"
)]
struct Cli {
    #[arg(short, long, value_name = "PATH", global = true)]
    config: Option<PathBuf>,

    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the local OpenAI-compatible HTTP server.
    Start,
    /// Withdraw balance above stake from the client contract to the Cocoon wallet.
    #[command(name = "request-withdraw")]
    RequestWithdraw {
        /// Client contract address. If omitted, rocoon resolves it through the proxy.
        #[arg(long, value_name = "ADDRESS")]
        client_contract: Option<String>,
    },
    /// Ask the client contract to close and refund to the Cocoon wallet.
    Close {
        /// Client contract address. If omitted, rocoon resolves it through the proxy.
        #[arg(long, value_name = "ADDRESS")]
        client_contract: Option<String>,
    },
    /// Sweep the closed Cocoon wallet balance to the owner wallet or --to.
    #[command(visible_alias = "sweep")]
    Withdraw {
        /// Client contract address. Pass it when the proxy can no longer resolve a closed contract.
        #[arg(long, value_name = "ADDRESS")]
        client_contract: Option<String>,

        /// Destination TON address. Defaults to `client.owner_address` from config.
        #[arg(long, value_name = "ADDRESS")]
        to: Option<String>,

        /// Nanotons to keep on the Cocoon wallet for fees.
        #[arg(
            long,
            value_name = "NANOTONS",
            default_value_t = COCOON_WALLET_RESERVE_NANOTONS
        )]
        reserve_nanotons: u64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    let config = RuntimeConfig::load_cli(cli.config, cli.verbose)?;
    if config.verbose {
        println!("config: {}", config.config_path.display());
    }

    match command {
        Command::Start => serve_http(&config),
        Command::RequestWithdraw { client_contract } => {
            request_withdraw(&config, client_contract.as_deref())
        }
        Command::Close { client_contract } => request_close(&config, client_contract.as_deref()),
        Command::Withdraw {
            client_contract,
            to,
            reserve_nanotons,
        } => {
            let client_contract = client_contract.or_else(|| cached_client_contract(&config));
            sweep_wallet(
                &config,
                client_contract.as_deref(),
                to.as_deref(),
                reserve_nanotons,
            )
        }
    }
}

fn serve_http(config: &RuntimeConfig) -> Result<()> {
    let client = CocoonClient::connect_interactive(config)?;
    let defaults = Defaults {
        max_coefficient: config.max_coefficient,
        max_tokens: config.max_tokens,
        timeout: config.request_timeout,
    };
    serve(&config.listen_addr, client, defaults)
}

fn request_withdraw(config: &RuntimeConfig, client_contract: Option<&str>) -> Result<()> {
    let result = CocoonClient::request_withdraw_interactive(config, client_contract)?;
    remember_client_contract(config, &result.client_contract_address);
    println!("✓ Withdraw request sent");
    println!("Client contract: {}", result.client_contract_address);
    println!("Wallet seqno: {}", result.wallet_seqno);
    println!(
        "Attached: {} TON",
        format_nanotons_as_ton(result.attached_value)
    );
    println!("Send status: {}", result.send_status);
    Ok(())
}

fn request_close(config: &RuntimeConfig, client_contract: Option<&str>) -> Result<()> {
    let result = CocoonClient::request_close_interactive(config, client_contract)?;
    remember_client_contract(config, &result.client_contract_address);
    println!("✓ Close request sent");
    println!("Client contract: {}", result.client_contract_address);
    println!("Wallet seqno: {}", result.wallet_seqno);
    println!(
        "Attached: {} TON",
        format_nanotons_as_ton(result.attached_value)
    );
    println!("Send status: {}", result.send_status);
    Ok(())
}

fn sweep_wallet(
    config: &RuntimeConfig,
    client_contract: Option<&str>,
    destination_address: Option<&str>,
    reserve_nanotons: u64,
) -> Result<()> {
    let result = CocoonClient::sweep_cocoon_wallet_interactive(
        config,
        client_contract,
        destination_address,
        reserve_nanotons,
    )?;
    println!("✓ Wallet withdraw sent");
    println!("Wallet: {}", result.wallet_address);
    println!("Destination: {}", result.destination_address);
    println!("Amount: {} TON", format_nanotons_as_ton(result.amount));
    println!("Reserve: {} TON", format_nanotons_as_ton(reserve_nanotons));
    println!("Wallet seqno: {}", result.wallet_seqno);
    println!("Send status: {}", result.send_status);
    Ok(())
}

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

#[derive(Debug)]
struct CliState {
    owner_address: String,
    cocoon_wallet_address: String,
    proxy_addr: String,
    client_contract_address: String,
}

impl CliState {
    fn new(config: &RuntimeConfig, client_contract_address: &str) -> Self {
        Self {
            owner_address: config.owner_address.clone(),
            cocoon_wallet_address: config.cocoon_wallet_address.clone(),
            proxy_addr: config.proxy_addr.clone(),
            client_contract_address: client_contract_address.to_string(),
        }
    }

    fn matches_config(&self, config: &RuntimeConfig) -> bool {
        self.owner_address == config.owner_address
            && self.cocoon_wallet_address == config.cocoon_wallet_address
            && self.proxy_addr == config.proxy_addr
    }

    fn render(&self) -> String {
        format!(
            "version=1\nowner_address={}\ncocoon_wallet_address={}\nproxy_addr={}\nclient_contract_address={}\n",
            self.owner_address,
            self.cocoon_wallet_address,
            self.proxy_addr,
            self.client_contract_address
        )
    }

    fn parse(data: &str) -> Result<Self> {
        let mut version = None;
        let mut owner_address = None;
        let mut cocoon_wallet_address = None;
        let mut proxy_addr = None;
        let mut client_contract_address = None;

        for line in data.lines().map(str::trim) {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "version" => version = Some(value.to_string()),
                "owner_address" => owner_address = Some(value.to_string()),
                "cocoon_wallet_address" => cocoon_wallet_address = Some(value.to_string()),
                "proxy_addr" => proxy_addr = Some(value.to_string()),
                "client_contract_address" => client_contract_address = Some(value.to_string()),
                _ => {}
            }
        }

        if version.as_deref() != Some("1") {
            anyhow::bail!("unsupported rocoon state version");
        }

        Ok(Self {
            owner_address: required_state_field(owner_address, "owner_address")?,
            cocoon_wallet_address: required_state_field(
                cocoon_wallet_address,
                "cocoon_wallet_address",
            )?,
            proxy_addr: required_state_field(proxy_addr, "proxy_addr")?,
            client_contract_address: required_state_field(
                client_contract_address,
                "client_contract_address",
            )?,
        })
    }
}

fn remember_client_contract(config: &RuntimeConfig, client_contract_address: &str) {
    let state = CliState::new(config, client_contract_address);
    let path = state_file_path(config);
    match fs::write(&path, state.render()) {
        Ok(()) if config.verbose => {
            println!("state: saved client contract to {}", path.display());
        }
        Ok(()) => {}
        Err(error) => {
            eprintln!("warning: failed to save {}: {error}", path.display());
        }
    }
}

fn cached_client_contract(config: &RuntimeConfig) -> Option<String> {
    let path = state_file_path(config);
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == ErrorKind::NotFound => return None,
        Err(error) => {
            eprintln!("warning: failed to read {}: {error}", path.display());
            return None;
        }
    };
    let state = match CliState::parse(&data) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("warning: ignoring invalid {}: {error:#}", path.display());
            return None;
        }
    };
    if !state.matches_config(config) {
        return None;
    }
    println!(
        "> Using cached client contract {}",
        state.client_contract_address
    );
    Some(state.client_contract_address)
}

fn state_file_path(config: &RuntimeConfig) -> PathBuf {
    config_dir(&config.config_path).join(STATE_FILE_NAME)
}

fn config_dir(config_path: &Path) -> &Path {
    config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn required_state_field(value: Option<String>, name: &str) -> Result<String> {
    value.with_context(|| format!("missing {name} in rocoon state"))
}
