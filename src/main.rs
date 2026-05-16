use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{Context, Result};
use clap::{ColorChoice, CommandFactory, Parser, Subcommand};
use inquire::Text;
use inquire::validator::{ErrorMessage, Validation};
use rocoon_client::{
    COCOON_WALLET_RESERVE_NANOTONS, CocoonClient, ModelInfo,
    is_client_contract_closed_or_closing_error,
};
use rocoon_config::{
    RuntimeConfig,
    color::{ColorMode, OwoColorize, init_color_mode},
};
use rocoon_server::{Defaults, serve};

mod commands;

const NANOTONS_PER_TON: u64 = 1_000_000_000;
const STATE_FILE_NAME: &str = ".rocoon-state";

#[derive(Debug, Parser)]
#[command(
    name = "rocoon",
    version,
    about = "Rust bridge for the Cocoon proxy protocol",
    color = ColorChoice::Auto
)]
struct Cli {
    #[arg(short, long, value_name = "PATH", global = true)]
    config: Option<PathBuf>,

    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(
        long,
        value_enum,
        global = true,
        value_name = "WHEN",
        default_value_t = ColorMode::Auto,
        help = "Control when to use colored output"
    )]
    color: ColorMode,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the local OpenAI-compatible HTTP server.
    Start,
    /// Check the local OpenAI-compatible HTTP server.
    Health,
    /// Query models advertised by the Cocoon proxy.
    Models {
        #[command(subcommand)]
        command: ModelsCommand,
    },
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

#[derive(Debug, Subcommand)]
enum ModelsCommand {
    /// List models advertised by the Cocoon proxy.
    List,
}

fn main() {
    if let Err(error) = run() {
        print_cli_error(&error);
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let Cli {
        config,
        verbose,
        color,
        command,
    } = Cli::parse();
    init_color_mode(color);

    let Some(command) = command else {
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    if matches!(command, Command::Start) && should_run_initial_setup(config.as_deref()) {
        run_initial_setup(&RuntimeConfig::default_config_path())?;
    }

    if matches!(command, Command::Health) {
        let listen_addr = RuntimeConfig::load_listen_addr_cli(config)?;
        return commands::health::run(&listen_addr, verbose);
    }

    let config = RuntimeConfig::load_cli(config, verbose)?;
    if config.verbose {
        println!("config: {}", config.config_path.display());
    }

    match command {
        Command::Start => serve_http(&config),
        Command::Health => unreachable!("health is handled before full config loading"),
        Command::Models {
            command: ModelsCommand::List,
        } => list_models(&config),
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

fn print_cli_error(error: &anyhow::Error) {
    if let Some(error) = error.downcast_ref::<ClosedClientContractStartError>() {
        print_closed_client_contract_error(error);
        return;
    }

    eprintln!("{} {error:#}", "error:".red().bold());
}

fn print_closed_client_contract_error(error: &ClosedClientContractStartError) {
    eprintln!(
        "{} Cocoon client contract is closing or closed",
        "error:".red().bold()
    );
    eprintln!(
        "The configured {} points to a contract that the {} will not reopen.",
        "client.node_wallet_key".cyan().bold(),
        "proxy".cyan().bold()
    );
    eprintln!();
    if let Some(address) = &error.client_contract_address {
        eprintln!("{} {address}", "client contract:".cyan().bold());
    }
    eprintln!(
        "{}   {}",
        "cocoon wallet:".cyan().bold(),
        error.cocoon_wallet_address
    );
    eprintln!(
        "{}      {}",
        "state file:".cyan().bold(),
        error.state_file_path.display()
    );
    eprintln!();
    eprintln!(
        "Generate a new 32-byte {} and update {} or {}.",
        "client.node_wallet_key".cyan().bold(),
        "rocoon.toml".cyan().bold(),
        "COCOON_NODE_WALLET_KEY".cyan().bold()
    );
    eprintln!(
        "To sweep old funds first, keep the old key configured and run: {}",
        "rocoon withdraw".cyan().bold()
    );
}

fn should_run_initial_setup(config_path: Option<&Path>) -> bool {
    config_path.is_none()
        && !RuntimeConfig::default_config_path().exists()
        && !has_complete_env_config()
}

fn has_complete_env_config() -> bool {
    env_value_present("COCOON_OWNER_ADDRESS") && env_value_present("COCOON_NODE_WALLET_KEY")
}

fn env_value_present(name: &str) -> bool {
    env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

fn run_initial_setup(config_path: &Path) -> Result<()> {
    print_initial_setup_welcome(config_path);
    let owner_address = prompt_owner_address()?;
    let node_wallet_key = RuntimeConfig::generate_node_wallet_key_base64();
    RuntimeConfig::write_default_config(config_path, &owner_address, &node_wallet_key)?;
    println!(
        "{} Created {}",
        "✓".green().bold(),
        config_path.display().to_string().cyan().bold()
    );
    Ok(())
}

fn print_initial_setup_welcome(config_path: &Path) {
    println!("{}", "Welcome to rocoon!".green().bold());
    println!(
        "No {} found in this directory.",
        config_path.display().to_string().cyan().bold()
    );
    println!();
    println!(
        "Initial setup needs a Cocoon wallet funded with {}.",
        "20 TON".cyan().bold()
    );
    println!(
        "You can withdraw the funds later with {}; total TON fees are usually around {}.",
        "rocoon withdraw".cyan().bold(),
        "1 TON".cyan().bold()
    );
    println!();
    println!(
        "Enter your own TON wallet address, rocoon will create {} and continue.",
        config_path.display().to_string().cyan().bold()
    );
}

fn prompt_owner_address() -> Result<String> {
    let owner_address = Text::new("Owner wallet address:")
        .with_validator(|input: &str| {
            let input = input.trim();
            if input.is_empty() {
                return Ok(Validation::Invalid(ErrorMessage::Custom(
                    "Enter your own TON wallet address".to_string(),
                )));
            }
            if RuntimeConfig::validate_owner_address(input).is_ok() {
                Ok(Validation::Valid)
            } else {
                Ok(Validation::Invalid(ErrorMessage::Custom(
                    "Enter a valid TON address".to_string(),
                )))
            }
        })
        .prompt()
        .context("read owner wallet address")?;
    let owner_address = owner_address.trim().to_string();
    RuntimeConfig::validate_owner_address(&owner_address)?;
    Ok(owner_address)
}

fn serve_http(config: &RuntimeConfig) -> Result<()> {
    let client = connect_cocoon_interactive(config)?;
    let defaults = Defaults {
        max_coefficient: config.max_coefficient,
        max_tokens: config.max_tokens,
        timeout: config.request_timeout,
    };
    serve(&config.listen_addr, client, defaults)
}

fn list_models(config: &RuntimeConfig) -> Result<()> {
    let mut client = connect_cocoon_interactive(config)?;
    println!("{} Fetching models", ">".cyan().bold());
    let models = client
        .get_worker_types_v2()
        .context("fetch Cocoon models")?;
    print_models(&models);
    Ok(())
}

fn connect_cocoon_interactive(config: &RuntimeConfig) -> Result<CocoonClient> {
    fail_if_cached_client_contract_is_closed(config)?;
    let client = match CocoonClient::connect_interactive(config) {
        Ok(client) => client,
        Err(error) if is_client_contract_closed_or_closing_error(&error) => {
            return Err(closed_client_contract_start_error(config));
        }
        Err(error) => return Err(error),
    };
    remember_client_contract(
        config,
        client.client_contract_address(),
        ClientContractStatus::Active,
    );
    Ok(client)
}

fn print_models(models: &[ModelInfo]) {
    if models.is_empty() {
        println!("{} No models available", "✓".green().bold());
        return;
    }

    println!(
        "{} Available models: {}",
        "✓".green().bold(),
        models.len().to_string().cyan().bold()
    );
    for model in models {
        println!("{}", model.id.cyan().bold());
    }
}

fn request_withdraw(config: &RuntimeConfig, client_contract: Option<&str>) -> Result<()> {
    let result = CocoonClient::request_withdraw_interactive(config, client_contract)?;
    remember_client_contract(
        config,
        &result.client_contract_address,
        ClientContractStatus::Active,
    );
    println!("{} Withdraw request sent", "✓".green().bold());
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
    client_contract_status: ClientContractStatus,
}

#[derive(Debug)]
struct ClosedClientContractStartError {
    cocoon_wallet_address: String,
    client_contract_address: Option<String>,
    state_file_path: PathBuf,
}

impl ClosedClientContractStartError {
    fn new(config: &RuntimeConfig, state: Option<&CliState>) -> Self {
        Self {
            cocoon_wallet_address: config.cocoon_wallet_address.clone(),
            client_contract_address: state.map(|state| state.client_contract_address.clone()),
            state_file_path: state_file_path(config),
        }
    }
}

impl fmt::Display for ClosedClientContractStartError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Cocoon client contract is closing or closed")
    }
}

impl Error for ClosedClientContractStartError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientContractStatus {
    Active,
    CloseRequested,
    Closed,
}

impl ClientContractStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::CloseRequested => "close_requested",
            Self::Closed => "closed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "close_requested" => Some(Self::CloseRequested),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

impl CliState {
    fn new(
        config: &RuntimeConfig,
        client_contract_address: &str,
        client_contract_status: ClientContractStatus,
    ) -> Self {
        Self {
            owner_address: config.owner_address.clone(),
            cocoon_wallet_address: config.cocoon_wallet_address.clone(),
            proxy_addr: config.proxy_addr.clone(),
            client_contract_address: client_contract_address.to_string(),
            client_contract_status,
        }
    }

    fn matches_config(&self, config: &RuntimeConfig) -> bool {
        self.owner_address == config.owner_address
            && self.cocoon_wallet_address == config.cocoon_wallet_address
            && self.proxy_addr == config.proxy_addr
    }

    fn render(&self) -> String {
        format!(
            "version=1\nowner_address={}\ncocoon_wallet_address={}\nproxy_addr={}\nclient_contract_address={}\nclient_contract_status={}\n",
            self.owner_address,
            self.cocoon_wallet_address,
            self.proxy_addr,
            self.client_contract_address,
            self.client_contract_status.as_str()
        )
    }

    fn parse(data: &str) -> Result<Self> {
        let mut version = None;
        let mut owner_address = None;
        let mut cocoon_wallet_address = None;
        let mut proxy_addr = None;
        let mut client_contract_address = None;
        let mut client_contract_status = None;

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
                "client_contract_status" => {
                    client_contract_status = ClientContractStatus::parse(value);
                }
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
            client_contract_status: client_contract_status.unwrap_or(ClientContractStatus::Active),
        })
    }
}

fn remember_client_contract(
    config: &RuntimeConfig,
    client_contract_address: &str,
    client_contract_status: ClientContractStatus,
) {
    let state = CliState::new(config, client_contract_address, client_contract_status);
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
    let state = read_matching_state(config, true)?;
    println!(
        "{} Using cached client contract {}",
        ">".cyan().bold(),
        state.client_contract_address
    );
    Some(state.client_contract_address)
}

fn read_matching_state(config: &RuntimeConfig, warn: bool) -> Option<CliState> {
    let path = state_file_path(config);
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(error) if error.kind() == ErrorKind::NotFound => return None,
        Err(error) => {
            if warn {
                eprintln!("warning: failed to read {}: {error}", path.display());
            }
            return None;
        }
    };
    let state = match CliState::parse(&data) {
        Ok(state) => state,
        Err(error) => {
            if warn {
                eprintln!("warning: ignoring invalid {}: {error:#}", path.display());
            }
            return None;
        }
    };
    if !state.matches_config(config) {
        return None;
    }
    Some(state)
}

fn fail_if_cached_client_contract_is_closed(config: &RuntimeConfig) -> Result<()> {
    let Some(state) = read_matching_state(config, false) else {
        return Ok(());
    };
    if state.client_contract_status != ClientContractStatus::Closed {
        return Ok(());
    }
    Err(ClosedClientContractStartError::new(config, Some(&state)).into())
}

fn closed_client_contract_start_error(config: &RuntimeConfig) -> anyhow::Error {
    let state = read_matching_state(config, false);
    if let Some(state) = &state {
        remember_client_contract(
            config,
            &state.client_contract_address,
            ClientContractStatus::Closed,
        );
    }
    ClosedClientContractStartError::new(config, state.as_ref()).into()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_state_parse_defaults_old_cache_to_active() -> Result<()> {
        let state = CliState::parse(
            "version=1\nowner_address=owner\ncocoon_wallet_address=wallet\nproxy_addr=proxy\nclient_contract_address=contract\n",
        )?;

        assert_eq!(state.client_contract_status, ClientContractStatus::Active);
        Ok(())
    }

    #[test]
    fn cli_state_round_trips_client_contract_status() -> Result<()> {
        let state = CliState::parse(
            "version=1\nowner_address=owner\ncocoon_wallet_address=wallet\nproxy_addr=proxy\nclient_contract_address=contract\nclient_contract_status=closed\n",
        )?;

        assert_eq!(state.client_contract_status, ClientContractStatus::Closed);
        assert!(state.render().contains("client_contract_status=closed\n"));
        Ok(())
    }
}
