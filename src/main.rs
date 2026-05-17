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
    COCOON_WALLET_RESERVE_NANOTONS, CocoonClient, is_client_contract_closed_or_closing_error,
};
use rocoon_config::{
    RuntimeConfig,
    color::{ColorMode, OwoColorize, init_color_mode},
};
use rocoon_state::{CliState, ClientContractStatus};

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
    /// Show local OpenAI-compatible HTTP server stats.
    Stats,
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
    /// Print registered proxies from the Cocoon root contract.
    Proxies {
        #[command(subcommand)]
        command: ProxiesCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ModelsCommand {
    /// List models advertised by the Cocoon proxy.
    List,
    /// Show workers and capacity for one model.
    Inspect {
        /// Model id from `rocoon models list`.
        #[arg(value_name = "MODEL")]
        model: String,
    },
}

#[derive(Debug, Subcommand)]
enum ProxiesCommand {
    /// List registered proxies from the Cocoon root contract.
    List {
        /// Root contract address. Defaults to `[ton].root_contract_address`.
        #[arg(long, value_name = "ADDRESS")]
        root_contract: Option<String>,
    },
    /// Show handshake details for one proxy.
    Inspect {
        /// Proxy seqno or address from `rocoon proxies list`.
        #[arg(value_name = "SEQNO_OR_ADDRESS")]
        proxy: String,

        /// Root contract address. Defaults to `[ton].root_contract_address`.
        #[arg(long, value_name = "ADDRESS")]
        root_contract: Option<String>,
    },
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
    if matches!(command, Command::Stats) {
        let listen_addr = RuntimeConfig::load_listen_addr_cli(config)?;
        return commands::stats::run(&listen_addr, verbose);
    }

    let config = RuntimeConfig::load_cli(config, verbose)?;
    if config.verbose {
        println!("config: {}", config.config_path.display());
    }

    match command {
        Command::Start => commands::start::run(&config),
        Command::Health => unreachable!("health is handled before full config loading"),
        Command::Stats => unreachable!("stats is handled before full config loading"),
        Command::Models { command } => match command {
            ModelsCommand::List => commands::models::list(&config),
            ModelsCommand::Inspect { model } => commands::models::inspect(&config, &model),
        },
        Command::RequestWithdraw { client_contract } => {
            commands::request_withdraw::run(&config, client_contract.as_deref())
        }
        Command::Close { client_contract } => {
            commands::close::run(&config, client_contract.as_deref())
        }
        Command::Withdraw {
            client_contract,
            to,
            reserve_nanotons,
        } => {
            let client_contract = client_contract.or_else(|| cached_client_contract(&config));
            commands::withdraw::run(
                &config,
                client_contract.as_deref(),
                to.as_deref(),
                reserve_nanotons,
            )
        }
        Command::Proxies { command } => match command {
            ProxiesCommand::List { root_contract } => {
                commands::proxies::list(&config, root_contract.as_deref())
            }
            ProxiesCommand::Inspect {
                proxy,
                root_contract,
            } => commands::proxies::inspect(&config, &proxy, root_contract.as_deref()),
        },
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

pub(crate) fn connect_cocoon_interactive(config: &RuntimeConfig) -> Result<CocoonClient> {
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
