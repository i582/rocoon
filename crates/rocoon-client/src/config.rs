//! Runtime configuration loading for `rocoon`.
//!
//! Configuration is intentionally split into two shapes:
//! `FileConfig` mirrors the TOML file layout, while `RuntimeConfig` is the
//! validated, flattened structure used by the rest of the program. Environment
//! variables override TOML values so the same binary can be used from local
//! runs, shells, and service managers without rewriting the config file.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;

use crate::wallet;

const DEFAULT_CONFIG_PATH: &str = "rocoon.toml";
const DEFAULT_PROXY_ADDR: &str = "91.108.4.11:8888";
const DEFAULT_MAINNET_ROOT_CONTRACT_ADDRESS: &str =
    "EQCns7bYSp0igFvS1wpb5wsZjCKCV19MD5AVzI4EyxsnU73k";
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_TON_QUERY_TIMEOUT_MILLIS: u64 = 5_000;

/// Validated configuration used by networking, Cocoon auth, and the HTTP API.
///
/// This type is cloned into `CocoonClient` so the client can reconnect using
/// the same settings after transient proxy/session failures.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Path that was actually used for TOML loading.
    pub config_path: PathBuf,
    /// Cocoon proxy TCP address, for example `91.108.4.11:8888`.
    pub proxy_addr: String,
    /// Maximum duration for opening the initial TCP connection.
    pub connect_timeout: Duration,
    /// Local OpenAI-compatible HTTP listen address.
    pub listen_addr: String,
    /// External TON wallet address that owns the Cocoon wallet contract.
    pub owner_address: String,
    /// Decoded Ed25519 seed used by the Cocoon wallet contract.
    pub node_wallet_key: NodeWalletKey,
    /// Derived Cocoon wallet smart-contract address used in `client.connectToProxy`.
    pub cocoon_wallet_address: String,
    /// Shared secret for short proxy authorization.
    pub client_secret: Option<String>,
    /// Minimum accepted on-chain Cocoon config version.
    pub min_config_version: i32,
    /// Upper bound for worker price coefficient selected by the proxy.
    pub max_coefficient: i32,
    /// Default token cap for local requests that do not provide one.
    pub max_tokens: i32,
    /// Default Cocoon request timeout in seconds.
    pub request_timeout: f64,
    /// TON liteclient read-only settings used by `/stats`.
    pub ton: TonRuntimeConfig,
}

/// Decoded Cocoon wallet Ed25519 seed with redacted formatting.
#[derive(Clone)]
pub struct NodeWalletKey([u8; 32]);

/// Validated read-only TON liteclient configuration.
#[derive(Debug, Clone)]
pub struct TonRuntimeConfig {
    /// Whether `rocoon` should read wallet/root state from TON liteservers.
    pub readonly_enabled: bool,
    /// Selects mainnet built-in liteserver config when no explicit config is set.
    pub mainnet: bool,
    /// Optional TON global config JSON path.
    pub config_path: Option<PathBuf>,
    /// Optional root contract address shown in diagnostics and used by future root polling.
    pub root_contract_address: Option<String>,
    /// Per-query timeout passed to `ton-rs` liteclient requests.
    pub query_timeout_millis: u64,
}

/// TOML root object before validation and environment overrides.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    network: NetworkConfig,
    server: ServerConfig,
    client: ClientConfig,
    request: RequestConfig,
    ton: TonConfig,
}

/// Network-related TOML section.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NetworkConfig {
    proxy_addr: String,
    connect_timeout_secs: u64,
}

/// Local HTTP server TOML section.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ServerConfig {
    listen_addr: String,
}

/// Cocoon client identity and authorization TOML section.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClientConfig {
    owner_address: String,
    node_wallet_key: String,
    secret: Option<String>,
    min_config_version: i32,
}

/// Per-request default limits used by the HTTP layer.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RequestConfig {
    max_coefficient: i32,
    max_tokens: i32,
    timeout_secs: f64,
}

/// Read-only TON liteclient TOML section.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TonConfig {
    readonly_enabled: bool,
    mainnet: bool,
    config_path: Option<PathBuf>,
    root_contract_address: Option<String>,
    query_timeout_millis: u64,
}

impl RuntimeConfig {
    /// Loads configuration from `rocoon.toml` or `--config path`.
    ///
    /// Missing default config is allowed and falls back to built-in defaults.
    /// Explicit `--config` paths must exist. Environment variables are applied
    /// after TOML loading and before validation.
    ///
    /// # Errors
    ///
    /// Returns an error if an explicit config cannot be read, TOML parsing
    /// fails, environment overrides cannot be parsed, or validation rejects the
    /// effective configuration.
    pub fn load() -> Result<Self> {
        let (config_path, explicit_config_path) = config_path_from_args(env::args_os().skip(1))?;
        let mut config = read_config(&config_path, explicit_config_path)?;

        if let Ok(value) = env::var("COCOON_PROXY_ADDR") {
            config.network.proxy_addr = value;
        }
        if let Ok(value) = env::var("COCOON_CONNECT_TIMEOUT_SECS") {
            config.network.connect_timeout_secs =
                value.parse().context("parse COCOON_CONNECT_TIMEOUT_SECS")?;
        }
        if let Ok(value) = env::var("ROCOON_LISTEN_ADDR") {
            config.server.listen_addr = value;
        }
        if let Ok(value) = env::var("COCOON_OWNER_ADDRESS") {
            config.client.owner_address = value;
        }
        if let Ok(value) = env::var("COCOON_NODE_WALLET_KEY") {
            config.client.node_wallet_key = value;
        }
        if let Ok(value) = env::var("COCOON_CLIENT_SECRET") {
            config.client.secret = Some(value);
        }
        if let Ok(value) = env::var("COCOON_MIN_CONFIG_VERSION") {
            config.client.min_config_version =
                value.parse().context("parse COCOON_MIN_CONFIG_VERSION")?;
        }
        if let Ok(value) = env::var("COCOON_MAX_COEFFICIENT") {
            config.request.max_coefficient =
                value.parse().context("parse COCOON_MAX_COEFFICIENT")?;
        }
        if let Ok(value) = env::var("COCOON_MAX_TOKENS") {
            config.request.max_tokens = value.parse().context("parse COCOON_MAX_TOKENS")?;
        }
        if let Ok(value) = env::var("COCOON_REQUEST_TIMEOUT_SECS") {
            config.request.timeout_secs =
                value.parse().context("parse COCOON_REQUEST_TIMEOUT_SECS")?;
        }
        if let Ok(value) = env::var("ROCOON_TON_READONLY_ENABLED") {
            config.ton.readonly_enabled =
                parse_bool(&value).context("parse ROCOON_TON_READONLY_ENABLED")?;
        }
        if let Ok(value) = env::var("ROCOON_TON_MAINNET") {
            config.ton.mainnet = parse_bool(&value).context("parse ROCOON_TON_MAINNET")?;
        }
        if let Ok(value) = env::var("ROCOON_TON_CONFIG_PATH") {
            config.ton.config_path = Some(PathBuf::from(value));
        }
        if let Ok(value) = env::var("COCOON_ROOT_CONTRACT_ADDRESS") {
            config.ton.root_contract_address = Some(value);
        }
        if let Ok(value) = env::var("ROCOON_TON_QUERY_TIMEOUT_MILLIS") {
            config.ton.query_timeout_millis = value
                .parse()
                .context("parse ROCOON_TON_QUERY_TIMEOUT_MILLIS")?;
        }
        validate(&config)?;
        let owner_address = ton_core::types::TonAddress::from_str(&config.client.owner_address)
            .context("parse client.owner_address as TON address")?;
        let node_wallet_key = NodeWalletKey(
            wallet::decode_node_wallet_key(&config.client.node_wallet_key)
                .context("decode client.node_wallet_key")?,
        );
        let cocoon_wallet_address = wallet::derive_cocoon_wallet_address_from_seed(
            &owner_address,
            node_wallet_key.seed(),
        )
        .context(
            "derive Cocoon wallet address from client.owner_address and client.node_wallet_key",
        )?;

        let root_contract_address = config.ton.root_contract_address.or_else(|| {
            config
                .ton
                .mainnet
                .then_some(DEFAULT_MAINNET_ROOT_CONTRACT_ADDRESS.to_string())
        });

        Ok(Self {
            config_path,
            proxy_addr: config.network.proxy_addr,
            connect_timeout: Duration::from_secs(config.network.connect_timeout_secs),
            listen_addr: config.server.listen_addr,
            owner_address: config.client.owner_address,
            node_wallet_key,
            cocoon_wallet_address,
            client_secret: config.client.secret,
            min_config_version: config.client.min_config_version,
            max_coefficient: config.request.max_coefficient,
            max_tokens: config.request.max_tokens,
            request_timeout: config.request.timeout_secs,
            ton: TonRuntimeConfig {
                readonly_enabled: config.ton.readonly_enabled,
                mainnet: config.ton.mainnet,
                config_path: config.ton.config_path,
                root_contract_address,
                query_timeout_millis: config.ton.query_timeout_millis,
            },
        })
    }
}

impl NodeWalletKey {
    /// Returns the decoded Ed25519 seed for internal signing code.
    pub(crate) const fn seed(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for NodeWalletKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NodeWalletKey(<redacted>)")
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            proxy_addr: DEFAULT_PROXY_ADDR.to_string(),
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:9999".to_string(),
        }
    }
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            max_coefficient: 4000,
            max_tokens: 10000,
            timeout_secs: 120.0,
        }
    }
}

impl Default for TonConfig {
    fn default() -> Self {
        Self {
            readonly_enabled: true,
            mainnet: true,
            config_path: None,
            root_contract_address: None,
            query_timeout_millis: DEFAULT_TON_QUERY_TIMEOUT_MILLIS,
        }
    }
}

/// Parses the minimal command-line interface.
///
/// The boolean in the result marks whether the config path was explicitly
/// provided. That distinction lets default `rocoon.toml` be optional while
/// still failing fast for mistyped explicit config paths.
fn config_path_from_args<I>(mut args: I) -> Result<(PathBuf, bool)>
where
    I: Iterator<Item = OsString>,
{
    let Some(first) = args.next() else {
        return Ok((PathBuf::from(DEFAULT_CONFIG_PATH), false));
    };

    let first = first
        .into_string()
        .map_err(|_| anyhow!("argument is not valid UTF-8"))?;

    match first.as_str() {
        "--config" | "-c" => {
            let path = args
                .next()
                .ok_or_else(|| anyhow!("missing path after {first}"))?;
            if let Some(extra) = args.next() {
                anyhow::bail!("unexpected extra argument: {}", extra.to_string_lossy());
            }
            Ok((PathBuf::from(path), true))
        }
        "--help" | "-h" => anyhow::bail!("usage: rocoon [--config path]"),
        _ => anyhow::bail!("unknown argument: {first}; use --config path"),
    }
}

/// Reads and deserializes the TOML file, or returns defaults when allowed.
fn read_config(path: &Path, explicit: bool) -> Result<FileConfig> {
    match fs::read_to_string(path) {
        Ok(data) => toml::from_str(&data).with_context(|| format!("parse {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !explicit => {
            Ok(FileConfig::default())
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Parses environment booleans accepted by common service managers and shells.
fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("expected one of: 1, 0, true, false, yes, no, on, off"),
    }
}

/// Performs semantic validation that TOML deserialization cannot express.
///
/// This keeps downstream code from repeatedly checking for empty addresses,
/// non-positive timeouts, or negative request limits.
fn validate(config: &FileConfig) -> Result<()> {
    if config.network.proxy_addr.trim().is_empty() {
        anyhow::bail!("network.proxy_addr must not be empty");
    }
    if config.network.connect_timeout_secs == 0 {
        anyhow::bail!("network.connect_timeout_secs must be greater than zero");
    }
    if config.server.listen_addr.trim().is_empty() {
        anyhow::bail!("server.listen_addr must not be empty");
    }
    if config.client.owner_address.trim().is_empty() {
        anyhow::bail!("client.owner_address must not be empty");
    }
    if config.client.node_wallet_key.trim().is_empty() {
        anyhow::bail!("client.node_wallet_key must not be empty");
    }
    if config.request.max_coefficient < 0 {
        anyhow::bail!("request.max_coefficient must not be negative");
    }
    if config.request.max_tokens < 0 {
        anyhow::bail!("request.max_tokens must not be negative");
    }
    if config.request.timeout_secs <= 0.0 {
        anyhow::bail!("request.timeout_secs must be greater than zero");
    }
    if let Some(path) = &config.ton.config_path
        && path.as_os_str().is_empty()
    {
        anyhow::bail!("ton.config_path must not be empty when set");
    }
    if let Some(address) = &config.ton.root_contract_address
        && address.trim().is_empty()
    {
        anyhow::bail!("ton.root_contract_address must not be empty when set");
    }
    if config.ton.query_timeout_millis == 0 {
        anyhow::bail!("ton.query_timeout_millis must be greater than zero");
    }
    Ok(())
}
