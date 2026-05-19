//! Runtime configuration loading for `rocoon`.
//!
//! Configuration is intentionally split into two shapes:
//! `FileConfig` mirrors the TOML file layout, while `RuntimeConfig` is the
//! validated, flattened structure used by the rest of the program. Environment
//! variables override TOML values so the same binary can be used from local
//! runs, shells, and service managers without rewriting the config file.

use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::wallet;

pub const DEFAULT_CONFIG_PATH: &str = "rocoon.toml";
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
    /// Enables verbose CLI diagnostics.
    pub verbose: bool,
    /// Cocoon proxy TCP address, for example `91.108.4.11:8888`.
    pub proxy_addr: String,
    /// Maximum duration for opening the initial TCP connection.
    pub connect_timeout: Duration,
    /// Local OpenAI-compatible HTTP listen address.
    pub listen_addr: String,
    /// Optional bearer token required by the local HTTP API.
    pub api_token: Option<String>,
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
    /// TON liteclient settings used by stats, auth, maintenance, and CLI controls.
    pub ton: TonRuntimeConfig,
}

/// Decoded Cocoon wallet Ed25519 seed with redacted formatting.
#[derive(Clone)]
pub struct NodeWalletKey([u8; 32]);

/// Validated TON liteclient configuration.
#[derive(Debug, Clone)]
pub struct TonRuntimeConfig {
    /// Selects mainnet, using rocoon's embedded mainnet config when no explicit config is set.
    pub mainnet: bool,
    /// Optional TON global config JSON path overriding the embedded/default config.
    pub config_path: Option<PathBuf>,
    /// Optional root contract address used to read registered proxies for diagnostics.
    pub root_contract_address: Option<String>,
    /// Per-query timeout passed to `ton-rs` liteclient requests.
    pub query_timeout_millis: u64,
}

/// Local HTTP settings loaded without requiring wallet credentials.
#[derive(Debug, Clone)]
pub struct LocalHttpRuntimeConfig {
    /// Local OpenAI-compatible HTTP listen address.
    pub listen_addr: String,
    /// Optional bearer token required by the local HTTP API.
    pub api_token: Option<String>,
}

/// TOML root object before validation and environment overrides.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    network: NetworkConfig,
    server: ServerConfig,
    client: ClientConfig,
    request: RequestConfig,
    ton: TonConfig,
}

/// Network-related TOML section.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct NetworkConfig {
    proxy_addr: String,
    connect_timeout_secs: u64,
}

/// Local HTTP server TOML section.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct ServerConfig {
    listen_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_token: Option<String>,
}

/// Cocoon client identity and authorization TOML section.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct ClientConfig {
    owner_address: String,
    node_wallet_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    min_config_version: i32,
}

/// Per-request default limits used by the HTTP layer.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct RequestConfig {
    max_coefficient: i32,
    max_tokens: i32,
    timeout_secs: f64,
}

/// TON liteclient TOML section.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct TonConfig {
    mainnet: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    root_contract_address: Option<String>,
    query_timeout_millis: u64,
}

impl RuntimeConfig {
    /// Default config path used when `--config` is not provided.
    #[must_use]
    pub fn default_config_path() -> PathBuf {
        PathBuf::from(DEFAULT_CONFIG_PATH)
    }

    /// Generates a fresh base64-encoded 32-byte Cocoon wallet seed.
    #[must_use]
    pub fn generate_node_wallet_key_base64() -> String {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        STANDARD.encode(seed)
    }

    /// Validates an external owner wallet address before writing a generated config.
    ///
    /// # Errors
    ///
    /// Returns an error when `address` is not a valid TON address.
    pub fn validate_owner_address(address: &str) -> Result<()> {
        ton_core::types::TonAddress::from_str(address)
            .context("parse client.owner_address as TON address")?;
        Ok(())
    }

    /// Writes a default config file with the provided owner address and wallet key.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the file cannot be written.
    pub fn write_default_config(
        path: &Path,
        owner_address: &str,
        node_wallet_key: &str,
    ) -> Result<()> {
        let config = default_file_config(owner_address, node_wallet_key);
        let data = toml::to_string_pretty(&config).context("serialize default rocoon config")?;
        if let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) {
            fs::create_dir_all(parent)
                .with_context(|| format!("create config directory {}", parent.display()))?;
        }
        fs::write(path, data).with_context(|| format!("write {}", path.display()))
    }

    /// Loads configuration using CLI-selected options.
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be loaded or validated.
    pub fn load_cli(config_path: Option<PathBuf>, verbose: bool) -> Result<Self> {
        let explicit_config_path = config_path.is_some();
        Self::load_from_path(
            config_path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
            explicit_config_path,
            verbose,
        )
    }

    /// Loads only the local HTTP settings using TOML defaults and env overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be read or local HTTP settings are invalid.
    pub fn load_local_http_cli(config_path: Option<PathBuf>) -> Result<LocalHttpRuntimeConfig> {
        let explicit_config_path = config_path.is_some();
        let config_path = config_path.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));
        let mut config = read_config(&config_path, explicit_config_path)?;
        apply_string_env("ROCOON_LISTEN_ADDR", &mut config.server.listen_addr)?;
        apply_optional_string_env("ROCOON_API_TOKEN", &mut config.server.api_token)?;
        validate_server(&config.server)?;
        Ok(LocalHttpRuntimeConfig {
            listen_addr: config.server.listen_addr,
            api_token: normalize_optional_string(config.server.api_token),
        })
    }

    /// Loads only the local HTTP listen address using TOML defaults and env overrides.
    ///
    /// # Errors
    ///
    /// Returns an error if the config cannot be read or local HTTP settings are invalid.
    pub fn load_listen_addr_cli(config_path: Option<PathBuf>) -> Result<String> {
        Self::load_local_http_cli(config_path).map(|config| config.listen_addr)
    }

    fn load_from_path(
        config_path: PathBuf,
        explicit_config_path: bool,
        verbose: bool,
    ) -> Result<Self> {
        let mut config = read_config(&config_path, explicit_config_path)?;
        apply_env_overrides(&mut config)?;
        validate(&config)?;
        Self::validate_owner_address(&config.client.owner_address)?;
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
        let ton_config_path = config
            .ton
            .config_path
            .map(|path| resolve_path_relative_to_config(path, &config_path));

        Ok(Self {
            config_path,
            verbose,
            proxy_addr: config.network.proxy_addr,
            connect_timeout: Duration::from_secs(config.network.connect_timeout_secs),
            listen_addr: config.server.listen_addr,
            api_token: normalize_optional_string(config.server.api_token),
            owner_address: config.client.owner_address,
            node_wallet_key,
            cocoon_wallet_address,
            client_secret: config.client.secret,
            min_config_version: config.client.min_config_version,
            max_coefficient: config.request.max_coefficient,
            max_tokens: config.request.max_tokens,
            request_timeout: config.request.timeout_secs,
            ton: TonRuntimeConfig {
                mainnet: config.ton.mainnet,
                config_path: ton_config_path,
                root_contract_address,
                query_timeout_millis: config.ton.query_timeout_millis,
            },
        })
    }
}

impl NodeWalletKey {
    /// Returns the decoded Ed25519 seed for internal signing code.
    #[must_use]
    pub const fn seed(&self) -> &[u8; 32] {
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
            api_token: None,
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
            mainnet: true,
            config_path: None,
            root_contract_address: None,
            query_timeout_millis: DEFAULT_TON_QUERY_TIMEOUT_MILLIS,
        }
    }
}

fn default_file_config(owner_address: &str, node_wallet_key: &str) -> FileConfig {
    FileConfig {
        server: ServerConfig {
            api_token: Some(String::new()),
            ..ServerConfig::default()
        },
        client: ClientConfig {
            owner_address: owner_address.to_string(),
            node_wallet_key: node_wallet_key.to_string(),
            secret: Some(String::new()),
            min_config_version: 0,
        },
        ..FileConfig::default()
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

fn resolve_path_relative_to_config(path: PathBuf, config_path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    let config_dir = config_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    config_dir.join(path)
}

fn apply_env_overrides(config: &mut FileConfig) -> Result<()> {
    apply_string_env("COCOON_PROXY_ADDR", &mut config.network.proxy_addr)?;
    apply_u64_env(
        "ROCOON_CONNECT_TIMEOUT_SECS",
        &mut config.network.connect_timeout_secs,
    )?;
    apply_string_env("ROCOON_LISTEN_ADDR", &mut config.server.listen_addr)?;
    apply_optional_string_env("ROCOON_API_TOKEN", &mut config.server.api_token)?;
    apply_string_env("COCOON_OWNER_ADDRESS", &mut config.client.owner_address)?;
    apply_string_env("COCOON_NODE_WALLET_KEY", &mut config.client.node_wallet_key)?;
    apply_optional_string_env("COCOON_CLIENT_SECRET", &mut config.client.secret)?;
    apply_i32_env(
        "COCOON_MIN_CONFIG_VERSION",
        &mut config.client.min_config_version,
    )?;
    apply_i32_env(
        "ROCOON_MAX_COEFFICIENT",
        &mut config.request.max_coefficient,
    )?;
    apply_i32_env("ROCOON_MAX_TOKENS", &mut config.request.max_tokens)?;
    apply_f64_env(
        "ROCOON_REQUEST_TIMEOUT_SECS",
        &mut config.request.timeout_secs,
    )?;
    apply_bool_env("ROCOON_TON_MAINNET", &mut config.ton.mainnet)?;
    apply_optional_path_env("ROCOON_TON_CONFIG_PATH", &mut config.ton.config_path)?;
    apply_optional_string_env(
        "COCOON_ROOT_CONTRACT_ADDRESS",
        &mut config.ton.root_contract_address,
    )?;
    apply_u64_env(
        "ROCOON_TON_QUERY_TIMEOUT_MILLIS",
        &mut config.ton.query_timeout_millis,
    )?;
    Ok(())
}

fn read_env(name: &str) -> Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(anyhow!(error)).with_context(|| format!("read {name}")),
    }
}

fn apply_string_env(name: &str, target: &mut String) -> Result<()> {
    if let Some(value) = read_env(name)? {
        *target = value;
    }
    Ok(())
}

fn apply_optional_string_env(name: &str, target: &mut Option<String>) -> Result<()> {
    if let Some(value) = read_env(name)? {
        *target = if value.is_empty() { None } else { Some(value) };
    }
    Ok(())
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn apply_optional_path_env(name: &str, target: &mut Option<PathBuf>) -> Result<()> {
    if let Some(value) = read_env(name)? {
        *target = if value.is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        };
    }
    Ok(())
}

fn apply_bool_env(name: &str, target: &mut bool) -> Result<()> {
    if let Some(value) = read_env(name)? {
        *target = parse_bool(&value).with_context(|| format!("parse {name}"))?;
    }
    Ok(())
}

fn apply_i32_env(name: &str, target: &mut i32) -> Result<()> {
    if let Some(value) = read_env(name)? {
        *target = value.parse().with_context(|| format!("parse {name}"))?;
    }
    Ok(())
}

fn apply_u64_env(name: &str, target: &mut u64) -> Result<()> {
    if let Some(value) = read_env(name)? {
        *target = value.parse().with_context(|| format!("parse {name}"))?;
    }
    Ok(())
}

fn apply_f64_env(name: &str, target: &mut f64) -> Result<()> {
    if let Some(value) = read_env(name)? {
        *target = value.parse().with_context(|| format!("parse {name}"))?;
    }
    Ok(())
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
    validate_server(&config.server)?;
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

fn validate_server(config: &ServerConfig) -> Result<()> {
    validate_listen_addr(&config.listen_addr)?;
    if let Some(api_token) = &config.api_token
        && !api_token.is_empty()
        && api_token.trim().is_empty()
    {
        anyhow::bail!("server.api_token must not be blank when set");
    }
    Ok(())
}

fn validate_listen_addr(listen_addr: &str) -> Result<()> {
    if listen_addr.trim().is_empty() {
        anyhow::bail!("server.listen_addr must not be empty");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FileConfig, RuntimeConfig, default_file_config, resolve_path_relative_to_config};
    use std::path::{Path, PathBuf};

    #[test]
    fn relative_ton_config_path_is_resolved_against_config_file_dir() {
        let resolved = resolve_path_relative_to_config(
            PathBuf::from("spec/mainnet-full-ton-config.json"),
            Path::new("/tmp/rocoon/rocoon.toml"),
        );

        assert_eq!(
            resolved,
            PathBuf::from("/tmp/rocoon/spec/mainnet-full-ton-config.json")
        );
    }

    #[test]
    fn absolute_ton_config_path_is_left_unchanged() {
        let path = PathBuf::from("/tmp/mainnet-full-ton-config.json");
        let resolved =
            resolve_path_relative_to_config(path.clone(), Path::new("/tmp/rocoon/rocoon.toml"));

        assert_eq!(resolved, path);
    }

    #[test]
    fn generated_default_config_round_trips() {
        let owner_address = "UQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJKZ";
        let node_wallet_key = RuntimeConfig::generate_node_wallet_key_base64();
        let config = default_file_config(owner_address, &node_wallet_key);
        let data = toml::to_string_pretty(&config).expect("default config should serialize");
        let parsed: FileConfig = toml::from_str(&data).expect("default config should parse");

        assert_eq!(parsed.client.owner_address, owner_address);
        assert_eq!(parsed.client.node_wallet_key, node_wallet_key);
        assert_eq!(parsed.network.proxy_addr, "91.108.4.11:8888");
        assert_eq!(parsed.server.api_token.as_deref(), Some(""));
        assert!(parsed.ton.mainnet);
    }
}
