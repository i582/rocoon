use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;

const DEFAULT_CONFIG_PATH: &str = "rocoon.toml";
const DEFAULT_PROXY_ADDR: &str = "91.108.4.11:8888";
const DEFAULT_OWNER_ADDRESS: &str = "UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H";
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub config_path: PathBuf,
    pub proxy_addr: String,
    pub connect_timeout: Duration,
    pub listen_addr: String,
    pub owner_address: String,
    pub client_secret: Option<String>,
    pub min_config_version: i32,
    pub max_coefficient: i32,
    pub max_tokens: i32,
    pub request_timeout: f64,
    pub enable_debug: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    network: NetworkConfig,
    server: ServerConfig,
    client: ClientConfig,
    request: RequestConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NetworkConfig {
    proxy_addr: String,
    connect_timeout_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ServerConfig {
    listen_addr: String,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClientConfig {
    owner_address: String,
    secret: Option<String>,
    min_config_version: i32,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RequestConfig {
    max_coefficient: i32,
    max_tokens: i32,
    timeout_secs: f64,
    enable_debug: bool,
}

impl RuntimeConfig {
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
        if let Ok(value) = env::var("COCOON_ENABLE_DEBUG") {
            config.request.enable_debug =
                parse_bool_env(&value).context("parse COCOON_ENABLE_DEBUG")?;
        }

        validate(&config)?;

        Ok(Self {
            config_path,
            proxy_addr: config.network.proxy_addr,
            connect_timeout: Duration::from_secs(config.network.connect_timeout_secs),
            listen_addr: config.server.listen_addr,
            owner_address: config.client.owner_address,
            client_secret: config.client.secret,
            min_config_version: config.client.min_config_version,
            max_coefficient: config.request.max_coefficient,
            max_tokens: config.request.max_tokens,
            request_timeout: config.request.timeout_secs,
            enable_debug: config.request.enable_debug,
        })
    }
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            server: ServerConfig::default(),
            client: ClientConfig::default(),
            request: RequestConfig::default(),
        }
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

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            owner_address: DEFAULT_OWNER_ADDRESS.to_string(),
            secret: None,
            min_config_version: 0,
        }
    }
}

impl Default for RequestConfig {
    fn default() -> Self {
        Self {
            max_coefficient: 4000,
            max_tokens: 10000,
            timeout_secs: 120.0,
            enable_debug: false,
        }
    }
}

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
                bail!("unexpected extra argument: {}", extra.to_string_lossy());
            }
            Ok((PathBuf::from(path), true))
        }
        "--help" | "-h" => bail!("usage: rocoon [--config path]"),
        _ => bail!("unknown argument: {first}; use --config path"),
    }
}

fn read_config(path: &Path, explicit: bool) -> Result<FileConfig> {
    match fs::read_to_string(path) {
        Ok(data) => toml::from_str(&data).with_context(|| format!("parse {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !explicit => {
            Ok(FileConfig::default())
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn validate(config: &FileConfig) -> Result<()> {
    if config.network.proxy_addr.trim().is_empty() {
        bail!("network.proxy_addr must not be empty");
    }
    if config.network.connect_timeout_secs == 0 {
        bail!("network.connect_timeout_secs must be greater than zero");
    }
    if config.server.listen_addr.trim().is_empty() {
        bail!("server.listen_addr must not be empty");
    }
    if config.client.owner_address.trim().is_empty() {
        bail!("client.owner_address must not be empty");
    }
    if config.request.max_coefficient < 0 {
        bail!("request.max_coefficient must not be negative");
    }
    if config.request.max_tokens < 0 {
        bail!("request.max_tokens must not be negative");
    }
    if config.request.timeout_secs <= 0.0 {
        bail!("request.timeout_secs must be greater than zero");
    }
    Ok(())
}

fn parse_bool_env(value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
        "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
        _ => bail!("expected boolean value"),
    }
}
