mod client;
mod cocoon;
mod config;
mod pow;
mod ratls;
mod server;
mod session;

use anyhow::Result;

fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = config::RuntimeConfig::load()?;
    println!("loaded config: {}", config.config_path.display());

    let client = client::CocoonClient::connect(&config)?;
    let defaults = server::Defaults {
        max_coefficient: config.max_coefficient,
        max_tokens: config.max_tokens,
        timeout: config.request_timeout,
        enable_debug: config.enable_debug,
    };
    server::serve(&config.listen_addr, client, defaults)
}
