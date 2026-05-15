use anyhow::Result;
use rocoon_client::{CocoonClient, RuntimeConfig};
use rocoon_openai_server::{Defaults, serve};

fn main() -> Result<()> {
    let config = RuntimeConfig::load()?;
    if config.verbose {
        println!("config: {}", config.config_path.display());
    }

    let client = CocoonClient::connect_interactive(&config)?;
    let defaults = Defaults {
        max_coefficient: config.max_coefficient,
        max_tokens: config.max_tokens,
        timeout: config.request_timeout,
    };
    serve(&config.listen_addr, client, defaults)
}
