use anyhow::Result;
use rocoon_client::{CocoonClient, RuntimeConfig};
use rocoon_openai_server::{Defaults, serve};
use std::io;
use std::thread;
use std::time::Duration;

const ACTION_REQUIRED_RETRY_ATTEMPTS: usize = 5;
const ACTION_REQUIRED_RETRY_DELAY: Duration = Duration::from_secs(2);

fn main() -> Result<()> {
    let config = RuntimeConfig::load()?;
    println!("loaded config: {}", config.config_path.display());

    let client = connect_interactively(&config)?;
    let defaults = Defaults {
        max_coefficient: config.max_coefficient,
        max_tokens: config.max_tokens,
        timeout: config.request_timeout,
    };
    serve(&config.listen_addr, client, defaults)
}

fn connect_interactively(config: &RuntimeConfig) -> Result<CocoonClient> {
    loop {
        match CocoonClient::connect(config) {
            Ok(client) => return Ok(client),
            Err(error) => {
                let Some(message) = action_required_message(&error) else {
                    return Err(error);
                };
                wait_for_user_action(&message)?;
            }
        }

        if let Some(client) = retry_connect(config)? {
            return Ok(client);
        }
    }
}

fn retry_connect(config: &RuntimeConfig) -> Result<Option<CocoonClient>> {
    let mut last_action_required = None;
    for attempt in 1..=ACTION_REQUIRED_RETRY_ATTEMPTS {
        println!(
            "retrying Cocoon connection after user action ({attempt}/{ACTION_REQUIRED_RETRY_ATTEMPTS})..."
        );
        match CocoonClient::connect(config) {
            Ok(client) => return Ok(Some(client)),
            Err(error) => {
                if let Some(message) = action_required_message(&error) {
                    println!("still requires action: {message}");
                    last_action_required = Some(message);
                } else if attempt == ACTION_REQUIRED_RETRY_ATTEMPTS {
                    return Err(error);
                } else {
                    println!("retry {attempt} failed: {error}");
                }
            }
        }
        if attempt != ACTION_REQUIRED_RETRY_ATTEMPTS {
            thread::sleep(ACTION_REQUIRED_RETRY_DELAY);
        }
    }

    if let Some(message) = last_action_required {
        wait_for_user_action(&message)?;
    }
    Ok(None)
}

fn wait_for_user_action(message: &str) -> Result<()> {
    println!();
    println!("ACTION REQUIRED");
    println!("{message}");
    println!("After fixing it, press Enter to retry.");

    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(())
}

fn action_required_message(error: &anyhow::Error) -> Option<String> {
    error
        .chain()
        .find_map(|cause| extract_action_required(&cause.to_string()))
}

fn extract_action_required(message: &str) -> Option<String> {
    message
        .split(';')
        .map(str::trim)
        .find(|part| part.starts_with("ACTION REQUIRED"))
        .map(ToOwned::to_owned)
}
