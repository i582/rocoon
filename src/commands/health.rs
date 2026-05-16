use anyhow::Result;
use rocoon_config::color::OwoColorize;

use super::local_http;

pub fn run(listen_addr: &str, verbose: bool) -> Result<()> {
    let url = local_http::url(listen_addr, "/health");
    println!("{} Checking {}", ">".cyan().bold(), url.cyan().bold());
    let response = local_http::get(listen_addr, "/health")?;
    if response.status_code != 200 {
        anyhow::bail!(
            "rocoon server at {} returned HTTP {}; expected 200",
            url.cyan().bold(),
            response.status_code
        );
    }
    println!("{} rocoon server is healthy", "✓".green().bold());
    if verbose {
        println!("{}", response.body.trim());
    }
    Ok(())
}
