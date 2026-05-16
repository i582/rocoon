use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Context, Result};
use rocoon_config::color::OwoColorize;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

pub fn run(listen_addr: &str, verbose: bool) -> Result<()> {
    let url = health_url(listen_addr);
    println!("{} Checking {}", ">".cyan().bold(), url.cyan().bold());
    let response = fetch_health(listen_addr)?;
    let status_code = parse_http_status_code(&response)?;
    if status_code != 200 {
        anyhow::bail!(
            "rocoon server at {} returned HTTP {}; expected 200",
            url.cyan().bold(),
            status_code
        );
    }
    println!("{} rocoon server is healthy", "✓".green().bold());
    if verbose && let Some((_, body)) = response.split_once("\r\n\r\n") {
        println!("{}", body.trim());
    }
    Ok(())
}

fn fetch_health(listen_addr: &str) -> Result<String> {
    let mut stream = match TcpStream::connect(listen_addr) {
        Ok(stream) => stream,
        Err(error) => return Err(health_connect_error(listen_addr, &error)),
    };
    stream
        .set_read_timeout(Some(HEALTH_TIMEOUT))
        .context("set health check read timeout")?;
    stream
        .set_write_timeout(Some(HEALTH_TIMEOUT))
        .context("set health check write timeout")?;
    let request =
        format!("GET /health HTTP/1.1\r\nHost: {listen_addr}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .context("send health check request")?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .context("read health check response")?;
    Ok(response)
}

fn health_connect_error(listen_addr: &str, error: &std::io::Error) -> anyhow::Error {
    let url = health_url(listen_addr);
    match error.kind() {
        ErrorKind::ConnectionRefused | ErrorKind::NotFound => anyhow::anyhow!(
            "rocoon server is not running at {}. Start it with {}.",
            url.cyan().bold(),
            "rocoon start".cyan().bold()
        ),
        ErrorKind::TimedOut => anyhow::anyhow!(
            "timed out connecting to rocoon server at {}",
            url.cyan().bold()
        ),
        _ => anyhow::anyhow!("connect to rocoon server at {}: {error}", url.cyan().bold()),
    }
}

fn parse_http_status_code(response: &str) -> Result<u16> {
    let status_line = response.lines().next().context("empty health response")?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().context("missing health HTTP version")?;
    if !version.starts_with("HTTP/") {
        anyhow::bail!("invalid health HTTP response: {status_line}");
    }
    let code = parts.next().context("missing health HTTP status code")?;
    code.parse::<u16>().context("parse health HTTP status code")
}

fn health_url(listen_addr: &str) -> String {
    format!("http://{listen_addr}/health")
}
