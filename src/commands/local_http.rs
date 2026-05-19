use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Context, Result};
use rocoon_config::color::OwoColorize;

const LOCAL_HTTP_TIMEOUT: Duration = Duration::from_secs(2);

pub struct LocalHttpResponse {
    pub status_code: u16,
    pub body: String,
}

pub fn get(listen_addr: &str, path: &str, api_token: Option<&str>) -> Result<LocalHttpResponse> {
    let mut stream = match TcpStream::connect(listen_addr) {
        Ok(stream) => stream,
        Err(error) => return Err(connect_error(listen_addr, path, &error)),
    };
    stream
        .set_read_timeout(Some(LOCAL_HTTP_TIMEOUT))
        .context("set local HTTP read timeout")?;
    stream
        .set_write_timeout(Some(LOCAL_HTTP_TIMEOUT))
        .context("set local HTTP write timeout")?;
    let authorization = api_token.map_or_else(String::new, |token| {
        format!("Authorization: Bearer {token}\r\n")
    });
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {listen_addr}\r\n{authorization}Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .with_context(|| format!("send local HTTP request {path}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .with_context(|| format!("read local HTTP response {path}"))?;
    parse_response(&response)
}

pub fn url(listen_addr: &str, path: &str) -> String {
    format!("http://{listen_addr}{path}")
}

fn connect_error(listen_addr: &str, path: &str, error: &std::io::Error) -> anyhow::Error {
    let url = url(listen_addr, path);
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

fn parse_response(response: &str) -> Result<LocalHttpResponse> {
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("local HTTP response is missing header terminator")?;
    let status_line = head.lines().next().context("empty local HTTP response")?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().context("missing local HTTP version")?;
    if !version.starts_with("HTTP/") {
        anyhow::bail!("invalid local HTTP response: {status_line}");
    }
    let code = parts.next().context("missing local HTTP status code")?;
    Ok(LocalHttpResponse {
        status_code: code.parse().context("parse local HTTP status code")?,
        body: body.to_string(),
    })
}
