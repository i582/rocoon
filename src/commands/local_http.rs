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

pub fn get(listen_addr: &str, path: &str) -> Result<LocalHttpResponse> {
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {listen_addr}\r\nConnection: close\r\n\r\n");
    send(listen_addr, path, request.as_bytes(), LOCAL_HTTP_TIMEOUT)
}

pub fn post_json(
    listen_addr: &str,
    path: &str,
    body: &[u8],
    timeout: Duration,
) -> Result<LocalHttpResponse> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {listen_addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(body);
    send(listen_addr, path, &request, timeout)
}

pub fn url(listen_addr: &str, path: &str) -> String {
    format!("http://{listen_addr}{path}")
}

fn send(
    listen_addr: &str,
    path: &str,
    request: &[u8],
    timeout: Duration,
) -> Result<LocalHttpResponse> {
    let mut stream = match TcpStream::connect(listen_addr) {
        Ok(stream) => stream,
        Err(error) => return Err(connect_error(listen_addr, path, &error)),
    };
    stream
        .set_read_timeout(Some(timeout))
        .context("set local HTTP read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("set local HTTP write timeout")?;
    stream
        .write_all(request)
        .with_context(|| format!("send local HTTP request {path}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .with_context(|| format!("read local HTTP response {path}"))?;
    parse_response(&response)
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

fn parse_response(response: &[u8]) -> Result<LocalHttpResponse> {
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("local HTTP response is missing header terminator")?;
    let head = std::str::from_utf8(&response[..head_end])
        .context("local HTTP response headers are not UTF-8")?;
    let body = &response[head_end + 4..];
    let status_line = head.lines().next().context("empty local HTTP response")?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().context("missing local HTTP version")?;
    if !version.starts_with("HTTP/") {
        anyhow::bail!("invalid local HTTP response: {status_line}");
    }
    let code = parts.next().context("missing local HTTP status code")?;
    Ok(LocalHttpResponse {
        status_code: code.parse().context("parse local HTTP status code")?,
        body: String::from_utf8_lossy(body).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_reads_status_and_body_from_bytes() {
        let response = parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
        )
        .expect("HTTP response should parse");

        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, r#"{"ok":true}"#);
    }
}
