//! Local OpenAI-compatible HTTP server.
//!
//! The server is deliberately small and synchronous: it accepts localhost HTTP
//! requests, translates the supported endpoints into `CocoonClient` calls, and
//! writes OpenAI-compatible responses. A single Cocoon session is protected by
//! a mutex so requests do not interleave bytes on the proxy connection.

use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use rocoon_client::CocoonClient;
use rocoon_openai::errors as openai_errors;

mod handlers;
mod http;
mod stats;

use http::{Error as HttpError, read_request, split_path_query, write_json};
use stats::ServerStats;

const MAINTENANCE_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Default per-request limits used when an HTTP request omits them.
#[derive(Clone, Copy)]
pub struct Defaults {
    /// Default maximum accepted Cocoon worker price coefficient.
    pub max_coefficient: i32,
    /// Default maximum token count.
    pub max_tokens: i32,
    /// Default Cocoon request timeout in seconds.
    pub timeout: f64,
}

/// Shared state for all local HTTP request handler threads.
pub(crate) struct ServerState {
    pub(crate) client: Mutex<CocoonClient>,
    pub(crate) stats: Mutex<ServerStats>,
}

/// Serves the local OpenAI-compatible API forever.
///
/// Supported endpoints are `/health`, `/stats`, `/jsonstats`, `/v1/stats`,
/// `/v1/models`, `/v1/chat/completions`, and `/v1/completions`. Each accepted
/// TCP connection is handled on a separate thread while access to the
/// underlying Cocoon client remains serialized.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or an incoming TCP connection
/// cannot be accepted. Per-request failures are converted to JSON HTTP errors
/// and do not stop the listener.
pub fn serve(listen_addr: &str, client: CocoonClient, defaults: Defaults) -> Result<()> {
    let listener = TcpListener::bind(listen_addr).with_context(|| format!("bind {listen_addr}"))?;
    println!("OpenAI-compatible HTTP server listening on http://{listen_addr}");

    let state = Arc::new(ServerState {
        client: Mutex::new(client),
        stats: Mutex::new(ServerStats::default()),
    });
    spawn_maintenance_thread(Arc::clone(&state));
    for stream in listener.incoming() {
        let stream = stream.context("accept HTTP connection")?;
        let state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(error) = handle_connection(stream, &state, defaults) {
                eprintln!("HTTP request failed: {error:#}");
                let HttpError {
                    stream,
                    status_code,
                    message,
                } = error;
                if let Some(mut stream) = stream {
                    let body = openai_errors::make_response(message, "rocoon_error");
                    let _ = write_json(&mut stream, status_code, &body, Vec::new());
                }
            }
        });
    }
    Ok(())
}

fn spawn_maintenance_thread(state: Arc<ServerState>) {
    thread::spawn(move || {
        loop {
            thread::sleep(MAINTENANCE_TICK_INTERVAL);
            match state.client.lock() {
                Ok(mut client) => client.maintenance_tick(),
                Err(error) => {
                    eprintln!("Cocoon client mutex poisoned in maintenance thread: {error}");
                    return;
                }
            }
        }
    });
}

/// Handles one accepted HTTP connection.
///
/// Errors are represented as `HttpError` so the caller can still write a JSON
/// error response if the socket is usable.
fn handle_connection(
    mut stream: TcpStream,
    state: &ServerState,
    defaults: Defaults,
) -> std::result::Result<(), HttpError> {
    let request = read_request(&mut stream)
        .map_err(|error| HttpError::new(stream.try_clone().ok(), 400, &error))?;
    let (path, _) = split_path_query(&request.path);

    match (request.method.as_str(), path) {
        ("GET", "/health") => handlers::health::handle(&mut stream),
        ("GET", "/stats" | "/jsonstats" | "/v1/stats") => {
            handlers::stats::handle(&mut stream, state)
        }
        ("GET", "/v1/models") => handlers::models::handle(&mut stream, state),
        ("POST", "/v1/chat/completions" | "/v1/completions") => {
            handlers::completions::handle(&mut stream, state, defaults, path, &request.body)
        }
        _ => write_json(
            &mut stream,
            404,
            &openai_errors::make_response("not found", "invalid_request_error"),
            Vec::new(),
        )
        .map_err(|error| HttpError::new(None, 500, &error)),
    }
}
