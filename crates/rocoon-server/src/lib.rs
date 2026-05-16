//! Local OpenAI-compatible HTTP server.
//!
//! The server is deliberately small and synchronous: `tiny_http` accepts and
//! parses localhost HTTP requests, this crate routes the supported endpoints
//! into `CocoonClient` calls, and a mutex keeps the single Cocoon session from
//! interleaving bytes on the proxy connection.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use rocoon_client::CocoonClient;
use rocoon_openai::errors as openai_errors;
use tiny_http::{Method, Request};

mod handlers;
mod http;
mod stats;

use http::{Error as HttpError, ServerResponse, json_response, read_body, split_path_query};
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
/// `/v1/models`, `/v1/chat/completions`, and `/v1/completions`. Each request is
/// handled on a separate thread while access to the underlying Cocoon client
/// remains serialized.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or an incoming TCP connection
/// cannot be accepted. Per-request failures are converted to JSON HTTP errors
/// and do not stop the listener.
pub fn serve(listen_addr: &str, client: CocoonClient, defaults: Defaults) -> Result<()> {
    let server = tiny_http::Server::http(listen_addr)
        .map_err(|error| anyhow::anyhow!("bind {listen_addr}: {error}"))?;
    println!("OpenAI-compatible HTTP server listening on http://{listen_addr}");

    let state = Arc::new(ServerState {
        client: Mutex::new(client),
        stats: Mutex::new(ServerStats::default()),
    });
    spawn_maintenance_thread(Arc::clone(&state));
    loop {
        let request = server.recv().context("accept HTTP request")?;
        let state = Arc::clone(&state);
        thread::spawn(move || {
            handle_request(request, &state, defaults);
        });
    }
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

/// Handles one accepted HTTP request.
fn handle_request(mut request: Request, state: &ServerState, defaults: Defaults) {
    let response = route_request(&mut request, state, defaults).unwrap_or_else(|error| {
        eprintln!("HTTP request failed: {error:#}");
        error_response(error)
    });
    if let Err(error) = request.respond(response) {
        eprintln!("HTTP response failed: {error}");
    }
}

fn route_request(
    request: &mut Request,
    state: &ServerState,
    defaults: Defaults,
) -> std::result::Result<ServerResponse, HttpError> {
    let method = request.method().clone();
    let path = split_path_query(request.url()).0.to_string();

    match (method, path.as_str()) {
        (Method::Get, "/health") => handlers::health::handle(),
        (Method::Get, "/stats" | "/jsonstats" | "/v1/stats") => handlers::stats::handle(state),
        (Method::Get, "/v1/models") => handlers::models::handle(state),
        (Method::Post, "/v1/chat/completions" | "/v1/completions") => {
            let body = read_body(request).map_err(|error| HttpError::new(400, &error))?;
            handlers::completions::handle(state, defaults, &path, &body)
        }
        _ => json_response(
            404,
            &openai_errors::make_response("not found", "invalid_request_error"),
            Vec::new(),
        )
        .map_err(|error| HttpError::new(500, &error)),
    }
}

fn error_response(error: HttpError) -> ServerResponse {
    let body = openai_errors::make_response(error.message, "rocoon_error");
    json_response(error.status_code, &body, Vec::new()).unwrap_or_else(|error| {
        eprintln!("HTTP error response failed: {error:#}");
        tiny_http::Response::from_string("internal server error")
            .with_status_code(tiny_http::StatusCode(500))
    })
}
