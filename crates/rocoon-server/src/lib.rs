//! Local OpenAI-compatible HTTP server.
//!
//! The server is deliberately small and synchronous: `tiny_http` accepts and
//! parses localhost HTTP requests, this crate routes the supported endpoints
//! into `CocoonClient` calls, and a mutex keeps the single Cocoon session from
//! interleaving bytes on the proxy connection.

use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rocoon_client::CocoonClient;
use rocoon_openai::errors as openai_errors;
use tiny_http::{Header, Method, Request, Server, StatusCode};

mod handlers;
mod http;
mod openai_handlers;
mod stats;

use http::{
    HandlerError, HandlerResult, Json, ServerResponse, bad_request, finalize, internal,
    internal_message, json_response, read_body, split_path_query,
};
use stats::ServerStats;
pub use stats::SessionSummary;

const MAINTENANCE_TICK_INTERVAL: Duration = Duration::from_secs(1);
const HTTP_ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(200);

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

/// Bound local HTTP listener reserved before proxy authorization starts.
pub struct Listener {
    listen_addr: String,
    server: Server,
}

/// Shared state for all local HTTP request handler threads.
pub(crate) struct ServerState {
    client: Mutex<CocoonClient>,
    stats: Mutex<ServerStats>,
    api_token: Option<String>,
}

impl ServerState {
    pub(crate) fn client(&self) -> HandlerResult<MutexGuard<'_, CocoonClient>> {
        self.client
            .lock()
            .map_err(|_| internal_message("Cocoon client mutex poisoned"))
    }

    pub(crate) fn stats(&self) -> HandlerResult<MutexGuard<'_, ServerStats>> {
        self.stats
            .lock()
            .map_err(|_| internal_message("stats mutex poisoned"))
    }
}

/// Binds the local HTTP listener and reserves the configured port.
///
/// # Errors
///
/// Returns an error if `listen_addr` cannot be bound.
pub fn bind(listen_addr: &str) -> Result<Listener> {
    let server = Server::http(listen_addr)
        .map_err(|error| anyhow::anyhow!("bind {listen_addr}: {error}"))?;
    Ok(Listener {
        listen_addr: listen_addr.to_string(),
        server,
    })
}

/// Serves the local OpenAI-compatible API until shutdown is requested.
///
/// Supported endpoints are `/health`, `/stats`, `/jsonstats`, `/v1/stats`,
/// `/v1/models`, `/v1/chat/completions`, and `/v1/completions`. Each request
/// is handled on a separate thread while access to the underlying Cocoon client
/// remains serialized.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or an incoming TCP connection
/// cannot be accepted. Per-request failures are converted to JSON HTTP errors
/// and do not stop the listener. On graceful shutdown returns a session summary.
pub fn serve(
    listen_addr: &str,
    client: CocoonClient,
    defaults: Defaults,
    api_token: Option<String>,
    shutdown_requested: &Arc<AtomicBool>,
) -> Result<SessionSummary> {
    let listener = bind(listen_addr)?;
    serve_bound(listener, client, defaults, api_token, shutdown_requested)
}

/// Serves the local OpenAI-compatible API using an already-bound listener.
///
/// # Errors
///
/// Returns an error if an incoming TCP connection cannot be accepted.
pub fn serve_bound(
    listener: Listener,
    client: CocoonClient,
    defaults: Defaults,
    api_token: Option<String>,
    shutdown_requested: &Arc<AtomicBool>,
) -> Result<SessionSummary> {
    let Listener {
        listen_addr,
        server,
    } = listener;
    let started_at = Instant::now();
    println!("OpenAI-compatible HTTP server listening on http://{listen_addr}");

    let state = Arc::new(ServerState {
        client: Mutex::new(client),
        stats: Mutex::new(ServerStats::default()),
        api_token: api_token.filter(|token| !token.is_empty()),
    });
    spawn_maintenance_thread(Arc::clone(&state), Arc::clone(shutdown_requested));
    while !shutdown_requested.load(Ordering::SeqCst) {
        let Some(request) = server
            .recv_timeout(HTTP_ACCEPT_POLL_INTERVAL)
            .context("accept HTTP request")?
        else {
            continue;
        };
        let state = Arc::clone(&state);
        thread::spawn(move || {
            handle_request(request, &state, defaults);
        });
    }

    let stats_guard = state
        .stats
        .lock()
        .map_err(|_| anyhow::anyhow!("stats mutex poisoned"))?;
    Ok(stats_guard.session_summary(started_at.elapsed()))
}

fn spawn_maintenance_thread(state: Arc<ServerState>, shutdown_requested: Arc<AtomicBool>) {
    thread::spawn(move || {
        while !shutdown_requested.load(Ordering::SeqCst) {
            thread::sleep(MAINTENANCE_TICK_INTERVAL);
            if shutdown_requested.load(Ordering::SeqCst) {
                break;
            }
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
        log_handler_error(&error);
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
) -> HandlerResult<ServerResponse> {
    let method = request.method().clone();
    let path = split_path_query(request.url()).0.to_string();
    if let Some(response) = unauthorized_response(request.headers(), state.api_token.as_deref())? {
        return Ok(response);
    }

    match (method.clone(), path.as_str()) {
        (Method::Get, "/health") => finalize(Ok(handlers::health::handle())),
        (Method::Get, "/stats" | "/jsonstats" | "/v1/stats") => {
            finalize(handlers::stats::handle(state))
        }
        (Method::Get, "/v1/models") => finalize(openai_handlers::v1::models::handle(state)),
        (Method::Post, "/v1/chat/completions") => {
            let body = read_body(request).map_err(bad_request)?;
            finalize(openai_handlers::v1::chat_completions::handle(
                state, defaults, &body,
            ))
        }
        (Method::Post, "/v1/completions") => {
            let body = read_body(request).map_err(bad_request)?;
            finalize(openai_handlers::v1::completions::handle(
                state, defaults, &body,
            ))
        }

        _ => {
            eprintln!("Unsupported HTTP method or path: {method} {path}");

            finalize(Ok(Json::new(
                tiny_http::StatusCode(404),
                openai_errors::make_response("not found", "invalid_request_error"),
            )))
        }
    }
}

fn unauthorized_response(
    headers: &[Header],
    api_token: Option<&str>,
) -> HandlerResult<Option<ServerResponse>> {
    let Some(api_token) = api_token else {
        return Ok(None);
    };

    if authorization_header_matches(headers, api_token) {
        return Ok(None);
    }

    let body = openai_errors::make_response("missing or invalid API token", "authentication_error");
    json_response(StatusCode(401), &body)
        .map(Some)
        .map_err(internal)
}

fn authorization_header_matches(headers: &[Header], api_token: &str) -> bool {
    let expected = format!("Bearer {api_token}");
    headers
        .iter()
        .any(|header| header.field.equiv("Authorization") && header.value.as_str() == expected)
}

fn log_handler_error((status_code, error): &HandlerError) {
    eprintln!("HTTP request failed ({}): {error:#}", status_code.0);
}

fn error_response((status_code, error): HandlerError) -> ServerResponse {
    let body = openai_errors::make_response(format!("{error:#}"), "rocoon_error");
    json_response(status_code, &body).unwrap_or_else(|error| {
        eprintln!("HTTP error response failed: {error:#}");
        tiny_http::Response::from_string("internal server error")
            .with_status_code(tiny_http::StatusCode(500))
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::authorization_header_matches;
    use tiny_http::Header;

    #[test]
    fn authorization_header_matches_configured_bearer_token() {
        let headers = [Header::from_str("Authorization: Bearer 12345")
            .expect("authorization header should parse")];

        assert!(authorization_header_matches(&headers, "12345"));
    }

    #[test]
    fn authorization_header_name_is_case_insensitive() {
        let headers = [Header::from_str("authorization: Bearer 12345")
            .expect("authorization header should parse")];

        assert!(authorization_header_matches(&headers, "12345"));
    }

    #[test]
    fn authorization_header_rejects_wrong_token() {
        let headers = [Header::from_str("Authorization: Bearer wrong")
            .expect("authorization header should parse")];

        assert!(!authorization_header_matches(&headers, "12345"));
    }
}
