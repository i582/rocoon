use std::net::TcpStream;

use crate::ServerState;
use crate::http::{Error as HttpError, write_json};

/// Handles `GET /stats`, `GET /jsonstats`, and `GET /v1/stats`.
pub fn handle(stream: &mut TcpStream, state: &ServerState) -> std::result::Result<(), HttpError> {
    let client_status = state
        .client
        .lock()
        .map_err(|_| {
            HttpError::message(stream.try_clone().ok(), 500, "Cocoon client mutex poisoned")
        })?
        .status();
    let stats_response = {
        let server_stats = state.stats.lock().map_err(|_| {
            HttpError::message(stream.try_clone().ok(), 500, "stats mutex poisoned")
        })?;
        server_stats.to_response(&client_status)
    };
    write_json(stream, 200, &stats_response, Vec::new())
        .map_err(|error| HttpError::new(None, 500, &error))
}
