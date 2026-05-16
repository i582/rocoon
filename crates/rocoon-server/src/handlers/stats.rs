use crate::ServerState;
use crate::http::{Error as HttpError, ServerResponse, json_response};

/// Handles `GET /stats`, `GET /jsonstats`, and `GET /v1/stats`.
pub fn handle(state: &ServerState) -> std::result::Result<ServerResponse, HttpError> {
    let client_status = state
        .client
        .lock()
        .map_err(|_| HttpError::message(500, "Cocoon client mutex poisoned"))?
        .status();
    let stats_response = {
        let server_stats = state
            .stats
            .lock()
            .map_err(|_| HttpError::message(500, "stats mutex poisoned"))?;
        server_stats.to_response(&client_status)
    };
    json_response(200, &stats_response, Vec::new()).map_err(|error| HttpError::new(500, &error))
}
