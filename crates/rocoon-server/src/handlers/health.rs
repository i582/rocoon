use serde::Serialize;

use crate::http::{Error as HttpError, ServerResponse, json_response};

/// Local health-check response.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Handles `GET /health`.
pub fn handle() -> std::result::Result<ServerResponse, HttpError> {
    json_response(200, &HealthResponse { status: "ok" }, Vec::new())
        .map_err(|error| HttpError::new(500, &error))
}
