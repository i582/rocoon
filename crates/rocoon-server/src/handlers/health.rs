use std::net::TcpStream;

use serde::Serialize;

use crate::http::{Error as HttpError, write_json};

/// Local health-check response.
#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Handles `GET /health`.
pub fn handle(stream: &mut TcpStream) -> std::result::Result<(), HttpError> {
    write_json(stream, 200, &HealthResponse { status: "ok" }, Vec::new())
        .map_err(|error| HttpError::new(None, 500, &error))
}
