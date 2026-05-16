use serde::Serialize;

use crate::http::Json;

/// Local health-check response.
#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}

/// Handles `GET /health`.
pub const fn handle() -> Json<HealthResponse> {
    Json::ok(HealthResponse { status: "ok" })
}
