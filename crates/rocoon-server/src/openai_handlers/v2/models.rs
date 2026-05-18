use crate::http::{HandlerResult, ServerResponse};

/// Handles `GET /v2/models`.
pub fn handle() -> HandlerResult<ServerResponse> {
    super::ok_response()
}
