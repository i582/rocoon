use crate::http::{HandlerResult, ServerResponse};

/// Handles `POST /v2/chat/completions`.
pub fn handle() -> HandlerResult<ServerResponse> {
    super::ok_response()
}
