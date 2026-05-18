pub mod chat_completions;
pub mod completions;
pub mod models;

use tiny_http::StatusCode;

use crate::http::{HandlerResult, ServerResponse, internal, response_with_body};

fn ok_response() -> HandlerResult<ServerResponse> {
    response_with_body(
        StatusCode(200),
        vec![("Content-Type".to_string(), "text/plain".to_string())],
        b"OK".to_vec(),
    )
    .map_err(internal)
}
