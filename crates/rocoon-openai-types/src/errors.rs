//! Types for OpenAI-compatible error responses.

use async_openai::error::{ApiError, WrappedError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ErrorResponse(WrappedError);

#[must_use]
pub fn make_response(message: impl Into<String>, r#type: impl Into<String>) -> ErrorResponse {
    ErrorResponse(WrappedError {
        error: ApiError {
            message: message.into(),
            r#type: Some(r#type.into()),
            param: None,
            code: None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_response_builds_openai_error() {
        let response = make_response("not found", "invalid_request_error");
        let response = serde_json::to_value(response).expect("error response should serialize");

        assert_eq!(response["error"]["message"], "not found");
        assert_eq!(response["error"]["type"], "invalid_request_error");
        assert!(response["error"]["param"].is_null());
        assert!(response["error"]["code"].is_null());
    }
}
