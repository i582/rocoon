//! OpenAI-compatible request and response types.
//!
//! This crate intentionally contains no HTTP client or bridge logic. It only
//! exposes typed request/response structures for code that wants to implement
//! OpenAI-compatible behavior itself.

pub mod chat_completion_stream;
pub mod chat_completions;
pub mod errors;
pub mod models;

mod request;

pub use chat_completions::{ChatCompletionRequest, ChatCompletionResponse};
pub use errors::ErrorResponse;
pub use models::{ListModelResponse, Model};
