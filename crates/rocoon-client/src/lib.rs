//! Reusable Cocoon proxy client.
//!
//! This crate owns the high-level client stack used by the `rocoon` binary:
//! Cocoon proxy authorization, model discovery, and completion requests. Lower
//! transport details live in `rocoon-transport`.

mod client;
pub mod config;
mod wallet;

pub use client::{
    AuthPaymentStatus, ClientStatus, CocoonClient, HttpExchange, ModelInfo, WorkerInfo,
};
pub use config::RuntimeConfig;
pub use rocoon_transport::{QueryFinalInfo, TokenUsage};
