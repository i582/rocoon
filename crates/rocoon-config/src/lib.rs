//! Shared runtime configuration and terminal formatting helpers.
//!
//! The binary owns CLI parsing, while this crate owns the validated
//! configuration shape, Cocoon wallet identity derivation, and the color-mode
//! behavior shared with command-line output.

pub mod color;
mod config;
pub mod wallet;

pub use config::{LocalHttpRuntimeConfig, NodeWalletKey, RuntimeConfig, TonRuntimeConfig};
