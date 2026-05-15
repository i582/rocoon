//! Reusable Cocoon proxy client.
//!
//! This crate owns the high-level client stack used by the `rocoon` binary:
//! Cocoon proxy authorization, model discovery, and completion requests. Lower
//! transport details live in `rocoon-transport`.

mod client;
mod ton_readonly;

pub use client::{
    AuthPaymentStatus, ClientContractClosedOrClosing, ClientStatus, CocoonClient, HttpExchange,
    ModelInfo, ProxyHandshakeInfo, WorkerInfo, is_client_contract_closed_or_closing_error,
};
pub use rocoon_config::RuntimeConfig;
pub use rocoon_transport::{QueryFinalInfo, TokenUsage};
pub use ton_readonly::{
    COCOON_WALLET_RESERVE_NANOTONS, ClientContractSnapshot, RegisteredProxySnapshot,
    RootContractSnapshot, TonAccountState, TonControlAction, TonControlResult,
    TonWalletTransferResult,
};
