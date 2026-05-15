//! TLB-backed Rust types for Cocoon smart contracts.
//!
//! The types in this crate describe on-chain cells and message bodies. Keep
//! network access and business logic in higher-level crates.
//! Source of truth: `cocoon-contracts/contracts/*.fc` and
//! `cocoon-contracts/contracts_tolk/*.tolk`.

pub mod client;
pub mod root;
pub mod wallet;

pub use client::{
    CocoonClientConstData, CocoonClientContractData, CocoonClientControlAction,
    CocoonClientControlBody, OWNER_CLIENT_REQUEST_REFUND, OWNER_CLIENT_WITHDRAW,
};
pub use root::{CocoonProxyInfo, CocoonRootData, CocoonRootStorage, EmptyDictValue};
pub use wallet::{
    COCOON_WALLET_CODE_BOC_HEX, CocoonWalletData, CocoonWalletUnsignedBody, cocoon_wallet_code,
    cocoon_wallet_init_data_cell, cocoon_wallet_signed_body, cocoon_wallet_state_init,
};
