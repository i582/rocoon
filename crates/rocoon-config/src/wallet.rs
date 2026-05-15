//! Cocoon wallet identity derivation.
//!
//! The C++ client does not send the external owner wallet address in
//! `client.connectToProxy`. It derives a Cocoon wallet smart-contract address
//! from `owner_address` and `node_wallet_key`, then sends that contract address
//! as `client_owner_address`. This module mirrors that derivation with
//! `ton_core` primitives from ton-rs instead of maintaining our own TON
//! cell/BOC/address code.

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use ton::block_tlb::StateInit;
use ton_core::types::TonAddress;

/// Derives the Cocoon wallet address from an already decoded Ed25519 seed.
///
/// # Errors
///
/// Returns an error if the Cocoon wallet state init cannot be built or the TON
/// address cannot be derived from it.
pub fn derive_cocoon_wallet_address_from_seed(
    owner: &TonAddress,
    private_key: &[u8; 32],
) -> Result<String> {
    let state_init = cocoon_wallet_state_init_from_seed(owner, private_key)?;
    let address = state_init
        .derive_address(owner.workchain)
        .context("derive Cocoon wallet address")?;

    Ok(address.to_base64(true, false, true))
}

/// Builds the Cocoon wallet state init from owner address and Ed25519 seed.
///
/// # Errors
///
/// Returns an error if the Cocoon wallet state init cannot be serialized from
/// the owner address and derived public key.
pub fn cocoon_wallet_state_init_from_seed(
    owner: &TonAddress,
    private_key: &[u8; 32],
) -> Result<StateInit> {
    let public_key = SigningKey::from_bytes(private_key)
        .verifying_key()
        .to_bytes();
    rocoon_contract::cocoon_wallet_state_init(owner.clone(), &public_key)
        .context("build Cocoon wallet state init")
}

/// Decodes a base64-encoded 32-byte node wallet key.
///
/// # Errors
///
/// Returns an error if the value is not valid standard or URL-safe base64, or
/// if it does not decode to exactly 32 bytes.
pub fn decode_node_wallet_key(value: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim();
    let decoded = STANDARD
        .decode(trimmed)
        .or_else(|_| STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| URL_SAFE.decode(trimmed))
        .or_else(|_| URL_SAFE_NO_PAD.decode(trimmed))
        .context("decode client.node_wallet_key as base64")?;

    decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            "client.node_wallet_key must decode to 32 bytes, got {}",
            bytes.len()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn derives_known_cocoon_wallet_address() -> Result<()> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let seed = decode_node_wallet_key("Eeo22fSR51UZHS9xUVwCGj4oIGa2pGGydUDHfG+YcEw=")?;
        let address = derive_cocoon_wallet_address_from_seed(&owner, &seed)?;

        assert_eq!(address, "UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi");
        Ok(())
    }
}
