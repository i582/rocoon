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
use ton_core::cell::TonCell;
use ton_core::traits::tlb::TLB;
use ton_core::types::TonAddress;

const COCOON_WALLET_CODE_BOC_HEX: &str = concat!(
    "b5ee9c724102110100024b000114ff00f4a413f4bcf2c80b010201200210020148030b0202ca040a020120050701f5d3b68bb7edb088831c",
    "02456f8007434c0c05c6c2456f83e900c0074c7c86084095964d32e88a08431669f34eeac48a084268491f02eac6497c0f83b513434c7f4c",
    "7f4fff4c7fe903454dc31c17cb90409a084271a7cddaea78415d7c1f4cfcc74c1f50c007ec03801b0003cb9044134c1f448301dc8701880b",
    "01d60600ea5312b121b1f2e411018e295f07820898968072fb0280777080185410337003c8cb0558cf1601fa02cb6a12cb1fcb07c98306fb",
    "00e0378e19350271b101c8cb1f12cb1f13cbff12cb1f01cf16c9ed54db31e0058e1d028210fffffffeb001c8cb1f12cb1f13cbff12cb1f01",
    "cf16c9ed54db31e05f05020276080900691cf232c1c044440072c7c7b2c7c732c01402be8094023e8085b2c7c532c7c4b2c7f2c7f2c7f2c7",
    "c07e80807e80bd003d003d00326000553434c1c07000fcb8fc34c7f4c7f4c03e803e8034c7f4c7f4c7f4c7f4c7f4c7fe803e803d013d013d",
    "010c200049a9f21402b3c5940233c585b2fff2413232c05400fe80807e80b2cfc4b2c7c4b2fff33332600201200c0f0201200d0e0017bb39",
    "ced44d0d33f31d70bff80011b8c97ed44d0d70b1f8001bbdfddf6a2684080b06b90fd2018400e0f28308d71820d31fd31fd31f02f823bbf2",
    "d406ed44d0d31fd31fd3ffd31ffa40d12171b0f2d4075154baf2e4085162baf2e40906f901541076f910f2e40af8276f2230821077359400",
    "b9f2d40bf800029320d74a96d307d402fb00e83001a4c8cb1f14cb1f12cbffcb1f01cf16c9ed545d2b2126"
);

/// Derives the Cocoon wallet address from an already decoded Ed25519 seed.
pub fn derive_cocoon_wallet_address_from_seed(
    owner: &TonAddress,
    private_key: &[u8; 32],
) -> Result<String> {
    let code = cocoon_wallet_code()?;
    let data = cocoon_wallet_init_data_from_seed(owner, private_key)?;
    let address =
        derive_address(code, data, owner.workchain).context("derive Cocoon wallet address")?;

    Ok(address.to_base64(true, false, true))
}

/// Returns the Cocoon wallet code cell used by the C++ client.
pub fn cocoon_wallet_code() -> Result<TonCell> {
    TonCell::from_boc_hex(COCOON_WALLET_CODE_BOC_HEX).context("parse Cocoon wallet code BOC")
}

/// Builds the Cocoon wallet data cell from owner address and Ed25519 seed.
pub fn cocoon_wallet_init_data_from_seed(
    owner: &TonAddress,
    private_key: &[u8; 32],
) -> Result<TonCell> {
    let public_key = SigningKey::from_bytes(private_key)
        .verifying_key()
        .to_bytes();
    cocoon_wallet_init_data(owner, &public_key)
}

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

fn cocoon_wallet_init_data(owner: &TonAddress, public_key: &[u8; 32]) -> Result<TonCell> {
    let mut builder = TonCell::builder();
    builder.write_num(&0u32, 32)?;
    builder.write_num(&0u32, 32)?;
    builder.write_bits(public_key, 256)?;
    builder.write_num(&0u32, 32)?;
    owner.to_msg_address_int().write(&mut builder)?;
    builder
        .build()
        .context("build Cocoon wallet init data cell")
}

fn derive_address(code: TonCell, data: TonCell, workchain: i32) -> Result<TonAddress> {
    let mut builder = TonCell::builder();
    builder.write_num(&0u8, 2)?;
    builder.write_num(&3u8, 2)?;
    builder.write_ref(code)?;
    builder.write_ref(data)?;
    builder.write_bit(false)?;
    let state_init = builder.build().context("build StateInit cell")?;
    Ok(TonAddress::new(workchain, state_init.hash()?.clone()))
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
