//! TLB-backed types and builders for the Cocoon wallet contract.

use ton::block_tlb::StateInit;
use ton::ton_core::TLB;
use ton::ton_core::cell::{TonCell, TonHash};
use ton::ton_core::errors::TonCoreError;
use ton::ton_core::traits::tlb::TLB;
use ton::ton_core::types::TonAddress;
use ton::ton_core::types::tlb_core::TLBRef;
use ton::ton_core::types::tlb_core::adapters::ConstLen;

/// Source contract: `contracts/cocoon_wallet.fc` /
/// `contracts_tolk/cocoon_wallet.tolk`.
pub const COCOON_WALLET_CODE_BOC_HEX: &str = concat!(
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

/// Parses the Cocoon wallet contract code cell.
///
/// Source contract: `contracts/cocoon_wallet.fc` /
/// `contracts_tolk/cocoon_wallet.tolk`.
///
/// # Errors
///
/// Returns an error if the embedded BOC cannot be decoded.
pub fn cocoon_wallet_code() -> Result<TonCell, TonCoreError> {
    TonCell::from_boc_hex(COCOON_WALLET_CODE_BOC_HEX)
}

/// Builds the Cocoon wallet data cell from owner address and public key.
///
/// Source representation:
///
/// ```tolk
/// struct WalletStorage {
///     seqno: uint32
///     subwalletId: uint32
///     publicKey: uint256
///     status: uint32
///     ownerAddress: address
/// }
/// ```
///
/// # Errors
///
/// Returns an error if the public key cannot be encoded as a TON hash or the
/// resulting data cell cannot be built.
pub fn cocoon_wallet_init_data_cell(
    owner_address: TonAddress,
    public_key: &[u8; 32],
) -> Result<TonCell, TonCoreError> {
    CocoonWalletData::from_public_key(owner_address, public_key)?.to_cell()
}

/// Builds Cocoon wallet `StateInit` from owner address and public key.
///
/// Source representation:
///
/// ```tlb
/// StateInit {
///     code: cocoon_wallet_code
///     data: WalletStorage
/// }
/// ```
///
/// # Errors
///
/// Returns an error if the wallet code or data cell cannot be built.
pub fn cocoon_wallet_state_init(
    owner_address: TonAddress,
    public_key: &[u8; 32],
) -> Result<StateInit, TonCoreError> {
    Ok(StateInit::new(
        cocoon_wallet_code()?,
        cocoon_wallet_init_data_cell(owner_address, public_key)?,
    ))
}

/// Builds the signed body accepted by the Cocoon wallet.
///
/// Source representation:
///
/// ```tolk
/// signature: bits512
/// struct ExternalSignedMessage {
///     subwalletId: uint32
///     validUntil: uint32
///     msgSeqno: uint32
///     rest: RemainingBitsAndRefs
/// }
/// ```
///
/// # Errors
///
/// Returns an error if the signature or unsigned body cannot be written into a
/// TON cell.
pub fn cocoon_wallet_signed_body(
    signature: &[u8; 64],
    unsigned_body: &TonCell,
) -> Result<TonCell, TonCoreError> {
    let mut builder = TonCell::builder();
    builder.write_bits(*signature, 512)?;
    builder.write_cell(unsigned_body)?;
    builder.build()
}

/// Data cell stored by the Cocoon wallet contract.
///
/// Source representation:
///
/// ```tolk
/// struct WalletStorage {
///     seqno: uint32
///     subwalletId: uint32
///     publicKey: uint256
///     status: uint32
///     ownerAddress: address
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, TLB)]
pub struct CocoonWalletData {
    /// Wallet seqno.
    #[tlb(bits_len = 32)]
    pub seqno: u32,
    /// Wallet subwallet id.
    #[tlb(bits_len = 32)]
    pub subwallet_id: u32,
    /// Ed25519 public key.
    pub public_key: TonHash,
    /// Wallet status flags.
    #[tlb(bits_len = 32)]
    pub status: u32,
    /// External owner wallet address.
    pub owner_address: TonAddress,
}

impl CocoonWalletData {
    /// Builds initial Cocoon wallet data for a public key.
    ///
    /// # Errors
    ///
    /// Returns an error if `public_key` cannot be represented as a 256-bit TON
    /// hash.
    pub fn from_public_key(
        owner_address: TonAddress,
        public_key: &[u8; 32],
    ) -> Result<Self, TonCoreError> {
        Ok(Self {
            seqno: 0,
            subwallet_id: 0,
            public_key: TonHash::from_slice(public_key)?,
            status: 0,
            owner_address,
        })
    }
}

/// Unsigned body signed by the Cocoon wallet owner key.
///
/// Source representation:
///
/// ```tolk
/// struct ExternalSignedMessage {
///     subwalletId: uint32
///     validUntil: uint32
///     msgSeqno: uint32
///     rest: RemainingBitsAndRefs
/// }
///
/// rest := repeated {
///     mode: uint8
///     message: ref cell
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, TLB)]
pub struct CocoonWalletUnsignedBody {
    /// Wallet subwallet id.
    #[tlb(bits_len = 32)]
    pub subwallet_id: u32,
    /// Unix timestamp until which this external message is valid.
    #[tlb(bits_len = 32)]
    pub valid_until: u32,
    /// Wallet seqno.
    #[tlb(bits_len = 32)]
    pub seqno: u32,
    /// Wallet send mode.
    #[tlb(bits_len = 8)]
    pub send_mode: u8,
    /// Internal message cell forwarded by the wallet.
    pub internal_message: TLBRef<TonCell>,
}

#[cfg(test)]
mod tests {
    use super::{
        CocoonWalletData, CocoonWalletUnsignedBody, cocoon_wallet_signed_body,
        cocoon_wallet_state_init,
    };
    use std::str::FromStr;
    use ton::ton_core::cell::TonCell;
    use ton::ton_core::traits::tlb::TLB;
    use ton::ton_core::types::TonAddress;

    #[test]
    fn wallet_data_round_trips_and_seqno_is_first_u32() -> Result<(), Box<dyn std::error::Error>> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let data = CocoonWalletData::from_public_key(owner.clone(), &[9_u8; 32])?;
        let cell = data.to_cell()?;
        let mut parser = cell.parser();

        assert_eq!(parser.read_num::<u32>(32)?, 0);
        assert_eq!(CocoonWalletData::from_cell(&cell)?, data);
        assert_eq!(data.owner_address, owner);
        Ok(())
    }

    #[test]
    fn wallet_unsigned_body_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let message = TonCell::empty().to_owned();
        let body = CocoonWalletUnsignedBody {
            subwallet_id: 0,
            valid_until: 1000,
            seqno: 7,
            send_mode: 0,
            internal_message: message.into(),
        };
        let cell = body.to_cell()?;
        let parsed = CocoonWalletUnsignedBody::from_cell(&cell)?;

        assert_eq!(parsed.valid_until, 1000);
        assert_eq!(parsed.seqno, 7);
        assert_eq!(parsed.send_mode, 0);
        Ok(())
    }

    #[test]
    fn wallet_signed_body_writes_signature_and_unsigned_body()
    -> Result<(), Box<dyn std::error::Error>> {
        let unsigned = CocoonWalletUnsignedBody {
            subwallet_id: 0,
            valid_until: 1000,
            seqno: 7,
            send_mode: 0,
            internal_message: TonCell::empty().to_owned().into(),
        }
        .to_cell()?;
        let signature = [9_u8; 64];
        let signed = cocoon_wallet_signed_body(&signature, &unsigned)?;
        let mut parser = signed.parser();

        assert_eq!(parser.read_bits(512)?, signature);
        assert_eq!(parser.read_remaining()?, unsigned);
        Ok(())
    }

    #[test]
    fn wallet_state_init_derives_known_cocoon_wallet_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let public_key = [
            76, 1, 240, 59, 22, 253, 249, 228, 158, 216, 240, 20, 32, 9, 161, 62, 188, 214, 132,
            171, 51, 159, 31, 60, 141, 144, 73, 101, 46, 214, 81, 191,
        ];
        let state_init = cocoon_wallet_state_init(owner.clone(), &public_key)?;
        let address = state_init.derive_address(owner.workchain)?;

        assert_eq!(
            address.to_base64(true, false, true),
            "UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi"
        );
        Ok(())
    }
}
