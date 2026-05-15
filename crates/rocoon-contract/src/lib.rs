//! TLB-backed Rust types for Cocoon smart contracts.
//!
//! The types in this crate describe on-chain cells and message bodies. Keep
//! network access and business logic in higher-level crates.
//! Source of truth: `cocoon-contracts/contracts/*.fc` and
//! `cocoon-contracts/contracts_tolk/*.tolk`.

use std::collections::HashMap;

use ton::block_tlb::StateInit;
use ton::tlb_adapters::{
    DictKeyAdapterTonHash, DictKeyAdapterUint, DictValAdapterTLB, TLBHashMapE,
};
use ton::ton_core::TLB;
use ton::ton_core::cell::{CellBuilder, CellParser, TonCell, TonHash};
use ton::ton_core::errors::TonCoreError;
use ton::ton_core::traits::tlb::TLB;
use ton::ton_core::types::TonAddress;
use ton::ton_core::types::tlb_core::adapters::ConstLen;
use ton::ton_core::types::tlb_core::{TLBCoins, TLBRef};

/// Source representation:
///
/// ```tolk
/// struct (0xda068e78) OwnerClientWithdraw {
///     queryId: uint64
///     sendExcessesTo: address
/// }
/// ```
pub const OWNER_CLIENT_WITHDRAW: u32 = 0xda06_8e78;
/// Source representation:
///
/// ```tolk
/// struct (0xfafa6cc1) OwnerClientRequestRefund {
///     queryId: uint64
///     sendExcessesTo: address
/// }
/// ```
pub const OWNER_CLIENT_REQUEST_REFUND: u32 = 0xfafa_6cc1;
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

/// Control action encoded into a Cocoon client-contract body.
///
/// Source representation:
///
/// ```tolk
/// struct (0xda068e78) OwnerClientWithdraw {
///     queryId: uint64
///     sendExcessesTo: address
/// }
/// struct (0xfafa6cc1) OwnerClientRequestRefund {
///     queryId: uint64
///     sendExcessesTo: address
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CocoonClientControlAction {
    /// Withdraw balance above stake.
    Withdraw,
    /// Ask the contract to close/refund.
    RequestRefund,
}

impl CocoonClientControlAction {
    /// Returns the 32-bit smart-contract opcode.
    #[must_use]
    pub const fn opcode(self) -> u32 {
        match self {
            Self::Withdraw => OWNER_CLIENT_WITHDRAW,
            Self::RequestRefund => OWNER_CLIENT_REQUEST_REFUND,
        }
    }
}

/// Body forwarded from the Cocoon wallet into the client contract.
///
/// Source representation:
///
/// ```tolk
/// struct (0xda068e78) OwnerClientWithdraw {
///     queryId: uint64
///     sendExcessesTo: address
/// }
/// struct (0xfafa6cc1) OwnerClientRequestRefund {
///     queryId: uint64
///     sendExcessesTo: address
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, TLB)]
pub struct CocoonClientControlBody {
    /// Smart-contract opcode.
    #[tlb(bits_len = 32)]
    pub opcode: u32,
    /// Query id used by the sender for tracking.
    #[tlb(bits_len = 64)]
    pub query_id: u64,
    /// Source field: `sendExcessesTo`; caller passes the Cocoon wallet address.
    pub wallet_address: TonAddress,
}

impl CocoonClientControlBody {
    /// Builds a control body from an action.
    #[must_use]
    pub const fn new(
        action: CocoonClientControlAction,
        query_id: u64,
        wallet_address: TonAddress,
    ) -> Self {
        Self {
            opcode: action.opcode(),
            query_id,
            wallet_address,
        }
    }
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

/// Data cell stored by the Cocoon client contract.
///
/// Source representation:
///
/// ```tolk
/// struct ClientStorage {
///     state: uint2
///     balance: coins
///     stake: coins
///     tokensUsed: uint64
///     unlockTs: uint32
///     secretHash: uint256
///     constDataRef: Cell<ClientConstData>
///     params: Cell<CocoonParams>
/// }
/// ```
///
/// `contracts/utils.fc` stores the same layout as:
///
/// ```func
/// store_uint(state, 2)
/// store_coins(balance)
/// store_coins(stake)
/// store_uint(tokens_used, 64)
/// store_uint(unlock_ts, 32)
/// store_uint(secret_hash, 256)
/// store_ref(const_data)
/// store_ref(params)
/// ```
#[derive(Clone, Debug, Eq, PartialEq, TLB)]
pub struct CocoonClientContractData {
    /// Raw contract state: 0 running, 1 closing, 2 closed.
    #[tlb(bits_len = 2)]
    pub state: u8,
    /// Request balance.
    pub balance: TLBCoins,
    /// Locked stake.
    pub stake: TLBCoins,
    /// Tokens used by this client contract.
    #[tlb(bits_len = 64)]
    pub tokens_used: u64,
    /// Refund unlock timestamp.
    #[tlb(bits_len = 32)]
    pub unlock_ts: u32,
    /// Client secret hash.
    pub secret_hash: TonHash,
    /// Immutable owner/proxy data stored as a ref.
    pub const_data: TLBRef<CocoonClientConstData>,
    /// Current Cocoon params cell.
    pub params: TLBRef<TonCell>,
}

/// Constant data ref stored by the Cocoon client contract.
///
/// Source representation:
///
/// ```tolk
/// struct ClientConstData {
///     ownerAddress: address
///     proxyAddress: address
///     proxyPublicKey: uint256
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, TLB)]
pub struct CocoonClientConstData {
    /// Client owner wallet address.
    pub owner_address: TonAddress,
    /// Proxy contract address.
    pub proxy_address: TonAddress,
    /// Proxy Ed25519 public key.
    pub proxy_public_key: TonHash,
}

/// Storage cell for `cocoon_root.fc`.
///
/// Source representation:
///
/// ```tolk
/// struct RootStorage {
///     ownerAddress: address
///     version: uint32
///     data: Cell<RootData>
///     params: Cell<CocoonParams>
/// }
/// ```
///
/// `contracts/utils.fc` version 4 additionally stores:
///
/// ```func
/// public_keys_manager_data: ref cell
/// ```
#[derive(Clone, Debug, Eq, PartialEq, TLB)]
pub struct CocoonRootStorage {
    /// Root contract owner address.
    pub owner_address: TonAddress,
    /// Root contract storage version.
    #[tlb(bits_len = 32)]
    pub version: u32,
    /// Root contract mutable dictionaries and counters.
    pub data: TLBRef<CocoonRootData>,
    /// Current Cocoon params cell.
    pub params: TLBRef<TonCell>,
    /// Public key manager data cell.
    pub public_keys_manager_data: TLBRef<TonCell>,
}

/// Data ref stored inside [`CocoonRootStorage`].
///
/// Source representation:
///
/// ```tolk
/// struct RootData {
///     proxyHashes: dict
///     registeredProxies: dict
///     lastProxySeqno: uint32
///     workerHashes: dict
///     modelHashes: dict
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq, TLB)]
#[allow(clippy::zero_sized_map_values)]
pub struct CocoonRootData {
    /// Allowed proxy image hashes. The contract stores this dict as a set.
    #[tlb(adapter = "TLBHashMapE::<DictKeyAdapterTonHash, DictValAdapterTLB<_>>::new(256)")]
    pub proxy_hashes: HashMap<TonHash, EmptyDictValue>,
    /// Registered proxy network addresses by registration seqno.
    #[tlb(adapter = "TLBHashMapE::<DictKeyAdapterUint<u32>, DictValAdapterTLB<_>>::new(32)")]
    pub registered_proxies: HashMap<u32, CocoonProxyInfo>,
    /// Last allocated proxy registration seqno.
    #[tlb(bits_len = 32)]
    pub last_proxy_seqno: u32,
    /// Allowed worker image hashes. The contract stores this dict as a set.
    #[tlb(adapter = "TLBHashMapE::<DictKeyAdapterTonHash, DictValAdapterTLB<_>>::new(256)")]
    pub worker_hashes: HashMap<TonHash, EmptyDictValue>,
    /// Allowed model image hashes. The contract stores this dict as a set.
    #[tlb(adapter = "TLBHashMapE::<DictKeyAdapterTonHash, DictValAdapterTLB<_>>::new(256)")]
    pub model_hashes: HashMap<TonHash, EmptyDictValue>,
}

/// Empty dictionary value used by contract dictionaries that act as sets.
///
/// Source representation:
///
/// ```func
/// proxy_hashes~udict_set(256, proxy_hash, "");
/// worker_hashes~udict_set(256, worker_hash, "");
/// model_hashes~udict_set(256, model_hash, "");
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmptyDictValue;

impl TLB for EmptyDictValue {
    fn read_definition(parser: &mut CellParser) -> Result<Self, TonCoreError> {
        let bits_left = parser.data_bits_left()?;
        let refs_left = parser.refs_left();
        if bits_left != 0 || refs_left != 0 {
            return Err(TonCoreError::Custom(format!(
                "expected empty Cocoon dict value, got {bits_left} bits and {refs_left} refs"
            )));
        }
        Ok(Self)
    }

    fn write_definition(&self, _builder: &mut CellBuilder) -> Result<(), TonCoreError> {
        Ok(())
    }
}

/// Network address value stored in the root contract registered proxy dict.
///
/// Source representation:
///
/// ```func
/// store_uint(0, 1)
/// store_uint(byte_len, 7)
/// store_slice(net_addr_bytes)
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CocoonProxyInfo {
    /// Raw proxy address string stored by the contract.
    pub address: String,
}

impl TLB for CocoonProxyInfo {
    fn read_definition(parser: &mut CellParser) -> Result<Self, TonCoreError> {
        if parser.read_bit()? {
            return Err(TonCoreError::Custom(
                "unsupported Cocoon proxy address tag".to_string(),
            ));
        }
        let len = parser.read_num::<u8>(7)? as usize;
        let bytes = parser.read_bits(len * 8)?;
        let bits_left = parser.data_bits_left()?;
        let refs_left = parser.refs_left();
        if bits_left != 0 || refs_left != 0 {
            return Err(TonCoreError::Custom(format!(
                "expected end of Cocoon proxy info, got {bits_left} bits and {refs_left} refs"
            )));
        }
        let address = String::from_utf8(bytes)?;
        Ok(Self { address })
    }

    fn write_definition(&self, builder: &mut CellBuilder) -> Result<(), TonCoreError> {
        let bytes = self.address.as_bytes();
        let len = u8::try_from(bytes.len())
            .map_err(|_| TonCoreError::Custom("Cocoon proxy address is too long".to_string()))?;
        if len > 127 {
            return Err(TonCoreError::Custom(
                "Cocoon proxy address is too long".to_string(),
            ));
        }
        builder.write_bit(false)?;
        builder.write_num(&len, 7)?;
        builder.write_bits(bytes, bytes.len() * 8)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CocoonClientConstData, CocoonClientContractData, CocoonClientControlAction,
        CocoonClientControlBody, CocoonProxyInfo, CocoonRootData, CocoonRootStorage,
        CocoonWalletData, CocoonWalletUnsignedBody, EmptyDictValue, OWNER_CLIENT_WITHDRAW,
        cocoon_wallet_signed_body, cocoon_wallet_state_init,
    };
    use std::collections::HashMap;
    use std::str::FromStr;
    use ton::ton_core::cell::{TonCell, TonHash};
    use ton::ton_core::traits::tlb::TLB;
    use ton::ton_core::types::TonAddress;
    use ton::ton_core::types::tlb_core::TLBCoins;

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
    fn client_contract_data_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let proxy = TonAddress::from_str("UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi")?;
        let data = CocoonClientContractData {
            state: 1,
            balance: TLBCoins::new(100),
            stake: TLBCoins::new(40),
            tokens_used: 17,
            unlock_ts: 123,
            secret_hash: TonHash::from_slice(&[3_u8; 32])?,
            const_data: CocoonClientConstData {
                owner_address: owner.clone(),
                proxy_address: proxy,
                proxy_public_key: TonHash::from_slice(&[4_u8; 32])?,
            }
            .into(),
            params: TonCell::empty().to_owned().into(),
        };
        let cell = data.to_cell()?;
        let parsed = CocoonClientContractData::from_cell(&cell)?;

        assert_eq!(parsed, data);
        assert_eq!(parsed.balance.to_u64()?, 100);
        assert_eq!(parsed.stake.to_u64()?, 40);
        assert_eq!(parsed.const_data.owner_address, owner);
        Ok(())
    }

    #[test]
    fn client_control_body_starts_with_opcode_and_query_id()
    -> Result<(), Box<dyn std::error::Error>> {
        let wallet = TonAddress::from_str("UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi")?;
        let body = CocoonClientControlBody::new(CocoonClientControlAction::Withdraw, 42, wallet);
        let cell = body.to_cell()?;
        let mut parser = cell.parser();

        assert_eq!(parser.read_num::<u32>(32)?, OWNER_CLIENT_WITHDRAW);
        assert_eq!(parser.read_num::<u64>(64)?, 42);
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

    #[test]
    #[allow(clippy::zero_sized_map_values)]
    fn root_storage_round_trips_registered_proxy_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let proxy_hash = TonHash::from_slice(&[7_u8; 32])?;
        let registered_proxies = HashMap::from([
            (
                2_u32,
                CocoonProxyInfo {
                    address: " worker.example:1000   client.example:2000 ".to_string(),
                },
            ),
            (
                1_u32,
                CocoonProxyInfo {
                    address: "single.example:3000".to_string(),
                },
            ),
        ]);
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let storage = CocoonRootStorage {
            owner_address: owner.clone(),
            version: 7,
            data: CocoonRootData {
                proxy_hashes: HashMap::from([(proxy_hash.clone(), EmptyDictValue)]),
                registered_proxies,
                last_proxy_seqno: 2,
                worker_hashes: HashMap::new(),
                model_hashes: HashMap::new(),
            }
            .into(),
            params: TonCell::empty().to_owned().into(),
            public_keys_manager_data: TonCell::empty().to_owned().into(),
        };
        let cell = storage.to_cell()?;

        let parsed = CocoonRootStorage::from_cell(&cell)?;
        assert_eq!(parsed.owner_address, owner);
        assert_eq!(parsed.version, 7);
        assert_eq!(parsed.data.last_proxy_seqno, 2);
        assert!(parsed.data.proxy_hashes.contains_key(&proxy_hash));
        assert_eq!(
            parsed.data.registered_proxies[&1].address,
            "single.example:3000"
        );
        assert_eq!(
            parsed.data.registered_proxies[&2].address,
            " worker.example:1000   client.example:2000 "
        );
        Ok(())
    }
}
