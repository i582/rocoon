//! TLB-backed types for the Cocoon root contract.
//!
//! Sources:
//! - `contracts_tolk/storage.tolk`
//! - `contracts/utils.fc`

use std::collections::HashMap;

use ton::tlb_adapters::{
    DictKeyAdapterTonHash, DictKeyAdapterUint, DictValAdapterTLB, TLBHashMapE,
};
use ton::ton_core::TLB;
use ton::ton_core::cell::{CellBuilder, CellParser, TonCell, TonHash};
use ton::ton_core::errors::TonCoreError;
use ton::ton_core::traits::tlb::TLB;
use ton::ton_core::types::TonAddress;
use ton::ton_core::types::tlb_core::TLBRef;
use ton::ton_core::types::tlb_core::adapters::ConstLen;

/// Storage cell for `cocoon_root.fc`.
///
/// Sources:
/// - `contracts_tolk/storage.tolk`
/// - `contracts/utils.fc`
///
/// Contract layout:
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
/// Additional `contracts/utils.fc` layout:
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
/// Sources:
/// - `contracts_tolk/storage.tolk`
/// - `contracts/utils.fc`
///
/// Contract layout:
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
/// Source: `contracts/utils.fc`.
///
/// Contract layout:
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
/// Source: `contracts/utils.fc`.
///
/// Contract layout:
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
    use super::{CocoonProxyInfo, CocoonRootData, CocoonRootStorage, EmptyDictValue};
    use std::collections::HashMap;
    use std::str::FromStr;
    use ton::ton_core::cell::{TonCell, TonHash};
    use ton::ton_core::traits::tlb::TLB;
    use ton::ton_core::types::TonAddress;

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
