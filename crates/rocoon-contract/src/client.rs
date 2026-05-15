//! TLB-backed types for the Cocoon client contract.

use ton::ton_core::TLB;
use ton::ton_core::cell::{TonCell, TonHash};
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

#[cfg(test)]
mod tests {
    use super::{
        CocoonClientConstData, CocoonClientContractData, CocoonClientControlAction,
        CocoonClientControlBody, OWNER_CLIENT_WITHDRAW,
    };
    use std::str::FromStr;
    use ton::ton_core::cell::{TonCell, TonHash};
    use ton::ton_core::traits::tlb::TLB;
    use ton::ton_core::types::TonAddress;
    use ton::ton_core::types::tlb_core::TLBCoins;

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
}
