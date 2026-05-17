//! TLB-backed types for the Cocoon proxy contract.
//!
//! Sources:
//! - `contracts_tolk/storage.tolk`
//! - `contracts/utils.fc`

use ton::ton_core::cell::{CellBuilder, CellParser, TonCell};
use ton::ton_core::errors::TonCoreError;
use ton::ton_core::traits::tlb::TLB;
use ton::ton_core::types::tlb_core::TLBCoins;

const COCOON_PARAMS_DEFAULT_MULTIPLIER: u32 = 10_000;
const LEGACY_MIN_STAKE_NANOTONS: u64 = 1_000_000_000;

/// Params cell used by the Cocoon proxy contract and forwarded to child
/// contracts.
///
/// Sources:
/// - `contracts_tolk/storage.tolk`
/// - `contracts/utils.fc`
///
/// Contract layout:
///
/// ```tolk
/// struct CocoonParams {
///     structVersion: uint8
///     paramsVersion: uint32
///     uniqueId: uint32
///     isTest: bool
///     pricePerToken: coins
///     workerFeePerToken: coins
///     promptTokensPriceMultiplier: uint32
///     cachedTokensPriceMultiplier: uint32
///     completionTokensPriceMultiplier: uint32
///     reasoningTokensPriceMultiplier: uint32
///     proxyDelayBeforeClose: uint32
///     clientDelayBeforeClose: uint32
///     minProxyStake: coins
///     minClientStake: coins
///     proxyScCode: cell?
///     workerScCode: cell?
///     clientScCode: cell?
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CocoonParams {
    /// Params layout version.
    pub struct_version: u8,
    /// Mutable params version.
    pub params_version: u32,
    /// Network-specific unique id.
    pub unique_id: u32,
    /// Whether params target a test environment.
    pub is_test: bool,
    /// Price paid by clients per token.
    pub price_per_token: TLBCoins,
    /// Worker fee per token.
    pub worker_fee_per_token: TLBCoins,
    /// Prompt token price multiplier.
    pub prompt_tokens_price_multiplier: u32,
    /// Cached token price multiplier.
    pub cached_tokens_price_multiplier: u32,
    /// Completion token price multiplier.
    pub completion_tokens_price_multiplier: u32,
    /// Reasoning token price multiplier.
    pub reasoning_tokens_price_multiplier: u32,
    /// Proxy close delay, in seconds.
    pub proxy_delay_before_close: u32,
    /// Client close delay, in seconds.
    pub client_delay_before_close: u32,
    /// Minimum proxy stake.
    pub min_proxy_stake: TLBCoins,
    /// Minimum client stake.
    pub min_client_stake: TLBCoins,
    /// Optional proxy smart-contract code.
    pub proxy_sc_code: Option<TonCell>,
    /// Optional worker smart-contract code.
    pub worker_sc_code: Option<TonCell>,
    /// Optional client smart-contract code.
    pub client_sc_code: Option<TonCell>,
}

impl CocoonParams {
    /// Returns the same params with all embedded contract code refs removed.
    ///
    /// This mirrors `CocoonParams.withoutCode()` from
    /// `contracts_tolk/storage.tolk`, which is used when
    /// params are embedded into child contract storage.
    #[must_use]
    pub fn without_code_refs(&self) -> Self {
        let mut params = self.clone();
        params.proxy_sc_code = None;
        params.worker_sc_code = None;
        params.client_sc_code = None;
        params
    }
}

impl TLB for CocoonParams {
    fn read_definition(parser: &mut CellParser) -> Result<Self, TonCoreError> {
        let struct_version = parser.read_num::<u8>(8)?;
        if struct_version > 5 {
            return Err(TonCoreError::Custom(format!(
                "unexpected Cocoon params struct_version: {struct_version}"
            )));
        }

        let params_version = parser.read_num::<u32>(32)?;
        let unique_id = parser.read_num::<u32>(32)?;
        let is_test = parser.read_bit()?;
        let price_per_token = TLBCoins::read(parser)?;
        let worker_fee_per_token = TLBCoins::read(parser)?;
        let prompt_tokens_price_multiplier = if struct_version >= 3 {
            parser.read_num::<u32>(32)?
        } else {
            COCOON_PARAMS_DEFAULT_MULTIPLIER
        };
        let cached_tokens_price_multiplier = if struct_version >= 2 {
            parser.read_num::<u32>(32)?
        } else {
            COCOON_PARAMS_DEFAULT_MULTIPLIER
        };
        let completion_tokens_price_multiplier = if struct_version >= 3 {
            parser.read_num::<u32>(32)?
        } else {
            COCOON_PARAMS_DEFAULT_MULTIPLIER
        };
        let reasoning_tokens_price_multiplier = if struct_version >= 2 {
            parser.read_num::<u32>(32)?
        } else {
            COCOON_PARAMS_DEFAULT_MULTIPLIER
        };
        let proxy_delay_before_close = parser.read_num::<u32>(32)?;
        let client_delay_before_close = parser.read_num::<u32>(32)?;
        let min_proxy_stake = if struct_version >= 1 {
            TLBCoins::read(parser)?
        } else {
            TLBCoins::new(u128::from(LEGACY_MIN_STAKE_NANOTONS))
        };
        let min_client_stake = if struct_version >= 1 {
            TLBCoins::read(parser)?
        } else {
            TLBCoins::new(u128::from(LEGACY_MIN_STAKE_NANOTONS))
        };
        let proxy_sc_code = read_maybe_ref(parser)?;
        let worker_sc_code = read_maybe_ref(parser)?;
        let client_sc_code = read_maybe_ref(parser)?;
        parser.ensure_empty()?;

        Ok(Self {
            struct_version,
            params_version,
            unique_id,
            is_test,
            price_per_token,
            worker_fee_per_token,
            prompt_tokens_price_multiplier,
            cached_tokens_price_multiplier,
            completion_tokens_price_multiplier,
            reasoning_tokens_price_multiplier,
            proxy_delay_before_close,
            client_delay_before_close,
            min_proxy_stake,
            min_client_stake,
            proxy_sc_code,
            worker_sc_code,
            client_sc_code,
        })
    }

    fn write_definition(&self, builder: &mut CellBuilder) -> Result<(), TonCoreError> {
        if self.struct_version > 5 {
            return Err(TonCoreError::Custom(format!(
                "unexpected Cocoon params struct_version: {}",
                self.struct_version
            )));
        }

        builder.write_num(&self.struct_version, 8)?;
        builder.write_num(&self.params_version, 32)?;
        builder.write_num(&self.unique_id, 32)?;
        builder.write_bit(self.is_test)?;
        self.price_per_token.write(builder)?;
        self.worker_fee_per_token.write(builder)?;
        if self.struct_version >= 2 {
            if self.struct_version >= 3 {
                builder.write_num(&self.prompt_tokens_price_multiplier, 32)?;
            }
            builder.write_num(&self.cached_tokens_price_multiplier, 32)?;
            if self.struct_version >= 3 {
                builder.write_num(&self.completion_tokens_price_multiplier, 32)?;
            }
            builder.write_num(&self.reasoning_tokens_price_multiplier, 32)?;
        }
        builder.write_num(&self.proxy_delay_before_close, 32)?;
        builder.write_num(&self.client_delay_before_close, 32)?;
        if self.struct_version >= 1 {
            self.min_proxy_stake.write(builder)?;
            self.min_client_stake.write(builder)?;
        }
        write_maybe_ref(builder, self.proxy_sc_code.as_ref())?;
        write_maybe_ref(builder, self.worker_sc_code.as_ref())?;
        write_maybe_ref(builder, self.client_sc_code.as_ref())
    }
}

fn read_maybe_ref(parser: &mut CellParser<'_>) -> Result<Option<TonCell>, TonCoreError> {
    if parser.read_bit()? {
        Ok(Some(parser.read_next_ref()?.clone()))
    } else {
        Ok(None)
    }
}

fn write_maybe_ref(builder: &mut CellBuilder, cell: Option<&TonCell>) -> Result<(), TonCoreError> {
    match cell {
        Some(cell) => {
            builder.write_bit(true)?;
            builder.write_ref(cell.clone())
        }
        None => builder.write_bit(false),
    }
}

#[cfg(test)]
mod tests {
    use super::CocoonParams;
    use ton::ton_core::cell::TonCell;
    use ton::ton_core::traits::tlb::TLB;
    use ton::ton_core::types::tlb_core::TLBCoins;

    #[test]
    fn cocoon_params_round_trips_and_drops_code_refs() -> Result<(), Box<dyn std::error::Error>> {
        let code = TonCell::empty().to_owned();
        let params = CocoonParams {
            struct_version: 4,
            params_version: 7,
            unique_id: 11,
            is_test: true,
            price_per_token: TLBCoins::new(100),
            worker_fee_per_token: TLBCoins::new(40),
            prompt_tokens_price_multiplier: 12_000,
            cached_tokens_price_multiplier: 8_000,
            completion_tokens_price_multiplier: 13_000,
            reasoning_tokens_price_multiplier: 14_000,
            proxy_delay_before_close: 30,
            client_delay_before_close: 40,
            min_proxy_stake: TLBCoins::new(1_000),
            min_client_stake: TLBCoins::new(2_000),
            proxy_sc_code: Some(code.clone()),
            worker_sc_code: None,
            client_sc_code: Some(code),
        };

        let parsed = CocoonParams::from_cell(&params.to_cell()?)?;
        assert_eq!(parsed, params);
        assert_eq!(parsed.price_per_token.to_u64()?, 100);

        let without_code = CocoonParams::from_cell(&parsed.without_code_refs().to_cell()?)?;
        assert!(without_code.proxy_sc_code.is_none());
        assert!(without_code.worker_sc_code.is_none());
        assert!(without_code.client_sc_code.is_none());
        assert_eq!(without_code.min_client_stake.to_u64()?, 2_000);
        Ok(())
    }
}
