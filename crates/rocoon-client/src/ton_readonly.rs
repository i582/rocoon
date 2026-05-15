//! Read-only TON liteclient access for diagnostics.
//!
//! The C++ Cocoon client keeps TON wallet state next to the proxy session and
//! exposes it from `/stats`. This module ports only the safe read path: it asks
//! liteservers for masterchain/account state and parses the Cocoon wallet data
//! cell. It never calls `sendMessage` and therefore cannot deploy, top up, or
//! otherwise mutate the chain.

use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use ton::block_tlb::{AccountState, MaybeAccount};
use ton::lite_client::{LiteClient, LiteReqParams};
use ton::ton_core::cell::TonCell;
use ton::ton_core::types::TonAddress;

use crate::config::TonRuntimeConfig;

/// Synchronous wrapper around `ton-rs` async liteclient.
pub struct TonReadonlyClient {
    runtime: Runtime,
    client: LiteClient,
    req_params: LiteReqParams,
}

/// Current TON state relevant to local diagnostics.
#[derive(Clone, Debug)]
pub struct TonReadonlySnapshot {
    /// Whether read-only TON polling is enabled by config.
    pub enabled: bool,
    /// Whether the last read-only query succeeded.
    pub ok: bool,
    /// Last read-only error formatted for diagnostics.
    pub last_error: Option<String>,
    /// Masterchain block seqno used for the account query.
    pub masterchain_seqno: Option<u32>,
    /// Cocoon wallet account state, when it could be fetched.
    pub wallet: Option<TonWalletSnapshot>,
}

/// Parsed Cocoon wallet account snapshot.
#[derive(Clone, Debug)]
pub struct TonWalletSnapshot {
    /// Account balance in nanotons.
    pub balance: Option<u64>,
    /// First 32 bits of the Cocoon wallet data cell, matching C++ `seqno`.
    pub seqno: Option<u32>,
    /// Human-readable account state.
    pub state: TonAccountState,
    /// Last transaction logical time from account storage.
    pub last_tx_lt: Option<u64>,
}

/// Account state categories exposed by TON account storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TonAccountState {
    /// Account does not exist.
    None,
    /// Account exists but is not initialized.
    Uninit,
    /// Account is frozen.
    Frozen,
    /// Account has active code/data.
    Active,
}

impl TonReadonlyClient {
    /// Creates the read-only liteclient from validated runtime config.
    ///
    /// # Errors
    ///
    /// Returns an error if the Tokio runtime, TON net config, or liteclient
    /// connection pool cannot be constructed.
    pub fn connect(config: &TonRuntimeConfig) -> Result<Self> {
        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .context("create TON read-only Tokio runtime")?;
        let mut builder = LiteClient::builder()
            .context("create TON liteclient builder")?
            .with_mainnet(config.mainnet)
            .context("select TON network")?;
        if let Some(path) = &config.config_path {
            builder = builder
                .with_net_config_path(path_to_str(path)?)
                .with_context(|| format!("load TON config {}", path.display()))?;
        }
        let client = builder.build().context("build TON liteclient")?;
        Ok(Self {
            runtime,
            client,
            req_params: LiteReqParams::new(1, 100, config.query_timeout_millis),
        })
    }

    /// Fetches masterchain state and the configured Cocoon wallet account.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is invalid, liteserver queries fail, or
    /// the active Cocoon wallet data cell cannot be parsed.
    pub fn wallet_snapshot(&self, address: &str) -> Result<TonReadonlySnapshot> {
        let address = TonAddress::from_str(address).context("parse Cocoon wallet address")?;
        self.runtime.block_on(self.fetch_wallet_snapshot(&address))
    }

    async fn fetch_wallet_snapshot(&self, address: &TonAddress) -> Result<TonReadonlySnapshot> {
        let masterchain = self
            .client
            .get_mc_info()
            .await
            .context("get TON masterchain info")?;
        let account = self
            .client
            .get_account_state(address, masterchain.last.seqno, Some(self.req_params))
            .await
            .context("get Cocoon wallet account state")?;
        let wallet =
            TonWalletSnapshot::from_account(&account).context("parse Cocoon wallet account")?;
        Ok(TonReadonlySnapshot {
            enabled: true,
            ok: true,
            last_error: None,
            masterchain_seqno: Some(masterchain.last.seqno),
            wallet: Some(wallet),
        })
    }
}

impl TonReadonlySnapshot {
    /// Snapshot for disabled TON polling.
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            ok: false,
            last_error: None,
            masterchain_seqno: None,
            wallet: None,
        }
    }

    /// Snapshot for a configured liteclient that could not be initialized.
    pub const fn failed(error: String) -> Self {
        Self {
            enabled: true,
            ok: false,
            last_error: Some(error),
            masterchain_seqno: None,
            wallet: None,
        }
    }
}

impl TonWalletSnapshot {
    fn from_account(account: &MaybeAccount) -> Result<Self> {
        let state = account_state(account);
        Ok(Self {
            balance: account
                .get_balance()
                .map(ton::ton_core::types::tlb_core::TLBCoins::to_u64)
                .transpose()
                .context("convert wallet balance to u64 nanotons")?,
            seqno: read_cocoon_wallet_seqno(account.get_data())?,
            state,
            last_tx_lt: last_tx_lt(account),
        })
    }
}

impl TonAccountState {
    /// Stable string representation used by `/stats`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Uninit => "uninit",
            Self::Frozen => "frozen",
            Self::Active => "active",
        }
    }
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn read_cocoon_wallet_seqno(data: Option<&TonCell>) -> Result<Option<u32>> {
    let Some(data) = data else {
        return Ok(None);
    };
    let mut parser = data.parser();
    let seqno = parser
        .read_num::<u32>(32)
        .context("read Cocoon wallet seqno from data cell")?;
    Ok(Some(seqno))
}

fn account_state(account: &MaybeAccount) -> TonAccountState {
    match account {
        MaybeAccount::None(_) => TonAccountState::None,
        MaybeAccount::Account(account) => match &account.storage.state {
            AccountState::Uninit(_) => TonAccountState::Uninit,
            AccountState::Frozen(_) => TonAccountState::Frozen,
            AccountState::Active(_) => TonAccountState::Active,
        },
    }
}

fn last_tx_lt(account: &MaybeAccount) -> Option<u64> {
    match account {
        MaybeAccount::None(_) => None,
        MaybeAccount::Account(account) => Some(account.storage.last_tx_lt),
    }
}

#[cfg(test)]
mod tests {
    use super::read_cocoon_wallet_seqno;
    use ton::ton_core::cell::TonCell;

    #[test]
    fn cocoon_wallet_seqno_is_first_u32_in_data_cell() -> anyhow::Result<()> {
        let mut builder = TonCell::builder();
        builder.write_num(&7_u32, 32)?;
        builder.write_num(&99_u32, 32)?;
        let cell = builder.build()?;

        assert_eq!(read_cocoon_wallet_seqno(Some(&cell))?, Some(7));
        Ok(())
    }
}
