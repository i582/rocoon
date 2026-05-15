//! TON liteclient access for Cocoon wallet diagnostics and control.
//!
//! The C++ Cocoon client keeps TON wallet state next to the proxy session and
//! exposes it from `/stats`. This module asks liteservers for
//! masterchain/account state, parses Cocoon wallet/client-contract data cells,
//! and contains the narrowly scoped wallet forwarding path used by local
//! `/request/withdraw` and `/request/close`.

use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use ton::block_tlb::{
    AccountState, CommonMsgInfo, CommonMsgInfoExtIn, CommonMsgInfoInt, CurrencyCollection,
    MaybeAccount, Msg, StateInit,
};
use ton::lite_client::{LiteClient, LiteReqParams};
use ton::ton_core::cell::TonCell;
use ton::ton_core::traits::tlb::TLB;
use ton::ton_core::types::TonAddress;
use ton::ton_core::types::tlb_core::{
    EitherRefLayout, MsgAddress, MsgAddressExt, TLBCoins, TLBEitherRef,
};

use crate::{config::TonRuntimeConfig, wallet};

const OWNER_CLIENT_WITHDRAW: u32 = 0xda06_8e78;
const OWNER_CLIENT_REQUEST_REFUND: u32 = 0xfafa_6cc1;
pub const CONTROL_MESSAGE_VALUE_NANOTONS: u64 = 700_000_000;
pub const COCOON_WALLET_RESERVE_NANOTONS: u64 = 100_000_000;
const WALLET_FORWARD_MODE: u8 = 0;
const WALLET_EXTERNAL_VALIDITY_SECS: u64 = 3_600;

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
    /// Client contract account state for the connected proxy.
    pub client_contract: Option<ClientContractSnapshot>,
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

/// Parsed Cocoon client contract account snapshot.
#[derive(Clone, Debug)]
pub struct ClientContractSnapshot {
    /// Account balance in nanotons.
    pub account_balance: Option<u64>,
    /// TON account state for the client contract.
    pub account_state: TonAccountState,
    /// Last transaction logical time for the client contract account.
    pub last_tx_lt: Option<u64>,
    /// Raw Cocoon client contract state: 0 running, 1 closing, 2 closed.
    pub state_raw: Option<u8>,
    /// Human-readable Cocoon client contract state.
    pub state: Option<&'static str>,
    /// Request balance from the client contract data cell, in nanotons.
    pub balance: Option<u64>,
    /// Locked stake from the client contract data cell, in nanotons.
    pub stake: Option<u64>,
    /// Tokens used from the client contract data cell.
    pub tokens_used: Option<u64>,
    /// Refund unlock timestamp from the client contract data cell.
    pub unlock_ts: Option<u32>,
    /// Balance above stake that can be withdrawn.
    pub withdrawable_balance: Option<u64>,
}

/// Control action sent through the Cocoon wallet to the client contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TonControlAction {
    /// `owner_client_withdraw`: withdraw balance above stake.
    Withdraw,
    /// `owner_client_request_refund`: ask the contract to close/refund.
    RequestRefund,
}

/// Inputs needed to send one Cocoon client contract control message.
pub struct TonControlRequest<'a> {
    /// Control action to encode in the client contract body.
    pub action: TonControlAction,
    /// External owner wallet address used to build Cocoon wallet state init.
    pub wallet_owner_address: &'a str,
    /// Cocoon wallet contract address.
    pub wallet_address: &'a str,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Connected client contract address returned by `client.connectToProxy`.
    pub client_contract_address: &'a str,
    /// Ed25519 seed used by the Cocoon wallet contract.
    pub wallet_seed: &'a [u8; 32],
}

/// Inputs needed to send value from the Cocoon wallet to a TON address.
pub struct TonWalletTransferRequest<'a> {
    /// External owner wallet address used to build Cocoon wallet state init.
    pub wallet_owner_address: &'a str,
    /// Cocoon wallet contract address.
    pub wallet_address: &'a str,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Ed25519 seed used by the Cocoon wallet contract.
    pub wallet_seed: &'a [u8; 32],
    /// Destination TON address.
    pub destination_address: &'a str,
    /// Value sent from the Cocoon wallet, in nanotons.
    pub amount: u64,
}

/// Signed external message prepared for a Cocoon wallet control transaction.
#[derive(Clone, Debug)]
pub struct TonControlPreparedMessage {
    /// Action that was encoded.
    pub action: TonControlAction,
    /// Random query id embedded into the client contract message.
    pub query_id: u64,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Attached internal message value in nanotons.
    pub attached_value: u64,
    /// Destination client contract address.
    pub client_contract_address: String,
    /// Cocoon wallet address that signed the external message.
    pub wallet_address: String,
    /// Full TON external message BOC, including state init when seqno is zero.
    pub external_message: Vec<u8>,
}

/// Signed external message prepared for a plain Cocoon wallet transfer.
#[derive(Clone, Debug)]
pub struct TonWalletTransferPreparedMessage {
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Value sent from the Cocoon wallet, in nanotons.
    pub amount: u64,
    /// Destination TON address.
    pub destination_address: String,
    /// Cocoon wallet address that signed the external message.
    pub wallet_address: String,
    /// Full TON external message BOC, including state init when seqno is zero.
    pub external_message: Vec<u8>,
}

/// Result returned after the external message is accepted by a liteserver.
#[derive(Clone, Debug)]
pub struct TonControlResult {
    /// Action that was sent.
    pub action: TonControlAction,
    /// Random query id embedded into the client contract message.
    pub query_id: u64,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Attached internal message value in nanotons.
    pub attached_value: u64,
    /// Liteserver send status returned by `liteServer.sendMessage`.
    pub send_status: u32,
    /// Destination client contract address.
    pub client_contract_address: String,
    /// Cocoon wallet address that signed the external message.
    pub wallet_address: String,
}

/// Result returned after a wallet transfer is accepted by a liteserver.
#[derive(Clone, Debug)]
pub struct TonWalletTransferResult {
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Value sent from the Cocoon wallet, in nanotons.
    pub amount: u64,
    /// Liteserver send status returned by `liteServer.sendMessage`.
    pub send_status: u32,
    /// Destination TON address.
    pub destination_address: String,
    /// Cocoon wallet address that signed the external message.
    pub wallet_address: String,
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
    /// Creates the liteclient from validated runtime config.
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

    /// Fetches masterchain state, wallet account, and optional client contract.
    ///
    /// # Errors
    ///
    /// Returns an error if an address is invalid, liteserver queries fail, or
    /// an active Cocoon data cell cannot be parsed.
    pub fn accounts_snapshot(
        &self,
        wallet_address: &str,
        client_contract_address: Option<&str>,
    ) -> Result<TonReadonlySnapshot> {
        let wallet_address =
            TonAddress::from_str(wallet_address).context("parse Cocoon wallet address")?;
        let client_contract_address = client_contract_address
            .map(TonAddress::from_str)
            .transpose()
            .context("parse Cocoon client contract address")?;
        self.runtime.block_on(
            self.fetch_accounts_snapshot(&wallet_address, client_contract_address.as_ref()),
        )
    }

    /// Builds and signs one owner control message without sending it.
    ///
    /// # Errors
    ///
    /// Returns an error if the wallet/client/owner addresses are invalid or
    /// signing/cell serialization fails.
    pub fn prepare_client_control_message(
        request: &TonControlRequest<'_>,
    ) -> Result<TonControlPreparedMessage> {
        let wallet_owner_address = TonAddress::from_str(request.wallet_owner_address)
            .context("parse Cocoon wallet owner address")?;
        let wallet_address =
            TonAddress::from_str(request.wallet_address).context("parse Cocoon wallet address")?;
        let client_contract_address = TonAddress::from_str(request.client_contract_address)
            .context("parse Cocoon client contract address")?;
        let query_id = random_query_id();
        let client_body = build_client_control_body(request.action, query_id, &wallet_address)
            .context("build client contract control body")?;
        let internal_msg = build_internal_message(
            &client_contract_address,
            CONTROL_MESSAGE_VALUE_NANOTONS,
            client_body,
        );
        let internal_msg_cell = internal_msg
            .to_cell()
            .context("serialize wallet-forwarded internal message")?;

        let external_msg = build_wallet_external_message(
            &wallet_address,
            &wallet_owner_address,
            request.wallet_seed,
            request.wallet_seqno,
            internal_msg_cell,
        )
        .context("build signed Cocoon wallet external message")?;

        Ok(TonControlPreparedMessage {
            action: request.action,
            query_id,
            wallet_seqno: request.wallet_seqno,
            attached_value: CONTROL_MESSAGE_VALUE_NANOTONS,
            client_contract_address: request.client_contract_address.to_string(),
            wallet_address: request.wallet_address.to_string(),
            external_message: external_msg,
        })
    }

    /// Builds and signs one plain TON transfer from the Cocoon wallet.
    ///
    /// # Errors
    ///
    /// Returns an error if wallet/owner/destination addresses are invalid or
    /// signing/cell serialization fails.
    pub fn prepare_wallet_transfer_message(
        request: &TonWalletTransferRequest<'_>,
    ) -> Result<TonWalletTransferPreparedMessage> {
        let wallet_owner_address = TonAddress::from_str(request.wallet_owner_address)
            .context("parse Cocoon wallet owner address")?;
        let wallet_address =
            TonAddress::from_str(request.wallet_address).context("parse Cocoon wallet address")?;
        let destination_address = TonAddress::from_str(request.destination_address)
            .context("parse destination address")?;

        // User-friendly `UQ...` owner wallets may still be uninitialized. Use a
        // non-bounceable internal transfer so the sweep does not bounce solely
        // because the destination account has not deployed wallet code yet.
        let internal_msg = build_internal_message_with_bounce(
            &destination_address,
            request.amount,
            TonCell::empty().to_owned(),
            false,
        );
        let internal_msg_cell = internal_msg
            .to_cell()
            .context("serialize wallet transfer internal message")?;

        let external_msg = build_wallet_external_message(
            &wallet_address,
            &wallet_owner_address,
            request.wallet_seed,
            request.wallet_seqno,
            internal_msg_cell,
        )
        .context("build signed Cocoon wallet transfer external message")?;

        Ok(TonWalletTransferPreparedMessage {
            wallet_seqno: request.wallet_seqno,
            amount: request.amount,
            destination_address: request.destination_address.to_string(),
            wallet_address: request.wallet_address.to_string(),
            external_message: external_msg,
        })
    }

    /// Sends a previously prepared Cocoon wallet control message.
    ///
    /// # Errors
    ///
    /// Returns an error if the liteserver rejects `sendMessage`.
    pub fn send_prepared_control_message(
        &self,
        message: &TonControlPreparedMessage,
    ) -> Result<TonControlResult> {
        let send_status = self.send_raw_message(&message.external_message)?;
        Ok(TonControlResult {
            action: message.action,
            query_id: message.query_id,
            wallet_seqno: message.wallet_seqno,
            attached_value: message.attached_value,
            send_status,
            client_contract_address: message.client_contract_address.clone(),
            wallet_address: message.wallet_address.clone(),
        })
    }

    /// Sends a previously prepared Cocoon wallet transfer.
    ///
    /// # Errors
    ///
    /// Returns an error if the liteserver rejects `sendMessage`.
    pub fn send_prepared_wallet_transfer_message(
        &self,
        message: &TonWalletTransferPreparedMessage,
    ) -> Result<TonWalletTransferResult> {
        let send_status = self.send_raw_message(&message.external_message)?;
        Ok(TonWalletTransferResult {
            wallet_seqno: message.wallet_seqno,
            amount: message.amount,
            send_status,
            destination_address: message.destination_address.clone(),
            wallet_address: message.wallet_address.clone(),
        })
    }

    /// Resends an already serialized TON external message.
    ///
    /// # Errors
    ///
    /// Returns an error if the liteserver rejects `sendMessage`.
    pub fn send_raw_message(&self, message: &[u8]) -> Result<u32> {
        self.runtime.block_on(async {
            self.client
                .send_msg(message.to_vec(), Some(self.req_params))
                .await
                .context("send TON external message")
        })
    }

    async fn fetch_accounts_snapshot(
        &self,
        wallet_address: &TonAddress,
        client_contract_address: Option<&TonAddress>,
    ) -> Result<TonReadonlySnapshot> {
        let masterchain = self
            .client
            .get_mc_info()
            .await
            .context("get TON masterchain info")?;
        let account = self
            .client
            .get_account_state(
                wallet_address,
                masterchain.last.seqno,
                Some(self.req_params),
            )
            .await
            .context("get Cocoon wallet account state")?;
        let wallet =
            TonWalletSnapshot::from_account(&account).context("parse Cocoon wallet account")?;
        let client_contract = if let Some(address) = client_contract_address {
            let account = self
                .client
                .get_account_state(address, masterchain.last.seqno, Some(self.req_params))
                .await
                .context("get Cocoon client contract account state")?;
            Some(
                ClientContractSnapshot::from_account(&account)
                    .context("parse Cocoon client contract account")?,
            )
        } else {
            None
        };
        Ok(TonReadonlySnapshot {
            enabled: true,
            ok: true,
            last_error: None,
            masterchain_seqno: Some(masterchain.last.seqno),
            wallet: Some(wallet),
            client_contract,
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
            client_contract: None,
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
            client_contract: None,
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

impl ClientContractSnapshot {
    fn from_account(account: &MaybeAccount) -> Result<Self> {
        let state = account_state(account);
        let data = read_client_contract_data(account.get_data())?;
        Ok(Self {
            account_balance: account
                .get_balance()
                .map(ton::ton_core::types::tlb_core::TLBCoins::to_u64)
                .transpose()
                .context("convert client contract account balance to u64 nanotons")?,
            account_state: state,
            last_tx_lt: last_tx_lt(account),
            state_raw: data.as_ref().map(|data| data.state),
            state: data
                .as_ref()
                .map(|data| client_contract_state_name(data.state)),
            balance: data.as_ref().map(|data| data.balance),
            stake: data.as_ref().map(|data| data.stake),
            tokens_used: data.as_ref().map(|data| data.tokens_used),
            unlock_ts: data.as_ref().map(|data| data.unlock_ts),
            withdrawable_balance: data
                .as_ref()
                .map(|data| data.balance.saturating_sub(data.stake)),
        })
    }
}

impl TonAccountState {
    /// Stable string representation used by `/stats`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Uninit => "uninit",
            Self::Frozen => "frozen",
            Self::Active => "active",
        }
    }
}

impl TonControlAction {
    /// Stable string representation used by control endpoint responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Withdraw => "withdraw",
            Self::RequestRefund => "close",
        }
    }

    const fn opcode(self) -> u32 {
        match self {
            Self::Withdraw => OWNER_CLIENT_WITHDRAW,
            Self::RequestRefund => OWNER_CLIENT_REQUEST_REFUND,
        }
    }
}

struct ClientContractData {
    state: u8,
    balance: u64,
    stake: u64,
    tokens_used: u64,
    unlock_ts: u32,
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

fn read_client_contract_data(data: Option<&TonCell>) -> Result<Option<ClientContractData>> {
    let Some(data) = data else {
        return Ok(None);
    };
    let mut parser = data.parser();
    let contract_state = parser
        .read_num::<u8>(2)
        .context("read client contract state")?;
    let balance = TLBCoins::read(&mut parser)
        .context("read client contract balance")?
        .to_u64()
        .context("convert client contract balance to u64")?;
    let stake = TLBCoins::read(&mut parser)
        .context("read client contract stake")?
        .to_u64()
        .context("convert client contract stake to u64")?;
    let tokens_used = parser
        .read_num::<u64>(64)
        .context("read client contract tokens_used")?;
    let unlock_ts = parser
        .read_num::<u32>(32)
        .context("read client contract unlock_ts")?;
    let _secret_hash = parser
        .read_bits(256)
        .context("read client contract secret_hash")?;
    Ok(Some(ClientContractData {
        state: contract_state,
        balance,
        stake,
        tokens_used,
        unlock_ts,
    }))
}

const fn client_contract_state_name(state: u8) -> &'static str {
    match state {
        0 => "running",
        1 => "closing",
        2 => "closed",
        _ => "unknown",
    }
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

fn build_client_control_body(
    action: TonControlAction,
    query_id: u64,
    wallet_address: &TonAddress,
) -> Result<TonCell> {
    let mut builder = TonCell::builder();
    builder.write_num(&action.opcode(), 32)?;
    builder.write_num(&query_id, 64)?;
    wallet_address.to_msg_address_int().write(&mut builder)?;
    builder
        .build()
        .context("build client contract control body cell")
}

fn build_internal_message(dest: &TonAddress, value_nanotons: u64, body: TonCell) -> Msg<TonCell> {
    build_internal_message_with_bounce(dest, value_nanotons, body, true)
}

fn build_internal_message_with_bounce(
    dest: &TonAddress,
    value_nanotons: u64,
    body: TonCell,
    bounce: bool,
) -> Msg<TonCell> {
    let info = CommonMsgInfoInt {
        ihr_disabled: true,
        dst: MsgAddress::Int(dest.to_msg_address_int()),
        bounce,
        value: CurrencyCollection::new(TLBCoins::new(u128::from(value_nanotons))),
        ..Default::default()
    };
    Msg {
        info: CommonMsgInfo::Int(info),
        init: None,
        body: TLBEitherRef::new_with_layout(body, EitherRefLayout::ToRef),
    }
}

fn build_wallet_external_message(
    wallet_address: &TonAddress,
    wallet_owner_address: &TonAddress,
    wallet_seed: &[u8; 32],
    wallet_seqno: u32,
    internal_msg_cell: TonCell,
) -> Result<Vec<u8>> {
    let unsigned_body =
        build_wallet_unsigned_body(wallet_seqno, internal_msg_cell).context("build wallet body")?;
    let signing_key = SigningKey::from_bytes(wallet_seed);
    let signature = signing_key.sign(unsigned_body.hash()?.as_slice());

    let mut signed_body_builder = TonCell::builder();
    signed_body_builder.write_bits(signature.to_bytes(), 512)?;
    signed_body_builder.write_cell(&unsigned_body)?;
    let signed_body = signed_body_builder
        .build()
        .context("build signed wallet body")?;
    let init = if wallet_seqno == 0 {
        Some(TLBEitherRef::new_with_layout(
            StateInit::new(
                wallet::cocoon_wallet_code()?,
                wallet::cocoon_wallet_init_data_from_seed(wallet_owner_address, wallet_seed)?,
            ),
            EitherRefLayout::ToRef,
        ))
    } else {
        None
    };

    let message = Msg {
        info: CommonMsgInfo::ExtIn(CommonMsgInfoExtIn {
            src: MsgAddressExt::NONE,
            dst: wallet_address.to_msg_address_int(),
            import_fee: TLBCoins::ZERO,
        }),
        init,
        body: TLBEitherRef::new_with_layout(signed_body, EitherRefLayout::ToRef),
    };
    message.to_boc().context("serialize external message BOC")
}

fn build_wallet_unsigned_body(wallet_seqno: u32, internal_msg_cell: TonCell) -> Result<TonCell> {
    let mut builder = TonCell::builder();
    builder.write_num(&0u32, 32)?;
    builder.write_num(&valid_until()?, 32)?;
    builder.write_num(&wallet_seqno, 32)?;
    builder.write_num(&WALLET_FORWARD_MODE, 8)?;
    builder.write_ref(internal_msg_cell)?;
    builder.build().context("build unsigned wallet body")
}

fn random_query_id() -> u64 {
    rand::thread_rng().next_u64()
}

fn valid_until() -> Result<u32> {
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs()
        .saturating_add(WALLET_EXTERNAL_VALIDITY_SECS);
    u32::try_from(expires_at).context("wallet external valid_until does not fit u32")
}

#[cfg(test)]
mod tests {
    use super::{
        OWNER_CLIENT_WITHDRAW, TonControlAction, build_client_control_body,
        build_wallet_external_message, read_cocoon_wallet_seqno,
    };
    use std::str::FromStr;
    use ton::block_tlb::Msg;
    use ton::ton_core::cell::TonCell;
    use ton::ton_core::traits::tlb::TLB;
    use ton::ton_core::types::TonAddress;

    #[test]
    fn cocoon_wallet_seqno_is_first_u32_in_data_cell() -> anyhow::Result<()> {
        let mut builder = TonCell::builder();
        builder.write_num(&7_u32, 32)?;
        builder.write_num(&99_u32, 32)?;
        let cell = builder.build()?;

        assert_eq!(read_cocoon_wallet_seqno(Some(&cell))?, Some(7));
        Ok(())
    }

    #[test]
    fn client_control_body_starts_with_opcode_and_query_id() -> anyhow::Result<()> {
        let wallet = TonAddress::from_str("UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi")?;
        let cell = build_client_control_body(TonControlAction::Withdraw, 42, &wallet)?;
        let mut parser = cell.parser();

        assert_eq!(parser.read_num::<u32>(32)?, OWNER_CLIENT_WITHDRAW);
        assert_eq!(parser.read_num::<u64>(64)?, 42);
        Ok(())
    }

    #[test]
    fn wallet_external_message_adds_state_init_for_seqno_zero() -> anyhow::Result<()> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let wallet = TonAddress::from_str("UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi")?;
        let seed =
            crate::wallet::decode_node_wallet_key("Eeo22fSR51UZHS9xUVwCGj4oIGa2pGGydUDHfG+YcEw=")?;

        let first_message =
            build_wallet_external_message(&wallet, &owner, &seed, 0, TonCell::empty().to_owned())?;
        let next_message =
            build_wallet_external_message(&wallet, &owner, &seed, 1, TonCell::empty().to_owned())?;

        assert!(Msg::<TonCell>::from_boc(first_message)?.init.is_some());
        assert!(Msg::<TonCell>::from_boc(next_message)?.init.is_none());
        Ok(())
    }
}
