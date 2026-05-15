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
use rocoon_contract::{
    CocoonClientContractData, CocoonClientControlAction, CocoonClientControlBody, CocoonWalletData,
    CocoonWalletUnsignedBody, cocoon_wallet_signed_body,
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use ton::block_tlb::{
    AccountState, CommonMsgInfo, CommonMsgInfoExtIn, CommonMsgInfoInt, CurrencyCollection,
    MaybeAccount, Msg, StateInit,
};
use ton::lite_client::{LiteClient, LiteReqParams};
use ton::ton_core::cell::{CellBuilder, CellParser, TonCell};
use ton::ton_core::traits::tlb::TLB;
use ton::ton_core::types::TonAddress;
use ton::ton_core::types::tlb_core::{
    EitherRefLayout, MsgAddress, MsgAddressExt, TLBCoins, TLBEitherRef,
};

use crate::{config::TonRuntimeConfig, wallet};

const OWNER_CLIENT_REGISTER: u32 = 0xc45f_9f3b;
pub const CONTROL_MESSAGE_VALUE_NANOTONS: u64 = 700_000_000;
const ACTIVE_CLIENT_REGISTER_VALUE_NANOTONS: u64 = 1_000_000_000;
pub const CLIENT_REGISTER_EXTRA_NANOTONS: u64 = 50_000_000;
pub const COCOON_WALLET_RESERVE_NANOTONS: u64 = 100_000_000;
const LEGACY_MIN_STAKE_NANOTONS: u64 = 1_000_000_000;
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

/// Inputs needed to build a Cocoon client long-auth registration message.
///
/// Long proxy authorization requires a TON transaction before the proxy accepts
/// `client.authorizeWithProxyLong`. The wallet forwards `owner_client_register`
/// to the proxy-specific client contract address returned by
/// `client.connectToProxy`.
pub struct TonClientRegisterRequest<'a> {
    /// External owner wallet address used to build Cocoon wallet state init.
    pub wallet_owner_address: &'a str,
    /// Cocoon wallet contract address.
    pub wallet_address: &'a str,
    /// Mainnet/testnet Cocoon root contract address.
    pub root_contract_address: &'a str,
    /// Client contract address returned by `client.connectToProxy`.
    pub client_contract_address: &'a str,
    /// Proxy smart-contract address returned by `client.connectToProxy`.
    pub proxy_contract_address: &'a str,
    /// Proxy public key returned by `client.connectToProxy`.
    pub proxy_public_key: &'a [u8; 32],
    /// Proxy-provided nonce embedded into `owner_client_register`.
    pub nonce: u64,
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

/// Signed external message prepared for long authorization registration.
#[derive(Clone, Debug)]
pub struct TonClientRegisterPreparedMessage {
    /// Random query id embedded into `owner_client_register`.
    pub query_id: u64,
    /// Proxy-provided nonce embedded into `owner_client_register`.
    pub nonce: u64,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Attached internal message value in nanotons.
    pub attached_value: u64,
    /// Destination client contract address.
    pub client_contract_address: String,
    /// Cocoon wallet address that signed the external message.
    pub wallet_address: String,
    /// Full TON external message BOC.
    ///
    /// The message includes Cocoon wallet `StateInit` when wallet seqno is zero,
    /// and the forwarded internal message includes client contract `StateInit`
    /// when the client contract is not active yet.
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

/// Result returned after long authorization registration is accepted by a liteserver.
#[derive(Clone, Debug)]
pub struct TonClientRegisterResult {
    /// Random query id embedded into `owner_client_register`.
    pub query_id: u64,
    /// Proxy-provided nonce embedded into `owner_client_register`.
    pub nonce: u64,
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

    /// Fetches root/wallet state, then builds and signs long-auth registration.
    ///
    /// # Errors
    ///
    /// Returns an error if TON state cannot be fetched, root params do not
    /// contain client contract code, the derived client contract address does
    /// not match the proxy response, the Cocoon wallet is underfunded, or cell
    /// serialization/signing fails.
    pub fn prepare_client_register_message(
        &self,
        request: &TonClientRegisterRequest<'_>,
    ) -> Result<TonClientRegisterPreparedMessage> {
        let wallet_owner_address = TonAddress::from_str(request.wallet_owner_address)
            .context("parse Cocoon wallet owner address")?;
        let wallet_address =
            TonAddress::from_str(request.wallet_address).context("parse Cocoon wallet address")?;
        let root_contract_address = TonAddress::from_str(request.root_contract_address)
            .context("parse Cocoon root contract address")?;
        let client_contract_address = TonAddress::from_str(request.client_contract_address)
            .context("parse Cocoon client contract address")?;
        let proxy_contract_address = TonAddress::from_str(request.proxy_contract_address)
            .context("parse Cocoon proxy contract address")?;

        let context = self
            .runtime
            .block_on(self.fetch_client_register_context(
                &wallet_address,
                &root_contract_address,
                &client_contract_address,
            ))
            .context("fetch TON state for long authorization")?;
        let client_contract_needs_state_init =
            context.client_contract.account_state != TonAccountState::Active;
        let attached_value =
            client_register_attached_value(&context.root_config, client_contract_needs_state_init)?;
        let wallet_seqno = validate_cocoon_wallet_can_send_value(
            request.wallet_address,
            &context.wallet,
            attached_value,
        )?;

        let state_init = build_client_contract_state_init(
            &context.root_config,
            &wallet_address,
            &proxy_contract_address,
            request.proxy_public_key,
        )
        .context("build Cocoon client contract state init")?;
        let derived_address = state_init
            .derive_address(client_contract_address.workchain)
            .context("derive Cocoon client contract address from state init")?;
        if derived_address != client_contract_address {
            anyhow::bail!(
                "client contract address mismatch: proxy returned {}, derived {}",
                request.client_contract_address,
                derived_address.to_hex()
            );
        }

        let query_id = random_query_id();
        let client_body = build_client_register_body(request.nonce, query_id, &wallet_address)
            .context("build client contract register body")?;
        let internal_msg = build_internal_message_with_state_init(
            &client_contract_address,
            attached_value,
            client_body,
            true,
            client_contract_needs_state_init.then_some(state_init),
        );
        let internal_msg_cell = internal_msg
            .to_cell()
            .context("serialize wallet-forwarded client register message")?;

        let external_msg = build_wallet_external_message(
            &wallet_address,
            &wallet_owner_address,
            request.wallet_seed,
            wallet_seqno,
            internal_msg_cell,
        )
        .context("build signed Cocoon wallet client register message")?;

        Ok(TonClientRegisterPreparedMessage {
            query_id,
            nonce: request.nonce,
            wallet_seqno,
            attached_value,
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

    /// Sends a previously prepared long-auth registration message.
    ///
    /// # Errors
    ///
    /// Returns an error if the liteserver rejects `sendMessage`.
    pub fn send_prepared_client_register_message(
        &self,
        message: &TonClientRegisterPreparedMessage,
    ) -> Result<TonClientRegisterResult> {
        let send_status = self.send_raw_message(&message.external_message)?;
        Ok(TonClientRegisterResult {
            query_id: message.query_id,
            nonce: message.nonce,
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

    async fn fetch_client_register_context(
        &self,
        wallet_address: &TonAddress,
        root_contract_address: &TonAddress,
        client_contract_address: &TonAddress,
    ) -> Result<ClientRegisterContext> {
        let masterchain = self
            .client
            .get_mc_info()
            .await
            .context("get TON masterchain info")?;
        let wallet_account = self
            .client
            .get_account_state(
                wallet_address,
                masterchain.last.seqno,
                Some(self.req_params),
            )
            .await
            .context("get Cocoon wallet account state")?;
        let root_account = self
            .client
            .get_account_state(
                root_contract_address,
                masterchain.last.seqno,
                Some(self.req_params),
            )
            .await
            .context("get Cocoon root contract account state")?;
        let client_contract_account = self
            .client
            .get_account_state(
                client_contract_address,
                masterchain.last.seqno,
                Some(self.req_params),
            )
            .await
            .context("get Cocoon client contract account state")?;
        Ok(ClientRegisterContext {
            wallet: TonWalletSnapshot::from_account(&wallet_account)
                .context("parse Cocoon wallet account")?,
            root_config: CocoonRootConfig::from_account(&root_account)
                .context("parse Cocoon root contract")?,
            client_contract: ClientContractSnapshot::from_account(&client_contract_account)
                .context("parse Cocoon client contract account")?,
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
        let account_status = account_state(account);
        let data = read_client_contract_data(account.get_data())?;
        let balance = data
            .as_ref()
            .map(|data| data.balance.to_u64())
            .transpose()
            .context("convert client contract balance to u64")?;
        let stake = data
            .as_ref()
            .map(|data| data.stake.to_u64())
            .transpose()
            .context("convert client contract stake to u64")?;
        Ok(Self {
            account_balance: account
                .get_balance()
                .map(ton::ton_core::types::tlb_core::TLBCoins::to_u64)
                .transpose()
                .context("convert client contract account balance to u64 nanotons")?,
            account_state: account_status,
            last_tx_lt: last_tx_lt(account),
            state_raw: data.as_ref().map(|data| data.state),
            state: data
                .as_ref()
                .map(|data| client_contract_state_name(data.state)),
            balance,
            stake,
            tokens_used: data.as_ref().map(|data| data.tokens_used),
            unlock_ts: data.as_ref().map(|data| data.unlock_ts),
            withdrawable_balance: balance
                .zip(stake)
                .map(|(balance, stake)| balance.saturating_sub(stake)),
        })
    }
}

impl CocoonRootConfig {
    fn from_account(account: &MaybeAccount) -> Result<Self> {
        if account_state(account) != TonAccountState::Active {
            anyhow::bail!(
                "Cocoon root contract account is not active: {}",
                account_state(account).as_str()
            );
        }
        let data = account
            .get_data()
            .context("Cocoon root contract data cell is unavailable")?;
        parse_root_config_from_data(data)
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
}

impl From<TonControlAction> for CocoonClientControlAction {
    fn from(action: TonControlAction) -> Self {
        match action {
            TonControlAction::Withdraw => Self::Withdraw,
            TonControlAction::RequestRefund => Self::RequestRefund,
        }
    }
}

struct ClientRegisterContext {
    wallet: TonWalletSnapshot,
    root_config: CocoonRootConfig,
    client_contract: ClientContractSnapshot,
}

struct CocoonRootConfig {
    min_client_stake: u64,
    client_sc_code: TonCell,
    client_params_cell: TonCell,
}

struct CocoonRootParams {
    struct_version: u8,
    params_version: u32,
    unique_id: u32,
    is_test: bool,
    price_per_token: u64,
    worker_fee_per_token: u64,
    prompt_tokens_price_multiplier: u32,
    cached_tokens_price_multiplier: u32,
    completion_tokens_price_multiplier: u32,
    reasoning_tokens_price_multiplier: u32,
    proxy_delay_before_close: u32,
    client_delay_before_close: u32,
    min_proxy_stake: u64,
    min_client_stake: u64,
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn read_cocoon_wallet_seqno(data: Option<&TonCell>) -> Result<Option<u32>> {
    let Some(data) = data else {
        return Ok(None);
    };
    let data = CocoonWalletData::from_cell(data).context("read Cocoon wallet data cell")?;
    Ok(Some(data.seqno))
}

fn read_client_contract_data(data: Option<&TonCell>) -> Result<Option<CocoonClientContractData>> {
    let Some(data) = data else {
        return Ok(None);
    };
    CocoonClientContractData::from_cell(data)
        .map(Some)
        .context("read Cocoon client contract data cell")
}

fn parse_root_config_from_data(data: &TonCell) -> Result<CocoonRootConfig> {
    let mut parser = data.parser();
    let _owner_address = TonAddress::read(&mut parser).context("read root owner address")?;
    let _ = parser
        .read_next_ref()
        .context("read root mutable data cell ref")?;
    let params_cell = parser
        .read_next_ref()
        .context("read root params cell ref")?
        .clone();
    let root_params = parse_root_params_cell(&params_cell).context("parse root params cell")?;
    let _root_version = parser
        .read_num::<u32>(32)
        .context("read root contract version")?;
    if root_params.struct_version >= 4 {
        let _key_manager_cell = parser
            .read_next_ref()
            .context("read root key manager cell ref")?;
    }
    if root_params.struct_version >= 5 {
        let _verified_keys_cell = parser
            .read_next_ref()
            .context("read root verified keys cell ref")?;
    }
    parser
        .ensure_empty()
        .context("root contract data has trailing fields")?;

    let client_params_cell = build_client_params_cell_without_code_refs(&root_params)
        .context("build client params cell without code refs")?;
    let client_sc_code = read_client_sc_code(&params_cell).context("read root client code ref")?;

    Ok(CocoonRootConfig {
        min_client_stake: root_params.min_client_stake,
        client_sc_code,
        client_params_cell,
    })
}

fn parse_root_params_cell(params_cell: &TonCell) -> Result<CocoonRootParams> {
    let mut parser = params_cell.parser();
    let struct_version = parser
        .read_num::<u8>(8)
        .context("read root params struct_version")?;
    if struct_version > 5 {
        anyhow::bail!("unexpected root params struct_version: {struct_version}");
    }
    let params_version = parser
        .read_num::<u32>(32)
        .context("read root params params_version")?;
    let unique_id = parser
        .read_num::<u32>(32)
        .context("read root params unique_id")?;
    let is_test = parser.read_bit().context("read root params is_test")?;
    let price_per_token = read_coins(&mut parser).context("read root params price_per_token")?;
    let worker_fee_per_token =
        read_coins(&mut parser).context("read root params worker_fee_per_token")?;
    let prompt_tokens_price_multiplier = if struct_version >= 3 {
        parser
            .read_num::<u32>(32)
            .context("read root params prompt multiplier")?
    } else {
        10_000
    };
    let cached_tokens_price_multiplier = if struct_version >= 2 {
        parser
            .read_num::<u32>(32)
            .context("read root params cached multiplier")?
    } else {
        10_000
    };
    let completion_tokens_price_multiplier = if struct_version >= 3 {
        parser
            .read_num::<u32>(32)
            .context("read root params completion multiplier")?
    } else {
        10_000
    };
    let reasoning_tokens_price_multiplier = if struct_version >= 2 {
        parser
            .read_num::<u32>(32)
            .context("read root params reasoning multiplier")?
    } else {
        10_000
    };
    let proxy_delay_before_close = parser
        .read_num::<u32>(32)
        .context("read root params proxy_delay_before_close")?;
    let client_delay_before_close = parser
        .read_num::<u32>(32)
        .context("read root params client_delay_before_close")?;
    let min_proxy_stake = if struct_version >= 1 {
        read_coins(&mut parser).context("read root params min_proxy_stake")?
    } else {
        LEGACY_MIN_STAKE_NANOTONS
    };
    let min_client_stake = if struct_version >= 1 {
        read_coins(&mut parser).context("read root params min_client_stake")?
    } else {
        LEGACY_MIN_STAKE_NANOTONS
    };

    let _proxy_sc_code = read_maybe_ref(&mut parser).context("read root proxy code ref flag")?;
    let _worker_sc_code = read_maybe_ref(&mut parser).context("read root worker code ref flag")?;
    let client_sc_code = read_maybe_ref(&mut parser).context("read root client code ref flag")?;
    parser
        .ensure_empty()
        .context("root params cell has trailing fields")?;
    if client_sc_code.is_none() {
        anyhow::bail!("root params do not contain client smart-contract code");
    }

    Ok(CocoonRootParams {
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
    })
}

fn read_client_sc_code(params_cell: &TonCell) -> Result<TonCell> {
    let mut parser = params_cell.parser();
    skip_root_params_until_code_refs(&mut parser)?;
    let _proxy_sc_code = read_maybe_ref(&mut parser).context("read proxy code ref")?;
    let _worker_sc_code = read_maybe_ref(&mut parser).context("read worker code ref")?;
    read_maybe_ref(&mut parser)
        .context("read client code ref")?
        .context("root params do not contain client smart-contract code")
}

fn skip_root_params_until_code_refs(parser: &mut CellParser<'_>) -> Result<()> {
    let struct_version = parser
        .read_num::<u8>(8)
        .context("read root params struct_version")?;
    parser.read_num::<u32>(32).context("skip params_version")?;
    parser.read_num::<u32>(32).context("skip unique_id")?;
    parser.read_bit().context("skip is_test")?;
    let _price_per_token = read_coins(parser).context("skip price_per_token")?;
    let _worker_fee_per_token = read_coins(parser).context("skip worker_fee_per_token")?;
    if struct_version >= 3 {
        parser
            .read_num::<u32>(32)
            .context("skip prompt multiplier")?;
    }
    if struct_version >= 2 {
        parser
            .read_num::<u32>(32)
            .context("skip cached multiplier")?;
    }
    if struct_version >= 3 {
        parser
            .read_num::<u32>(32)
            .context("skip completion multiplier")?;
    }
    if struct_version >= 2 {
        parser
            .read_num::<u32>(32)
            .context("skip reasoning multiplier")?;
    }
    parser
        .read_num::<u32>(32)
        .context("skip proxy_delay_before_close")?;
    parser
        .read_num::<u32>(32)
        .context("skip client_delay_before_close")?;
    if struct_version >= 1 {
        let _min_proxy_stake = read_coins(parser).context("skip min_proxy_stake")?;
        let _min_client_stake = read_coins(parser).context("skip min_client_stake")?;
    }
    Ok(())
}

fn build_client_params_cell_without_code_refs(params: &CocoonRootParams) -> Result<TonCell> {
    let mut builder = TonCell::builder();
    builder.write_num(&params.struct_version, 8)?;
    builder.write_num(&params.params_version, 32)?;
    builder.write_num(&params.unique_id, 32)?;
    builder.write_bit(params.is_test)?;
    write_coins(&mut builder, params.price_per_token)?;
    write_coins(&mut builder, params.worker_fee_per_token)?;
    if params.struct_version >= 2 {
        if params.struct_version >= 3 {
            builder.write_num(&params.prompt_tokens_price_multiplier, 32)?;
        }
        builder.write_num(&params.cached_tokens_price_multiplier, 32)?;
        if params.struct_version >= 3 {
            builder.write_num(&params.completion_tokens_price_multiplier, 32)?;
        }
        builder.write_num(&params.reasoning_tokens_price_multiplier, 32)?;
    }
    builder.write_num(&params.proxy_delay_before_close, 32)?;
    builder.write_num(&params.client_delay_before_close, 32)?;
    if params.struct_version >= 1 {
        write_coins(&mut builder, params.min_proxy_stake)?;
        write_coins(&mut builder, params.min_client_stake)?;
    }
    builder.write_bit(false)?;
    builder.write_bit(false)?;
    builder.write_bit(false)?;
    builder
        .build()
        .context("build root params cell without code refs")
}

fn read_maybe_ref(parser: &mut CellParser<'_>) -> Result<Option<TonCell>> {
    if parser.read_bit()? {
        Ok(Some(parser.read_next_ref()?.clone()))
    } else {
        Ok(None)
    }
}

fn read_coins(parser: &mut CellParser<'_>) -> Result<u64> {
    TLBCoins::read(parser)
        .context("read coins")?
        .to_u64()
        .context("convert coins to u64")
}

fn write_coins(builder: &mut CellBuilder, value: u64) -> Result<()> {
    TLBCoins::new(u128::from(value))
        .write(builder)
        .context("write coins")
}

fn client_register_attached_value(
    root_config: &CocoonRootConfig,
    needs_state_init: bool,
) -> Result<u64> {
    if needs_state_init {
        root_config
            .min_client_stake
            .checked_add(CLIENT_REGISTER_EXTRA_NANOTONS)
            .context("client register attached value overflow")
    } else {
        Ok(ACTIVE_CLIENT_REGISTER_VALUE_NANOTONS)
    }
}

fn validate_cocoon_wallet_can_send_value(
    wallet_address: &str,
    snapshot: &TonWalletSnapshot,
    value_nanotons: u64,
) -> Result<u32> {
    let wallet_seqno = match snapshot.state {
        TonAccountState::Active => snapshot
            .seqno
            .context("Cocoon wallet seqno is unavailable in active account")?,
        TonAccountState::Uninit => 0,
        TonAccountState::None | TonAccountState::Frozen => {
            anyhow::bail!(
                "Cocoon wallet account cannot send messages: {}",
                snapshot.state.as_str()
            );
        }
    };
    let balance = snapshot
        .balance
        .context("Cocoon wallet balance is unavailable")?;
    let required_balance = value_nanotons.saturating_add(COCOON_WALLET_RESERVE_NANOTONS);
    if balance < required_balance {
        anyhow::bail!(
            "ACTION REQUIRED: BALANCE ON CONTRACT {wallet_address} IS TOO LOW: SENDING MESSAGE OF VALUE {value_nanotons} CURRENT {balance}"
        );
    }
    Ok(wallet_seqno)
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
    CocoonClientControlBody::new(action.into(), query_id, wallet_address.clone())
        .to_cell()
        .context("build client contract control body cell")
}

fn build_client_register_body(
    nonce: u64,
    query_id: u64,
    wallet_address: &TonAddress,
) -> Result<TonCell> {
    let mut builder = TonCell::builder();
    builder.write_num(&OWNER_CLIENT_REGISTER, 32)?;
    builder.write_num(&query_id, 64)?;
    builder.write_num(&nonce, 64)?;
    wallet_address.to_msg_address_int().write(&mut builder)?;
    builder
        .build()
        .context("build client contract register body cell")
}

fn build_client_contract_state_init(
    root_config: &CocoonRootConfig,
    wallet_address: &TonAddress,
    proxy_contract_address: &TonAddress,
    proxy_public_key: &[u8; 32],
) -> Result<StateInit> {
    let mut const_data_builder = TonCell::builder();
    wallet_address
        .to_msg_address_int()
        .write(&mut const_data_builder)?;
    proxy_contract_address
        .to_msg_address_int()
        .write(&mut const_data_builder)?;
    const_data_builder.write_bits(proxy_public_key, 256)?;
    let const_data = const_data_builder
        .build()
        .context("build client contract const data cell")?;

    let mut data_builder = TonCell::builder();
    data_builder.write_num(&0u8, 2)?;
    write_coins(&mut data_builder, 0)?;
    write_coins(&mut data_builder, root_config.min_client_stake)?;
    data_builder.write_num(&0u64, 64)?;
    data_builder.write_num(&0u32, 32)?;
    data_builder.write_bits([0u8; 32], 256)?;
    data_builder.write_ref(const_data)?;
    data_builder.write_ref(root_config.client_params_cell.clone())?;
    let data = data_builder
        .build()
        .context("build client contract data cell")?;

    Ok(StateInit::new(root_config.client_sc_code.clone(), data))
}

fn build_internal_message(dest: &TonAddress, value_nanotons: u64, body: TonCell) -> Msg<TonCell> {
    build_internal_message_with_bounce(dest, value_nanotons, body, true)
}

fn build_internal_message_with_state_init(
    dest: &TonAddress,
    value_nanotons: u64,
    body: TonCell,
    bounce: bool,
    state_init: Option<StateInit>,
) -> Msg<TonCell> {
    let mut message = build_internal_message_with_bounce(dest, value_nanotons, body, bounce);
    message.init =
        state_init.map(|init| TLBEitherRef::new_with_layout(init, EitherRefLayout::ToRef));
    message
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
    let signature = signature.to_bytes();
    let signed_body = cocoon_wallet_signed_body(&signature, &unsigned_body)
        .context("build signed wallet body")?;
    let init = if wallet_seqno == 0 {
        Some(TLBEitherRef::new_with_layout(
            wallet::cocoon_wallet_state_init_from_seed(wallet_owner_address, wallet_seed)?,
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
    CocoonWalletUnsignedBody {
        subwallet_id: 0,
        valid_until: valid_until()?,
        seqno: wallet_seqno,
        send_mode: WALLET_FORWARD_MODE,
        internal_message: internal_msg_cell.into(),
    }
    .to_cell()
    .context("build unsigned wallet body")
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
        ACTIVE_CLIENT_REGISTER_VALUE_NANOTONS, CLIENT_REGISTER_EXTRA_NANOTONS,
        OWNER_CLIENT_REGISTER, TonControlAction, build_client_control_body,
        build_client_register_body, build_wallet_external_message, client_register_attached_value,
        read_cocoon_wallet_seqno,
    };
    use rocoon_contract::OWNER_CLIENT_WITHDRAW;
    use std::str::FromStr;
    use ton::block_tlb::Msg;
    use ton::ton_core::cell::TonCell;
    use ton::ton_core::traits::tlb::TLB;
    use ton::ton_core::types::TonAddress;

    #[test]
    fn cocoon_wallet_seqno_is_first_u32_in_data_cell() -> anyhow::Result<()> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let cell =
            rocoon_contract::CocoonWalletData::from_public_key(owner, &[9_u8; 32])?.to_cell()?;

        assert_eq!(read_cocoon_wallet_seqno(Some(&cell))?, Some(0));
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
    fn client_register_body_matches_cpp_layout() -> anyhow::Result<()> {
        let wallet = TonAddress::from_str("UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi")?;
        let cell = build_client_register_body(99, 42, &wallet)?;
        let mut parser = cell.parser();

        assert_eq!(parser.read_num::<u32>(32)?, OWNER_CLIENT_REGISTER);
        assert_eq!(parser.read_num::<u64>(64)?, 42);
        assert_eq!(parser.read_num::<u64>(64)?, 99);
        assert_eq!(TonAddress::read(&mut parser)?, wallet);
        parser.ensure_empty()?;
        Ok(())
    }

    #[test]
    fn client_register_value_depends_on_state_init() -> anyhow::Result<()> {
        let root_config = super::CocoonRootConfig {
            min_client_stake: 15_000_000_000,
            client_sc_code: TonCell::empty().to_owned(),
            client_params_cell: TonCell::empty().to_owned(),
        };

        assert_eq!(
            client_register_attached_value(&root_config, true)?,
            root_config.min_client_stake + CLIENT_REGISTER_EXTRA_NANOTONS
        );
        assert_eq!(
            client_register_attached_value(&root_config, false)?,
            ACTIVE_CLIENT_REGISTER_VALUE_NANOTONS
        );
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
