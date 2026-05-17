//! TON liteclient access for Cocoon wallet diagnostics and control.
//!
//! The C++ Cocoon client keeps TON wallet state next to the proxy session and
//! exposes it from `/stats`. This module asks liteservers for
//! masterchain/account state, parses Cocoon wallet/client-contract data cells,
//! and contains the narrowly scoped wallet forwarding path used by local
//! `request-withdraw` and `close` CLI commands.

use std::path::Path;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rocoon_contract::{
    CocoonClientContractData, CocoonClientControlAction, CocoonClientControlBody,
    CocoonClientRegisterBody, CocoonClientSecretHashBody, CocoonClientTopUpBody, CocoonParams,
    CocoonRootStorage, CocoonWalletData, CocoonWalletUnsignedBody, cocoon_client_state_init,
    cocoon_wallet_signed_body,
};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};
use ton::block_tlb::{
    AccountState, CommonMsgInfo, CommonMsgInfoExtIn, CommonMsgInfoInt, CurrencyCollection,
    MaybeAccount, Msg, StateInit,
};
use ton::errors::TonError;
use ton::lite_client::{LiteClient, LiteReqParams};
use ton::ton_core::cell::TonCell;
use ton::ton_core::traits::tlb::TLB;
use ton::ton_core::types::TonAddress;
use ton::ton_core::types::tlb_core::{
    EitherRefLayout, MsgAddress, MsgAddressExt, TLBCoins, TLBEitherRef,
};
use ton_core::errors::TonCoreError;

use rocoon_config::{TonRuntimeConfig, wallet};

pub const CONTROL_MESSAGE_VALUE_NANOTONS: u64 = 700_000_000;
const ACTIVE_CLIENT_REGISTER_VALUE_NANOTONS: u64 = 1_000_000_000;
const CLIENT_TOP_UP_EXTRA_NANOTONS: u64 = 700_000_000;
pub const COCOON_WALLET_RESERVE_NANOTONS: u64 = 10_000_000;
pub const COCOON_WALLET_MIN_BALANCE_NANOTONS: u64 = 2_100_000_000;
const WALLET_FORWARD_MODE: u8 = 0;
const WALLET_EXTERNAL_VALIDITY_SECS: u64 = 3_600;
const EMBEDDED_MAINNET_FULL_TON_CONFIG: &str =
    include_str!("../../../spec/mainnet-full-ton-config.json");

/// Synchronous wrapper around `ton-rs` async liteclient.
pub struct TonReadonlyClient {
    runtime: Runtime,
    client: LiteClient,
    req_params: LiteReqParams,
}

/// Current TON state relevant to local diagnostics.
#[derive(Clone, Debug)]
pub struct TonReadonlySnapshot {
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
    /// Root contract account state, including the registered proxy list.
    pub root_contract: Option<RootContractSnapshot>,
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
    /// Short-auth secret hash stored by the client contract.
    pub secret_hash: Option<[u8; 32]>,
    /// Balance above stake that can be withdrawn.
    pub withdrawable_balance: Option<u64>,
}

/// Parsed Cocoon root contract account snapshot.
#[derive(Clone, Debug)]
pub struct RootContractSnapshot {
    /// TON account state for the root contract.
    pub account_state: TonAccountState,
    /// Last transaction logical time for the root contract account.
    pub last_tx_lt: Option<u64>,
    /// Root contract storage version.
    pub version: Option<u32>,
    /// Last proxy seqno stored in root data.
    pub last_proxy_seqno: Option<u32>,
    /// Registered Cocoon proxy network addresses.
    pub registered_proxies: Vec<RegisteredProxySnapshot>,
}

/// One registered proxy entry from the root contract dictionary.
#[derive(Clone, Debug)]
pub struct RegisteredProxySnapshot {
    /// Proxy registration seqno.
    pub seqno: u32,
    /// Raw address string stored in the root contract.
    pub address: String,
    /// Address used by workers when connecting to this proxy.
    pub address_for_workers: String,
    /// Address used by clients when connecting to this proxy.
    pub address_for_clients: String,
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

/// Inputs needed to top up the client contract request balance.
///
/// C++ sends `ext_client_top_up` separately from long authorization register:
/// register only links the client contract to the proxy, while top-up funds the
/// balance that the proxy later converts into usable request tokens.
pub struct TonClientTopUpRequest<'a> {
    /// External owner wallet address used to build Cocoon wallet state init.
    pub wallet_owner_address: &'a str,
    /// Cocoon wallet contract address.
    pub wallet_address: &'a str,
    /// Mainnet/testnet Cocoon root contract address.
    pub root_contract_address: &'a str,
    /// Client contract address returned by `client.connectToProxy`.
    pub client_contract_address: &'a str,
    /// Ed25519 seed used by the Cocoon wallet contract.
    pub wallet_seed: &'a [u8; 32],
}

/// Inputs needed to update the short-auth secret hash on a client contract.
pub struct TonClientSecretHashRequest<'a> {
    /// External owner wallet address used to build Cocoon wallet state init.
    pub wallet_owner_address: &'a str,
    /// Cocoon wallet contract address.
    pub wallet_address: &'a str,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Connected client contract address returned by `client.connectToProxy`.
    pub client_contract_address: &'a str,
    /// Desired `sha256(secret)` value accepted by short auth.
    pub secret_hash: &'a [u8; 32],
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

/// Signed external message prepared for client contract top-up.
#[derive(Clone, Debug)]
pub struct TonClientTopUpPreparedMessage {
    /// Random query id embedded into `ext_client_top_up`.
    pub query_id: u64,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Amount added to the client request balance, in nanotons.
    pub top_up_amount: u64,
    /// Attached internal message value in nanotons.
    pub attached_value: u64,
    /// Destination client contract address.
    pub client_contract_address: String,
    /// Cocoon wallet address that signed the external message.
    pub wallet_address: String,
    /// Full TON external message BOC.
    pub external_message: Vec<u8>,
}

/// Signed external message prepared for `owner_client_change_secret_hash`.
#[derive(Clone, Debug)]
pub struct TonClientSecretHashPreparedMessage {
    /// Random query id embedded into `owner_client_change_secret_hash`.
    pub query_id: u64,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Attached internal message value in nanotons.
    pub attached_value: u64,
    /// Destination client contract address.
    pub client_contract_address: String,
    /// Cocoon wallet address that signed the external message.
    pub wallet_address: String,
    /// Full TON external message BOC.
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

/// Result returned after client contract top-up is accepted by a liteserver.
#[derive(Clone, Debug)]
pub struct TonClientTopUpResult {
    /// Random query id embedded into `ext_client_top_up`.
    pub query_id: u64,
    /// Cocoon wallet seqno used for signing.
    pub wallet_seqno: u32,
    /// Amount added to the client request balance, in nanotons.
    pub top_up_amount: u64,
    /// Attached internal message value in nanotons.
    pub attached_value: u64,
    /// Liteserver send status returned by `liteServer.sendMessage`.
    pub send_status: u32,
    /// Destination client contract address.
    pub client_contract_address: String,
    /// Cocoon wallet address that signed the external message.
    pub wallet_address: String,
}

/// Result returned after secret-hash update is accepted by a liteserver.
#[derive(Clone, Debug)]
pub struct TonClientSecretHashResult {
    /// Random query id embedded into `owner_client_change_secret_hash`.
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
        } else if config.mainnet {
            builder = builder
                .with_net_config_json(EMBEDDED_MAINNET_FULL_TON_CONFIG)
                .context("load embedded mainnet TON config")?;
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
        root_contract_address: Option<&str>,
    ) -> Result<TonReadonlySnapshot> {
        let wallet_address =
            TonAddress::from_str(wallet_address).context("parse Cocoon wallet address")?;
        let client_contract_address = client_contract_address
            .map(TonAddress::from_str)
            .transpose()
            .context("parse Cocoon client contract address")?;
        let root_contract_address = root_contract_address
            .map(TonAddress::from_str)
            .transpose()
            .context("parse Cocoon root contract address")?;
        self.runtime.block_on(self.fetch_accounts_snapshot(
            &wallet_address,
            client_contract_address.as_ref(),
            root_contract_address.as_ref(),
        ))
    }

    /// Fetches the Cocoon root contract state and registered proxy list.
    ///
    /// # Errors
    ///
    /// Returns an error if the root contract address is invalid, liteserver
    /// queries fail, or the contract data cell cannot be parsed.
    pub fn root_contract_snapshot(
        &self,
        root_contract_address: &str,
    ) -> Result<RootContractSnapshot> {
        let root_contract_address = TonAddress::from_str(root_contract_address)
            .context("parse Cocoon root contract address")?;
        self.runtime
            .block_on(self.fetch_root_contract_snapshot(&root_contract_address))
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

    /// Builds and signs an `owner_client_change_secret_hash` message.
    ///
    /// # Errors
    ///
    /// Returns an error if addresses are invalid or signing/cell serialization fails.
    pub fn prepare_client_secret_hash_message(
        request: &TonClientSecretHashRequest<'_>,
    ) -> Result<TonClientSecretHashPreparedMessage> {
        let wallet_owner_address = TonAddress::from_str(request.wallet_owner_address)
            .context("parse Cocoon wallet owner address")?;
        let wallet_address =
            TonAddress::from_str(request.wallet_address).context("parse Cocoon wallet address")?;
        let client_contract_address = TonAddress::from_str(request.client_contract_address)
            .context("parse Cocoon client contract address")?;
        let query_id = random_query_id();
        let client_body =
            build_client_secret_hash_body(request.secret_hash, query_id, &wallet_address)
                .context("build client contract secret hash body")?;
        let internal_msg = build_internal_message(
            &client_contract_address,
            CONTROL_MESSAGE_VALUE_NANOTONS,
            client_body,
        );
        let internal_msg_cell = internal_msg
            .to_cell()
            .context("serialize wallet-forwarded secret hash message")?;

        let external_msg = build_wallet_external_message(
            &wallet_address,
            &wallet_owner_address,
            request.wallet_seed,
            request.wallet_seqno,
            internal_msg_cell,
        )
        .context("build signed Cocoon wallet secret hash message")?;

        Ok(TonClientSecretHashPreparedMessage {
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
        let attached_value = client_register_attached_value();
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

    /// Fetches wallet/root/client state, then builds and signs a top-up if needed.
    ///
    /// # Errors
    ///
    /// Returns an error if TON state cannot be fetched, the client contract is
    /// not active, the Cocoon wallet is underfunded, or serialization fails.
    pub fn prepare_client_top_up_message(
        &self,
        request: &TonClientTopUpRequest<'_>,
    ) -> Result<Option<TonClientTopUpPreparedMessage>> {
        let wallet_owner_address = TonAddress::from_str(request.wallet_owner_address)
            .context("parse Cocoon wallet owner address")?;
        let wallet_address =
            TonAddress::from_str(request.wallet_address).context("parse Cocoon wallet address")?;
        let root_contract_address = TonAddress::from_str(request.root_contract_address)
            .context("parse Cocoon root contract address")?;
        let client_contract_address = TonAddress::from_str(request.client_contract_address)
            .context("parse Cocoon client contract address")?;

        let context = self
            .runtime
            .block_on(self.fetch_client_register_context(
                &wallet_address,
                &root_contract_address,
                &client_contract_address,
            ))
            .context("fetch TON state for client top-up")?;
        if context.client_contract.account_state != TonAccountState::Active {
            anyhow::bail!(
                "Cocoon client contract is not active for top-up: {}",
                context.client_contract.account_state.as_str()
            );
        }

        let Some(top_up_amount) = client_top_up_amount(&context)? else {
            return Ok(None);
        };
        let attached_value = top_up_amount
            .checked_add(CLIENT_TOP_UP_EXTRA_NANOTONS)
            .context("client top-up attached value overflow")?;
        let wallet_seqno = validate_cocoon_wallet_can_send_value(
            request.wallet_address,
            &context.wallet,
            attached_value,
        )?;

        let query_id = random_query_id();
        let client_body = build_client_top_up_body(top_up_amount, query_id, &wallet_address)
            .context("build client contract top-up body")?;
        let internal_msg =
            build_internal_message(&client_contract_address, attached_value, client_body);
        let internal_msg_cell = internal_msg
            .to_cell()
            .context("serialize wallet-forwarded client top-up message")?;

        let external_msg = build_wallet_external_message(
            &wallet_address,
            &wallet_owner_address,
            request.wallet_seed,
            wallet_seqno,
            internal_msg_cell,
        )
        .context("build signed Cocoon wallet client top-up message")?;

        Ok(Some(TonClientTopUpPreparedMessage {
            query_id,
            wallet_seqno,
            top_up_amount,
            attached_value,
            client_contract_address: request.client_contract_address.to_string(),
            wallet_address: request.wallet_address.to_string(),
            external_message: external_msg,
        }))
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

    /// Sends a previously prepared Cocoon client secret-hash update.
    ///
    /// # Errors
    ///
    /// Returns an error if the liteserver rejects `sendMessage`.
    pub fn send_prepared_client_secret_hash_message(
        &self,
        message: &TonClientSecretHashPreparedMessage,
    ) -> Result<TonClientSecretHashResult> {
        let send_status = self.send_raw_message(&message.external_message)?;
        Ok(TonClientSecretHashResult {
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

    /// Sends a previously prepared client top-up message.
    ///
    /// # Errors
    ///
    /// Returns an error if the liteserver rejects `sendMessage`.
    pub fn send_prepared_client_top_up_message(
        &self,
        message: &TonClientTopUpPreparedMessage,
    ) -> Result<TonClientTopUpResult> {
        let send_status = self.send_raw_message(&message.external_message)?;
        Ok(TonClientTopUpResult {
            query_id: message.query_id,
            wallet_seqno: message.wallet_seqno,
            top_up_amount: message.top_up_amount,
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
        root_contract_address: Option<&TonAddress>,
    ) -> Result<TonReadonlySnapshot> {
        let masterchain = self
            .client
            .get_mc_info()
            .await
            .context("get TON masterchain info")?;
        let account = self
            .get_account_state_allowing_empty(wallet_address, masterchain.last.seqno)
            .await
            .context("get Cocoon wallet account state")?;
        let wallet =
            TonWalletSnapshot::from_account(&account).context("parse Cocoon wallet account")?;
        let client_contract = if let Some(address) = client_contract_address {
            let account = self
                .get_account_state_allowing_empty(address, masterchain.last.seqno)
                .await
                .context("get Cocoon client contract account state")?;
            Some(
                ClientContractSnapshot::from_account(&account)
                    .context("parse Cocoon client contract account")?,
            )
        } else {
            None
        };
        let root_contract = if let Some(root_contract_address) = root_contract_address {
            Some(
                self.fetch_root_contract_snapshot_at(root_contract_address, masterchain.last.seqno)
                    .await?,
            )
        } else {
            None
        };
        Ok(TonReadonlySnapshot {
            ok: true,
            last_error: None,
            masterchain_seqno: Some(masterchain.last.seqno),
            wallet: Some(wallet),
            client_contract,
            root_contract,
        })
    }

    async fn fetch_root_contract_snapshot(
        &self,
        root_contract_address: &TonAddress,
    ) -> Result<RootContractSnapshot> {
        let masterchain = self
            .client
            .get_mc_info()
            .await
            .context("get TON masterchain info")?;
        self.fetch_root_contract_snapshot_at(root_contract_address, masterchain.last.seqno)
            .await
    }

    async fn fetch_root_contract_snapshot_at(
        &self,
        root_contract_address: &TonAddress,
        masterchain_seqno: u32,
    ) -> Result<RootContractSnapshot> {
        let account = self
            .client
            .get_account_state(
                root_contract_address,
                masterchain_seqno,
                Some(self.req_params),
            )
            .await
            .context("get Cocoon root contract account state")?;
        RootContractSnapshot::from_account(&account).context("parse Cocoon root contract account")
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
            .get_account_state_allowing_empty(wallet_address, masterchain.last.seqno)
            .await
            .context("get Cocoon wallet account state")?;
        let root_account = self
            .get_account_state_allowing_empty(root_contract_address, masterchain.last.seqno)
            .await
            .context("get Cocoon root contract account state")?;
        let client_contract_account = self
            .get_account_state_allowing_empty(client_contract_address, masterchain.last.seqno)
            .await
            .context("get Cocoon client contract account state")?;
        Ok(ClientRegisterContext {
            wallet: TonWalletSnapshot::from_account(&wallet_account)
                .context("parse Cocoon wallet account")?,
            root_config: root_config_from_account(&root_account)
                .context("parse Cocoon root contract")?,
            client_contract: ClientContractSnapshot::from_account(&client_contract_account)
                .context("parse Cocoon client contract account")?,
        })
    }

    async fn get_account_state_allowing_empty(
        &self,
        address: &TonAddress,
        masterchain_seqno: u32,
    ) -> Result<MaybeAccount> {
        match self
            .client
            .get_account_state(address, masterchain_seqno, Some(self.req_params))
            .await
        {
            Ok(account) => Ok(account),
            Err(error) if is_empty_account_boc_error(&error) => Ok(MaybeAccount::default()),
            Err(error) => Err(error.into()),
        }
    }
}

impl TonReadonlySnapshot {
    /// Snapshot for a configured liteclient that could not be initialized.
    pub const fn failed(error: String) -> Self {
        Self {
            ok: false,
            last_error: Some(error),
            masterchain_seqno: None,
            wallet: None,
            client_contract: None,
            root_contract: None,
        }
    }
}

impl TonWalletSnapshot {
    fn from_account(account: &MaybeAccount) -> Result<Self> {
        let state = account_state(account);
        Ok(Self {
            balance: wallet_balance(account)?,
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
            secret_hash: data.as_ref().map(|data| *data.secret_hash.as_slice_sized()),
            withdrawable_balance: balance
                .zip(stake)
                .map(|(balance, stake)| balance.saturating_sub(stake)),
        })
    }
}

impl RootContractSnapshot {
    fn from_account(account: &MaybeAccount) -> Result<Self> {
        let state = account_state(account);
        let data = read_root_contract_storage(account.get_data())?;
        Ok(Self {
            account_state: state,
            last_tx_lt: last_tx_lt(account),
            version: data.as_ref().map(|storage| storage.version),
            last_proxy_seqno: data.as_ref().map(|storage| storage.data.last_proxy_seqno),
            registered_proxies: data.map_or_else(Vec::new, registered_proxy_snapshots),
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
    price_per_token: u64,
    client_sc_code: TonCell,
    client_params_cell: TonCell,
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

fn root_config_from_account(account: &MaybeAccount) -> Result<CocoonRootConfig> {
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

fn parse_root_config_from_data(data: &TonCell) -> Result<CocoonRootConfig> {
    let root_storage = CocoonRootStorage::from_cell(data).context("read Cocoon root storage")?;
    let params_cell = root_storage.params.into_inner();
    let root_params = CocoonParams::from_cell(&params_cell).context("parse root params cell")?;
    let client_params_cell = root_params
        .without_code_refs()
        .to_cell()
        .context("build client params cell without code refs")?;
    let client_sc_code = root_params
        .client_sc_code
        .clone()
        .context("root params do not contain client smart-contract code")?;

    Ok(CocoonRootConfig {
        min_client_stake: root_params
            .min_client_stake
            .to_u64()
            .context("convert min_client_stake to u64")?,
        price_per_token: root_params
            .price_per_token
            .to_u64()
            .context("convert price_per_token to u64")?,
        client_sc_code,
        client_params_cell,
    })
}

const fn client_register_attached_value() -> u64 {
    ACTIVE_CLIENT_REGISTER_VALUE_NANOTONS
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
        TonAccountState::None | TonAccountState::Uninit => 0,
        TonAccountState::Frozen => {
            anyhow::bail!(
                "Cocoon wallet account cannot send messages: {}",
                snapshot.state.as_str()
            );
        }
    };
    let balance = snapshot
        .balance
        .context("Cocoon wallet balance is unavailable")?;
    let required_for_message = value_nanotons.saturating_add(COCOON_WALLET_RESERVE_NANOTONS);
    let required_balance = required_for_message.max(COCOON_WALLET_MIN_BALANCE_NANOTONS);
    if balance < required_balance {
        let missing_balance = required_balance - balance;
        anyhow::bail!(
            "ACTION REQUIRED: Cocoon wallet {wallet_address} balance is too low: current={balance} nanotons, required={required_balance} nanotons, missing={missing_balance} nanotons. Required balance is max(message value {value_nanotons} + reserve {COCOON_WALLET_RESERVE_NANOTONS}, minimum wallet balance {COCOON_WALLET_MIN_BALANCE_NANOTONS}). Top up the Cocoon wallet before retrying."
        );
    }
    Ok(wallet_seqno)
}

fn read_root_contract_storage(data: Option<&TonCell>) -> Result<Option<CocoonRootStorage>> {
    let Some(data) = data else {
        return Ok(None);
    };
    CocoonRootStorage::from_cell(data)
        .map(Some)
        .context("read Cocoon root storage")
}

fn registered_proxy_snapshots(storage: CocoonRootStorage) -> Vec<RegisteredProxySnapshot> {
    let data = storage.data.into_inner();
    let mut registered_proxies = data
        .registered_proxies
        .into_iter()
        .map(|(seqno, value)| registered_proxy_snapshot(seqno, value.address))
        .collect::<Vec<_>>();
    registered_proxies.sort_by_key(|proxy| proxy.seqno);
    registered_proxies
}

fn registered_proxy_snapshot(seqno: u32, address: String) -> RegisteredProxySnapshot {
    let normalized_address = address.trim();
    let (address_for_workers, address_for_clients) =
        if let Some((workers, clients)) = normalized_address.split_once(' ') {
            (workers.trim().to_string(), clients.trim().to_string())
        } else {
            let address = normalized_address.to_string();
            (address.clone(), address)
        };
    RegisteredProxySnapshot {
        seqno,
        address,
        address_for_workers,
        address_for_clients,
    }
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

fn wallet_balance(account: &MaybeAccount) -> Result<Option<u64>> {
    match account {
        MaybeAccount::None(_) => Ok(Some(0)),
        MaybeAccount::Account(_) => account
            .get_balance()
            .map(ton::ton_core::types::tlb_core::TLBCoins::to_u64)
            .transpose()
            .context("convert wallet balance to u64 nanotons"),
    }
}

fn is_empty_account_boc_error(error: &TonError) -> bool {
    matches!(
        error,
        TonError::TLCoreError(TonCoreError::DataError { msg, .. })
            if msg.contains("Can't read BOC from empty slice")
    )
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
    CocoonClientRegisterBody::new(query_id, nonce, wallet_address.clone())
        .to_cell()
        .context("build client contract register body cell")
}

fn build_client_secret_hash_body(
    secret_hash: &[u8; 32],
    query_id: u64,
    wallet_address: &TonAddress,
) -> Result<TonCell> {
    CocoonClientSecretHashBody::new(query_id, secret_hash, wallet_address.clone())?
        .to_cell()
        .context("build client contract secret hash body cell")
}

fn build_client_top_up_body(
    top_up_amount: u64,
    query_id: u64,
    wallet_address: &TonAddress,
) -> Result<TonCell> {
    CocoonClientTopUpBody::new(query_id, top_up_amount, wallet_address.clone())
        .to_cell()
        .context("build client contract top-up body cell")
}

fn client_top_up_amount(context: &ClientRegisterContext) -> Result<Option<u64>> {
    let stake = context
        .client_contract
        .stake
        .unwrap_or(context.root_config.min_client_stake);
    if context.root_config.price_per_token == 0 {
        return Ok(None);
    }
    let balance = context
        .client_contract
        .balance
        .context("Cocoon client contract request balance is unavailable")?;
    let available_tokens = balance / context.root_config.price_per_token;
    let stake_tokens = stake / context.root_config.price_per_token;
    if available_tokens >= stake_tokens / 2 {
        return Ok(None);
    }

    let rounded = stake - stake % context.root_config.price_per_token;
    if rounded == 0 {
        anyhow::bail!("client top-up amount rounded to zero");
    }
    Ok(Some(rounded))
}

fn build_client_contract_state_init(
    root_config: &CocoonRootConfig,
    wallet_address: &TonAddress,
    proxy_contract_address: &TonAddress,
    proxy_public_key: &[u8; 32],
) -> Result<StateInit> {
    cocoon_client_state_init(
        root_config.client_sc_code.clone(),
        wallet_address.clone(),
        proxy_contract_address.clone(),
        proxy_public_key,
        root_config.min_client_stake,
        root_config.client_params_cell.clone(),
    )
    .context("build client contract state init")
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
        ACTIVE_CLIENT_REGISTER_VALUE_NANOTONS, CLIENT_TOP_UP_EXTRA_NANOTONS,
        COCOON_WALLET_MIN_BALANCE_NANOTONS, COCOON_WALLET_RESERVE_NANOTONS,
        CONTROL_MESSAGE_VALUE_NANOTONS, ClientContractSnapshot, ClientRegisterContext,
        CocoonRootConfig, EMBEDDED_MAINNET_FULL_TON_CONFIG, TonAccountState, TonControlAction,
        TonWalletSnapshot, build_client_control_body, build_client_register_body,
        build_client_top_up_body, build_wallet_external_message, client_register_attached_value,
        client_top_up_amount, parse_root_config_from_data, read_cocoon_wallet_seqno,
        validate_cocoon_wallet_can_send_value,
    };
    use rocoon_config::wallet;
    use rocoon_contract::{
        CocoonParams, CocoonRootData, CocoonRootStorage, EXT_CLIENT_TOP_UP, OWNER_CLIENT_REGISTER,
        OWNER_CLIENT_WITHDRAW,
    };
    use std::collections::HashMap;
    use std::str::FromStr;
    use ton::block_tlb::{MaybeAccount, Msg};
    use ton::lite_client::LiteClient;
    use ton::ton_core::cell::TonCell;
    use ton::ton_core::traits::tlb::TLB;
    use ton::ton_core::types::TonAddress;
    use ton::ton_core::types::tlb_core::TLBCoins;

    #[test]
    fn embedded_mainnet_config_is_valid_for_lite_client_builder() -> anyhow::Result<()> {
        LiteClient::builder()?.with_net_config_json(EMBEDDED_MAINNET_FULL_TON_CONFIG)?;

        Ok(())
    }

    #[test]
    fn cocoon_wallet_seqno_is_first_u32_in_data_cell() -> anyhow::Result<()> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let cell =
            rocoon_contract::CocoonWalletData::from_public_key(owner, &[9_u8; 32])?.to_cell()?;

        assert_eq!(read_cocoon_wallet_seqno(Some(&cell))?, Some(0));
        Ok(())
    }

    #[test]
    #[allow(clippy::zero_sized_map_values)]
    fn root_config_uses_contract_storage_and_params_layout() -> anyhow::Result<()> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let client_code = TonCell::empty().to_owned();
        let params_cell = CocoonParams {
            struct_version: 4,
            params_version: 1,
            unique_id: 2,
            is_test: false,
            price_per_token: TLBCoins::new(25),
            worker_fee_per_token: TLBCoins::new(10),
            prompt_tokens_price_multiplier: 10_000,
            cached_tokens_price_multiplier: 10_000,
            completion_tokens_price_multiplier: 10_000,
            reasoning_tokens_price_multiplier: 10_000,
            proxy_delay_before_close: 60,
            client_delay_before_close: 120,
            min_proxy_stake: TLBCoins::new(1_000),
            min_client_stake: TLBCoins::new(2_000),
            proxy_sc_code: None,
            worker_sc_code: None,
            client_sc_code: Some(client_code.clone()),
        }
        .to_cell()?;
        let root_cell = CocoonRootStorage {
            owner_address: owner,
            version: 7,
            data: CocoonRootData {
                proxy_hashes: HashMap::new(),
                registered_proxies: HashMap::new(),
                last_proxy_seqno: 0,
                worker_hashes: HashMap::new(),
                model_hashes: HashMap::new(),
            }
            .into(),
            params: params_cell.into(),
            public_keys_manager_data: TonCell::empty().to_owned().into(),
        }
        .to_cell()?;

        let config = parse_root_config_from_data(&root_cell)?;
        assert_eq!(config.min_client_stake, 2_000);
        assert_eq!(config.price_per_token, 25);
        assert_eq!(config.client_sc_code, client_code);
        assert!(
            CocoonParams::from_cell(&config.client_params_cell)?
                .client_sc_code
                .is_none()
        );
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
    fn client_register_value_matches_cpp_long_auth_register() {
        assert_eq!(
            client_register_attached_value(),
            ACTIVE_CLIENT_REGISTER_VALUE_NANOTONS
        );
    }

    #[test]
    fn client_top_up_body_matches_cpp_layout() -> anyhow::Result<()> {
        let wallet = TonAddress::from_str("UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi")?;
        let cell = build_client_top_up_body(15_000_000_000, 42, &wallet)?;
        let mut parser = cell.parser();

        assert_eq!(parser.read_num::<u32>(32)?, EXT_CLIENT_TOP_UP);
        assert_eq!(parser.read_num::<u64>(64)?, 42);
        assert_eq!(
            ton::ton_core::types::tlb_core::TLBCoins::read(&mut parser)?.to_u64()?,
            15_000_000_000
        );
        assert_eq!(TonAddress::read(&mut parser)?, wallet);
        parser.ensure_empty()?;
        Ok(())
    }

    #[test]
    fn client_top_up_amount_matches_cpp_threshold() -> anyhow::Result<()> {
        let empty_context = client_register_context(0, 15_000_000_000, 20);
        assert_eq!(client_top_up_amount(&empty_context)?, Some(15_000_000_000));

        let half_funded_context = client_register_context(7_500_000_000, 15_000_000_000, 20);
        assert_eq!(client_top_up_amount(&half_funded_context)?, None);

        let no_price_context = client_register_context(0, 15_000_000_000, 0);
        assert_eq!(client_top_up_amount(&no_price_context)?, None);
        Ok(())
    }

    #[test]
    fn client_top_up_attaches_cpp_extra_value() {
        assert_eq!(CLIENT_TOP_UP_EXTRA_NANOTONS, CONTROL_MESSAGE_VALUE_NANOTONS);
    }

    #[test]
    fn cocoon_wallet_send_balance_check_matches_cpp_minimum_and_reserve() -> anyhow::Result<()> {
        let close_value = CONTROL_MESSAGE_VALUE_NANOTONS;
        let low_control_wallet = active_wallet(COCOON_WALLET_MIN_BALANCE_NANOTONS - 1);
        let error =
            validate_cocoon_wallet_can_send_value("wallet", &low_control_wallet, close_value)
                .expect_err("control message below C++ wallet minimum must be rejected");
        assert!(error.to_string().contains("minimum wallet balance"));

        let funded_control_wallet = active_wallet(COCOON_WALLET_MIN_BALANCE_NANOTONS);
        assert_eq!(
            validate_cocoon_wallet_can_send_value("wallet", &funded_control_wallet, close_value)?,
            7
        );

        let top_up_value = 15_700_000_000;
        let required_top_up_balance = top_up_value + COCOON_WALLET_RESERVE_NANOTONS;
        let low_top_up_wallet = active_wallet(required_top_up_balance - 1);
        assert!(
            validate_cocoon_wallet_can_send_value("wallet", &low_top_up_wallet, top_up_value)
                .is_err()
        );

        let funded_top_up_wallet = active_wallet(required_top_up_balance);
        assert_eq!(
            validate_cocoon_wallet_can_send_value("wallet", &funded_top_up_wallet, top_up_value)?,
            7
        );
        Ok(())
    }

    #[test]
    fn missing_cocoon_wallet_account_is_reported_as_zero_balance() -> anyhow::Result<()> {
        let wallet = TonWalletSnapshot::from_account(&MaybeAccount::default())?;

        assert_eq!(wallet.state, TonAccountState::None);
        assert_eq!(wallet.balance, Some(0));
        assert_eq!(wallet.seqno, None);

        let error = validate_cocoon_wallet_can_send_value(
            "wallet",
            &wallet,
            CONTROL_MESSAGE_VALUE_NANOTONS,
        )
        .expect_err("missing wallet account must fail as underfunded");
        assert!(error.to_string().contains("current=0 nanotons"));
        Ok(())
    }

    #[test]
    fn wallet_external_message_adds_state_init_for_seqno_zero() -> anyhow::Result<()> {
        let owner = TonAddress::from_str("UQD5MEMHNCHR-zkATB3elGUvRfNiZAlK_luIj0matDI1xH_H")?;
        let wallet = TonAddress::from_str("UQA9iqwh-HWRz20_M4h5idcVcVesVHL6KVeaaJdCU5Ydq2Bi")?;
        let seed = wallet::decode_node_wallet_key("Eeo22fSR51UZHS9xUVwCGj4oIGa2pGGydUDHfG+YcEw=")?;

        let first_message =
            build_wallet_external_message(&wallet, &owner, &seed, 0, TonCell::empty().to_owned())?;
        let next_message =
            build_wallet_external_message(&wallet, &owner, &seed, 1, TonCell::empty().to_owned())?;

        assert!(Msg::<TonCell>::from_boc(first_message)?.init.is_some());
        assert!(Msg::<TonCell>::from_boc(next_message)?.init.is_none());
        Ok(())
    }

    fn active_wallet(balance: u64) -> TonWalletSnapshot {
        TonWalletSnapshot {
            balance: Some(balance),
            seqno: Some(7),
            state: TonAccountState::Active,
            last_tx_lt: Some(42),
        }
    }

    fn client_register_context(
        balance: u64,
        stake: u64,
        price_per_token: u64,
    ) -> ClientRegisterContext {
        ClientRegisterContext {
            wallet: active_wallet(COCOON_WALLET_MIN_BALANCE_NANOTONS),
            root_config: CocoonRootConfig {
                min_client_stake: stake,
                price_per_token,
                client_sc_code: TonCell::empty().to_owned(),
                client_params_cell: TonCell::empty().to_owned(),
            },
            client_contract: ClientContractSnapshot {
                account_balance: Some(stake),
                account_state: TonAccountState::Active,
                last_tx_lt: Some(1),
                state_raw: Some(0),
                state: Some("running"),
                balance: Some(balance),
                stake: Some(stake),
                tokens_used: Some(0),
                unlock_ts: Some(0),
                secret_hash: Some([0; 32]),
                withdrawable_balance: Some(balance.saturating_sub(stake)),
            },
        }
    }
}
