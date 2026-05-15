//! Cocoon TL schema bindings and encoding helpers.
//!
//! The Cocoon proxy speaks a TL-based protocol. Most message types in this
//! crate are thin Rust representations of those wire objects and are used only
//! for serialization/deserialization. `tl-proto` handles the objects here, with
//! a custom raw-double writer for `client.runQueryEx` because Cocoon's C++ peer
//! expects IEEE-754 bits rather than `tl-proto`'s normalized `f64` writer.
//! Source of truth: `cocoon/tl/generate/scheme/cocoon_api.tl`.

pub mod client;
pub mod http;
pub mod proxy;
pub mod tokens_used;

pub use client::{
    AuthorizationWithProxy, ConnectedToProxy, PaymentStatus, ProxyConnectionAuth, QueryAnswerEx,
    QueryFinalInfo, RunQueryOptions, WorkerInstanceV2, WorkerTypeV2, WorkerTypesV2,
    decode_authorization_with_proxy, decode_connected_to_proxy, decode_payment_status,
    decode_query_answer_ex, decode_worker_types_v2, encode_authorize_with_proxy_long,
    encode_authorize_with_proxy_short, encode_connect_to_proxy, encode_get_worker_types_v2,
    encode_run_query_ex, encode_update_payment_status,
};
pub use http::{HttpHeader, HttpResponse, decode_http_response, encode_http_request};
pub use proxy::{ProxyParams, SignedPayment};
pub use tokens_used::TokensUsed;
