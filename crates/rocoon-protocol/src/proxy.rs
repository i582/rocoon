//! TL objects in the `proxy.*` namespace.

use tl_proto::TlRead;

/// Proxy metadata returned during connection setup.
///
/// Source TL:
///
/// ```tl
/// proxy.params#d5c5609f
///     flags:#
///     proxy_public_key:int256
///     proxy_owner_address:string
///     proxy_sc_address:string
///     is_test:flags.0?Bool
///     proto_version:flags.1?int
///     = proxy.Params;
/// ```
#[derive(Debug, TlRead)]
#[non_exhaustive]
pub struct ProxyParams<'tl> {
    #[tl(flags)]
    #[doc(hidden)]
    pub flags: (),
    pub proxy_public_key: &'tl [u8; 32],
    pub proxy_owner_address: &'tl [u8],
    pub proxy_sc_address: &'tl [u8],
    #[tl(flags_bit = 0)]
    pub is_test: Option<bool>,
    #[tl(flags_bit = 1)]
    pub proto_version: Option<i32>,
}

/// Optional signed payment data returned by authorization.
///
/// Source TL:
///
/// ```tl
/// proxy.signedPayment
///     data:bytes
///     = proxy.SignedPayment;
/// proxy.signedPaymentEmpty
///     = proxy.SignedPayment;
/// ```
#[derive(Debug, TlRead)]
#[tl(boxed)]
pub enum SignedPayment<'tl> {
    #[tl(id = 0x02998182)]
    Data { data: &'tl [u8] },
    #[tl(id = 0xb347ce64)]
    Empty,
}
