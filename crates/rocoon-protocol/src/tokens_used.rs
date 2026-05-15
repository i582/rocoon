//! TL object for `tokensUsed`.

use tl_proto::TlRead;

/// Token usage counters inside `QueryFinalInfo`.
///
/// Source TL:
///
/// ```tl
/// tokensUsed
///     prompt_tokens_used:long
///     cached_tokens_used:long
///     completion_tokens_used:long
///     reasoning_tokens_used:long
///     total_tokens_used:long
///     = TokensUsed;
/// ```
#[derive(Debug, Clone, Copy, TlRead)]
pub struct TokensUsed {
    pub prompt_tokens_used: i64,
    pub cached_tokens_used: i64,
    pub completion_tokens_used: i64,
    pub reasoning_tokens_used: i64,
    pub total_tokens_used: i64,
}
