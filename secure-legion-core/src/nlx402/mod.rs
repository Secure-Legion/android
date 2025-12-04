//! NLx402 Payment Protocol
//!
//! A lightweight 402-style payment protocol for P2P payments.
//! Provides quote generation and payment verification with replay protection.

pub mod quote;
pub mod verify;

pub use quote::{PaymentQuote, QuoteError, create_quote, create_quote_with_expiry, parse_quote_from_memo};
pub use verify::{VerifyError, verify_payment, verify_payment_simple, extract_quote_hash_from_memo, VerificationResult};

/// Protocol version for NLx402
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// Default quote expiration time in seconds (24 hours)
pub const DEFAULT_QUOTE_EXPIRY_SECS: u64 = 86400;

/// Memo prefix for NLx402 payments
pub const MEMO_PREFIX: &str = "NLx402:";
