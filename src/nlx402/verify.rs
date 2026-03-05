//! Payment verification for NLx402 protocol
//!
//! Verifies that a transaction is valid payment for a quote:
//! 1. Transaction memo contains the correct quote hash
//! 2. Amount matches (or exceeds) the quoted amount
//! 3. Recipient matches the quoted recipient
//! 4. Quote hasn't expired
//! 5. Transaction signature hasn't been used before (replay protection)

use sha3::{Digest, Sha3_256};
use thiserror::Error;

use super::quote::PaymentQuote;
use super::MEMO_PREFIX;

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Quote has expired")]
    QuoteExpired,
    #[error("Invalid memo format")]
    InvalidMemo,
    #[error("Quote hash mismatch")]
    HashMismatch,
    #[error("Amount insufficient: expected {expected}, got {actual}")]
    InsufficientAmount { expected: u64, actual: u64 },
    #[error("Recipient mismatch: expected {expected}, got {actual}")]
    RecipientMismatch { expected: String, actual: String },
    #[error("Transaction already used (replay attack detected)")]
    ReplayDetected,
    #[error("Transaction not confirmed")]
    NotConfirmed,
    #[error("Token mismatch: expected {expected}, got {actual}")]
    TokenMismatch { expected: String, actual: String },
}

pub type Result<T> = std::result::Result<T, VerifyError>;

/// Result of a successful payment verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// The quote that was paid
    pub quote: PaymentQuote,
    /// Transaction signature
    pub tx_signature: String,
    /// Actual amount paid (may exceed quoted amount)
    pub amount_paid: u64,
    /// Block/slot when transaction was confirmed
    pub confirmed_at: Option<u64>,
}

/// Extract the quote hash from a transaction memo
///
/// # Arguments
/// * `memo` - Transaction memo string
///
/// # Returns
/// The quote hash hex string if the memo is valid NLx402 format
pub fn extract_quote_hash_from_memo(memo: &str) -> Result<String> {
    if !memo.starts_with(MEMO_PREFIX) {
        return Err(VerifyError::InvalidMemo);
    }

    let hash = &memo[MEMO_PREFIX.len()..];
    if hash.len() != 32 {
        // Expecting 16 bytes = 32 hex chars
        return Err(VerifyError::InvalidMemo);
    }

    // Validate it's valid hex
    if hex::decode(hash).is_err() {
        return Err(VerifyError::InvalidMemo);
    }

    Ok(hash.to_string())
}

/// Verify a payment against a quote
///
/// # Arguments
/// * `quote` - The payment quote to verify against
/// * `tx_memo` - Transaction memo containing the quote hash
/// * `tx_amount` - Amount sent in the transaction (in smallest unit)
/// * `tx_recipient` - Recipient address in the transaction
/// * `tx_token` - Token type in the transaction
/// * `tx_signature` - Transaction signature (for replay protection)
/// * `is_confirmed` - Whether the transaction is confirmed on-chain
/// * `check_replay` - Callback to check if tx_signature was already used
///
/// # Returns
/// VerificationResult on success
pub fn verify_payment<F>(
    quote: &PaymentQuote,
    tx_memo: &str,
    tx_amount: u64,
    tx_recipient: &str,
    tx_token: &str,
    tx_signature: &str,
    is_confirmed: bool,
    check_replay: F,
) -> Result<VerificationResult>
where
    F: FnOnce(&str) -> bool, // Returns true if signature was already used
{
    // 1. Check if quote is expired
    if quote.is_expired() {
        return Err(VerifyError::QuoteExpired);
    }

    // 2. Verify memo contains correct quote hash
    let memo_hash = extract_quote_hash_from_memo(tx_memo)?;
    let expected_hash = quote.hash_hex();

    if memo_hash != expected_hash {
        return Err(VerifyError::HashMismatch);
    }

    // 3. Verify recipient matches
    if tx_recipient != quote.recipient {
        return Err(VerifyError::RecipientMismatch {
            expected: quote.recipient.clone(),
            actual: tx_recipient.to_string(),
        });
    }

    // 4. Verify token type matches
    if tx_token != quote.token {
        return Err(VerifyError::TokenMismatch {
            expected: quote.token.clone(),
            actual: tx_token.to_string(),
        });
    }

    // 5. Verify amount is sufficient
    if tx_amount < quote.amount {
        return Err(VerifyError::InsufficientAmount {
            expected: quote.amount,
            actual: tx_amount,
        });
    }

    // 6. Check transaction is confirmed
    if !is_confirmed {
        return Err(VerifyError::NotConfirmed);
    }

    // 7. Check for replay attacks
    if check_replay(tx_signature) {
        return Err(VerifyError::ReplayDetected);
    }

    Ok(VerificationResult {
        quote: quote.clone(),
        tx_signature: tx_signature.to_string(),
        amount_paid: tx_amount,
        confirmed_at: None,
    })
}

/// Simple verification without replay check (for client-side pre-validation)
/// Full verification with replay protection should be done server-side or with a local DB
pub fn verify_payment_simple(
    quote: &PaymentQuote,
    tx_memo: &str,
    tx_amount: u64,
    tx_recipient: &str,
    tx_token: &str,
) -> Result<()> {
    // Check if quote is expired
    if quote.is_expired() {
        return Err(VerifyError::QuoteExpired);
    }

    // Verify memo contains correct quote hash
    let memo_hash = extract_quote_hash_from_memo(tx_memo)?;
    let expected_hash = quote.hash_hex();

    if memo_hash != expected_hash {
        return Err(VerifyError::HashMismatch);
    }

    // Verify recipient matches
    if tx_recipient != quote.recipient {
        return Err(VerifyError::RecipientMismatch {
            expected: quote.recipient.clone(),
            actual: tx_recipient.to_string(),
        });
    }

    // Verify token type matches
    if tx_token != quote.token {
        return Err(VerifyError::TokenMismatch {
            expected: quote.token.clone(),
            actual: tx_token.to_string(),
        });
    }

    // Verify amount is sufficient
    if tx_amount < quote.amount {
        return Err(VerifyError::InsufficientAmount {
            expected: quote.amount,
            actual: tx_amount,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nlx402::quote::create_quote;

    #[test]
    fn test_extract_quote_hash() {
        let memo = "NLx402:1234567890abcdef1234567890abcdef";
        let hash = extract_quote_hash_from_memo(memo).unwrap();
        assert_eq!(hash, "1234567890abcdef1234567890abcdef");
    }

    #[test]
    fn test_invalid_memo() {
        // Wrong prefix
        let result = extract_quote_hash_from_memo("WRONG:1234567890abcdef");
        assert!(result.is_err());

        // Too short
        let result = extract_quote_hash_from_memo("NLx402:abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_payment_success() {
        let quote = create_quote(
            "TestRecipient123",
            1_000_000,
            "SOL",
            None,
            None,
            None,
        ).unwrap();

        let memo = quote.to_memo();

        let result = verify_payment(
            &quote,
            &memo,
            1_000_000,
            "TestRecipient123",
            "SOL",
            "tx_sig_12345",
            true,
            |_| false, // No replay
        );

        assert!(result.is_ok());
        let verification = result.unwrap();
        assert_eq!(verification.amount_paid, 1_000_000);
    }

    #[test]
    fn test_verify_insufficient_amount() {
        let quote = create_quote(
            "TestRecipient",
            1_000_000,
            "SOL",
            None,
            None,
            None,
        ).unwrap();

        let memo = quote.to_memo();

        let result = verify_payment(
            &quote,
            &memo,
            500_000, // Less than quoted
            "TestRecipient",
            "SOL",
            "tx_sig",
            true,
            |_| false,
        );

        assert!(matches!(result, Err(VerifyError::InsufficientAmount { .. })));
    }

    #[test]
    fn test_verify_recipient_mismatch() {
        let quote = create_quote(
            "CorrectRecipient",
            1_000_000,
            "SOL",
            None,
            None,
            None,
        ).unwrap();

        let memo = quote.to_memo();

        let result = verify_payment(
            &quote,
            &memo,
            1_000_000,
            "WrongRecipient",
            "SOL",
            "tx_sig",
            true,
            |_| false,
        );

        assert!(matches!(result, Err(VerifyError::RecipientMismatch { .. })));
    }

    #[test]
    fn test_verify_replay_detected() {
        let quote = create_quote(
            "TestRecipient",
            1_000_000,
            "SOL",
            None,
            None,
            None,
        ).unwrap();

        let memo = quote.to_memo();

        let result = verify_payment(
            &quote,
            &memo,
            1_000_000,
            "TestRecipient",
            "SOL",
            "tx_sig_used",
            true,
            |_| true, // Signature already used
        );

        assert!(matches!(result, Err(VerifyError::ReplayDetected)));
    }

    #[test]
    fn test_verify_simple() {
        let quote = create_quote(
            "TestRecipient",
            1_000_000,
            "USDC",
            None,
            None,
            None,
        ).unwrap();

        let memo = quote.to_memo();

        let result = verify_payment_simple(
            &quote,
            &memo,
            1_000_000,
            "TestRecipient",
            "USDC",
        );

        assert!(result.is_ok());
    }
}
