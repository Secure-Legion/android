package com.securelegion.crypto

import android.util.Log
import org.json.JSONObject
import java.math.BigDecimal

/**
 * NLx402 Payment Protocol Manager
 *
 * Provides high-level Kotlin API for NLx402 payments:
 * - Creating payment quotes
 * - Verifying payments
 * - Managing payment requests via chat
 */
object NLx402Manager {
    private const val TAG = "NLx402Manager"

    // Expiry time options in seconds
    const val EXPIRY_15_MIN = 900L
    const val EXPIRY_1_HOUR = 3600L
    const val EXPIRY_6_HOURS = 21600L
    const val EXPIRY_24_HOURS = 86400L
    const val EXPIRY_48_HOURS = 172800L
    const val EXPIRY_7_DAYS = 604800L

    // Default expiry (24 hours)
    const val DEFAULT_EXPIRY_SECS = EXPIRY_24_HOURS

    /**
     * Payment quote data class for Kotlin usage
     */
    data class PaymentQuote(
        val quoteId: String,
        val recipient: String,
        val amount: Long,
        val token: String,
        val description: String?,
        val createdAt: Long,
        val expiresAt: Long,
        val senderHandle: String?,
        val recipientHandle: String?,
        val rawJson: String
    ) {
        val isExpired: Boolean
            get() = System.currentTimeMillis() / 1000 > expiresAt

        val formattedAmount: String
            get() = formatTokenAmount(amount, token)

        val memo: String
            get() = RustBridge.getQuoteMemo(rawJson)

        companion object {
            fun fromJson(json: String): PaymentQuote? {
                return try {
                    val obj = JSONObject(json)
                    PaymentQuote(
                        quoteId = obj.getString("quote_id"),
                        recipient = obj.getString("recipient"),
                        amount = obj.getLong("amount"),
                        token = obj.getString("token"),
                        description = obj.optString("description", null),
                        createdAt = obj.getLong("created_at"),
                        expiresAt = obj.getLong("expires_at"),
                        senderHandle = obj.optString("sender_handle", null),
                        recipientHandle = obj.optString("recipient_handle", null),
                        rawJson = json
                    )
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse quote JSON: ${e.message}")
                    null
                }
            }
        }
    }

    /**
     * Payment verification result
     */
    sealed class VerificationResult {
        data class Success(val quote: PaymentQuote, val txSignature: String) : VerificationResult()
        data class Failed(val reason: String) : VerificationResult()
    }

    /**
     * Create a payment quote with custom expiry
     *
     * @param recipientAddress Recipient wallet address
     * @param amount Amount in smallest unit (lamports/zatoshis)
     * @param token Token type (SOL, ZEC, USDC)
     * @param description Optional description
     * @param senderHandle Optional sender's handle
     * @param recipientHandle Optional recipient's handle
     * @param expirySecs Custom expiry in seconds (default: 24 hours)
     * @return PaymentQuote on success, null on failure
     */
    fun createQuote(
        recipientAddress: String,
        amount: Long,
        token: String,
        description: String? = null,
        senderHandle: String? = null,
        recipientHandle: String? = null,
        expirySecs: Long = DEFAULT_EXPIRY_SECS
    ): PaymentQuote? {
        return try {
            val quoteJson = RustBridge.createPaymentQuote(
                recipientAddress,
                amount,
                token,
                description ?: "",
                senderHandle ?: "",
                recipientHandle ?: "",
                expirySecs
            )
            Log.d(TAG, "Created quote: $quoteJson")
            PaymentQuote.fromJson(quoteJson)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create quote: ${e.message}")
            null
        }
    }

    /**
     * Create a quote from a human-readable amount (e.g., 1.5 SOL)
     */
    fun createQuoteFromAmount(
        recipientAddress: String,
        amount: BigDecimal,
        token: String,
        description: String? = null,
        senderHandle: String? = null,
        recipientHandle: String? = null,
        expirySecs: Long = DEFAULT_EXPIRY_SECS
    ): PaymentQuote? {
        val smallestUnit = convertToSmallestUnit(amount, token)
        return createQuote(recipientAddress, smallestUnit, token, description, senderHandle, recipientHandle, expirySecs)
    }

    /**
     * Get human-readable expiry label
     */
    fun getExpiryLabel(expirySecs: Long): String {
        return when (expirySecs) {
            EXPIRY_15_MIN -> "15 minutes"
            EXPIRY_1_HOUR -> "1 hour"
            EXPIRY_6_HOURS -> "6 hours"
            EXPIRY_24_HOURS -> "24 hours"
            EXPIRY_48_HOURS -> "48 hours"
            EXPIRY_7_DAYS -> "7 days"
            else -> "${expirySecs / 3600} hours"
        }
    }

    /**
     * Get remaining time for a quote
     */
    fun getRemainingTime(quote: PaymentQuote): String {
        val now = System.currentTimeMillis() / 1000
        val remaining = quote.expiresAt - now

        if (remaining <= 0) return "Expired"

        val hours = remaining / 3600
        val minutes = (remaining % 3600) / 60

        return when {
            hours >= 24 -> "${hours / 24}d ${hours % 24}h"
            hours > 0 -> "${hours}h ${minutes}m"
            minutes > 0 -> "${minutes}m"
            else -> "< 1m"
        }
    }

    /**
     * Verify a payment against a quote
     *
     * @param quote The quote to verify against
     * @param txMemo Transaction memo
     * @param txAmount Amount in transaction
     * @param txRecipient Recipient in transaction
     * @param txToken Token type in transaction
     * @param txSignature Transaction signature (for replay protection)
     * @param checkReplay Callback to check if signature was already used
     * @return VerificationResult
     */
    fun verifyPayment(
        quote: PaymentQuote,
        txMemo: String,
        txAmount: Long,
        txRecipient: String,
        txToken: String,
        txSignature: String,
        checkReplay: (String) -> Boolean
    ): VerificationResult {
        // First check if quote is expired
        if (quote.isExpired) {
            return VerificationResult.Failed("Quote has expired")
        }

        // Check replay protection
        if (checkReplay(txSignature)) {
            return VerificationResult.Failed("Transaction already used (replay detected)")
        }

        // Verify with Rust (checks hash, amount, recipient, token)
        val isValid = try {
            RustBridge.verifyPayment(
                quote.rawJson,
                txMemo,
                txAmount,
                txRecipient,
                txToken
            )
        } catch (e: Exception) {
            Log.e(TAG, "Verification error: ${e.message}")
            return VerificationResult.Failed("Verification error: ${e.message}")
        }

        return if (isValid) {
            VerificationResult.Success(quote, txSignature)
        } else {
            VerificationResult.Failed("Payment details do not match quote")
        }
    }

    /**
     * Check if a quote has expired
     */
    fun isQuoteExpired(quoteJson: String): Boolean {
        return RustBridge.isQuoteExpired(quoteJson)
    }

    /**
     * Extract quote hash from transaction memo
     */
    fun extractQuoteHash(memo: String): String? {
        val hash = RustBridge.extractQuoteHashFromMemo(memo)
        return if (hash.isEmpty()) null else hash
    }

    /**
     * Get NLx402 protocol version
     */
    fun getProtocolVersion(): String {
        return RustBridge.getNLx402Version()
    }

    // ==================== HELPER FUNCTIONS ====================

    /**
     * Convert smallest unit to human-readable amount
     */
    fun formatTokenAmount(amount: Long, token: String): String {
        val decimals = getTokenDecimals(token)
        val divisor = BigDecimal.TEN.pow(decimals)
        val humanAmount = BigDecimal(amount).divide(divisor)
        return "${humanAmount.stripTrailingZeros().toPlainString()} $token"
    }

    /**
     * Convert human-readable amount to smallest unit
     */
    fun convertToSmallestUnit(amount: BigDecimal, token: String): Long {
        val decimals = getTokenDecimals(token)
        val multiplier = BigDecimal.TEN.pow(decimals)
        return amount.multiply(multiplier).toLong()
    }

    /**
     * Get decimal places for a token
     */
    private fun getTokenDecimals(token: String): Int {
        return when (token.uppercase()) {
            "SOL" -> 9 // 1 SOL = 1,000,000,000 lamports
            "ZEC" -> 8 // 1 ZEC = 100,000,000 zatoshis
            "USDC" -> 6 // 1 USDC = 1,000,000 micro-USDC
            "USDT" -> 6 // 1 USDT = 1,000,000 micro-USDT
            else -> 9 // Default to 9 decimals
        }
    }

    /**
     * Parse amount string like "1.5" or "1.5 SOL" to BigDecimal
     */
    fun parseAmount(amountStr: String): BigDecimal? {
        return try {
            // Remove token suffix if present
            val numericPart = amountStr.split(" ").firstOrNull() ?: amountStr
            BigDecimal(numericPart.replace(",", ""))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse amount: $amountStr")
            null
        }
    }
}
