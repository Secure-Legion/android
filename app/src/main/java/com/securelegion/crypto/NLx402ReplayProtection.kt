package com.securelegion.crypto

import android.content.Context
import android.util.Log
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.UsedSignature

/**
 * NLx402 Replay Protection Manager
 *
 * Prevents the same blockchain transaction from being used to fulfill
 * multiple payment requests. This is a critical security feature.
 *
 * How it works:
 * 1. When a payment is verified, we check if the TX signature exists in our database
 * 2. If it exists, reject the payment (replay attack)
 * 3. If it's new, record the signature and accept the payment
 */
object NLx402ReplayProtection {
    private const val TAG = "NLx402ReplayProtection"

    /**
     * Check if a transaction signature has already been used
     * @return true if signature was already used (REJECT), false if new (OK)
     */
    suspend fun isSignatureUsed(
        context: Context,
        keyManager: KeyManager,
        signature: String
    ): Boolean {
        return try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
            val isUsed = database.usedSignatureDao().isSignatureUsed(signature)

            if (isUsed) {
                Log.w(TAG, "REPLAY DETECTED: Signature $signature was already used!")
            }

            isUsed
        } catch (e: Exception) {
            Log.e(TAG, "Error checking signature: ${e.message}")
            // Fail safe - if we can't check, reject
            true
        }
    }

    /**
     * Record a transaction signature as used
     * Call this AFTER verifying and accepting a payment
     */
    suspend fun recordSignature(
        context: Context,
        keyManager: KeyManager,
        signature: String,
        quoteId: String,
        token: String,
        amount: Long
    ): Boolean {
        return try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            val usedSignature = UsedSignature(
                signature = signature,
                quoteId = quoteId,
                token = token,
                amount = amount
            )

            val id = database.usedSignatureDao().insertSignature(usedSignature)

            if (id > 0) {
                Log.i(TAG, "Recorded signature $signature for quote $quoteId")
                true
            } else {
                Log.w(TAG, "Signature $signature already recorded (duplicate insert)")
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error recording signature: ${e.message}")
            false
        }
    }

    /**
     * Verify a payment with replay protection
     * Combines signature check + NLx402 verification + signature recording
     *
     * @return NLx402Manager.VerificationResult
     */
    suspend fun verifyPaymentWithReplayProtection(
        context: Context,
        keyManager: KeyManager,
        quote: NLx402Manager.PaymentQuote,
        txMemo: String,
        txAmount: Long,
        txRecipient: String,
        txToken: String,
        txSignature: String
    ): NLx402Manager.VerificationResult {
        // Step 1: Check for replay
        val isReplay = isSignatureUsed(context, keyManager, txSignature)
        if (isReplay) {
            return NLx402Manager.VerificationResult.Failed("Transaction already used (replay detected)")
        }

        // Step 2: Verify payment details with NLx402
        val verificationResult = NLx402Manager.verifyPayment(
            quote = quote,
            txMemo = txMemo,
            txAmount = txAmount,
            txRecipient = txRecipient,
            txToken = txToken,
            txSignature = txSignature,
            checkReplay = { false } // We already checked above
        )

        // Step 3: If valid, record the signature
        if (verificationResult is NLx402Manager.VerificationResult.Success) {
            recordSignature(
                context = context,
                keyManager = keyManager,
                signature = txSignature,
                quoteId = quote.quoteId,
                token = txToken,
                amount = txAmount
            )
        }

        return verificationResult
    }

    /**
     * Clean up old signatures (call periodically for maintenance)
     * By default, keeps signatures for 90 days
     */
    suspend fun cleanupOldSignatures(
        context: Context,
        keyManager: KeyManager,
        maxAgeDays: Int = 90
    ) {
        try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)

            val cutoffTime = System.currentTimeMillis() - (maxAgeDays.toLong() * 24 * 60 * 60 * 1000)
            database.usedSignatureDao().cleanupOldSignatures(cutoffTime)

            Log.i(TAG, "Cleaned up signatures older than $maxAgeDays days")
        } catch (e: Exception) {
            Log.e(TAG, "Error cleaning up signatures: ${e.message}")
        }
    }

    /**
     * Get count of recorded signatures (for debugging/stats)
     */
    suspend fun getSignatureCount(
        context: Context,
        keyManager: KeyManager
    ): Int {
        return try {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(context, dbPassphrase)
            database.usedSignatureDao().getCount()
        } catch (e: Exception) {
            Log.e(TAG, "Error getting signature count: ${e.message}")
            0
        }
    }
}
