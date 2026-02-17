package com.securelegion.services

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.network.OkHttpProvider
import org.bitcoinj.core.Base58
import java.io.IOException
import java.nio.ByteBuffer
import java.util.UUID

/**
 * ShadowWire Privacy Pool API Client
 *
 * Interacts with ShadowWire REST API for private Solana transactions
 * using Bulletproof zero-knowledge proofs.
 *
 * All traffic routed through Tor SOCKS5 proxy via OkHttpProvider.
 *
 * Operations:
 * - Deposit: Move SOL into privacy pool
 * - Withdraw: Pull SOL out of privacy pool
 * - Internal Transfer: Send within pool (amounts hidden via ZK proofs)
 * - External Transfer: Send to any Solana wallet (sender anonymous)
 */
class ShadowWireService(private val context: Context, private val walletId: String = "main") {

    private val keyManager = KeyManager.getInstance(context)
    private val solanaService = SolanaService(context)

    /** Get the Solana address for the active wallet */
    private fun getWalletAddress(): String {
        return keyManager.getWalletSolanaAddress(walletId)
    }

    /** Get the private key for the active wallet */
    private fun getWalletPrivateKey(): ByteArray {
        return if (walletId == "main") {
            keyManager.getSigningKeyBytes()
        } else {
            keyManager.getWalletPrivateKey(walletId)
                ?: throw ShadowWireException("Wallet private key not found: $walletId")
        }
    }

    companion object {
        private const val TAG = "ShadowWireService"
        private const val BASE_URL = "https://shadow.radr.fun/shadowpay/api"
        private const val JSON_CONTENT_TYPE = "application/json"
    }

    private val client get() = OkHttpProvider.getGenericClient()

    /**
     * Safely parse response body as JSON.
     * If the body isn't valid JSON, wrap it in a JSONObject with an "error" field.
     */
    private fun parseResponse(body: String): JSONObject {
        return try {
            JSONObject(body)
        } catch (e: JSONException) {
            Log.w(TAG, "Response is not JSON: $body")
            JSONObject().put("error", body.trim())
        }
    }

    // --- Authentication ---

    /**
     * Generate ShadowWire auth signature
     * Message format: "shadowpay:{transferType}:{nonce}:{timestamp}"
     * Signed with Ed25519 via KeyManager, base58-encoded
     *
     * nonce matches SDK: Math.floor(Date.now() / 1000) — epoch seconds as integer
     */
    private fun generateAuth(transferType: String): SignatureAuth {
        val nonce = (System.currentTimeMillis() / 1000).toString()
        val timestamp = System.currentTimeMillis() / 1000
        val message = "shadowpay:$transferType:$nonce:$timestamp"
        val messageBytes = message.toByteArray(Charsets.UTF_8)
        val privateKey = getWalletPrivateKey()
        val signatureBytes = RustBridge.signData(messageBytes, privateKey)
        val signatureBase58 = Base58.encode(signatureBytes)
        return SignatureAuth(
            nonce = nonce,
            senderSignature = signatureBase58,
            signatureMessage = message
        )
    }

    // --- Pool Balance ---

    /**
     * Get current pool balance for the active wallet
     * @return PoolBalance with available and deposited amounts
     */
    suspend fun getPoolBalance(): Result<PoolBalance> = withContext(Dispatchers.IO) {
        try {
            val wallet = getWalletAddress()
            Log.d(TAG, "Fetching pool balance for: $wallet")

            val request = Request.Builder()
                .url("$BASE_URL/pool/balance/$wallet")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.e(TAG, "Pool balance request failed: ${response.code}")
                    return@withContext Result.failure(IOException("HTTP ${response.code}"))
                }

                val body = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response"))

                val json = JSONObject(body)
                if (json.has("error") && !json.isNull("error") && json.optString("error", "").isNotEmpty()) {
                    return@withContext Result.failure(
                        ShadowWireException(json.getString("error"))
                    )
                }

                val availableRaw = json.optDouble("available", 0.0)
                val depositedRaw = json.optDouble("deposited", 0.0)
                // API returns lamports — convert to SOL if value looks like lamports (>= 1000)
                val lamportsThreshold = 1000.0
                val available = if (availableRaw >= lamportsThreshold) availableRaw / 1_000_000_000.0 else availableRaw
                val deposited = if (depositedRaw >= lamportsThreshold) depositedRaw / 1_000_000_000.0 else depositedRaw
                val balance = PoolBalance(
                    wallet = json.optString("wallet", wallet),
                    available = available,
                    deposited = deposited,
                    poolAddress = json.optString("pool_address", "")
                )
                Log.i(TAG, "Pool balance: ${balance.available} SOL available")
                Result.success(balance)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get pool balance", e)
            Result.failure(e)
        }
    }

    // --- Pool Activity (Local Storage) ---

    /**
     * Save a pool activity item to local storage
     */
    fun savePoolActivity(item: PoolActivityItem) {
        try {
            val prefs = context.getSharedPreferences("pool_activity_$walletId", Context.MODE_PRIVATE)
            val existing = prefs.getString("items", "[]") ?: "[]"
            val array = JSONArray(existing)

            val json = JSONObject().apply {
                put("type", item.type)
                put("amount", item.amount)
                put("timestamp", item.timestamp)
                put("txSignature", item.txSignature)
                put("recipient", item.recipient)
                put("status", item.status)
            }

            // Prepend new item (most recent first)
            val newArray = JSONArray()
            newArray.put(json)
            for (i in 0 until minOf(array.length(), 99)) {
                newArray.put(array.getJSONObject(i))
            }

            prefs.edit().putString("items", newArray.toString()).apply()
            Log.d(TAG, "Saved pool activity: ${item.type} ${item.amount} SOL")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save pool activity", e)
        }
    }

    /**
     * Get pool activity from local storage
     * @param limit Number of items to return
     * @return List of pool activity items
     */
    fun getPoolHistory(limit: Int = 20): List<PoolActivityItem> {
        try {
            val prefs = context.getSharedPreferences("pool_activity_$walletId", Context.MODE_PRIVATE)
            val existing = prefs.getString("items", "[]") ?: "[]"
            val array = JSONArray(existing)

            val items = mutableListOf<PoolActivityItem>()
            for (i in 0 until minOf(array.length(), limit)) {
                val json = array.getJSONObject(i)
                items.add(PoolActivityItem(
                    type = json.optString("type", "unknown"),
                    amount = json.optDouble("amount", 0.0),
                    timestamp = json.optLong("timestamp", 0L),
                    txSignature = json.optString("txSignature", ""),
                    recipient = json.optString("recipient", ""),
                    status = json.optString("status", "confirmed")
                ))
            }

            Log.d(TAG, "Loaded ${items.size} pool activity items from local storage")
            return items
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load pool activity", e)
            return emptyList()
        }
    }

    // --- Deposit ---

    /**
     * Deposit SOL into the privacy pool
     * Returns an unsigned transaction that must be signed and broadcast
     * @param amountLamports Amount in lamports to deposit
     */
    suspend fun deposit(amountLamports: Long): Result<DepositResult> = withContext(Dispatchers.IO) {
        try {
            val wallet = getWalletAddress()
            Log.d(TAG, "Depositing $amountLamports lamports from $wallet")

            val body = JSONObject().apply {
                put("wallet", wallet)
                put("amount", amountLamports)
            }

            Log.d(TAG, "Deposit request body: $body")

            val request = Request.Builder()
                .url("$BASE_URL/pool/deposit")
                .addHeader("Content-Type", JSON_CONTENT_TYPE)
                .post(body.toString().toRequestBody(JSON_CONTENT_TYPE.toMediaType()))
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response"))

                Log.d(TAG, "Deposit response (${response.code}): $responseBody")

                val json = parseResponse(responseBody)
                val hasError = json.has("error") && !json.isNull("error") && json.optString("error", "").isNotEmpty()
                if (!response.isSuccessful || hasError) {
                    val error = json.optString("error", json.optString("message", "Deposit failed"))
                    Log.e(TAG, "Deposit failed: $error")
                    return@withContext Result.failure(ShadowWireException(error))
                }

                val result = DepositResult(
                    unsignedTx = json.optString("unsigned_tx_base64", ""),
                    poolAddress = json.optString("pool_address", ""),
                    userBalancePda = json.optString("user_balance_pda", "")
                )
                Log.i(TAG, "Deposit TX prepared, pool: ${result.poolAddress}")
                Result.success(result)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Deposit failed", e)
            Result.failure(e)
        }
    }

    // --- Withdraw ---

    /**
     * Withdraw SOL from the privacy pool
     * @param amountLamports Amount in lamports to withdraw
     */
    suspend fun withdraw(amountLamports: Long): Result<WithdrawResult> = withContext(Dispatchers.IO) {
        try {
            val wallet = getWalletAddress()
            Log.d(TAG, "Withdrawing $amountLamports lamports to $wallet")

            // Request withdrawal from API (matches SDK: wallet + amount only)
            val body = JSONObject().apply {
                put("wallet", wallet)
                put("amount", amountLamports)
            }

            val request = Request.Builder()
                .url("$BASE_URL/pool/withdraw")
                .addHeader("Content-Type", JSON_CONTENT_TYPE)
                .post(body.toString().toRequestBody(JSON_CONTENT_TYPE.toMediaType()))
                .build()

            Log.d(TAG, "Withdraw request: $body")

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response"))

                Log.d(TAG, "Withdraw response (${response.code}): $responseBody")

                val json = parseResponse(responseBody)
                val hasError = json.has("error") && !json.isNull("error") && json.optString("error", "").isNotEmpty()
                if (!response.isSuccessful || hasError) {
                    val error = json.optString("error", "").ifEmpty {
                        json.optString("message", "").ifEmpty { responseBody.take(200) }
                    }
                    Log.e(TAG, "Withdraw failed: $error")
                    return@withContext Result.failure(ShadowWireException(error))
                }

                val txSignature = json.optString("tx_signature", "")
                val unsignedTxBase64 = json.optString("unsigned_tx_base64", "")

                if (txSignature.isNotEmpty() && txSignature != "null") {
                    // API handled it directly
                    Log.i(TAG, "Withdraw completed server-side: $txSignature")
                    return@withContext Result.success(WithdrawResult(unsignedTx = "", txSignature = txSignature))
                }

                if (unsignedTxBase64.isEmpty()) {
                    return@withContext Result.failure(ShadowWireException("No tx_signature or unsigned_tx returned"))
                }

                // Relayer already signed slot 0 — sign our slot and broadcast (no blockhash change)
                Log.d(TAG, "Got unsigned TX, signing our slot and broadcasting")
                val signedTxBase64 = signTransaction(unsignedTxBase64)
                val broadcastResult = solanaService.broadcastTransaction(signedTxBase64)
                broadcastResult.map { sig ->
                    WithdrawResult(unsignedTx = "", txSignature = sig)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Withdraw failed", e)
            Result.failure(e)
        }
    }

    // --- Internal Transfer (ZK, hidden amounts) ---

    /**
     * Transfer SOL within the privacy pool
     * Amounts are hidden using Bulletproof zero-knowledge proofs
     * @param recipient Recipient's Solana wallet address
     * @param amountLamports Amount in lamports
     */
    suspend fun internalTransfer(
        recipient: String,
        amountLamports: Long
    ): Result<TransferResult> = withContext(Dispatchers.IO) {
        try {
            val wallet = getWalletAddress()
            val auth = generateAuth("internal_transfer")
            Log.d(TAG, "Internal transfer $amountLamports lamports to $recipient")

            // Generate Bulletproof range proof (proves amount in [0, 2^64) without revealing it)
            val zkProof = RustBridge.generateRangeProofParsed(amountLamports)
            val proofBase64 = android.util.Base64.encodeToString(zkProof.proofBytes, android.util.Base64.NO_WRAP)
            val commitmentBase64 = android.util.Base64.encodeToString(zkProof.commitment, android.util.Base64.NO_WRAP)
            Log.d(TAG, "Generated ZK range proof: ${zkProof.proofBytes.size} bytes, commitment: 32 bytes")

            val body = JSONObject().apply {
                put("sender_wallet", wallet)
                put("recipient_wallet", recipient)
                put("amount", amountLamports)
                put("token", "SOL")
                put("nonce", auth.nonce)
                put("proof_bytes", proofBase64)
                put("commitment", commitmentBase64)
                put("sender_signature", auth.senderSignature)
                put("signature_message", auth.signatureMessage)
            }

            val request = Request.Builder()
                .url("$BASE_URL/zk/internal-transfer")
                .post(body.toString().toRequestBody(JSON_CONTENT_TYPE.toMediaType()))
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response"))

                val json = parseResponse(responseBody)
                val hasError = json.has("error") && !json.isNull("error") && json.optString("error", "").isNotEmpty()
                if (!response.isSuccessful || hasError) {
                    val error = json.optString("error", json.optString("message", "Transfer failed"))
                    Log.e(TAG, "Internal transfer failed: $error")
                    return@withContext Result.failure(ShadowWireException(error))
                }

                val result = TransferResult(
                    txSignature = json.optString("tx_signature", ""),
                    success = json.optBoolean("success", true),
                    amountHidden = json.optBoolean("amount_hidden", true)
                )
                Log.i(TAG, "Internal transfer completed: ${result.txSignature}")
                Result.success(result)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Internal transfer failed", e)
            Result.failure(e)
        }
    }

    // --- External Transfer (anonymous sender) ---

    /**
     * Transfer SOL from the pool to any Solana wallet
     * Sender identity is anonymized, amount is visible
     * @param recipient Recipient's Solana wallet address
     * @param amountLamports Amount in lamports
     */
    suspend fun externalTransfer(
        recipient: String,
        amountLamports: Long
    ): Result<TransferResult> = withContext(Dispatchers.IO) {
        try {
            val wallet = getWalletAddress()
            val auth = generateAuth("external_transfer")
            Log.d(TAG, "External transfer $amountLamports lamports to $recipient")

            // Generate Bulletproof range proof for external transfers too
            val zkProof = RustBridge.generateRangeProofParsed(amountLamports)
            val proofBase64 = android.util.Base64.encodeToString(zkProof.proofBytes, android.util.Base64.NO_WRAP)
            val commitmentBase64 = android.util.Base64.encodeToString(zkProof.commitment, android.util.Base64.NO_WRAP)
            Log.d(TAG, "Generated ZK range proof: ${zkProof.proofBytes.size} bytes")

            val body = JSONObject().apply {
                put("sender_wallet", wallet)
                put("recipient_wallet", recipient)
                put("amount", amountLamports)
                put("token", "SOL")
                put("nonce", auth.nonce)
                put("proof_bytes", proofBase64)
                put("commitment", commitmentBase64)
                put("sender_signature", auth.senderSignature)
                put("signature_message", auth.signatureMessage)
            }

            val request = Request.Builder()
                .url("$BASE_URL/zk/external-transfer")
                .post(body.toString().toRequestBody(JSON_CONTENT_TYPE.toMediaType()))
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response"))

                val json = parseResponse(responseBody)
                val hasError = json.has("error") && !json.isNull("error") && json.optString("error", "").isNotEmpty()
                if (!response.isSuccessful || hasError) {
                    val error = json.optString("error", json.optString("message", "Transfer failed"))
                    Log.e(TAG, "External transfer failed: $error")
                    return@withContext Result.failure(ShadowWireException(error))
                }

                val result = TransferResult(
                    txSignature = json.optString("tx_signature", ""),
                    success = json.optBoolean("success", true),
                    amountHidden = false
                )
                Log.i(TAG, "External transfer completed: ${result.txSignature}")
                Result.success(result)
            }
        } catch (e: Exception) {
            Log.e(TAG, "External transfer failed", e)
            Result.failure(e)
        }
    }

    // --- Sign & Broadcast Unsigned TX ---

    /**
     * Replace the blockhash in a Solana transaction message with a fresh one.
     * Message format: [header 3 bytes] [compact-u16 num accounts] [N * 32 byte accounts] [32 byte blockhash] [instructions...]
     * Returns the modified TX bytes with all signatures zeroed out (must re-sign after).
     */
    private fun replaceBlockhash(txBytes: ByteArray, newBlockhashBytes: ByteArray): ByteArray {
        val sigCount = txBytes[0].toInt() and 0xFF
        val sigSectionSize = 1 + (sigCount * 64)
        val msgStart = sigSectionSize

        // Parse message header (3 bytes)
        // byte 0: num required signatures
        // byte 1: num readonly signed
        // byte 2: num readonly unsigned
        val headerOffset = msgStart
        // val numRequiredSigs = txBytes[headerOffset].toInt() and 0xFF

        // Parse compact-u16 for account count (at offset msgStart + 3)
        val accountCountOffset = headerOffset + 3
        val (numAccounts, accountCountSize) = readCompactU16(txBytes, accountCountOffset)

        // Blockhash is right after all account public keys
        val accountsStart = accountCountOffset + accountCountSize
        val blockhashOffset = accountsStart + (numAccounts * 32)

        Log.d(TAG, "Replacing blockhash at offset $blockhashOffset (sigSection=$sigSectionSize, accounts=$numAccounts)")

        val modified = txBytes.copyOf()
        // Replace blockhash
        System.arraycopy(newBlockhashBytes, 0, modified, blockhashOffset, 32)
        // Zero out all signatures (message changed, all sigs are now invalid)
        for (i in 0 until sigCount) {
            val sigOffset = 1 + (i * 64)
            for (j in sigOffset until sigOffset + 64) {
                modified[j] = 0
            }
        }
        return modified
    }

    /** Read a compact-u16 from a byte array. Returns (value, bytesConsumed). */
    private fun readCompactU16(data: ByteArray, offset: Int): Pair<Int, Int> {
        val b0 = data[offset].toInt() and 0xFF
        if (b0 < 0x80) return Pair(b0, 1)
        val b1 = data[offset + 1].toInt() and 0xFF
        if (b1 < 0x80) return Pair((b0 and 0x7F) or (b1 shl 7), 2)
        val b2 = data[offset + 2].toInt() and 0xFF
        return Pair((b0 and 0x7F) or ((b1 and 0x7F) shl 7) or (b2 shl 14), 3)
    }

    /**
     * Sign an unsigned Solana transaction (without broadcasting).
     * Optionally replaces the blockhash with a fresh one.
     * Returns the signed transaction as base64.
     */
    fun signTransaction(unsignedTxBase64: String, freshBlockhashBytes: ByteArray? = null): String {
        var txBytes = android.util.Base64.decode(unsignedTxBase64, android.util.Base64.DEFAULT)

        // Replace blockhash if provided (zeros all signatures)
        if (freshBlockhashBytes != null) {
            txBytes = replaceBlockhash(txBytes, freshBlockhashBytes)
            Log.d(TAG, "Replaced blockhash in TX")
        }

        val sigCount = txBytes[0].toInt() and 0xFF
        val sigSectionSize = 1 + (sigCount * 64)
        val message = txBytes.copyOfRange(sigSectionSize, txBytes.size)

        val privateKey = getWalletPrivateKey()
        val signature = RustBridge.signData(message, privateKey)
        Log.d(TAG, "signTransaction: ${message.size} byte message, $sigCount sig(s)")

        val signedTxBytes = txBytes.copyOf()
        for (i in 0 until sigCount) {
            val offset = 1 + (i * 64)
            val isPlaceholder = (offset until offset + 64).all { signedTxBytes[it] == 0.toByte() }
            if (isPlaceholder) {
                System.arraycopy(signature, 0, signedTxBytes, offset, 64)
                Log.d(TAG, "Replaced placeholder at slot $i")
                break
            }
        }

        return android.util.Base64.encodeToString(signedTxBytes, android.util.Base64.NO_WRAP)
    }

    /**
     * Sign an unsigned Solana transaction from the ShadowWire API and broadcast it.
     * Fetches a fresh blockhash to avoid stale blockhash errors, then re-signs.
     * Only works for single-signer TXs (deposits). For multi-sig (withdrawals), use the two-step API flow.
     */
    suspend fun signAndBroadcast(unsignedTxBase64: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            // Fetch fresh blockhash
            val blockhashResult = solanaService.getRecentBlockhash()
            if (blockhashResult.isFailure) {
                return@withContext Result.failure(
                    ShadowWireException("Failed to get blockhash: ${blockhashResult.exceptionOrNull()?.message}")
                )
            }
            val blockhash = blockhashResult.getOrThrow()
            val blockhashBytes = Base58.decode(blockhash)
            Log.d(TAG, "Fresh blockhash: $blockhash")

            // Sign with fresh blockhash (replaces stale one, zeros all sigs, then signs our slot)
            val signedTxBase64 = signTransaction(unsignedTxBase64, blockhashBytes)
            Log.d(TAG, "Broadcasting deposit TX with fresh blockhash")

            // Broadcast via SolanaService
            solanaService.broadcastTransaction(signedTxBase64)
        } catch (e: Exception) {
            Log.e(TAG, "Sign and broadcast failed", e)
            Result.failure(e)
        }
    }

    // --- Fee Calculation ---

    /**
     * Calculate fee for a given amount (0.5% for SOL)
     * @param amountLamports Amount in lamports
     * @return FeeInfo with fee amount and net amount
     */
    fun calculateFee(amountLamports: Long): FeeInfo {
        val fee = (amountLamports * 5) / 1000 // 0.5%
        return FeeInfo(
            feeLamports = fee,
            netLamports = amountLamports - fee,
            feePercent = 0.5
        )
    }

    // --- Data Classes ---

    data class SignatureAuth(
        val nonce: String,
        val senderSignature: String,
        val signatureMessage: String
    )

    data class PoolBalance(
        val wallet: String,
        val available: Double,
        val deposited: Double,
        val poolAddress: String
    )

    data class PoolActivityItem(
        val type: String, // "deposit", "withdraw", "internal_transfer", "external_transfer"
        val amount: Double, // SOL amount
        val timestamp: Long, // epoch millis
        val txSignature: String, // on-chain tx signature
        val recipient: String, // recipient address (for transfers)
        val status: String // "confirmed", "pending", "failed"
    )

    data class DepositResult(
        val unsignedTx: String,
        val poolAddress: String,
        val userBalancePda: String
    )

    data class WithdrawResult(
        val unsignedTx: String,
        val txSignature: String
    )

    data class TransferResult(
        val txSignature: String,
        val success: Boolean,
        val amountHidden: Boolean
    )

    data class FeeInfo(
        val feeLamports: Long,
        val netLamports: Long,
        val feePercent: Double
    )

    class ShadowWireException(message: String) : Exception(message)
}
