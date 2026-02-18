package com.securelegion.services

import android.util.Base64
import android.util.Log
import com.securelegion.BuildConfig
import com.securelegion.crypto.RustBridge
import com.securelegion.network.OkHttpProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException

/**
 * Jupiter Ultra Swap API Service
 *
 * Provides Solana token swaps via Jupiter's Ultra API.
 * Two-call flow: getOrder() -> signTransaction() -> execute()
 *
 * All traffic routed through Tor SOCKS proxy.
 * Transaction signing happens locally via RustBridge Ed25519.
 */
class JupiterService {

    companion object {
        private const val TAG = "JupiterService"
        private const val BASE_URL = "https://api.jup.ag/ultra/v1"

        // API key loaded from BuildConfig (sourced from gitignored keystore.properties)
        private val API_KEY = BuildConfig.JUPITER_API_KEY

        // Token mint addresses
        const val SOL_MINT = "So11111111111111111111111111111111111111112"
        const val USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        const val USDT_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
        const val ZEC_MINT = "A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS"
        const val USD1_MINT = "USD1ttGY1N17NEEHLmELoaybftRBUSErhqYiQzvEmuB"
        const val SECURE_MINT = "GFJbQ7WDQry73iTaGkJcXKjvi1ViFTFmHSENgz92jFPP"

        // Referral account for fee collection (80/20 split: integrator keeps 80%)
        const val REFERRAL_ACCOUNT = "D34sNRUsWR2G5P38VpxjQRcb7uj8bZhirQhtPmeQsndY"
        const val REFERRAL_FEE_BPS = 100 // 1% fee (100 basis points)
    }

    private val client get() = OkHttpProvider.getJupiterClient()

    /**
     * Order response from Jupiter Ultra API
     *
     * Response varies by router type (iris aggregator vs jupiterz RFQ):
     * - signatureFeeLamports: number (5000 for iris, 0 for gasless RFQ)
     * - platformFee: optional object with amount + feeBps (RFQ only)
     * - feeBps/feeMint: top-level fee info (both types)
     */
    data class JupiterOrder(
        val requestId: String,
        val transaction: String,
        val inputMint: String,
        val outputMint: String,
        val inAmount: String,
        val outAmount: String,
        val otherAmountThreshold: String,
        val slippageBps: Int,
        val priceImpactPct: String,
        val feeBps: Int,
        val feeMint: String,
        val platformFeeAmount: String,
        val signatureFeeLamports: Long,
        val gasless: Boolean
    )

    /**
     * Execute response from Jupiter Ultra API
     */
    data class JupiterExecuteResult(
        val status: String,
        val signature: String
    )

    /**
     * Get a swap order (unsigned transaction + pricing) from Jupiter Ultra
     *
     * @param inputMint Token mint to swap from
     * @param outputMint Token mint to swap to
     * @param amount Amount in smallest units (lamports for SOL, etc.)
     * @param taker User's Solana public key (base58)
     * @param referralAccount Optional referral account for fee collection
     * @param referralFee Optional fee in basis points (50-255)
     * @return JupiterOrder with unsigned transaction and pricing details
     */
    suspend fun getOrder(
        inputMint: String,
        outputMint: String,
        amount: Long,
        taker: String,
        referralAccount: String? = REFERRAL_ACCOUNT,
        referralFee: Int? = REFERRAL_FEE_BPS
    ): Result<JupiterOrder> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching Jupiter order: $amount $inputMint -> $outputMint for $taker")

            val urlBuilder = "$BASE_URL/order".toHttpUrl().newBuilder()
                .addQueryParameter("inputMint", inputMint)
                .addQueryParameter("outputMint", outputMint)
                .addQueryParameter("amount", amount.toString())
                .addQueryParameter("taker", taker)

            if (referralAccount != null) {
                urlBuilder.addQueryParameter("referralAccount", referralAccount)
            }
            if (referralFee != null) {
                urlBuilder.addQueryParameter("referralFee", referralFee.toString())
            }

            val request = Request.Builder()
                .url(urlBuilder.build())
                .get()
                .addHeader("x-api-key", API_KEY)
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response body"))

                Log.d(TAG, "Order response: ${response.code}")

                if (!response.isSuccessful) {
                    Log.e(TAG, "Order request failed: ${response.code} $responseBody")
                    return@withContext Result.failure(IOException("HTTP ${response.code}: $responseBody"))
                }

                val json = JSONObject(responseBody)

                // Check for error
                if (json.has("errorCode")) {
                    val errorCode = json.getInt("errorCode")
                    val errorMessage = json.optString("error", "Unknown error")
                    Log.e(TAG, "Jupiter order error $errorCode: $errorMessage")
                    return@withContext Result.failure(IOException("Jupiter error $errorCode: $errorMessage"))
                }

                val order = JupiterOrder(
                    requestId = json.getString("requestId"),
                    transaction = json.getString("transaction"),
                    inputMint = json.getString("inputMint"),
                    outputMint = json.getString("outputMint"),
                    inAmount = json.getString("inAmount"),
                    outAmount = json.getString("outAmount"),
                    otherAmountThreshold = json.optString("otherAmountThreshold", "0"),
                    slippageBps = json.optInt("slippageBps", 0),
                    priceImpactPct = json.optString("priceImpactPct", "0"),
                    feeBps = json.optInt("feeBps", 0),
                    feeMint = json.optString("feeMint", ""),
                    platformFeeAmount = json.optJSONObject("platformFee")?.optString("amount", "0") ?: "0",
                    signatureFeeLamports = json.optLong("signatureFeeLamports", 5000),
                    gasless = json.optBoolean("gasless", false)
                )

                Log.i(TAG, "Order received: ${order.inAmount} -> ${order.outAmount}, requestId=${order.requestId}")
                Result.success(order)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get Jupiter order", e)
            Result.failure(e)
        }
    }

    /**
     * Sign a Solana VersionedTransaction returned by Jupiter
     *
     * Flow: decode base64 -> parse compact-u16 sig count -> extract message ->
     *       sign with Ed25519 -> insert signature -> re-encode base64
     *
     * @param base64Transaction Base64-encoded unsigned transaction from Jupiter
     * @param privateKey 32-byte Ed25519 private key
     * @return Base64-encoded signed transaction
     */
    fun signTransaction(base64Transaction: String, privateKey: ByteArray): String {
        val txBytes = Base64.decode(base64Transaction, Base64.DEFAULT)

        // Parse compact-u16 signature count at offset 0
        val (sigCount, sigCountBytes) = readCompactU16(txBytes, 0)
        Log.d(TAG, "Transaction has $sigCount signature slot(s)")

        // Signature slots start after the compact-u16 header
        val sigSlotsStart = sigCountBytes
        // Each signature is 64 bytes
        val messageStart = sigSlotsStart + (sigCount * 64)

        // Extract message bytes (everything after signature slots)
        val message = txBytes.copyOfRange(messageStart, txBytes.size)

        // Sign the message with Ed25519
        val signature = RustBridge.signData(message, privateKey)
        Log.d(TAG, "Signed transaction message (${message.size} bytes), signature: ${signature.size} bytes")

        // Write signature into the first slot
        System.arraycopy(signature, 0, txBytes, sigSlotsStart, 64)

        return Base64.encodeToString(txBytes, Base64.NO_WRAP)
    }

    /**
     * Execute a signed swap transaction via Jupiter Ultra
     *
     * Jupiter handles broadcasting, priority fees, slippage, and tx landing.
     * The same request can be resubmitted within 2 minutes for status polling.
     *
     * @param signedTransaction Base64-encoded signed transaction
     * @param requestId Request ID from the order response
     * @return Execution result with status and on-chain signature
     */
    suspend fun execute(
        signedTransaction: String,
        requestId: String
    ): Result<JupiterExecuteResult> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Executing swap, requestId=$requestId")

            val body = JSONObject().apply {
                put("signedTransaction", signedTransaction)
                put("requestId", requestId)
            }

            val request = Request.Builder()
                .url("$BASE_URL/execute")
                .post(body.toString().toRequestBody("application/json".toMediaType()))
                .addHeader("x-api-key", API_KEY)
                .addHeader("Content-Type", "application/json")
                .build()

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response body"))

                Log.d(TAG, "Execute response: ${response.code}")

                if (!response.isSuccessful) {
                    Log.e(TAG, "Execute request failed: ${response.code} $responseBody")
                    return@withContext Result.failure(IOException("HTTP ${response.code}: $responseBody"))
                }

                val json = JSONObject(responseBody)

                val status = json.optString("status", "Unknown")
                val signature = json.optString("signature", "")

                if (status == "Success") {
                    Log.i(TAG, "Swap executed successfully: $signature")
                } else {
                    Log.w(TAG, "Swap status: $status, signature: $signature")
                }

                Result.success(JupiterExecuteResult(status = status, signature = signature))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to execute swap", e)
            Result.failure(e)
        }
    }

    /**
     * Read a compact-u16 value from a byte array (Solana wire format)
     * @return Pair of (decoded value, number of bytes consumed)
     */
    private fun readCompactU16(data: ByteArray, offset: Int): Pair<Int, Int> {
        var value = 0
        var bytesRead = 0
        var shift = 0
        while (true) {
            val b = data[offset + bytesRead].toInt() and 0xFF
            bytesRead++
            value = value or ((b and 0x7F) shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        return Pair(value, bytesRead)
    }

    /**
     * Get decimal count for a token mint
     */
    fun getDecimals(mint: String): Int = when (mint) {
        SOL_MINT, SECURE_MINT -> 9
        USDC_MINT, USDT_MINT, USD1_MINT -> 6
        ZEC_MINT -> 8
        else -> 9
    }

    /**
     * Convert display amount to smallest units (lamports, etc.)
     */
    fun toSmallestUnits(amount: Double, mint: String): Long {
        val decimals = getDecimals(mint)
        return (amount * Math.pow(10.0, decimals.toDouble())).toLong()
    }

    /**
     * Convert smallest units back to display amount
     */
    fun fromSmallestUnits(amount: String, mint: String): Double {
        val decimals = getDecimals(mint)
        return amount.toLongOrNull()?.toDouble()?.div(Math.pow(10.0, decimals.toDouble())) ?: 0.0
    }

    /**
     * Get mint address for a token symbol
     */
    fun getMint(token: String): String = when (token) {
        "SOL" -> SOL_MINT
        "USDC" -> USDC_MINT
        "USDT" -> USDT_MINT
        "ZEC" -> ZEC_MINT
        "USD1" -> USD1_MINT
        "SECURE" -> SECURE_MINT
        else -> SOL_MINT
    }

    /**
     * Get token symbol for a mint address
     */
    fun getSymbol(mint: String): String = when (mint) {
        SOL_MINT -> "SOL"
        USDC_MINT -> "USDC"
        USDT_MINT -> "USDT"
        ZEC_MINT -> "ZEC"
        USD1_MINT -> "USD1"
        SECURE_MINT -> "SECURE"
        else -> "Unknown"
    }
}
