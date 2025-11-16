package com.securelegion.services

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.TorManager
import java.io.IOException
import java.util.concurrent.TimeUnit
import android.util.Base64
import org.bitcoinj.core.Base58
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Solana RPC Service
 * Interacts with Solana blockchain via Helius RPC endpoint
 *
 * Free tier: 5 TPS per IP, API key hidden in URL
 *
 * Direct HTTP connection for testing (Tor integration will be added later)
 * Transaction signing happens locally in secure Rust enclave - private keys never exposed
 */
class SolanaService(context: Context) {

    private val keyManager = KeyManager.getInstance(context)

    companion object {
        private const val TAG = "SolanaService"

        // Helius fast mainnet RPC with hidden API key
        // Limited to 5 TPS per IP - ideal for frontend use
        private const val HELIUS_RPC_URL = "https://berget-7aodbg-fast-mainnet.helius-rpc.com"

        // Lamports per SOL (1 SOL = 1 billion lamports)
        private const val LAMPORTS_PER_SOL = 1_000_000_000L

        // System program ID for SOL transfers
        private const val SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
    }

    // Direct HTTP connection (Tor for messaging only, not Solana RPC)
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        .writeTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        .build()

    /**
     * Get SOL balance for a wallet address
     * @param publicKey The Solana public key (base58 encoded)
     * @return Balance in SOL (e.g., 0.5 SOL), or null if error
     */
    suspend fun getBalance(publicKey: String): Result<Double> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching SOL balance for: $publicKey")
            Log.d(TAG, "Making request to: $HELIUS_RPC_URL")

            // Build JSON-RPC 2.0 request
            val rpcRequest = JSONObject().apply {
                put("jsonrpc", "2.0")
                put("id", 1)
                put("method", "getBalance")
                put("params", JSONArray().apply {
                    put(publicKey)
                })
            }

            val requestBody = rpcRequest.toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(HELIUS_RPC_URL)
                .post(requestBody)
                .build()

            Log.d(TAG, "Executing RPC request...")
            client.newCall(request).execute().use { response ->
                Log.d(TAG, "Got response: ${response.code} ${response.message}")
                if (!response.isSuccessful) {
                    Log.e(TAG, "RPC request failed: ${response.code}")
                    return@withContext Result.failure(IOException("HTTP ${response.code}: ${response.message}"))
                }

                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response body"))

                val jsonResponse = JSONObject(responseBody)

                // Check for RPC error
                if (jsonResponse.has("error")) {
                    val error = jsonResponse.getJSONObject("error")
                    val errorMessage = error.optString("message", "Unknown RPC error")
                    Log.e(TAG, "RPC error: $errorMessage")
                    return@withContext Result.failure(IOException("RPC error: $errorMessage"))
                }

                // Extract balance in lamports
                val result = jsonResponse.getJSONObject("result")
                val lamports = result.getLong("value")

                // Convert lamports to SOL
                val balanceSOL = lamports.toDouble() / LAMPORTS_PER_SOL

                Log.i(TAG, "Balance: $balanceSOL SOL ($lamports lamports)")
                Result.success(balanceSOL)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch balance", e)
            Result.failure(e)
        }
    }

    /**
     * Transaction info model
     */
    data class TransactionInfo(
        val signature: String,
        val timestamp: Long,
        val amount: Double,
        val type: String, // "send" or "receive"
        val status: String, // "success" or "failed"
        val otherPartyAddress: String // The address of the other party in the transaction
    )

    /**
     * SPL Token account info
     */
    data class TokenAccount(
        val mint: String,
        val balance: Double,
        val decimals: Int,
        val symbol: String
    )

    /**
     * Get recent transactions with details for a wallet
     * @param publicKey The Solana public key (base58 encoded)
     * @param limit Maximum number of transactions to return (default: 10)
     * @return List of transaction info, or empty list if error
     */
    suspend fun getRecentTransactions(
        publicKey: String,
        limit: Int = 10
    ): Result<List<TransactionInfo>> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching recent transactions for: $publicKey")

            // First get transaction signatures
            val signaturesResult = getSignaturesForAddress(publicKey, limit)
            if (signaturesResult.isFailure) {
                return@withContext Result.failure(signaturesResult.exceptionOrNull()!!)
            }

            val signatures = signaturesResult.getOrNull() ?: emptyList()
            val transactions = mutableListOf<TransactionInfo>()

            // For each signature, get transaction details
            for (signature in signatures) {
                try {
                    val txResult = getTransaction(signature, publicKey)
                    if (txResult.isSuccess) {
                        txResult.getOrNull()?.let { transactions.add(it) }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to get transaction $signature: ${e.message}")
                    // Continue with other transactions
                }
            }

            Log.i(TAG, "Loaded ${transactions.size} transactions")
            Result.success(transactions)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch transactions", e)
            Result.failure(e)
        }
    }

    /**
     * Get transaction details
     */
    private suspend fun getTransaction(signature: String, walletAddress: String): Result<TransactionInfo> {
        try {
            val rpcRequest = JSONObject().apply {
                put("jsonrpc", "2.0")
                put("id", 1)
                put("method", "getTransaction")
                put("params", JSONArray().apply {
                    put(signature)
                    put(JSONObject().apply {
                        put("encoding", "jsonParsed")
                        put("maxSupportedTransactionVersion", 0)
                    })
                })
            }

            val requestBody = rpcRequest.toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(HELIUS_RPC_URL)
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return Result.failure(IOException("HTTP ${response.code}"))
                }

                val responseBody = response.body?.string()
                    ?: return Result.failure(IOException("Empty response"))

                val jsonResponse = JSONObject(responseBody)

                if (jsonResponse.has("error")) {
                    return Result.failure(IOException("RPC error"))
                }

                val result = jsonResponse.getJSONObject("result")
                val blockTime = result.optLong("blockTime", 0L)
                val meta = result.optJSONObject("meta")
                val transaction = result.optJSONObject("transaction")

                // Parse transaction to determine if send or receive
                var amount = 0.0
                var type = "receive"
                var otherPartyAddress = ""

                if (meta != null && transaction != null) {
                    // Get pre and post balances
                    val preBalances = meta.optJSONArray("preBalances")
                    val postBalances = meta.optJSONArray("postBalances")
                    val accountKeys = transaction.getJSONObject("message").getJSONArray("accountKeys")

                    // Find wallet's account index
                    var walletIndex = -1
                    for (i in 0 until accountKeys.length()) {
                        val account = accountKeys.getJSONObject(i)
                        if (account.getString("pubkey") == walletAddress) {
                            walletIndex = i
                            break
                        }
                    }

                    if (walletIndex >= 0 && preBalances != null && postBalances != null) {
                        val preBal = preBalances.getLong(walletIndex)
                        val postBal = postBalances.getLong(walletIndex)
                        val diff = postBal - preBal

                        amount = kotlin.math.abs(diff.toDouble()) / LAMPORTS_PER_SOL
                        type = if (diff < 0) "send" else "receive"

                        // Find the other party's address (the other account that's not the wallet and not a program)
                        for (i in 0 until accountKeys.length()) {
                            if (i != walletIndex && preBalances != null && postBalances != null && i < preBalances.length() && i < postBalances.length()) {
                                val account = accountKeys.getJSONObject(i)
                                val address = account.getString("pubkey")
                                // Check if this account's balance changed (not a program account)
                                val accPreBal = preBalances.getLong(i)
                                val accPostBal = postBalances.getLong(i)
                                if (accPreBal != accPostBal && address != SYSTEM_PROGRAM_ID) {
                                    otherPartyAddress = address
                                    break
                                }
                            }
                        }
                    }
                }

                val status = if (meta?.isNull("err") == false) "failed" else "success"

                return Result.success(
                    TransactionInfo(
                        signature = signature,
                        timestamp = blockTime * 1000, // Convert to milliseconds
                        amount = amount,
                        type = type,
                        status = status,
                        otherPartyAddress = otherPartyAddress
                    )
                )
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse transaction $signature", e)
            return Result.failure(e)
        }
    }

    /**
     * Get SPL token accounts for a wallet
     * @param publicKey The Solana public key (base58 encoded)
     * @return List of token accounts with balances
     */
    suspend fun getTokenAccounts(publicKey: String): Result<List<TokenAccount>> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching token accounts for: $publicKey")

            // Build JSON-RPC 2.0 request for SPL token accounts
            val rpcRequest = JSONObject().apply {
                put("jsonrpc", "2.0")
                put("id", 1)
                put("method", "getTokenAccountsByOwner")
                put("params", JSONArray().apply {
                    put(publicKey)
                    put(JSONObject().apply {
                        put("programId", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") // SPL Token Program
                    })
                    put(JSONObject().apply {
                        put("encoding", "jsonParsed")
                    })
                })
            }

            val requestBody = rpcRequest.toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(HELIUS_RPC_URL)
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.e(TAG, "RPC request failed: ${response.code}")
                    return@withContext Result.failure(IOException("HTTP ${response.code}"))
                }

                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response body"))

                val jsonResponse = JSONObject(responseBody)

                // Check for RPC error
                if (jsonResponse.has("error")) {
                    val error = jsonResponse.getJSONObject("error")
                    val errorMessage = error.optString("message", "Unknown RPC error")
                    Log.e(TAG, "RPC error: $errorMessage")
                    return@withContext Result.failure(IOException("RPC error: $errorMessage"))
                }

                // Parse token accounts
                val result = jsonResponse.getJSONObject("result")
                val value = result.getJSONArray("value")
                val tokenAccounts = mutableListOf<TokenAccount>()

                for (i in 0 until value.length()) {
                    try {
                        val accountObj = value.getJSONObject(i)
                        val account = accountObj.getJSONObject("account")
                        val data = account.getJSONObject("data")
                        val parsed = data.getJSONObject("parsed")
                        val info = parsed.getJSONObject("info")

                        val mint = info.getString("mint")
                        val tokenAmount = info.getJSONObject("tokenAmount")
                        val uiAmount = tokenAmount.getDouble("uiAmount")
                        val decimals = tokenAmount.getInt("decimals")

                        // Get token symbol from known mints
                        val symbol = when (mint) {
                            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" -> "USDC"
                            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB" -> "USDT"
                            "So11111111111111111111111111111111111111112" -> "SOL"
                            else -> "Unknown"
                        }

                        // Only add tokens with non-zero balance
                        if (uiAmount > 0) {
                            tokenAccounts.add(
                                TokenAccount(
                                    mint = mint,
                                    balance = uiAmount,
                                    decimals = decimals,
                                    symbol = symbol
                                )
                            )
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to parse token account: ${e.message}")
                        continue
                    }
                }

                Log.i(TAG, "Found ${tokenAccounts.size} token accounts")
                Result.success(tokenAccounts)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch token accounts", e)
            Result.failure(e)
        }
    }

    /**
     * Get recent transaction signatures for a wallet
     * @param publicKey The Solana public key (base58 encoded)
     * @param limit Maximum number of signatures to return (default: 10)
     * @return List of transaction signatures, or empty list if error
     */
    suspend fun getSignaturesForAddress(
        publicKey: String,
        limit: Int = 10
    ): Result<List<String>> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Fetching transaction signatures for: $publicKey")

            // Build JSON-RPC 2.0 request
            val rpcRequest = JSONObject().apply {
                put("jsonrpc", "2.0")
                put("id", 1)
                put("method", "getSignaturesForAddress")
                put("params", JSONArray().apply {
                    put(publicKey)
                    put(JSONObject().apply {
                        put("limit", limit)
                    })
                })
            }

            val requestBody = rpcRequest.toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(HELIUS_RPC_URL)
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.e(TAG, "RPC request failed: ${response.code}")
                    return@withContext Result.failure(IOException("HTTP ${response.code}"))
                }

                val responseBody = response.body?.string()
                    ?: return@withContext Result.failure(IOException("Empty response body"))

                val jsonResponse = JSONObject(responseBody)

                // Check for RPC error
                if (jsonResponse.has("error")) {
                    val error = jsonResponse.getJSONObject("error")
                    val errorMessage = error.optString("message", "Unknown RPC error")
                    Log.e(TAG, "RPC error: $errorMessage")
                    return@withContext Result.failure(IOException("RPC error: $errorMessage"))
                }

                // Extract signatures
                val result = jsonResponse.getJSONArray("result")
                val signatures = mutableListOf<String>()

                for (i in 0 until result.length()) {
                    val item = result.getJSONObject(i)
                    val signature = item.getString("signature")
                    signatures.add(signature)
                }

                Log.i(TAG, "Found ${signatures.size} transaction signatures")
                Result.success(signatures)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch transaction signatures", e)
            Result.failure(e)
        }
    }

    /**
     * Send SOL transaction
     * @param fromPublicKey Sender's Solana public key (base58)
     * @param toPublicKey Recipient's Solana public key (base58)
     * @param amountSOL Amount in SOL to send
     * @param keyManager KeyManager instance for secure signing
     * @return Transaction signature if successful
     */
    suspend fun sendTransaction(
        fromPublicKey: String,
        toPublicKey: String,
        amountSOL: Double,
        keyManager: KeyManager
    ): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Sending $amountSOL SOL from $fromPublicKey to $toPublicKey")

            // Convert SOL to lamports
            val lamports = (amountSOL * LAMPORTS_PER_SOL).toLong()

            // Step 1: Get recent blockhash
            val blockhashResult = getRecentBlockhash()
            if (blockhashResult.isFailure) {
                return@withContext Result.failure(blockhashResult.exceptionOrNull()!!)
            }
            val blockhash = blockhashResult.getOrNull()!!

            // Step 2: Build transaction message manually
            val fromPubKeyBytes = Base58.decode(fromPublicKey)
            val toPubKeyBytes = Base58.decode(toPublicKey)
            val blockhashBytes = Base58.decode(blockhash)

            // SystemProgram ID
            val systemProgramId = Base58.decode("11111111111111111111111111111111")

            // Build transaction message
            val message = buildTransferMessage(
                fromPubKeyBytes,
                toPubKeyBytes,
                systemProgramId,
                blockhashBytes,
                lamports
            )

            // Step 3: Sign using KeyManager (private key stays secure in Rust)
            val signature = keyManager.signData(message)

            // Step 4: Build final transaction
            val transaction = buildTransaction(signature, message)
            val base64Transaction = Base64.encodeToString(transaction, Base64.NO_WRAP)

            // Step 5: Broadcast transaction
            val broadcastResult = broadcastTransaction(base64Transaction)
            if (broadcastResult.isFailure) {
                return@withContext Result.failure(broadcastResult.exceptionOrNull()!!)
            }

            val txSignature = broadcastResult.getOrNull()!!
            Log.i(TAG, "Transaction sent successfully: $txSignature")
            return@withContext Result.success(txSignature)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send transaction", e)
            Result.failure(e)
        }
    }

    /**
     * Build Solana transfer transaction message
     */
    private fun buildTransferMessage(
        fromPubKey: ByteArray,
        toPubKey: ByteArray,
        systemProgramId: ByteArray,
        recentBlockhash: ByteArray,
        lamports: Long
    ): ByteArray {
        val buffer = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)

        // Message header
        buffer.put(1.toByte()) // 1 required signature
        buffer.put(0.toByte()) // 0 readonly signed accounts
        buffer.put(1.toByte()) // 1 readonly unsigned account (SystemProgram)

        // Account addresses (compact-u16 array)
        buffer.put(3.toByte()) // 3 accounts total
        buffer.put(fromPubKey) // Account 0: sender (writable, signer)
        buffer.put(toPubKey)    // Account 1: recipient (writable)
        buffer.put(systemProgramId) // Account 2: SystemProgram (readonly)

        // Recent blockhash
        buffer.put(recentBlockhash)

        // Instructions (compact-u16 array)
        buffer.put(1.toByte()) // 1 instruction

        // SystemProgram Transfer instruction
        buffer.put(2.toByte()) // program_id_index = 2 (SystemProgram)
        buffer.put(2.toByte()) // 2 accounts in instruction
        buffer.put(0.toByte()) // account index 0 (sender)
        buffer.put(1.toByte()) // account index 1 (recipient)

        // Instruction data (transfer instruction = type 2, + 8 bytes lamports)
        buffer.put(12.toByte()) // data length
        buffer.putInt(2) // instruction type: Transfer
        buffer.putLong(lamports)

        // Return only the used portion of the buffer
        val messageSize = buffer.position()
        val message = ByteArray(messageSize)
        buffer.rewind()
        buffer.get(message)
        return message
    }

    /**
     * Build final transaction with signature
     */
    private fun buildTransaction(signature: ByteArray, message: ByteArray): ByteArray {
        val buffer = ByteBuffer.allocate(signature.size + message.size + 10)

        // Compact-u16 encoded number of signatures
        buffer.put(1.toByte()) // 1 signature

        // Signature
        buffer.put(signature)

        // Message
        buffer.put(message)

        val txSize = buffer.position()
        val transaction = ByteArray(txSize)
        buffer.rewind()
        buffer.get(transaction)
        return transaction
    }

    /**
     * Broadcast signed transaction to blockchain
     */
    private suspend fun broadcastTransaction(base64Transaction: String): Result<String> {
        try {
            val rpcRequest = JSONObject().apply {
                put("jsonrpc", "2.0")
                put("id", 1)
                put("method", "sendTransaction")
                put("params", JSONArray().apply {
                    put(base64Transaction)
                    put(JSONObject().apply {
                        put("encoding", "base64")
                        put("skipPreflight", false)
                        put("preflightCommitment", "confirmed")
                        put("maxRetries", 3)
                    })
                })
            }

            val requestBody = rpcRequest.toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(HELIUS_RPC_URL)
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return Result.failure(IOException("HTTP ${response.code}"))
                }

                val responseBody = response.body?.string()
                    ?: return Result.failure(IOException("Empty response"))

                val jsonResponse = JSONObject(responseBody)

                if (jsonResponse.has("error")) {
                    val error = jsonResponse.getJSONObject("error")
                    val errorMessage = error.optString("message", "Unknown error")
                    Log.e(TAG, "Broadcast error: $errorMessage")
                    return Result.failure(IOException("Transaction failed: $errorMessage"))
                }

                val result = jsonResponse.getString("result")
                Log.i(TAG, "Transaction broadcast successful: $result")
                return Result.success(result)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to broadcast transaction", e)
            return Result.failure(e)
        }
    }

    /**
     * Get recent blockhash for transactions
     */
    private suspend fun getRecentBlockhash(): Result<String> {
        try {
            val rpcRequest = JSONObject().apply {
                put("jsonrpc", "2.0")
                put("id", 1)
                put("method", "getLatestBlockhash")
                put("params", JSONArray().apply {
                    put(JSONObject().apply {
                        put("commitment", "finalized")
                    })
                })
            }

            val requestBody = rpcRequest.toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url(HELIUS_RPC_URL)
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return Result.failure(IOException("HTTP ${response.code}"))
                }

                val responseBody = response.body?.string()
                    ?: return Result.failure(IOException("Empty response"))

                val jsonResponse = JSONObject(responseBody)

                if (jsonResponse.has("error")) {
                    return Result.failure(IOException("RPC error"))
                }

                val result = jsonResponse.getJSONObject("result")
                val value = result.getJSONObject("value")
                val blockhash = value.getString("blockhash")

                Log.i(TAG, "Got recent blockhash: $blockhash")
                return Result.success(blockhash)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Failed to get recent blockhash", e)
            return Result.failure(e)
        }
    }

    /**
     * Sign an arbitrary message with the user's Solana wallet
     * Used for Lighthouse API key generation and other wallet-based authentication
     * @param message The message to sign (from Lighthouse API or other services)
     * @return Signed message as Base64 string
     */
    suspend fun signMessage(message: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Signing message for wallet authentication")

            // Sign message using KeyManager (uses Ed25519 signing key)
            val messageBytes = message.toByteArray(Charsets.UTF_8)
            val signatureBytes = keyManager.signData(messageBytes)

            // Return signature as hex (no 0x prefix - Crust format)
            val signatureHex = signatureBytes.joinToString("") { "%02x".format(it) }

            Log.i(TAG, "Successfully signed message (hex format, no prefix)")
            Log.d(TAG, "Signature length: ${signatureBytes.size} bytes")
            Result.success(signatureHex)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to sign message", e)
            Result.failure(e)
        }
    }
}
