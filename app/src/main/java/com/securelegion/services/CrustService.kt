package com.securelegion.services

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import com.securelegion.network.OkHttpProvider
import java.io.IOException
import android.util.Base64

/**
 * Crust Network IPFS Service
 * Decentralized storage using Solana wallet-based authentication
 * Each user signs their public key with their wallet - no shared API key needed
 *
 * Free tier: Web3 authenticated gateway
 * No API key exposure - each user authenticates with their own wallet signature
 */
class CrustService(
    private val context: Context,
    private val solanaService: SolanaService
) {

    companion object {
        private const val TAG = "CrustService"
        // W3Auth gateway for authenticated uploads
        private const val CRUST_AUTH_GATEWAY = "https://gw.crustfiles.app"
        // Public IPFS gateway for downloading (no auth required)
        private const val PUBLIC_IPFS_GATEWAY = "https://ipfs.io"
        private const val CRUST_PIN_SERVICE = "https://pin.crustcode.com/psa"
    }

    // Get OkHttpClient from centralized provider (supports connection reset on network changes)
    private val client get() = OkHttpProvider.getCrustClient()

    /**
     * Create Crust authentication header
     * Format: Basic base64("sol-<PublicKey>:<SignedPublicKey>")
     */
    private suspend fun createAuthHeader(publicKey: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Creating Crust auth header for wallet: $publicKey")

            // Sign the public key itself (not a message from server)
            val signatureResult = solanaService.signMessage(publicKey)
            if (signatureResult.isFailure) {
                return@withContext Result.failure(
                    signatureResult.exceptionOrNull() ?: Exception("Failed to sign public key")
                )
            }
            val signature = signatureResult.getOrThrow()

            // Create auth string: "sol-<PublicKey>:<Signature>"
            val authString = "sol-$publicKey:$signature"

            // Base64 encode for Basic auth
            val authHeader = "Basic " + Base64.encodeToString(
                authString.toByteArray(Charsets.UTF_8),
                Base64.NO_WRAP
            )

            Log.i(TAG, "Successfully created Crust auth header")
            Result.success(authHeader)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create auth header", e)
            Result.failure(e)
        }
    }

    /**
     * Upload encrypted contact card to Crust IPFS
     * @param encryptedData The encrypted contact card as byte array
     * @param publicKey User's Solana public key (for authentication)
     * @return IPFS CID
     */
    suspend fun uploadContactCard(encryptedData: ByteArray, publicKey: String): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Uploading encrypted contact card to Crust (${encryptedData.size} bytes)")

            // Get auth header
            val authHeaderResult = createAuthHeader(publicKey)
            if (authHeaderResult.isFailure) {
                return@withContext Result.failure(
                    authHeaderResult.exceptionOrNull() ?: Exception("Failed to create auth header")
                )
            }
            val authHeader = authHeaderResult.getOrThrow()

            // Create multipart request
            val requestBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart(
                    "file",
                    "contact_${System.currentTimeMillis()}.bin",
                    encryptedData.toRequestBody("application/octet-stream".toMediaType())
                )
                .build()

            val request = Request.Builder()
                .url("$CRUST_AUTH_GATEWAY/api/v0/add")
                .addHeader("Authorization", authHeader)
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val errorBody = response.body?.string() ?: "Unknown error"
                    Log.e(TAG, "Crust upload failed: ${response.code} - $errorBody")
                    return@withContext Result.failure(
                        IOException("Upload failed: ${response.code} - $errorBody")
                    )
                }

                val responseJson = JSONObject(response.body!!.string())
                val cid = responseJson.getString("Hash")

                Log.i(TAG, "Successfully uploaded to Crust: $cid")

                // Pin the file to Crust network for permanent storage (with 3 retries)
                val pinResult = pinToCrust(cid, publicKey)
                if (pinResult.isFailure) {
                    Log.w(TAG, "WARNING: Pinning failed after retries: ${pinResult.exceptionOrNull()?.message}")
                    Log.w(TAG, "File is temporarily accessible on IPFS but may disappear. User should re-upload contact card.")
                    // Continue anyway - file is temporarily accessible
                    // TODO: In the future, we could queue this for background retry
                } else {
                    Log.i(TAG, "Successfully pinned to Crust network - file will be permanently stored")
                }

                Result.success(cid)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to upload to Crust", e)
            Result.failure(e)
        }
    }

    /**
     * Pin file to Crust network for permanent storage
     * @param cid IPFS CID to pin
     * @param publicKey User's Solana public key (for authentication)
     * @param retryCount Number of retries attempted (for recursion)
     * @return Success or failure
     */
    private suspend fun pinToCrust(cid: String, publicKey: String, retryCount: Int = 0): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Pinning $cid to Crust network for permanent storage (attempt ${retryCount + 1}/3)")

            // Get auth header (Bearer token for pinning service)
            val authHeaderResult = createAuthHeader(publicKey)
            if (authHeaderResult.isFailure) {
                return@withContext Result.failure(
                    authHeaderResult.exceptionOrNull() ?: Exception("Failed to create auth header")
                )
            }
            val authHeader = authHeaderResult.getOrThrow()

            // Create pinning request
            val pinRequest = JSONObject().apply {
                put("cid", cid)
                put("name", "contact_card_$cid")
            }

            val requestBody = pinRequest.toString()
                .toRequestBody("application/json".toMediaType())

            val request = Request.Builder()
                .url("$CRUST_PIN_SERVICE/pins")
                .addHeader("Authorization", authHeader.replace("Basic", "Bearer"))
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val errorBody = response.body?.string() ?: "Unknown error"
                    Log.e(TAG, "Crust pinning failed: ${response.code} - $errorBody")

                    // Retry on network errors (timeout, connection issues, 5xx errors)
                    if (retryCount < 2 && (response.code >= 500 || response.code == 408)) {
                        Log.w(TAG, "Retrying pinning after ${(retryCount + 1) * 2} seconds...")
                        kotlinx.coroutines.delay((retryCount + 1) * 2000L)
                        return@withContext pinToCrust(cid, publicKey, retryCount + 1)
                    }

                    return@withContext Result.failure(
                        IOException("Pinning failed after ${retryCount + 1} attempts: ${response.code} - $errorBody")
                    )
                }

                Log.i(TAG, "Successfully pinned $cid to Crust network")
                Result.success(Unit)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to pin to Crust", e)

            // Retry on network exceptions (timeout, connection refused, etc.)
            if (retryCount < 2 && (e is IOException)) {
                Log.w(TAG, "Retrying pinning after ${(retryCount + 1) * 2} seconds due to: ${e.message}")
                kotlinx.coroutines.delay((retryCount + 1) * 2000L)
                return@withContext pinToCrust(cid, publicKey, retryCount + 1)
            }

            Result.failure(Exception("Pinning failed after ${retryCount + 1} attempts: ${e.message}", e))
        }
    }

    /**
     * Download encrypted contact card from IPFS using CID
     * @param cid IPFS Content Identifier
     * @return Encrypted contact card as byte array
     */
    suspend fun downloadContactCard(cid: String): Result<ByteArray> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Downloading contact card from IPFS: $cid")

            // Validate CID format (CIDv0: Qm..., CIDv1: baf...)
            if (!cid.startsWith("Qm") && !cid.startsWith("baf")) {
                return@withContext Result.failure(
                    IllegalArgumentException("Invalid IPFS CID format: $cid")
                )
            }

            // Download from public IPFS gateway (no auth required)
            val url = "$PUBLIC_IPFS_GATEWAY/ipfs/$cid"
            Log.d(TAG, "Downloading from IPFS gateway: $url")
            Log.d(TAG, "Using Tor SOCKS proxy: 127.0.0.1:9050")

            val request = Request.Builder()
                .url(url)
                .addHeader("User-Agent", "Mozilla/5.0 (Android; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
                .get()
                .build()

            Log.d(TAG, "Starting HTTP GET request...")
            val startTime = System.currentTimeMillis()

            client.newCall(request).execute().use { response ->
                val elapsedTime = System.currentTimeMillis() - startTime
                Log.d(TAG, "HTTP response received after ${elapsedTime}ms - Code: ${response.code}")

                if (!response.isSuccessful) {
                    val errorBody = response.body?.string() ?: "Unknown error"
                    Log.e(TAG, "Download failed: ${response.code} - $errorBody")
                    return@withContext Result.failure(
                        IOException("Download failed: ${response.code} - $errorBody")
                    )
                }

                Log.d(TAG, "Reading response body...")
                val encryptedData = response.body!!.bytes()
                Log.i(TAG, "Successfully downloaded from IPFS (${encryptedData.size} bytes in ${elapsedTime}ms)")
                Result.success(encryptedData)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to download from IPFS", e)
            Result.failure(e)
        }
    }
}
