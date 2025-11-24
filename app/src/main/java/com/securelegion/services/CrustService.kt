package com.securelegion.services

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
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

    // Configure OkHttpClient to use Tor SOCKS5 proxy for privacy
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 9050)))
        .build()

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

                // Pin the file to Crust network for permanent storage
                val pinResult = pinToCrust(cid, publicKey)
                if (pinResult.isFailure) {
                    Log.w(TAG, "Pinning failed but file is uploaded: ${pinResult.exceptionOrNull()?.message}")
                    // Continue anyway - file is temporarily accessible
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
     * @return Success or failure
     */
    private suspend fun pinToCrust(cid: String, publicKey: String): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Pinning $cid to Crust network for permanent storage")

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
                    return@withContext Result.failure(
                        IOException("Pinning failed: ${response.code} - $errorBody")
                    )
                }

                Log.i(TAG, "Successfully pinned $cid to Crust network")
                Result.success(Unit)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to pin to Crust", e)
            Result.failure(e)
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
            Log.d(TAG, "Downloading from IPFS gateway: $PUBLIC_IPFS_GATEWAY/ipfs/$cid")

            val request = Request.Builder()
                .url("$PUBLIC_IPFS_GATEWAY/ipfs/$cid")
                .addHeader("User-Agent", "Mozilla/5.0 (Android; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val errorBody = response.body?.string() ?: "Unknown error"
                    Log.e(TAG, "Download failed: ${response.code} - $errorBody")
                    return@withContext Result.failure(
                        IOException("Download failed: ${response.code} - $errorBody")
                    )
                }

                val encryptedData = response.body!!.bytes()
                Log.i(TAG, "Successfully downloaded from Crust (${encryptedData.size} bytes)")
                Result.success(encryptedData)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to download from IPFS", e)
            Result.failure(e)
        }
    }
}
