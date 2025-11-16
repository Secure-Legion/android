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
        private const val CRUST_GATEWAY = "https://gw.crustfiles.app"
        private const val CRUST_IPFS_GATEWAY = "https://ipfs.io"
    }

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
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
                .url("$CRUST_GATEWAY/api/v0/add")
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
                Result.success(cid)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to upload to Crust", e)
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

            val request = Request.Builder()
                .url("$CRUST_IPFS_GATEWAY/ipfs/$cid")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    Log.e(TAG, "Failed to download from IPFS: ${response.code}")
                    return@withContext Result.failure(
                        IOException("Download failed: ${response.code}")
                    )
                }

                val encryptedData = response.body!!.bytes()
                Log.i(TAG, "Successfully downloaded from IPFS (${encryptedData.size} bytes)")
                Result.success(encryptedData)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to download from IPFS", e)
            Result.failure(e)
        }
    }
}
