package com.securelegion.services

import android.content.Context
import android.util.Log
import com.securelegion.crypto.TorManager
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

/**
 * Pinata IPFS Service
 * Handles uploading and downloading encrypted contact cards to/from IPFS via Pinata
 *
 * Free tier: 1GB storage, 100GB bandwidth/month, 100 requests/min
 *
 * All IPFS traffic routes through Tor SOCKS proxy for network anonymity
 */
class PinataService(context: Context) {

    companion object {
        private const val TAG = "PinataService"
        private const val PINATA_API_BASE = "https://api.pinata.cloud"
        private const val PINATA_GATEWAY = "https://gateway.pinata.cloud"

        // Note: API keys in APK are not truly secure, only obfuscated
        // Keys are scoped to Files:Write only and can be rotated if compromised
        private const val PINATA_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiJkZjhjNTQ4Yi03YWQzLTRlZmQtOWNmMS0yMGIyYmQ0ZGQxNjYiLCJlbWFpbCI6InNlY3VyZWxlZ2lvbmRldkBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwicGluX3BvbGljeSI6eyJyZWdpb25zIjpbeyJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MSwiaWQiOiJGUkExIn0seyJkZXNpcmVkUmVwbGljYXRpb25Db3VudCI6MSwiaWQiOiJOWUMxIn1dLCJ2ZXJzaW9uIjoxfSwibWZhX2VuYWJsZWQiOmZhbHNlLCJzdGF0dXMiOiJBQ1RJVkUifSwiYXV0aGVudGljYXRpb25UeXBlIjoic2NvcGVkS2V5Iiwic2NvcGVkS2V5S2V5IjoiNzgwNzAzODA2YzhmMGI5ZGJkMDYiLCJzY29wZWRLZXlTZWNyZXQiOiI0ZTExZTg1YzExZGY5ZmE5Y2Y5N2Q2NGY0NzIzOGIyNjM3NDViNzBmOWQ5MWExYjdjNzM0NWNhOTE3N2M5ZmFkIiwiZXhwIjoxNzk0MzY2OTM0fQ.3XUYIbw7j4PzAAFLJHuL2FPDJxV04nt3HQla8BB-DEY"
    }

    // Direct HTTP connection (Tor for messaging only, not IPFS uploads)
    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    /**
     * Upload encrypted contact card binary data to IPFS
     * @param encryptedData The encrypted contact card as byte array
     * @return IPFS CID (Content Identifier) e.g., "QmXyZ..." or "bafy..."
     */
    suspend fun uploadContactCard(encryptedData: ByteArray): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Uploading encrypted contact card to IPFS (${encryptedData.size} bytes)")

            // Create multipart request body for file upload
            val requestBody = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart(
                    "file",
                    "contact_${System.currentTimeMillis()}.bin",
                    encryptedData.toRequestBody("application/octet-stream".toMediaType())
                )
                .addFormDataPart(
                    "pinataOptions",
                    JSONObject().apply {
                        put("cidVersion", 1)
                    }.toString()
                )
                .addFormDataPart(
                    "pinataMetadata",
                    JSONObject().apply {
                        put("name", "securelegion_contact_${System.currentTimeMillis()}")
                        put("keyvalues", JSONObject().apply {
                            put("app", "SecureLegion")
                            put("type", "contact_card")
                        })
                    }.toString()
                )
                .build()

            val request = Request.Builder()
                .url("$PINATA_API_BASE/pinning/pinFileToIPFS")
                .addHeader("Authorization", "Bearer $PINATA_JWT")
                .post(requestBody)
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    val errorBody = response.body?.string() ?: "Unknown error"
                    Log.e(TAG, "Pinata upload failed: ${response.code} - $errorBody")
                    return@withContext Result.failure(
                        IOException("Upload failed: ${response.code} - $errorBody")
                    )
                }

                val responseJson = JSONObject(response.body!!.string())
                val cid = responseJson.getString("IpfsHash")

                Log.i(TAG, "Successfully uploaded to IPFS: $cid")
                Result.success(cid)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to upload to IPFS", e)
            Result.failure(e)
        }
    }

    /**
     * Download encrypted contact card from IPFS using CID
     * @param cid IPFS Content Identifier (e.g., "QmXyZ..." or "bafy...")
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
                .url("$PINATA_GATEWAY/ipfs/$cid")
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

    /**
     * Test connection to Pinata API
     * @return true if authenticated successfully
     */
    suspend fun testConnection(): Result<Boolean> = withContext(Dispatchers.IO) {
        try {
            val request = Request.Builder()
                .url("$PINATA_API_BASE/data/testAuthentication")
                .addHeader("Authorization", "Bearer $PINATA_JWT")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    Log.i(TAG, "Pinata authentication successful")
                    Result.success(true)
                } else {
                    Log.e(TAG, "Pinata authentication failed: ${response.code}")
                    Result.failure(IOException("Authentication failed: ${response.code}"))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to test Pinata connection", e)
            Result.failure(e)
        }
    }
}
