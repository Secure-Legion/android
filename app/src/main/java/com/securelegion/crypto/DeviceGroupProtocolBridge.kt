package com.securelegion.crypto

import org.json.JSONObject
import android.util.Base64

/** Stateless canonical group validation. The SQLCipher host owns committed state and trust. */
internal object DeviceGroupProtocolBridge {
    private const val MAX_REQUEST_BYTES = 72 * 1024 * 1024

    init {
        System.loadLibrary("secure_group_mobile")
    }

    private external fun executeNative(
        request: ByteArray,
        signingSeed: ByteArray?,
        groupKey: ByteArray?
    ): ByteArray

    fun execute(request: JSONObject, signingSeed: ByteArray? = null,
                groupKey: ByteArray? = null): JSONObject {
        require(request.optString("operation") != "ratify") {
            "Account-root ratification requires the separate primary approval path"
        }
        require(signingSeed == null || signingSeed.size == 32)
        require(groupKey == null || groupKey.size == 32)
        val bytes = request.toString().toByteArray(Charsets.UTF_8)
        require(bytes.isNotEmpty() && bytes.size <= MAX_REQUEST_BYTES)
        return JSONObject(executeNative(bytes, signingSeed, groupKey).toString(Charsets.UTF_8))
    }

    /** Only the primary's exact accepted-operation approval service calls this. */
    fun ratifyExact(encoded: ByteArray, approvedHash: String,
                    accountSeed: ByteArray): ByteArray {
        require(encoded.size in 1..69_632 &&
            approvedHash.matches(Regex("[0-9a-f]{64}")) &&
            accountSeed.size == 32)
        val request = JSONObject().put("operation", "ratify")
            .put("encoded", Base64.encodeToString(encoded, Base64.NO_WRAP))
            .put("approved_hash", approvedHash)
        val result = JSONObject(executeNative(request.toString()
            .toByteArray(Charsets.UTF_8), accountSeed, null)
            .toString(Charsets.UTF_8))
        require(result.getString("hash") == approvedHash)
        return Base64.decode(result.getString("ratification"), Base64.DEFAULT)
            .also { require(it.size == 134) }
    }
}
