package com.securelegion.crypto

import org.json.JSONObject

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
}
