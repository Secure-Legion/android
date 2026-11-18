package com.securelegion.sync

import com.securelegion.crypto.RustBridge
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64

/** Validates build-48 group snapshots and Tor-safe group connection metadata. */
internal object DeviceSyncGroupDelta {
    // Base64 expansion must still fit the 8 MiB canonical history delta.
    private const val MAX_LINK_BYTES = 5_900_000
    private const val MAX_SNAPSHOT_BYTES = 23 * 1024 * 1024
    private val hex64 = Regex("[0-9a-f]{64}")
    private val fields = setOf("group_snapshot_id", "group_id", "packed_ops", "group_secret")

    data class Snapshot(val groupId: String, val objectId: String,
                        val packedOps: ByteArray, val secret: ByteArray)

    fun parse(delta: JSONObject, topic: String, objectId: String): Snapshot? {
        require(topic == "groups" || topic == "group_links")
        if (delta.opt("deleted") == true) {
            require(delta.keys().asSequence().toSet() ==
                setOf("group_snapshot_id", "deleted") &&
                hex64.matches(objectId) && delta.optString("group_snapshot_id") == objectId)
            return null
        }
        require(delta.keys().asSequence().toSet() == fields)
        val groupId = delta.getString("group_id")
        require(hex64.matches(groupId))
        val limit = if (topic == "groups") MAX_SNAPSHOT_BYTES else MAX_LINK_BYTES
        val packed = strictBase64(delta.getString("packed_ops"), limit)
        require(packed.isNotEmpty() && validFraming(packed))
        if (topic == "group_links") require(RustBridge.validateDeviceGroupLinkOps(packed))
        val secret = strictBase64(delta.getString("group_secret"), 32)
        require(secret.size == 32)
        val digest = MessageDigest.getInstance("SHA-256").digest(packed).toHex()
        require(objectId == "$groupId:$digest" &&
            delta.getString("group_snapshot_id") == objectId)
        return Snapshot(groupId, objectId, packed, secret)
    }

    /** Frame structure is shared by iOS and Android CRDT replay. */
    fun validFraming(packed: ByteArray): Boolean {
        if (packed.isEmpty() || packed.size > MAX_SNAPSHOT_BYTES) return false
        var offset = 0
        var count = 0
        while (offset < packed.size) {
            if (packed.size - offset < 4 || ++count > 500_000) return false
            val length = ((packed[offset].toInt() and 255) shl 24) or
                ((packed[offset + 1].toInt() and 255) shl 16) or
                ((packed[offset + 2].toInt() and 255) shl 8) or
                (packed[offset + 3].toInt() and 255)
            offset += 4
            if (length !in 1..66_560 || length > packed.size - offset) return false
            offset += length
        }
        return offset == packed.size
    }

    private fun strictBase64(value: String, limit: Int): ByteArray {
        require(value.length <= ((limit + 2) / 3) * 4)
        val bytes = Base64.getDecoder().decode(value)
        require(bytes.size <= limit && Base64.getEncoder().encodeToString(bytes) == value)
        return bytes
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it.toInt() and 255) }
}
