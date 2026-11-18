package com.securelegion.sync

import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/** Exact build-48 offer representation. Parsing alone does not start a transfer. */
internal object NearbyHistoryOfferWire {
    data class Offer(val host: String, val port: Int, val session: String,
                     val expiresAtMs: Long, val peerDeviceId: String,
                     val localDeviceId: String, val accountEd: ByteArray,
                     val fingerprint: String, val signature: ByteArray,
                     val transcript: ByteArray)

    private val fields = setOf("v", "type", "host", "port", "session", "expires",
        "device", "source", "account", "tls_sha256", "signature")
    private val idPattern = Regex("[A-Za-z0-9_-]{43}")
    private val digestPattern = Regex("[0-9a-f]{64}")

    fun parse(raw: String, nowMs: Long = System.currentTimeMillis()): Offer {
        require(raw.toByteArray(Charsets.UTF_8).size in 1..8192)
        val json = JSONObject(raw)
        require(json.keys().asSequence().toSet() == fields)
        require(strictLong(json.opt("v")) == 1L && json.optString("type") == "secure-nearby-history")
        val host = json.getString("host")
        require(privateIPv4(host))
        val port = strictLong(json.opt("port"))
        require(port in 1024..65535)
        val session = json.getString("session")
        val expires = strictLong(json.opt("expires"))
        val peer = json.getString("device")
        val local = json.getString("source")
        val account64 = json.getString("account")
        val fingerprint = json.getString("tls_sha256")
        val signature64 = json.getString("signature")
        require(idPattern.matches(session) && idPattern.matches(peer) && idPattern.matches(local))
        require(nowMs > 0 && expires > nowMs && expires <= nowMs + 600_000L)
        require(digestPattern.matches(fingerprint))
        val account = strictBase64(account64, 32)
        val signature = strictBase64(signature64, 64)
        val transcript = JSONArray().put("secure-nearby-history-v1")
            .put(host).put(port).put(session).put(expires).put(peer).put(local)
            .put(account64).put(fingerprint).toString().toByteArray(Charsets.UTF_8)
        return Offer(host, port.toInt(), session, expires, peer, local,
            account, fingerprint, signature, transcript)
    }

    fun parseAuthorized(raw: String, accountEd: ByteArray, localDeviceId: String,
                        roster: DeviceRosterStore,
                        nowMs: Long = System.currentTimeMillis()): Offer {
        val offer = parse(raw, nowMs)
        require(accountEd.size == 32 && offer.accountEd.contentEquals(accountEd))
        require(offer.localDeviceId == localDeviceId)
        require(roster.isLocalAuthorized(accountEd, localDeviceId, 0x02, nowMs))
        val peer = roster.authorizedPeer(accountEd, offer.peerDeviceId, 0x02, nowMs)
            ?: throw IllegalArgumentException("Unauthorized nearby peer")
        require(RustBridge.verifySignature(offer.transcript, offer.signature, peer.signingKey))
        return offer
    }

    private fun strictLong(value: Any?): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong().also { require(it > 0 && it <= 9_007_199_254_740_991L) }
    }

    private fun strictBase64(text: String, length: Int): ByteArray {
        val decoded = Base64.getDecoder().decode(text)
        require(decoded.size == length && Base64.getEncoder().encodeToString(decoded) == text)
        return decoded
    }

    fun privateIPv4(host: String): Boolean {
        val parts = host.split('.')
        if (parts.size != 4) return false
        val octets = parts.map { part ->
            val value = part.toIntOrNull()
            if (value == null || value !in 0..255 || value.toString() != part) return false
            value
        }
        return octets[0] == 10 || octets[0] == 172 && octets[1] in 16..31 ||
            octets[0] == 192 && octets[1] == 168
    }
}
