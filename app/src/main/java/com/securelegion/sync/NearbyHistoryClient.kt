package com.securelegion.sync

import android.content.Context
import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncOutboxStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.SessionManager
import org.json.JSONObject

/** Client side of the Desktop build-48 pinned-TLS history transfer. */
internal class NearbyHistoryClient(private val context: Context,
                                   private val keys: KeyManager,
                                   private val database: SecureLegionDatabase) {
    private val roster = DeviceRosterStore(database)
    private val outbox = DeviceSyncOutboxStore(database, roster)
    private val noncePattern = Regex("[A-Za-z0-9_-]{43}")
    @Volatile private var cancelled = false
    @Volatile private var active: NearbyHistoryTlsConnection? = null

    fun cancel() {
        cancelled = true
        runCatching { active?.close() }
    }

    data class Result(val copied: Int, val remaining: Int)

    fun run(rawOffer: String, progress: (String) -> Unit): Result {
        check(!cancelled)
        check(SessionManager.isUnlocked(context))
        val account = keys.getSigningPublicKey()
        LocalDeviceIdentity.loadExisting(context).use { identity ->
            val offer = NearbyHistoryOfferWire.parseAuthorized(rawOffer, account,
                identity.deviceId, roster)
            fun peer(topic: String? = null): DeviceRosterStore.PeerKeys {
                check(!cancelled && SessionManager.isUnlocked(context) &&
                    account.contentEquals(keys.getSigningPublicKey()))
                val now = System.currentTimeMillis()
                check(roster.isLocalAuthorized(account,
                    identity.deviceId, if (topic == "groups") 0x06 else 0x02, now))
                val current = roster.authorizedPeer(account, offer.peerDeviceId,
                    if (topic == "groups") 0x06 else 0x02, now)
                    ?: error("Desktop is no longer authorized")
                check(current.signingKey.size == 32 && current.encryptionKey.size == 32)
                return current
            }
            fun encode(kind: DeviceSyncFrameV2.Kind, payload: JSONObject): ByteArray =
                NearbyHistoryFrame.encode(kind, identity, offer.peerDeviceId,
                    peer().encryptionKey, payload)
            fun decode(raw: String, kind: DeviceSyncFrameV2.Kind): NearbyHistoryFrame.Frame {
                val bytes = Base64.decode(raw, Base64.NO_WRAP)
                val current = peer()
                return NearbyHistoryFrame.decode(bytes, current.deviceId, identity,
                    current.signingKey, current.encryptionKey).also { check(it.kind == kind) }
            }
            progress("Connecting securely…")
            NearbyHistoryTlsConnection.open(context, offer).use { transport ->
                active = transport
                check(!cancelled)
                val challenge = transport.read()
                check(challenge.keys().asSequence().toSet() ==
                    setOf("type", "v", "session", "challenge") &&
                    challenge.optString("type") == "challenge" &&
                    challenge.opt("v") == 1 && challenge.opt("v") is Int &&
                    challenge.optString("session") == offer.session &&
                    noncePattern.matches(challenge.getString("challenge")))
                val nonce = challenge.getString("challenge")
                val hello = localHello(offer.peerDeviceId, identity.deviceId, account)
                    .put("nearby_v", 1).put("session", offer.session)
                    .put("challenge", nonce)
                peer()
                transport.write(JSONObject().put("type", "hello")
                    .put("wire", Base64.encodeToString(encode(
                        DeviceSyncFrameV2.Kind.HELLO, hello), Base64.NO_WRAP)))
                val ack = transport.read()
                check(ack.optString("type") == "hello_ack")
                val reply = decode(ack.getString("wire"), DeviceSyncFrameV2.Kind.HELLO_ACK)
                val replyPayload = JSONObject(reply.payload.toString())
                check(replyPayload.opt("nearby_v") == 1 &&
                    replyPayload.optString("session") == offer.session &&
                    replyPayload.optString("challenge") == nonce)
                replyPayload.remove("nearby_v")
                replyPayload.remove("session")
                replyPayload.remove("challenge")
                val peerHello = DeviceSyncHelloWire.parse(replyPayload)
                check("durable_history_v2" in peerHello.capabilities)
                progress("Preparing history…")
                NearbyHistoryPublisher(context, database, roster, keys).prepare(
                    account, identity.deviceId, offer.peerDeviceId,
                    peerHello.capabilities, progress) { peer(); Unit }
                var afterTopic = ""
                var afterObject = ""
                var index = 0
                var copied = 0
                while (true) {
                    peer()
                    val event = outbox.nearbyPage(account, identity.deviceId,
                        offer.peerDeviceId, afterTopic, afterObject) ?: break
                    check(index < 1_000_000)
                    if (event.topic == "groups" && runCatching { peer("groups") }.isFailure) {
                        afterTopic = event.topic; afterObject = event.objectId
                        continue
                    }
                    val parts = DeviceSyncOutboundWire.payloads(event.copy(isLive = false))
                    var settled = false
                    for ((partIndex, payload) in parts.withIndex()) {
                        peer(event.topic)
                        val wire = encode(DeviceSyncFrameV2.Kind.PUSH, payload)
                        transport.write(JSONObject().put("type", "push")
                            .put("index", index).put("last", partIndex == parts.lastIndex)
                            .put("wire", Base64.encodeToString(wire, Base64.NO_WRAP)))
                        val result = transport.read()
                        check(result.optString("type") == "result" &&
                            (result.opt("index") as? Number)?.toInt() == index)
                        if (result.has("wire") && !result.isNull("wire")) {
                            val response = decode(result.getString("wire"),
                                DeviceSyncFrameV2.Kind.PULL_RESPONSE)
                            val settlement = DeviceSyncSettlementWire.parse(response.payload)
                            check(settlement.kind == DeviceSyncSettlementWire.Kind.SETTLED &&
                                settlement.eventId == event.eventId)
                            peer(event.topic)
                            settled = outbox.settle(account, identity.deviceId,
                                offer.peerDeviceId, DeviceSyncOutboxStore.Transport.NEARBY,
                                settlement.eventId, settlement.digestHex, settlement.topic,
                                settlement.objectId, settlement.eventTimeMs) || settled
                        }
                        index++
                    }
                    if (settled) copied++
                    progress("Copied $copied history updates")
                    afterTopic = event.topic
                    afterObject = event.objectId
                }
                peer()
                val remaining = outbox.nearbyPendingCount(offer.peerDeviceId)
                transport.write(JSONObject().put("type", "done")
                    .put("index", index).put("remaining", remaining))
                val done = transport.read()
                check(done.optString("type") == "done_ack" &&
                    (done.opt("index") as? Number)?.toInt() == index)
                return Result(copied, remaining)
            }
        }
    }

    private fun localHello(peerId: String, localId: String,
                           account: ByteArray): JSONObject {
        val db = database.openHelper.readableDatabase
        val cursors = HashMap<String, Pair<Long, Long>>()
        db.query(SimpleSQLiteQuery("SELECT topic,pushed_seq,received_seq " +
            "FROM device_sync_cursors WHERE peer_device_id=?", arrayOf(peerId))).use { c ->
            while (c.moveToNext()) cursors[c.getString(0)] = c.getLong(1) to c.getLong(2)
        }
        val capabilities = mutableSetOf("durable_history_v2",
            "contact_roster_v1", "account_profile_v1", "tor_metadata_only_v1",
            DeviceSyncTorPolicy.LIVE_CAPABILITY)
        if (roster.isLocalAuthorized(account, localId, 0x06) &&
            roster.isAuthorized(account, peerId, 0x06)) {
            capabilities.add("group_snapshots_v1")
            capabilities.add("group_links_v1")
        }
        return DeviceSyncHelloWire.payload(capabilities, cursors)
    }
}
