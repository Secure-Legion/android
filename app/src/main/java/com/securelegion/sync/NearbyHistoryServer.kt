package com.securelegion.sync

import android.content.Context
import android.os.Build
import android.util.Base64
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LinkedProfileContentCrypto
import com.securelegion.crypto.LinkedProfileCredentialStore
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.crypto.RustBridge
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.DeviceSyncChunkStore
import com.securelegion.database.LinkedChatStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.SessionManager
import org.json.JSONArray
import org.json.JSONObject
import java.io.Closeable
import java.security.SecureRandom
import javax.net.ssl.SSLSocket

/** A single signed QR offer accepts one authenticated history archive over local Wi-Fi. */
internal class NearbyHistoryServer private constructor(
    private val context: Context,
    private val identity: LocalDeviceIdentity,
    private val tls: NearbyHistoryTlsServer,
    private val database: SecureLegionDatabase,
    private val roster: DeviceRosterStore,
    private val account: ByteArray,
    private val peerId: String,
    private val primary: Boolean,
    val offer: String,
    private val session: String,
    private val expires: Long
) : Closeable {
    private val linkedCredentials = if (primary) null else LinkedProfileCredentialStore(context)
    @Volatile private var cancelled = false
    @Volatile private var socket: SSLSocket? = null

    data class Result(val imported: Int, val deferred: Int)

    override fun close() {
        cancelled = true
        runCatching { socket?.close() }
        tls.close()
        identity.close()
    }

    fun run(progress: (String) -> Unit): Result {
        checkActive()
        progress("Waiting for your other device…")
        tls.accept().use { connected ->
            socket = connected
            val nonce = randomId()
            write(connected, JSONObject().put("type", "challenge").put("v", 1)
                .put("session", session).put("challenge", nonce))
            val helloRecord = read(connected)
            require(helloRecord.keys().asSequence().toSet() == setOf("type", "wire") &&
                helloRecord.getString("type") == "hello")
            val hello = decode(helloRecord.getString("wire"), DeviceSyncFrameV2.Kind.HELLO)
            val payload = JSONObject(hello.payload.toString())
            require(payload.opt("nearby_v") == 1 && payload.optString("session") == session &&
                payload.optString("challenge") == nonce)
            payload.remove("nearby_v"); payload.remove("session"); payload.remove("challenge")
            val parsed = DeviceSyncHelloWire.parse(payload)
            require("durable_history_v2" in parsed.capabilities)
            val cursors = HashMap<String, Pair<Long, Long>>()
            database.openHelper.readableDatabase.query(SimpleSQLiteQuery(
                "SELECT topic,pushed_seq,received_seq FROM device_sync_cursors " +
                    "WHERE peer_device_id=?", arrayOf(peerId))).use { c ->
                while (c.moveToNext()) cursors[c.getString(0)] = c.getLong(1) to c.getLong(2)
            }
            val capabilities = mutableSetOf("durable_history_v2",
                "contact_roster_v1", "account_profile_v1", "tor_metadata_only_v1")
            if (roster.isLocalAuthorized(account, identity.deviceId, 0x06) &&
                roster.isAuthorized(account, peerId, 0x06)) {
                capabilities.add("group_snapshots_v1")
                capabilities.add("group_links_v1")
                capabilities.add("delegated_groups_v1")
            }
            val ack = DeviceSyncHelloWire.payload(capabilities, cursors)
                .put("nearby_v", 1).put("session", session).put("challenge", nonce)
            write(connected, JSONObject().put("type", "hello_ack")
                .put("wire", encode(DeviceSyncFrameV2.Kind.HELLO_ACK, ack)))
            progress("Receiving encrypted history…")
            val linkedCrypto = if (primary) null else LinkedProfileContentCrypto(context)
            val keys = if (primary) KeyManager.getInstance(context) else null
            val media = if (primary) DeviceSyncMediaFiles(context, keys!!)
                else DeviceSyncMediaFiles(context, linkedCrypto!!::encryptImage,
                    linkedCrypto::encryptVoice)
            val linkedChat = if (primary) null else LinkedChatStore(database, roster,
                linkedCrypto!!::encryptText, media).also { it.ensureSchema() }
            val contacts = DeviceSyncContactReceiver(database, roster, linkedChat)
            val settings = DeviceSyncAccountSettingsReceiver(database, roster)
            val messages = DeviceSyncLiveMessageReceiver(database, roster,
                if (primary) keys!!::encryptDeviceSyncContent else linkedCrypto!!::encryptText,
                media::store, linkedChat)
            val receipts = DeviceSyncLiveReceiptReceiver(database, roster, linkedChat)
            val groups = DeviceSyncGroupReceiver(database, roster)
            var index = 0
            var imported = 0
            var deferred = 0
            while (true) {
                val record = read(connected)
                when (record.optString("type")) {
                    "push" -> {
                        require(record.keys().asSequence().toSet() ==
                            setOf("type", "index", "last", "wire") &&
                            record.opt("index") is Int && record.getInt("index") == index &&
                            record.opt("last") is Boolean && index < 1_000_000)
                        val frame = decode(record.getString("wire"), DeviceSyncFrameV2.Kind.PUSH)
                        val part = DeviceSyncPushWire.parse(DeviceSyncFrameV2.Frame(
                            frame.kind, frame.sender, frame.recipient, frame.timestampMs,
                            frame.payload, frame.wireHash), false, nearby = true)
                        val capability = if (part.topic == "groups") 0x06 else 0x02
                        peer(capability)
                        val outcome = when (part.topic) {
                            "contacts" -> contacts.receive(account, identity.deviceId, part)
                            "settings" -> settings.receive(account, identity.deviceId, part)
                            "messages" -> messages.receive(account, identity.deviceId, part,
                                false, archiveAuthenticated = true)
                            "receipts" -> receipts.receive(account, identity.deviceId, part,
                                false, archiveAuthenticated = true)
                            "groups" -> groups.receive(account, identity.deviceId, part)
                            else -> error("Unsupported Nearby topic")
                        }
                        val last = record.getBoolean("last")
                        require(!last || part.index == part.total - 1)
                        require(last || part.index < part.total - 1)
                        val answer = JSONObject().put("type", "result").put("index", index)
                        if (outcome == DeviceSyncChunkStore.Result.COMMITTED && last) {
                            peer(capability)
                            answer.put("wire", encode(DeviceSyncFrameV2.Kind.PULL_RESPONSE,
                                DeviceSyncPushWire.settled(part)))
                            imported++
                        } else {
                            answer.put("wire", JSONObject.NULL)
                            if (outcome == DeviceSyncChunkStore.Result.DEFERRED && last) deferred++
                        }
                        write(connected, answer)
                        index++
                        if (last) progress("Imported $imported updates; $deferred deferred")
                    }
                    "done" -> {
                        require(record.keys().asSequence().toSet() ==
                            setOf("type", "index", "remaining") &&
                            record.opt("index") is Int && record.getInt("index") == index &&
                            (record.opt("remaining") as? Number)?.toLong()?.let { it >= 0 } == true)
                        write(connected, JSONObject().put("type", "done_ack").put("index", index))
                        if (primary) runCatching { settings.materializePrimary(context, keys!!) }
                        return Result(imported, deferred)
                    }
                    else -> error("Invalid Nearby record")
                }
            }
        }
    }

    private fun checkActive() {
        check(!cancelled && System.currentTimeMillis() < expires &&
            SessionManager.isUnlocked(context))
        tls.checkWifi()
        peer()
    }

    private fun peer(capability: Int = 0x02): DeviceRosterStore.PeerKeys {
        check(!cancelled && SessionManager.isUnlocked(context))
        val currentAccount = if (primary) KeyManager.getInstance(context)
            .takeIf { it.isInitialized() }?.getSigningPublicKey()
            else linkedCredentials?.activeProfile()?.accountEd
        check(currentAccount != null && currentAccount.contentEquals(account)) {
            "Nearby profile changed"
        }
        val now = System.currentTimeMillis()
        check(now < expires && roster.isLocalAuthorized(account, identity.deviceId,
            capability, now))
        return roster.authorizedPeer(account, peerId, capability, now)
            ?: error("Nearby peer is no longer authorized")
    }

    private fun decode(raw: String, kind: DeviceSyncFrameV2.Kind): NearbyHistoryFrame.Frame {
        checkActive()
        val current = peer()
        return NearbyHistoryFrame.decode(Base64.decode(raw, Base64.NO_WRAP), peerId,
            identity, current.signingKey, current.encryptionKey)
            .also { require(it.kind == kind) }
    }

    private fun encode(kind: DeviceSyncFrameV2.Kind, payload: JSONObject): String {
        checkActive()
        return Base64.encodeToString(NearbyHistoryFrame.encode(kind, identity, peerId,
            peer().encryptionKey, payload), Base64.NO_WRAP)
    }

    private fun read(connected: SSLSocket): JSONObject {
        checkActive()
        return NearbyHistoryTlsConnection.readRecord(connected.inputStream)
    }

    private fun write(connected: SSLSocket, value: JSONObject) {
        checkActive()
        NearbyHistoryTlsConnection.writeRecord(connected.outputStream, value)
    }

    companion object {
        fun open(context: Context, selectedPeerId: String): NearbyHistoryServer {
            check(SessionManager.isUnlocked(context))
            val app = context.applicationContext
            val keys = KeyManager.getInstance(app)
            val primary = keys.isInitialized()
            val linked = if (primary) null else LinkedProfileCredentialStore(app)
            val account = if (primary) keys.getSigningPublicKey()
                else linked!!.activeProfile()?.accountEd ?: error("Linked profile unavailable")
            val databaseKey = if (primary) keys.getDatabasePassphrase()
                else linked!!.activeDatabaseKey() ?: error("Linked database unavailable")
            val database = try { SecureLegionDatabase.getInstance(app, databaseKey) }
                finally { databaseKey.fill(0) }
            val roster = DeviceRosterStore(database)
            val identity = LocalDeviceIdentity.loadExisting(app)
            try {
                require(roster.isLocalAuthorized(account, identity.deviceId, 0x02))
                val peer = roster.authorizedPeer(account, selectedPeerId, 0x02)
                    ?: error("Select an authorized device")
                require(peer.signingKey.size == 32 && peer.encryptionKey.size == 32)
                val tls = NearbyHistoryTlsServer.open(app)
                try {
                    val session = randomId()
                    val expires = System.currentTimeMillis() + 600_000L
                    val account64 = Base64.encodeToString(account, Base64.NO_WRAP)
                    val transcript = JSONArray().put("secure-nearby-history-v1")
                        .put(tls.host).put(tls.port).put(session).put(expires)
                        .put(identity.deviceId).put(selectedPeerId).put(account64)
                        .put(tls.fingerprint).toString().toByteArray(Charsets.UTF_8)
                    val offer = JSONObject().put("v", 1)
                        .put("type", "secure-nearby-history")
                        .put("host", tls.host).put("port", tls.port)
                        .put("session", session).put("expires", expires)
                        .put("device", identity.deviceId).put("source", selectedPeerId)
                        .put("account", account64).put("tls_sha256", tls.fingerprint)
                        .put("signature", Base64.encodeToString(identity.sign(transcript),
                            Base64.NO_WRAP)).toString()
                    val verified = NearbyHistoryOfferWire.parse(offer)
                    check(verified.peerDeviceId == identity.deviceId &&
                        verified.localDeviceId == selectedPeerId &&
                        verified.accountEd.contentEquals(account) &&
                        RustBridge.verifySignature(verified.transcript,
                            verified.signature, identity.signingPublicKey))
                    return NearbyHistoryServer(app, identity, tls, database, roster,
                        account, selectedPeerId, primary, offer, session, expires)
                } catch (e: Exception) { tls.close(); throw e }
            } catch (e: Exception) { identity.close(); throw e }
        }

        private fun randomId(): String = ByteArray(32).also { SecureRandom().nextBytes(it) }
            .let { Base64.encodeToString(it,
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING) }
    }
}
