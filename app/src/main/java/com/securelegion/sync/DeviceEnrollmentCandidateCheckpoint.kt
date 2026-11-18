package com.securelegion.sync

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONObject

/** Keystore-protected A3 retry material; never an account seed or unlock token. */
internal class DeviceEnrollmentCandidateCheckpoint(context: Context) {
    data class State(val qr: String, val ephemeral: ByteArray, val offer: ByteArray? = null,
                     val localApproved: Boolean = false, val ownerApproval: ByteArray? = null)

    private val prefs = EncryptedSharedPreferences.create(
        context.applicationContext, "secure_legion_keys",
        MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun save(state: State) {
        require(state.qr.length in 32..8192 && state.ephemeral.size == 32 &&
            (state.offer == null || state.offer.size in 6..96 * 1024) &&
            (state.ownerApproval == null || state.ownerApproval.size in 6..4096))
        val value = JSONObject().put("qr", state.qr)
            .put("ephemeral", b64(state.ephemeral))
            .put("offer", state.offer?.let(::b64) ?: JSONObject.NULL)
            .put("local_approved", state.localApproved)
            .put("owner_approval", state.ownerApproval?.let(::b64) ?: JSONObject.NULL)
        check(prefs.edit().putString(KEY, value.toString()).commit())
    }

    fun load(nowMs: Long = System.currentTimeMillis()): State? {
        val raw = prefs.getString(KEY, null) ?: return null
        return try {
            val value = JSONObject(raw)
            require(value.keys().asSequence().toSet() == setOf("qr", "ephemeral", "offer",
                "local_approved", "owner_approval"))
            val qr = value.getString("qr")
            DeviceEnrollmentWire.parseCandidateQr(qr, nowMs)
            val secret = decode(value.getString("ephemeral"), 32, 32)
            val offer = if (value.isNull("offer")) null
                else decode(value.getString("offer"), 6, 96 * 1024)
            val approval = if (value.isNull("owner_approval")) null
                else decode(value.getString("owner_approval"), 6, 4096)
            val local = value.getBoolean("local_approved")
            require(!local || offer != null)
            State(qr, secret, offer, local, approval)
        } catch (_: Exception) {
            discard()
            null
        }
    }

    fun discard() { check(prefs.edit().remove(KEY).commit()) }

    private fun b64(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun decode(encoded: String, min: Int, max: Int): ByteArray {
        val bytes = Base64.decode(encoded, Base64.DEFAULT)
        require(bytes.size in min..max && b64(bytes) == encoded)
        return bytes
    }

    private companion object { const val KEY = "device_candidate_a3_checkpoint_v1" }
}
