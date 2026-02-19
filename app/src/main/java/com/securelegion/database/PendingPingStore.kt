package com.securelegion.database

import android.os.SystemClock
import android.util.Log
import com.securelegion.database.dao.PendingPingDao
import com.securelegion.database.entities.PendingPing

/**
 * JNI-callable bridge for pending ping signer persistence.
 *
 * Rust calls these @JvmStatic methods via JNI to store/lookup/delete ping signers
 * in the encrypted Room database. All methods are blocking (called from Rust threads).
 *
 * Class path for JNI: com/securelegion/database/PendingPingStore
 */
object PendingPingStore {

    private const val TAG = "PendingPingStore"
    private const val DEFAULT_TTL_MS = 72L * 60 * 60 * 1000 // 72 hours — Tor peers routinely offline for hours/days

    lateinit var dao: PendingPingDao

    val isInitialized: Boolean get() = ::dao.isInitialized

    /**
     * Called from Rust sendPing — persist signer before wire send.
     * @param pingId hex-encoded ping nonce (48 chars)
     * @param signerPubKey Ed25519 pubkey of recipient (32 bytes)
     * @param nowElapsed ignored — we use SystemClock.elapsedRealtime() internally
     * @param ttlMs time-to-live in ms (default 30 min)
     */
    @JvmStatic
    fun store(pingId: String, signerPubKey: ByteArray, nowElapsed: Long, ttlMs: Long) {
        check(isInitialized) {
            "PendingPingStore.dao not initialized before sendPing — signer for $pingId will be " +
            "lost on restart. Ensure SecureLegionDatabase.getInstance() runs before any send path."
        }
        try {
            // Always use elapsedRealtime() — Rust can't call Android APIs,
            // so the nowElapsed param from JNI is ignored.
            val elapsed = SystemClock.elapsedRealtime()
            val entity = PendingPing(
                pingId = pingId,
                signerPubKey = signerPubKey,
                createdAtElapsed = elapsed,
                expiresAtElapsed = elapsed + ttlMs
            )
            dao.upsert(entity)
            Log.d(TAG, "store: persisted signer for pingId=${pingId.take(12)}...")
        } catch (e: Exception) {
            Log.e(TAG, "store: failed to persist signer for $pingId", e)
        }
    }

    /**
     * Called from Rust pong verification — fallback when in-memory cache misses.
     * @param pingId hex-encoded ping nonce
     * @return 32-byte Ed25519 pubkey, or null if not found / expired
     */
    @JvmStatic
    fun lookupSigner(pingId: String): ByteArray? {
        if (!isInitialized) {
            Log.w(TAG, "lookupSigner: DAO not initialized, returning null for $pingId")
            return null
        }
        return try {
            val result = dao.getSigner(pingId)
            if (result != null) {
                Log.i(TAG, "lookupSigner: DB hit for pingId=${pingId.take(12)}...")
            } else {
                Log.d(TAG, "lookupSigner: DB miss for pingId=${pingId.take(12)}...")
            }
            result
        } catch (e: Exception) {
            Log.e(TAG, "lookupSigner: query failed for $pingId", e)
            null
        }
    }

    /**
     * Called from Rust after successful pong/ack verification — clean up.
     * @param pingId hex-encoded ping nonce
     */
    @JvmStatic
    fun delete(pingId: String) {
        if (!isInitialized) return
        try {
            dao.delete(pingId)
            Log.d(TAG, "delete: removed pingId=${pingId.take(12)}...")
        } catch (e: Exception) {
            Log.e(TAG, "delete: failed for $pingId", e)
        }
    }

    /**
     * Purge expired entries. Call periodically (e.g., on app start, hourly).
     */
    @JvmStatic
    fun purgeExpired() {
        if (!isInitialized) return
        try {
            val now = SystemClock.elapsedRealtime()
            dao.purgeExpired(now)
        } catch (e: Exception) {
            Log.e(TAG, "purgeExpired: failed", e)
        }
    }
}
