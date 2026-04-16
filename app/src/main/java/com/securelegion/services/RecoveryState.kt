package com.securelegion.services

import android.content.Context
import android.util.Log

/**
 * Contact-list recovery state — tracks whether this device was just restored
 * from a 12-word seed and is looking to pull its contact list back from the
 * first friend it re-adds.
 *
 * Matches the iOS flow described in `docs/contact-list-recovery-android-sync.md`:
 * flipped on during seed restore, consumed by the FR-completion path to fire a
 * single signed `0x80` REQUEST at the newly-added friend, cleared after the
 * encrypted blob is decrypted and imported. Auto-expires after 48 hours so a
 * permanently-failed recovery doesn't hang forever.
 *
 * Stored in plain SharedPreferences — the data is not sensitive (no keys, no
 * PINs; just a boolean + a public content-id + a timestamp), and we need it
 * reachable before the DB passphrase is available on first boot after restore.
 */
object RecoveryState {
    private const val TAG = "RecoveryState"
    private const val PREFS_NAME = "recovery_state"

    private const val KEY_RECOVERY_NEEDED = "recovery_needed"
    private const val KEY_EXPECTED_CID = "expected_cid"
    private const val KEY_STARTED_AT = "started_at"

    /** Auto-expire window — after 48h we assume the recovery will never succeed. */
    private const val EXPIRY_MS = 48L * 60L * 60L * 1000L

    /**
     * Flip recovery on. Called from the seed-restore code path in
     * `CreateAccountActivity` once the contact-list CID has been derived.
     */
    fun setActive(context: Context, expectedCid: String) {
        val now = System.currentTimeMillis()
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .putBoolean(KEY_RECOVERY_NEEDED, true)
            .putString(KEY_EXPECTED_CID, expectedCid)
            .putLong(KEY_STARTED_AT, now)
            .apply()
        Log.i(TAG, "recovery armed: cid=${expectedCid.take(20)}… started_at=$now")
    }

    /**
     * True if recovery is armed AND within the 48h window. If the window has
     * already expired this silently clears the state as a side-effect so the
     * next caller sees a clean slate.
     */
    fun isActive(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_RECOVERY_NEEDED, false)) return false

        val startedAt = prefs.getLong(KEY_STARTED_AT, 0L)
        if (startedAt <= 0L) {
            // Legacy record from before this helper existed — treat as just-started
            // rather than dropping state someone else set. Stamp it now.
            prefs.edit().putLong(KEY_STARTED_AT, System.currentTimeMillis()).apply()
            return true
        }

        val elapsed = System.currentTimeMillis() - startedAt
        if (elapsed > EXPIRY_MS) {
            Log.i(TAG, "recovery expired after ${elapsed}ms — clearing")
            clear(context)
            return false
        }
        return true
    }

    fun getExpectedCid(context: Context): String? =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getString(KEY_EXPECTED_CID, null)
            ?.takeIf { it.isNotEmpty() }

    /**
     * Clear all recovery state. Called once a `0x81` RESPONSE is imported
     * successfully for the expected CID, or when the 48h window expires.
     */
    fun clear(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
            .remove(KEY_RECOVERY_NEEDED)
            .remove(KEY_EXPECTED_CID)
            .remove(KEY_STARTED_AT)
            .apply()
        Log.i(TAG, "recovery cleared")
    }
}
