package com.securelegion

import android.content.Context
import android.util.Log
import androidx.core.os.UserManagerCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File

/**
 * Idempotent post-unlock initialization. Holds all Credential-Encrypted-storage
 * touching work that USED to live in [SecureLegionApplication.onCreate].
 *
 * Direct-Boot architecture: [SecureLegionApplication.onCreate] runs whenever
 * Android attaches the process — including pre-unlock wakes from BootReceiver,
 * WorkManager, GCM, JobScheduler, etc. CE storage (`getSharedPreferences`,
 * `EncryptedSharedPreferences`, `KeyStore` user-auth keys, `filesDir` on FBE
 * devices) is **inaccessible** until the user unlocks. Touching it pre-unlock
 * throws [IllegalStateException] and crashes the process.
 *
 * Call sites (all idempotent — first call wins, repeated calls cheap):
 *   - [SecureLegionApplication.onCreate]: only if user already unlocked at
 *     process attach.
 *   - [UnlockReceiver]: on `Intent.ACTION_USER_UNLOCKED` for headless wake paths.
 *   - [BaseActivity.onCreate] / [SplashActivity] / [LockActivity] /
 *     [MainActivity]: belt-and-suspenders, in case neither path above fired.
 *
 * Thread-safe: a two-flag pattern (`initializing` + `initialized`) prevents both
 * double-init AND racing incomplete init across two threads. If init throws
 * mid-run, `initializing` is cleared so the next call gets to retry.
 */
object SecureRuntime {
    private const val TAG = "SecureRuntime"

    @Volatile private var initialized = false
    @Volatile private var initializing = false
    private val initLock = Any()

    fun initializeAfterUnlock(context: Context) {
        // Fast path — no lock needed.
        if (initialized) return

        if (!UserManagerCompat.isUserUnlocked(context)) {
            Log.w(TAG, "initializeAfterUnlock called while user still locked — skipping")
            return
        }

        synchronized(initLock) {
            if (initialized || initializing) return
            initializing = true
        }

        val app = context.applicationContext
        Log.i(TAG, "Running post-unlock init")

        var success = false
        try {
            // Auto-start Tor if account exists (was Application.onCreate:94-119).
            try {
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(app)
                if (keyManager.isInitialized()) {
                    val shutdownFile = File(app.filesDir, "tor/last_shutdown_time")
                    val recentShutdown = try {
                        shutdownFile.exists() &&
                            (System.currentTimeMillis() -
                                (shutdownFile.readText().trim().toLongOrNull() ?: 0L)) in 1..30_000
                    } catch (_: Exception) { false }

                    if (recentShutdown) {
                        Log.w(TAG, "Tor shutdown was within last 30s — suppressing auto-start to prevent restart storm")
                    } else {
                        Log.d(TAG, "Existing account — auto-starting Tor")
                        com.securelegion.services.TorService.start(app)
                        Log.d(TAG, "Tor initialization started")
                    }
                } else {
                    Log.i(TAG, "First-time setup — skipping Tor auto-start (user will press Start)")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to initialize Tor", e)
            }

            // IPFS Manager — gated behind BuildConfig.ENABLE_CRUST_IPFS. On flavors with
            // Crust/IPFS disabled (googleplay, googleplaydemo, fdroid), skip the local
            // pin-cache directory init entirely; nothing in those builds reads from it.
            if (com.securelegion.BuildConfig.ENABLE_CRUST_IPFS) {
                try {
                    Log.d(TAG, "Initializing IPFS Manager...")
                    CoroutineScope(Dispatchers.IO).launch {
                        val r = com.securelegion.services.IPFSManager.getInstance(app).initialize()
                        if (r.isSuccess) {
                            Log.i(TAG, "IPFS Manager initialized successfully")
                        } else {
                            Log.e(TAG, "IPFS Manager initialization failed: ${r.exceptionOrNull()?.message}")
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to initialize IPFS Manager", e)
                }
            } else {
                Log.d(TAG, "Skipping IPFS Manager init — ENABLE_CRUST_IPFS=false in this flavor")
            }

            success = true
        } finally {
            synchronized(initLock) {
                if (success) initialized = true
                initializing = false
            }
        }
    }
}
