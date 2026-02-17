package com.securelegion.workers

import android.content.Context
import android.os.SystemClock
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.models.TorFailureType
import com.securelegion.models.TorHealthSnapshot
import com.securelegion.models.TorHealthStatus
import com.securelegion.services.TorService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit

/**
 * Periodic Tor health monitor
 *
 * Runs every 60 seconds to detect and recover from Tor PROCESS failures only.
 *
 * DESIGN PRINCIPLE:
 * - Only restart on process-level failures (SOCKS down, bootstrap stuck)
 * - NEVER restart on circuit-level failures (they are normal Tor behavior)
 *
 * Health checks:
 * 1. SOCKS5 reachability (127.0.0.1:9050 socket connect)
 * 2. Bootstrap progress (assume 100% if SOCKS responds)
 * 3. Circuit test (TELEMETRY ONLY - never triggers restart)
 *
 * What is HEALTHY:
 * - SOCKS port responding + bootstrap complete
 *
 * What is UNHEALTHY (restart):
 * - SOCKS port not responding for >N checks
 * - Bootstrap stuck < 100% (future implementation)
 *
 * What is NOT a failure:
 * - Circuit timeouts (CIRC_CLOSED TIMEOUT)
 * - Onion unreachable (REP=6, HS descriptor delay)
 * - Rendezvous failures
 *
 * CRITICAL: Uses monotonic time (elapsedRealtime) for all calculations
 */
class TorHealthMonitorWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "TorHealthMonitor"
        private const val SOCKS_HOST = "127.0.0.1"
        private const val SOCKS_PORT = 9050
        private const val SOCKS_TIMEOUT_MS = 2000 // Fast fail if SOCKS not responding

        private const val WARMUP_WINDOW_MS = 120000 // 2 minutes: Tor/HS needs time to stabilize after restart
        private const val FAILURE_THRESHOLD = 5 // Go UNHEALTHY after 5 failures
        private const val TIME_SINCE_OK_THRESHOLD_MS = 120000 // 2 minutes: only restart if Tor has been good in last 2m

        /**
         * Schedule periodic Tor health checks
         * Called once at app startup
         */
        fun schedulePeriodicCheck(context: Context) {
            val healthCheckRequest = PeriodicWorkRequestBuilder<TorHealthMonitorWorker>(
                60, // Run every 60 seconds
                TimeUnit.SECONDS
            ).build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "tor_health_monitor",
                ExistingPeriodicWorkPolicy.KEEP,
                healthCheckRequest
            )

            Log.i(TAG, "Scheduled periodic Tor health monitor (60s)")
        }
    }

    override suspend fun doWork(): Result {
        return withContext(Dispatchers.IO) {
            try {
                val snapshot = checkTorHealth()
                saveTorHealthSnapshot(snapshot)

                Log.i(TAG, "Health check complete: ${snapshot.status} (failCount=${snapshot.failCount}, error=${snapshot.lastError.take(50)})")
                Result.success()
            } catch (e: Exception) {
                Log.e(TAG, "Health check failed: ${e.message}", e)
                Result.retry()
            }
        }
    }

    /**
     * Main health check logic
     *
     * NEW DESIGN (restart loop fixed):
     * 1. Check SOCKS5 reachability (fast fail) → restart if down
     * 2. Check bootstrap progress → wait if < 100%
     * 3. Test self-onion circuit (TELEMETRY ONLY) → never restart
     * 4. If SOCKS OK + bootstrap 100% → HEALTHY (always)
     *
     * CRITICAL: Only restart on process-level failures (SOCKS down).
     * Circuit failures are NORMAL and do not trigger restarts.
     */
    private suspend fun checkTorHealth(): TorHealthSnapshot {
        val current = getTorHealthSnapshot()
        val now = SystemClock.elapsedRealtime()

        Log.d(TAG, "Starting health check (current status: ${current.status})")

        // PHASE 1: SOCKS5 reachability (fast, hard fail)
        val socksAlive = checkSocks5Reachable()
        if (!socksAlive) {
            Log.w(TAG, "SOCKS5 not responding on port $SOCKS_PORT")
            val updated = current.copy(
                status = TorHealthStatus.UNHEALTHY,
                failCount = current.failCount + 1,
                lastCheckElapsedMs = now,
                lastFailureType = TorFailureType.SOCKS_DOWN,
                lastError = "SOCKS5 not responding on port $SOCKS_PORT",
                lastStatusChangeElapsedMs = if (current.status != TorHealthStatus.UNHEALTHY) now else current.lastStatusChangeElapsedMs
            )
            attemptRestartIfAllowed(updated)
            return updated
        }

        Log.d(TAG, "SOCKS5 reachable")

        // PHASE 2: Check Tor bootstrap status
        val bootstrapPercent = checkTorBootstrap()
        Log.d(TAG, "Tor bootstrap: $bootstrapPercent%")

        // REFINEMENT B: Don't restart while bootstrapping
        if (bootstrapPercent < 100) {
            Log.d(TAG, "Tor still bootstrapping ($bootstrapPercent%), staying RECOVERING")
            return current.copy(
                status = TorHealthStatus.RECOVERING,
                failCount = 0, // Reset failCount while bootstrapping
                lastCheckElapsedMs = now,
                lastFailureType = TorFailureType.BOOTSTRAP_NOT_READY,
                lastError = "Bootstrapping ($bootstrapPercent%)",
                lastStatusChangeElapsedMs = if (current.status != TorHealthStatus.RECOVERING) now else current.lastStatusChangeElapsedMs
            )
        }

        Log.d(TAG, "Bootstrap complete (100%)")

        // PHASE 3: Circuit test (TELEMETRY ONLY - NEVER TRIGGERS RESTART)
        //
        // CRITICAL DESIGN CHANGE (per deep-dive analysis):
        // Circuit failures (REP=6, TTL expired, onion offline, HS descriptor delays, timeouts)
        // are NORMAL Tor behavior and do NOT indicate local Tor is broken.
        //
        // Restarting Tor based on circuit failures creates a restart loop:
        // - Normal circuit churn → onion CONNECT fails
        // - Worker restarts Tor → tears down listeners/SOCKS/OkHttp
        // - Restart causes MORE circuit churn
        // - Loop repeats
        //
        // NEW LOGIC:
        // - If SOCKS reachable AND bootstrap=100% → Tor is HEALTHY (period)
        // - Circuit test is telemetry only (log but don't escalate)
        // - Only restart on process-level failures (SOCKS down, bootstrap stuck)
        //
        val ownOnion = getTorOnionAddress()
        if (ownOnion.isNotEmpty()) {
            // Run circuit test for telemetry (helps diagnose HS descriptor issues)
            val circuitWorking = checkCircuitToOnion(ownOnion, 9150)
            if (circuitWorking) {
                Log.i(TAG, "Circuit telemetry: Can reach own .onion:9150 ")
            } else {
                Log.i(TAG, "Circuit telemetry: Cannot reach own .onion:9150 (normal - descriptor delay, circuit churn, or listener not ready)")
            }
        } else {
            Log.d(TAG, "Circuit telemetry: Skipped (own onion not available)")
        }

        // If we got here: SOCKS is reachable AND bootstrap is 100%
        // → Tor process is HEALTHY regardless of circuit test result
        Log.i(TAG, "Tor process healthy (SOCKS OK + bootstrap 100%)")
        return current.copy(
            status = TorHealthStatus.HEALTHY,
            lastOkElapsedMs = now,
            lastCheckElapsedMs = now,
            failCount = 0,
            lastError = "",
            lastStatusChangeElapsedMs = if (current.status != TorHealthStatus.HEALTHY) now else current.lastStatusChangeElapsedMs
        )
    }

    /**
     * Check if SOCKS5 proxy is reachable on 127.0.0.1:9050
     * Fast check: 2 second timeout
     */
    private suspend fun checkSocks5Reachable(): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress(SOCKS_HOST, SOCKS_PORT), SOCKS_TIMEOUT_MS)
                socket.close()
                true
            } catch (e: Exception) {
                Log.d(TAG, "SOCKS5 check failed: ${e.message}")
                false
            }
        }
    }

    /**
     * Check Tor bootstrap progress (0-100%)
     *
     * Currently uses a heuristic: assume 100% if SOCKS responds (simplest approach)
     * TODO: Integrate Tor control port for accurate bootstrap status
     */
    private suspend fun checkTorBootstrap(): Int {
        // Heuristic: if we got here, SOCKS is responding
        // In a real implementation, you'd query Tor control port:
        // `GETINFO status/bootstrap-phase`
        // For now, trust that bootstrap is complete
        return 100
    }

    /**
     * Test if Tor can route to an onion via SOCKS5 CONNECT
     *
     * TELEMETRY ONLY - NEVER USE THIS TO TRIGGER RESTARTS 
     *
     * This test is useful for diagnosing HS descriptor issues, but failures
     * do NOT indicate local Tor is broken. Common normal failures:
     * - REP=6: TTL expired (circuit churned mid-connect)
     * - REP=5: Connection refused (onion offline or listener not ready)
     * - Timeout: HS descriptor not yet published, rendezvous delay
     *
     * SOCKS5 protocol:
     * 1. Connect to SOCKS5 server (127.0.0.1:9050)
     * 2. Auth handshake (no auth required)
     * 3. Send CONNECT request with onion address + port
     * 4. Server responds with REP code (0=success, 5=refused, 6=TTL expired, etc.)
     *
     * REP ≠ 0 is NORMAL on mobile Tor and does NOT mean restart is needed.
     */
    private suspend fun checkCircuitToOnion(onionAddress: String, port: Int): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val socket = Socket()
                socket.soTimeout = 3000 // 3s timeout for SOCKS handshake
                socket.connect(InetSocketAddress(SOCKS_HOST, SOCKS_PORT), 2000)

                val output = socket.getOutputStream()
                val input = socket.getInputStream()

                // SOCKS5 auth handshake: no auth required
                output.write(byteArrayOf(0x05, 0x01, 0x00)) // VER=5, NMETHODS=1, METHOD=0
                output.flush()

                val authResp = ByteArray(2)
                if (input.read(authResp) != 2) {
                    socket.close()
                    return@withContext false
                }

                if (authResp[0] != 0x05.toByte() || authResp[1] != 0x00.toByte()) {
                    socket.close()
                    return@withContext false
                }

                // SOCKS5 CONNECT request to onion
                val onionBytes = onionAddress.toByteArray()
                val connectReq = ByteArray(6 + onionBytes.size)
                connectReq[0] = 0x05 // VER
                connectReq[1] = 0x01 // CMD=CONNECT
                connectReq[2] = 0x00 // RSV
                connectReq[3] = 0x03 // ATYP=DOMAINNAME
                connectReq[4] = onionBytes.size.toByte() // domain length
                onionBytes.copyInto(connectReq, 5)
                connectReq[5 + onionBytes.size] = (port shr 8).toByte() // port high byte
                connectReq[6 + onionBytes.size] = (port and 0xFF).toByte() // port low byte

                output.write(connectReq)
                output.flush()

                // Read CONNECT response
                val connectResp = ByteArray(4 + 256) // max domain response
                val bytesRead = input.read(connectResp)
                socket.close()

                // Response: VER=5, REP (0=success, others=fail), RSV=0, ATYP, ADDR, PORT
                if (bytesRead < 4) {
                    return@withContext false
                }

                val isSuccess = connectResp[0] == 0x05.toByte() && connectResp[1] == 0x00.toByte()
                if (!isSuccess) {
                    val repCode = connectResp[1].toInt() and 0xFF
                    Log.d(TAG, "Circuit test to $onionAddress:$port failed: SOCKS5 status $repCode")
                }

                isSuccess
            } catch (e: Exception) {
                Log.d(TAG, "Circuit test to $onionAddress:$port failed: ${e.message}")
                false
            }
        }
    }

    /**
     * Get this device's own .onion address
     */
    private suspend fun getTorOnionAddress(): String {
        return withContext(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(applicationContext)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(applicationContext, dbPassphrase)

                // Get own device's onion (stored in Contact or config)
                // For now, return empty (will skip circuit test)
                // TODO: Implement once you have a way to store own onion
                ""
            } catch (e: Exception) {
                Log.w(TAG, "Failed to get own onion address: ${e.message}")
                ""
            }
        }
    }

    /**
     * Attempt to restart Tor if cooldown allows
     * Respects exponential backoff: 1s → 5s → 30s → 60s
     */
    private suspend fun attemptRestartIfAllowed(snapshot: TorHealthSnapshot) {
        if (snapshot.shouldAttemptRestart()) {
            Log.w(TAG, "Triggering Tor restart (reason: ${snapshot.lastFailureType})")
            TorService.requestRestart("health monitor: ${snapshot.lastFailureType}")

            val updated = snapshot.copy(
                status = TorHealthStatus.RECOVERING,
                lastRestartElapsedMs = SystemClock.elapsedRealtime(),
                restartCooldownMs = snapshot.nextRestartCooldown()
            )
            saveTorHealthSnapshot(updated)
        } else {
            val timeUntilRetry = snapshot.restartCooldownMs - (SystemClock.elapsedRealtime() - snapshot.lastRestartElapsedMs)
            Log.d(TAG, "Restart cooldown active (retry in ${timeUntilRetry}ms)")
        }
    }

    /**
     * Get current Tor health snapshot from SharedPreferences
     */
    private fun getTorHealthSnapshot(): TorHealthSnapshot {
        val prefs = applicationContext.getSharedPreferences("tor_health", Context.MODE_PRIVATE)
        val prefsString = prefs.getString("snapshot", "")
        return if (prefsString.isNullOrEmpty()) {
            TorHealthSnapshot()
        } else {
            TorHealthSnapshot.fromPrefsString(prefsString)
        }
    }

    /**
     * Save Tor health snapshot to SharedPreferences
     */
    private fun saveTorHealthSnapshot(snapshot: TorHealthSnapshot) {
        val prefs = applicationContext.getSharedPreferences("tor_health", Context.MODE_PRIVATE)
        prefs.edit().putString("snapshot", TorHealthSnapshot.toPrefsString(snapshot)).apply()
    }
}
