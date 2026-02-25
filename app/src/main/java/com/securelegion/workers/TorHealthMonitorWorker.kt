package com.securelegion.workers

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import android.util.Log
import androidx.work.*
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.models.TorFailureType
import com.securelegion.models.TorHealthSnapshot
import com.securelegion.models.TorHealthStatus
import com.securelegion.services.TorService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.net.ConnectivityManager
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
 * 3. HS listener liveness (loop heartbeat + accept heartbeat + self-circuit test)
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
        private const val WORK_NAME = "tor_health_monitor"
        private const val CHECK_INTERVAL_SECONDS = 60L
        private const val SOCKS_HOST = "127.0.0.1"
        private const val SOCKS_PORT = 9050
        private const val SOCKS_TIMEOUT_MS = 2000 // Fast fail if SOCKS not responding

        private const val WARMUP_WINDOW_MS = 120000 // 2 minutes: Tor/HS needs time to stabilize after restart
        private const val FAILURE_THRESHOLD = 5 // Go UNHEALTHY after 5 failures
        private const val TIME_SINCE_OK_THRESHOLD_MS = 120000 // 2 minutes: only restart if Tor has been good in last 2m

        // HS liveness thresholds
        private const val HS_LOOP_STALE_THRESHOLD_MS = 90_000L  // 90s: accept loop ticks every 30s, 3x margin
        private const val HS_SELF_TEST_FAILURE_THRESHOLD = 3    // Restart listeners after 3 consecutive failures (~3min)
        private const val HS_RESTART_COOLDOWN_MS = 3 * 60_000L  // 3 minutes between listener restarts
        private const val HS_ACCEPT_RECENT_MS = 5 * 60_000L     // If accept heartbeat <5min old, skip self-test

        // DEGRADED escalation: circuits=0 recovery ladder
        private const val DEGRADED_GRACE_MS = 180_000L         // 3 minutes before escalating
        private const val DEGRADED_RECOVERY_COOLDOWN_MS = 60_000L // 60s between recovery attempts
        private const val HS_SERVICE_PORT = 9150                 // Virtual port on .onion (9150 → local 8080)

        /**
         * Schedule periodic Tor health checks
         * Called once at app startup
         */
        fun schedulePeriodicCheck(context: Context) {
            // Use a chained OneTimeWork cadence to support sub-15-minute intervals.
            // WorkManager periodic requests enforce a 15-minute minimum.
            val wm = WorkManager.getInstance(context)
            wm.cancelUniqueWork(WORK_NAME) // Migrate any legacy periodic registration with same name
            val kickoff = OneTimeWorkRequestBuilder<TorHealthMonitorWorker>().build()
            wm.enqueueUniqueWork(
                WORK_NAME,
                ExistingWorkPolicy.REPLACE,
                kickoff
            )
            Log.i(TAG, "Scheduled Tor health monitor cadence (${CHECK_INTERVAL_SECONDS}s)")
        }

        private fun scheduleNextCheck(context: Context) {
            val next = OneTimeWorkRequestBuilder<TorHealthMonitorWorker>()
                .setInitialDelay(CHECK_INTERVAL_SECONDS, TimeUnit.SECONDS)
                .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                WORK_NAME,
                ExistingWorkPolicy.APPEND,
                next
            )
        }
    }

    override suspend fun doWork(): Result {
        return withContext(Dispatchers.IO) {
            try {
                val snapshot = checkTorHealth()
                saveTorHealthSnapshot(snapshot)
                scheduleNextCheck(applicationContext)

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

        // PHASE 3: HS Listener Liveness (ACTIONABLE — triggers LISTENER restart, never Tor restart)
        //
        // Tor process is HEALTHY at this point (SOCKS + bootstrap OK).
        // But the hidden service listener may be dead/wedged → incoming messages broken.
        //
        // Two heartbeats from Rust:
        //   loop heartbeat  = accept-loop task is alive (ticks every 30s)
        //   accept heartbeat = valid protocol frame processed (real inbound traffic)
        //
        // Decision tree:
        //   1. loop == 0           → startup phase, skip
        //   2. loop stale >90s     → listener task wedged → restart listeners (cooldown)
        //   3. loop fresh + accept recent (<5min) → real traffic flowing → skip self-test
        //   4. loop fresh + accept stale → run self-test; N failures → restart listeners (cooldown)
        //
        val nowMs = System.currentTimeMillis()
        val hsLoopHb = com.securelegion.crypto.RustBridge.getLastHsLoopHeartbeat()
        val hsAcceptHb = com.securelegion.crypto.RustBridge.getLastHsAcceptHeartbeat()
        val hsLoopAgeMs = if (hsLoopHb > 0) nowMs - hsLoopHb else Long.MAX_VALUE
        val hsAcceptAgeMs = if (hsAcceptHb > 0) nowMs - hsAcceptHb else Long.MAX_VALUE

        val healthPrefs = applicationContext.getSharedPreferences("tor_health", Context.MODE_PRIVATE)

        // Warmup guard: skip HS liveness checks during post-restart stabilization
        // Without this, the worker can restart listeners during normal bootstrap, fighting TorRehydrator
        val timeSinceLastRestart = now - current.lastRestartElapsedMs
        val hsInWarmup = current.lastRestartElapsedMs > 0 && timeSinceLastRestart < WARMUP_WINDOW_MS
        if (hsInWarmup) {
            Log.d(TAG, "HS liveness: skipping (warmup window, ${timeSinceLastRestart / 1000}s since restart)")
        } else when {
            hsLoopHb == 0L -> {
                // CASE 1: Listener never started yet
                Log.d(TAG, "HS liveness: loop heartbeat not initialized (listener starting)")
            }
            hsLoopAgeMs > HS_LOOP_STALE_THRESHOLD_MS -> {
                // CASE 2: Loop heartbeat stale — accept loop is wedged/dead
                Log.w(TAG, "HS liveness: loop heartbeat STALE (${hsLoopAgeMs}ms) → listener dead")
                requestListenerRestartWithCooldown(healthPrefs, nowMs,
                    "HS loop heartbeat stale: ${hsLoopAgeMs}ms")
            }
            hsAcceptAgeMs < HS_ACCEPT_RECENT_MS -> {
                // CASE 3: Loop alive + real inbound traffic recently → fully healthy
                // Real inbound traffic IS proof of onion reachability (better than self-test)
                Log.d(TAG, "HS liveness: loop OK, accept recent (${hsAcceptAgeMs}ms) → healthy + proof OK")
                healthPrefs.edit().putInt("hs_self_test_failures", 0).apply()
                RustBridge.setTorProofOk()
            }
            else -> {
                // CASE 4: Loop alive but no recent inbound — run self-circuit test
                // Skip self-test if cooldown is active (avoid hammering during recovery)
                val lastRestart = healthPrefs.getLong("hs_last_restart_ms", 0L)
                if (nowMs - lastRestart < HS_RESTART_COOLDOWN_MS) {
                    Log.d(TAG, "HS liveness: cooldown active, skipping self-test")
                } else {
                    val ownOnion = getTorOnionAddress()
                    if (ownOnion.isNotEmpty()) {
                        val circuitWorking = checkCircuitToOnion(ownOnion, HS_SERVICE_PORT)
                        if (circuitWorking) {
                            Log.i(TAG, "HS self-test PASSED: .onion:$HS_SERVICE_PORT reachable")
                            healthPrefs.edit().putInt("hs_self_test_failures", 0).apply()
                            // Record proof — UI uses this to determine "receivable via onion"
                            RustBridge.setTorProofOk()
                        } else {
                            val failures = healthPrefs.getInt("hs_self_test_failures", 0) + 1
                            healthPrefs.edit().putInt("hs_self_test_failures", failures).apply()
                            Log.w(TAG, "HS self-test FAILED ($failures/$HS_SELF_TEST_FAILURE_THRESHOLD)")

                            if (failures >= HS_SELF_TEST_FAILURE_THRESHOLD) {
                                healthPrefs.edit().putInt("hs_self_test_failures", 0).apply()
                                requestListenerRestartWithCooldown(healthPrefs, nowMs,
                                    "HS self-test failed $failures consecutive times")
                            }
                        }
                    } else {
                        Log.w(TAG, "HS self-test DISABLED: own onion not available — " +
                            "inbound liveness limited to loop heartbeat only")
                    }
                }
            }
        }

        // PHASE 4: Circuit-level connectivity check
        // SOCKS + bootstrap OK, but do we actually have circuits to the Tor network?
        // Without circuits, outbound works via cached SOCKS but inbound is dead.
        val circuitsEstablished = try {
            com.securelegion.crypto.RustBridge.getCircuitEstablished()
        } catch (e: Exception) { 0 }

        if (circuitsEstablished == 0) {
            Log.w(TAG, "SOCKS OK + bootstrap=$bootstrapPercent but circuits=0 → DEGRADED")

            // Track consecutive zero-circuit samples to avoid false escalation from transient dips
            val circuitsZeroStreak = healthPrefs.getInt("circuits_zero_streak", 0) + 1
            healthPrefs.edit().putInt("circuits_zero_streak", circuitsZeroStreak).apply()

            // --- DEGRADED escalation ladder ---
            // Guards:
            //   A) Require consecutive circuits==0 samples (not single transient dip)
            //   B) Require bootstrap nearly done AND device has VALIDATED internet
            //   C) Warmup guard: don't escalate within 2min of last Tor restart
            val timeSinceLastRestart = now - current.lastRestartElapsedMs
            val inWarmup = current.lastRestartElapsedMs > 0 && timeSinceLastRestart < WARMUP_WINDOW_MS

            if (circuitsZeroStreak < 2) {
                Log.d(TAG, "DEGRADED: circuits=0 streak=$circuitsZeroStreak (need ≥2 consecutive) — waiting for next sample")
            } else if (inWarmup) {
                Log.d(TAG, "DEGRADED: in warmup window (${timeSinceLastRestart / 1000}s / ${WARMUP_WINDOW_MS / 1000}s since restart) — skipping escalation")
            } else if (bootstrapPercent >= 90 && hasInternetConnectivity()) {
                val degradedSince = healthPrefs.getLong("degraded_since_ms", 0L)
                val degradedStep = healthPrefs.getInt("degraded_recovery_step", 0)
                val lastRecovery = healthPrefs.getLong("degraded_last_recovery_ms", 0L)

                // Guard D: Don't escalate listener restart if one happened recently
                val lastListenerRestart = healthPrefs.getLong("hs_last_restart_ms", 0L)

                // First time entering DEGRADED: record timestamp
                if (degradedSince == 0L) {
                    healthPrefs.edit().putLong("degraded_since_ms", nowMs).apply()
                    Log.i(TAG, "DEGRADED: starting grace period (${DEGRADED_GRACE_MS / 1000}s)")
                } else if (nowMs - degradedSince > DEGRADED_GRACE_MS
                    && nowMs - lastRecovery > DEGRADED_RECOVERY_COOLDOWN_MS) {
                    // Grace period elapsed + cooldown expired → escalate
                    when (degradedStep) {
                        0 -> {
                            Log.w(TAG, "DEGRADED escalation step 0: sending NEWNYM")
                            TorService.requestNewnym("DEGRADED escalation: circuits=0 for ${(nowMs - degradedSince) / 1000}s")
                            healthPrefs.edit()
                                .putInt("degraded_recovery_step", 1)
                                .putLong("degraded_last_recovery_ms", nowMs)
                                .apply()
                        }
                        1 -> {
                            // Guard: skip if listener was recently restarted (by HS liveness or rehydrator)
                            if (nowMs - lastListenerRestart < HS_RESTART_COOLDOWN_MS) {
                                Log.w(TAG, "DEGRADED step 1 suppressed: listener restarted ${(nowMs - lastListenerRestart) / 1000}s ago")
                            } else {
                                Log.w(TAG, "DEGRADED escalation step 1: restarting HS listeners")
                                TorService.requestListenerRestart("DEGRADED escalation: circuits=0 after NEWNYM")
                                healthPrefs.edit()
                                    .putLong("hs_last_restart_ms", nowMs)
                                    .apply()
                            }
                            healthPrefs.edit()
                                .putInt("degraded_recovery_step", 2)
                                .putLong("degraded_last_recovery_ms", nowMs)
                                .apply()
                        }
                        else -> {
                            Log.w(TAG, "DEGRADED escalation step 2: full Tor restart")
                            TorService.requestRestart("DEGRADED escalation: circuits=0 after listener restart")
                            healthPrefs.edit()
                                .putInt("degraded_recovery_step", 0)
                                .putLong("degraded_last_recovery_ms", nowMs)
                                .putLong("degraded_since_ms", 0L)
                                .apply()
                        }
                    }
                } else {
                    val graceRemaining = maxOf(0, DEGRADED_GRACE_MS - (nowMs - degradedSince)) / 1000
                    val cooldownRemaining = maxOf(0, DEGRADED_RECOVERY_COOLDOWN_MS - (nowMs - lastRecovery)) / 1000
                    Log.d(TAG, "DEGRADED: waiting (grace=${graceRemaining}s, cooldown=${cooldownRemaining}s, step=$degradedStep)")
                }
            } else {
                Log.d(TAG, "DEGRADED: bootstrap=$bootstrapPercent (still starting) or no validated internet — skipping escalation")
            }

            return current.copy(
                status = TorHealthStatus.DEGRADED,
                lastCheckElapsedMs = now,
                lastFailureType = TorFailureType.CIRCUIT_FAILED,
                lastError = "No circuits established (bootstrap=$bootstrapPercent%)",
                lastStatusChangeElapsedMs = if (current.status != TorHealthStatus.DEGRADED) now else current.lastStatusChangeElapsedMs
            )
        }

        // Tor process is HEALTHY (SOCKS OK + bootstrap 100% + circuits established)
        // Clear DEGRADED tracking + zero-circuit streak if we were previously degraded
        val prevDegradedSince = healthPrefs.getLong("degraded_since_ms", 0L)
        val prevStreak = healthPrefs.getInt("circuits_zero_streak", 0)
        if (prevDegradedSince != 0L || prevStreak > 0) {
            Log.i(TAG, "Circuits recovered — clearing DEGRADED escalation state (streak was $prevStreak)")
            healthPrefs.edit()
                .putLong("degraded_since_ms", 0L)
                .putInt("degraded_recovery_step", 0)
                .putLong("degraded_last_recovery_ms", 0L)
                .putInt("circuits_zero_streak", 0)
                .apply()
        }

        Log.i(TAG, "Tor process healthy (SOCKS OK + bootstrap 100% + circuits=1)")
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
    private suspend fun checkTorBootstrap(): Int = withContext(Dispatchers.IO) {
        try {
            val bootstrap = com.securelegion.crypto.RustBridge.getBootstrapStatus()
            if (bootstrap in 1..100) return@withContext bootstrap

            // bootstrap==0 → event listener not attached yet OR Tor not started.
            // Use circuitsEstablished as the real "Tor network usable" signal.
            val circuits = com.securelegion.crypto.RustBridge.getCircuitEstablished()
            if (circuits == 1) 100 else 0
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read bootstrap status: ${e.message}")
            0
        }
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
                socket.soTimeout = 25000 // 25s: cold .onion connections need 10-20s after circuit rebuild
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
                val connectReq = ByteArray(7 + onionBytes.size)
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
                // Primary: messaging onion (the HS that listens on port 8080)
                val onion = keyManager.getMessagingOnion()
                if (!onion.isNullOrEmpty()) {
                    return@withContext onion
                }
                // Fallback: TorManager's stored onion
                val torManager = com.securelegion.crypto.TorManager.getInstance(applicationContext)
                torManager.getOnionAddress() ?: ""
            } catch (e: Exception) {
                Log.w(TAG, "Failed to get own onion address: ${e.message}")
                ""
            }
        }
    }

    /**
     * Check if device has internet connectivity (WiFi or cellular).
     * Used to gate DEGRADED escalation — no point sending NEWNYM without a network.
     */
    private fun hasInternetConnectivity(): Boolean {
        val cm = applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        val network = cm.activeNetwork ?: return false
        val capabilities = cm.getNetworkCapabilities(network) ?: return false
        // Require VALIDATED (not just INTERNET) to avoid false positives on dead wifi / captive portals.
        // INTERNET alone only means "network claims it can reach internet" — VALIDATED means Android
        // actually verified connectivity, which prevents NEWNYM/restart storms during dead wifi.
        return capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            && capabilities.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED)
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
     * Request HS listener restart with cooldown protection.
     * Prevents restart loops during recovery or unstable networks.
     */
    private fun requestListenerRestartWithCooldown(
        prefs: SharedPreferences,
        nowMs: Long,
        reason: String
    ) {
        val lastRestart = prefs.getLong("hs_last_restart_ms", 0L)
        if (nowMs - lastRestart < HS_RESTART_COOLDOWN_MS) {
            Log.w(TAG, "HS listener restart suppressed (cooldown active, ${(nowMs - lastRestart) / 1000}s / ${HS_RESTART_COOLDOWN_MS / 1000}s): $reason")
            return
        }
        prefs.edit()
            .putLong("hs_last_restart_ms", nowMs)
            .putInt("hs_self_test_failures", 0)
            .apply()
        Log.w(TAG, "Requesting HS listener restart: $reason")
        TorService.requestListenerRestart(reason)
    }

    /**
     * Get current Tor health snapshot from SharedPreferences
     */
    private fun getTorHealthSnapshot(): TorHealthSnapshot {
        val prefs = applicationContext.getSharedPreferences("tor_health", Context.MODE_PRIVATE)
        val prefsString = prefs.getString("snapshot", "")
        return if (prefsString.isNullOrEmpty()) {
            // No snapshot yet → RECOVERING (safe default, prevents false-healthy at cold start)
            TorHealthSnapshot(status = TorHealthStatus.RECOVERING, lastError = "no health snapshot yet")
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
