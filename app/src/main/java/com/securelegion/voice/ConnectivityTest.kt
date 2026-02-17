package com.securelegion.voice

import android.util.Log
import com.securelegion.crypto.RustBridge
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import java.util.UUID

/**
 * ConnectivityTest - PING/PONG connectivity proof protocol
 *
 * Purpose: Verify Tor circuits are bidirectionally working BEFORE attempting voice calls
 *
 * Test Flow:
 * 1. Device A establishes Tor circuit to Device B's onion address
 * 2. Device A sends PING message
 * 3. Device B receives PING and replies with PONG
 * 4. Device A receives PONG → connectivity proven
 * 5. Only then allow voice calls or messaging
 *
 * This isolates Tor connectivity from audio, encryption, and multi-circuit complexity.
 * If PING/PONG fails, voice will never work.
 */
object ConnectivityTest {
    private const val TAG = "ConnectivityTest"

    // Message type for Rust protocol
    private const val MSG_TYPE_PING_PONG: Byte = 0x0E // New message type for connectivity tests

    // Protocol messages
    const val TYPE_PING = "PING"
    const val TYPE_PONG = "PONG"

    // Test timeout
    private const val PING_TIMEOUT_MS = 30000L // 30 seconds for full round trip
    private const val PONG_POLL_INTERVAL_MS = 100L // Poll for PONG every 100ms

    // Track pending PONGs (testId -> received timestamp)
    private val pendingPongs = java.util.concurrent.ConcurrentHashMap<String, Long>()

    /**
     * Test connectivity to a contact's voice onion address
     *
     * @param recipientX25519PublicKey Contact's X25519 key for encryption
     * @param recipientVoiceOnion Contact's VOICE .onion address (not messaging onion)
     * @return ConnectivityResult with success status and details
     */
    suspend fun testConnectivity(
        recipientX25519PublicKey: ByteArray,
        recipientVoiceOnion: String
    ): ConnectivityResult = withContext(Dispatchers.IO) {
        val testId = UUID.randomUUID().toString().take(8)
        val startTime = System.currentTimeMillis()

        Log.i(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        Log.i(TAG, "PING/PONG Connectivity Test Started")
        Log.i(TAG, "Test ID: $testId")
        Log.i(TAG, "Target: $recipientVoiceOnion")
        Log.i(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        try {
            // Phase 1: Send PING
            Log.d(TAG, "Phase 1: Sending PING to $recipientVoiceOnion...")
            val pingJson = JSONObject().apply {
                put("type", TYPE_PING)
                put("testId", testId)
                put("timestamp", System.currentTimeMillis())
                put("seq", 1)
            }

            val message = pingJson.toString()

            // Prepend metadata byte 0x0E so recipient knows this is PING/PONG
            val metadataByte = byteArrayOf(MSG_TYPE_PING_PONG)
            val messageBytes = message.toByteArray(Charsets.UTF_8)
            val messageWithMetadata = metadataByte + messageBytes

            // Encrypt the message with metadata
            val encryptedMessage = RustBridge.encryptMessage(
                String(messageWithMetadata, Charsets.ISO_8859_1), // Binary string for JNI
                recipientX25519PublicKey
            )

            Log.d(TAG, "PING message created (${message.length} bytes, encrypted: ${encryptedMessage.size} bytes)")
            Log.d(TAG, "Calling RustBridge.sendMessageBlob...")

            // Attempt to send PING (this will block if circuit not ready)
            // Note: withTimeout won't interrupt JNI call, but will eventually cancel the coroutine
            val sendResult = try {
                withTimeout(PING_TIMEOUT_MS) {
                    RustBridge.sendMessageBlob(
                        recipientVoiceOnion,
                        encryptedMessage,
                        MSG_TYPE_PING_PONG
                    )
                }
            } catch (e: kotlinx.coroutines.TimeoutCancellationException) {
                Log.e(TAG, "⏱ PING send timed out after ${PING_TIMEOUT_MS}ms")
                Log.e(TAG, "This indicates Tor circuit could not be established")
                return@withContext ConnectivityResult(
                    success = false,
                    phase = "PING_SEND",
                    error = "Timeout - Tor circuit not established",
                    latencyMs = System.currentTimeMillis() - startTime
                )
            }

            if (!sendResult) {
                Log.e(TAG, "RustBridge.sendMessageBlob returned false")
                Log.e(TAG, "Phase 1 Failed: Could not send PING")
                return@withContext ConnectivityResult(
                    success = false,
                    phase = "PING_SEND",
                    error = "sendMessageBlob failed - Tor circuit issue",
                    latencyMs = System.currentTimeMillis() - startTime
                )
            }

            val pingTime = System.currentTimeMillis() - startTime
            Log.i(TAG, "Phase 1 Complete: PING sent successfully (${pingTime}ms)")

            // Phase 2: Wait for PONG
            Log.d(TAG, "Phase 2: Waiting for PONG response...")
            Log.d(TAG, "Timeout: ${PING_TIMEOUT_MS}ms")

            // Poll for PONG with timeout
            val pongStartTime = System.currentTimeMillis()
            var pongReceived = false

            while (System.currentTimeMillis() - pongStartTime < PING_TIMEOUT_MS) {
                // Check if PONG was received
                if (pendingPongs.containsKey(testId)) {
                    pongReceived = true
                    val pongTime = pendingPongs.remove(testId)!!
                    val roundTripTime = pongTime - startTime

                    Log.i(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
                    Log.i(TAG, "CONNECTIVITY TEST PASSED (Full Round-Trip)")
                    Log.i(TAG, "Test ID: $testId")
                    Log.i(TAG, "Round-trip time: ${roundTripTime}ms")
                    Log.i(TAG, "Status: PING sent + PONG received")
                    Log.i(TAG, "Interpretation: Bidirectional Tor circuit working!")
                    Log.i(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

                    return@withContext ConnectivityResult(
                        success = true,
                        phase = "PONG_RECEIVED",
                        error = null,
                        latencyMs = roundTripTime
                    )
                }

                // Sleep before next poll
                kotlinx.coroutines.delay(PONG_POLL_INTERVAL_MS)
            }

            // PONG timeout - circuit might be unidirectional
            Log.e(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            Log.e(TAG, "CONNECTIVITY TEST FAILED")
            Log.e(TAG, "Test ID: $testId")
            Log.e(TAG, "Phase: PONG timeout")
            Log.e(TAG, "PING was sent successfully")
            Log.e(TAG, "But PONG was NOT received after ${PING_TIMEOUT_MS}ms")
            Log.e(TAG, "Likely cause: Reverse Tor circuit not established")
            Log.e(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

            ConnectivityResult(
                success = false,
                phase = "PONG_TIMEOUT",
                error = "No response from contact (reverse circuit not ready)",
                latencyMs = System.currentTimeMillis() - startTime
            )

        } catch (e: Exception) {
            val totalTime = System.currentTimeMillis() - startTime
            Log.e(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            Log.e(TAG, "CONNECTIVITY TEST FAILED")
            Log.e(TAG, "Test ID: $testId")
            Log.e(TAG, "Total time: ${totalTime}ms")
            Log.e(TAG, "Error: ${e.message}", e)
            Log.e(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

            ConnectivityResult(
                success = false,
                phase = "EXCEPTION",
                error = e.message ?: "Unknown error",
                latencyMs = totalTime
            )
        }
    }

    /**
     * Mark PONG as received (called by TorService when 0x0E PONG arrives)
     */
    fun markPongReceived(testId: String) {
        pendingPongs[testId] = System.currentTimeMillis()
        Log.i(TAG, "PONG received and marked for test ID: $testId")
    }

    /**
     * Parse PING/PONG message
     * Called by message service when MSG_TYPE_PING_PONG received
     */
    fun parsePingPongMessage(decryptedMessage: String): PingPongMessage? {
        try {
            val json = JSONObject(decryptedMessage)
            val type = json.optString("type")

            if (type !in listOf(TYPE_PING, TYPE_PONG)) {
                return null
            }

            val testId = json.getString("testId")
            val timestamp = json.getLong("timestamp")
            val seq = json.getInt("seq")

            return when (type) {
                TYPE_PING -> PingPongMessage.Ping(testId, timestamp, seq)
                TYPE_PONG -> PingPongMessage.Pong(testId, timestamp, seq)
                else -> null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing PING/PONG message", e)
            return null
        }
    }

    /**
     * Handle incoming PING - send PONG reply
     * Called by message service when PING received
     */
    suspend fun handleIncomingPing(
        ping: PingPongMessage.Ping,
        senderX25519PublicKey: ByteArray,
        senderVoiceOnion: String
    ) = withContext(Dispatchers.IO) {
        Log.i(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        Log.i(TAG, "Received PING from $senderVoiceOnion")
        Log.i(TAG, "Test ID: ${ping.testId}, Seq: ${ping.seq}")
        Log.i(TAG, "Sending PONG reply...")
        Log.i(TAG, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        try {
            val pongJson = JSONObject().apply {
                put("type", TYPE_PONG)
                put("testId", ping.testId)
                put("timestamp", System.currentTimeMillis())
                put("seq", ping.seq)
            }

            val message = pongJson.toString()

            // Prepend metadata byte 0x0E so sender knows this is PING/PONG
            val metadataByte = byteArrayOf(MSG_TYPE_PING_PONG)
            val messageBytes = message.toByteArray(Charsets.UTF_8)
            val messageWithMetadata = metadataByte + messageBytes

            // Encrypt the message with metadata
            val encryptedMessage = RustBridge.encryptMessage(
                String(messageWithMetadata, Charsets.ISO_8859_1), // Binary string for JNI
                senderX25519PublicKey
            )

            val success = RustBridge.sendMessageBlob(
                senderVoiceOnion,
                encryptedMessage,
                MSG_TYPE_PING_PONG
            )

            if (success) {
                Log.i(TAG, "PONG sent successfully")
            } else {
                Log.e(TAG, "Failed to send PONG")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error sending PONG reply", e)
        }
    }

    /**
     * Sealed class for PING/PONG messages
     */
    sealed class PingPongMessage {
        data class Ping(
            val testId: String,
            val timestamp: Long,
            val seq: Int
        ) : PingPongMessage()

        data class Pong(
            val testId: String,
            val timestamp: Long,
            val seq: Int
        ) : PingPongMessage()
    }

    /**
     * Result of connectivity test
     */
    data class ConnectivityResult(
        val success: Boolean,
        val phase: String, // Which phase succeeded/failed: PING_SEND, PONG_WAIT, etc.
        val error: String?,
        val latencyMs: Long
    ) {
        fun toReadableString(): String = buildString {
            if (success) {
                append("Connectivity OK")
                append("\nLatency: ${latencyMs}ms")
                append("\nPhase: $phase")
            } else {
                append("Connectivity Failed")
                append("\nPhase: $phase")
                append("\nError: $error")
                append("\nTime: ${latencyMs}ms")
            }
        }
    }
}
