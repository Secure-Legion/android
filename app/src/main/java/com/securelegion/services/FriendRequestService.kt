package com.securelegion.services

import android.content.Context
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import kotlinx.coroutines.*

/**
 * Contact Exchange Service (v2.0)
 *
 * Manages the contact exchange endpoint on friend request .onion:
 * - Starts P2P listener on friend request .onion address
 * - Serves encrypted contact card at GET /contact-card
 *
 * Friend requests are handled by v1.0 wire protocol (0x07/0x08) on messaging .onion.
 * See TorService.handleFriendRequest() for friend request processing.
 */
class FriendRequestService(private val context: Context) {

    companion object {
        private const val TAG = "FriendRequestService"
        private const val SERVER_PORT = 8081

        @Volatile
        private var instance: FriendRequestService? = null

        fun getInstance(context: Context): FriendRequestService {
            return instance ?: synchronized(this) {
                instance ?: FriendRequestService(context.applicationContext).also { instance = it }
            }
        }
    }

    private var serverStarted = false

    /**
     * Start the contact exchange listener
     * Note: Friend requests use v1.0 wire protocol (0x07/0x08) on messaging .onion
     */
    suspend fun startServer(): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                if (serverStarted) {
                    Log.d(TAG, "Contact exchange listener already running")
                    return@withContext Result.success(Unit)
                }

                Log.i(TAG, "Starting contact exchange listener...")

                // Get KeyManager and contact card info
                val keyManager = KeyManager.getInstance(context)
                if (!keyManager.hasContactCardInfo()) {
                    Log.w(TAG, "No contact card info available - listener not started")
                    return@withContext Result.failure(Exception("Contact card not initialized"))
                }

                val cid = keyManager.getIPFSCID()
                    ?: return@withContext Result.failure(Exception("No CID"))

                val pin = keyManager.getContactPin()
                    ?: return@withContext Result.failure(Exception("No PIN"))

                // Create contact card
                val torManager = com.securelegion.crypto.TorManager.getInstance(context)
                val contactCard = com.securelegion.models.ContactCard(
                    displayName = keyManager.getUsername() ?: "User",
                    solanaPublicKey = keyManager.getSolanaPublicKey(),
                    x25519PublicKey = keyManager.getEncryptionPublicKey(),
                    kyberPublicKey = keyManager.getKyberPublicKey(),
                    solanaAddress = keyManager.getSolanaAddress(),
                    friendRequestOnion = keyManager.getFriendRequestOnion() ?: "",
                    messagingOnion = keyManager.getMessagingOnion() ?: "",
                    voiceOnion = torManager.getVoiceOnionAddress() ?: "",
                    contactPin = pin,
                    ipfsCid = cid,
                    timestamp = System.currentTimeMillis()
                )

                // Encrypt contact card with PIN
                val cardManager = ContactCardManager(context)
                val contactCardJson = contactCard.toJson()
                val encryptedCardResult = cardManager.encryptWithPin(contactCardJson, pin)

                Log.d(TAG, "Encrypted contact card: ${encryptedCardResult.size} bytes")

                // Start contact exchange endpoint via Rust
                val started = RustBridge.startFriendRequestServer(SERVER_PORT)
                if (!started) {
                    throw Exception("Failed to start contact exchange endpoint")
                }

                // Store encrypted card in endpoint
                RustBridge.serveContactCard(encryptedCardResult, encryptedCardResult.size, cid)

                serverStarted = true
                Log.i(TAG, "Contact exchange endpoint started on port $SERVER_PORT (CID: $cid)")

                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start contact exchange endpoint", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Stop the contact exchange listener
     */
    fun stopServer() {
        try {
            RustBridge.stopFriendRequestServer()
            serverStarted = false
            Log.i(TAG, "Contact exchange endpoint stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop contact exchange endpoint", e)
        }
    }
}
