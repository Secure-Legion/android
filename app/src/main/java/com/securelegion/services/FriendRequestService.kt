package com.securelegion.services

import android.content.Context
import android.util.Log
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.RustBridge
import kotlinx.coroutines.*

/**
 * Contact Card Server (v2.0)
 *
 * Manages the contact card HTTP server on friend request .onion:
 * - Starts HTTP server on friend request .onion address
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
     * Start the contact card HTTP server
     * Note: Friend requests use v1.0 wire protocol (0x07/0x08) on messaging .onion
     */
    suspend fun startServer(): Result<Unit> {
        return withContext(Dispatchers.IO) {
            try {
                if (serverStarted) {
                    Log.d(TAG, "Contact card server already running")
                    return@withContext Result.success(Unit)
                }

                Log.i(TAG, "Starting contact card HTTP server...")

                // Get KeyManager and contact card info
                val keyManager = KeyManager.getInstance(context)
                if (!keyManager.hasContactCardInfo()) {
                    Log.w(TAG, "No contact card info available - server not started")
                    return@withContext Result.failure(Exception("Contact card not initialized"))
                }

                val cid = keyManager.getIPFSCID()
                    ?: return@withContext Result.failure(Exception("No CID"))

                val pin = keyManager.getContactPin()
                    ?: return@withContext Result.failure(Exception("No PIN"))

                // Create contact card
                val contactCard = com.securelegion.models.ContactCard(
                    displayName = keyManager.getUsername() ?: "User",
                    solanaPublicKey = keyManager.getSolanaPublicKey(),
                    x25519PublicKey = keyManager.getEncryptionPublicKey(),
                    solanaAddress = keyManager.getSolanaAddress(),
                    friendRequestOnion = keyManager.getFriendRequestOnion() ?: "",
                    messagingOnion = keyManager.getMessagingOnion() ?: "",
                    contactPin = pin,
                    ipfsCid = cid,
                    timestamp = System.currentTimeMillis()
                )

                // Encrypt contact card with PIN
                val cardManager = ContactCardManager(context)
                val contactCardJson = contactCard.toJson()
                val encryptedCardResult = cardManager.encryptWithPin(contactCardJson, pin)

                Log.d(TAG, "Encrypted contact card: ${encryptedCardResult.size} bytes")

                // Start HTTP server via Rust
                val started = RustBridge.startFriendRequestServer(SERVER_PORT)
                if (!started) {
                    throw Exception("Failed to start contact card server")
                }

                // Store encrypted card in server
                RustBridge.serveContactCard(encryptedCardResult, encryptedCardResult.size, cid)

                serverStarted = true
                Log.i(TAG, "Contact card server started on port $SERVER_PORT (CID: $cid)")

                Result.success(Unit)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start contact card server", e)
                Result.failure(e)
            }
        }
    }

    /**
     * Stop the contact card HTTP server
     */
    fun stopServer() {
        try {
            RustBridge.stopFriendRequestServer()
            serverStarted = false
            Log.i(TAG, "Contact card server stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop contact card server", e)
        }
    }
}
