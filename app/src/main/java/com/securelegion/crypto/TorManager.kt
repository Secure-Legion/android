package com.securelegion.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Log

/**
 * Manages Tor network initialization and hidden service setup
 *
 * Responsibilities:
 * - Initialize Tor client on app startup
 * - Create hidden service for receiving messages
 * - Store/retrieve .onion address
 * - Provide access to Tor functionality
 */
class TorManager(private val context: Context) {

    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    companion object {
        private const val TAG = "TorManager"
        private const val PREFS_NAME = "tor_prefs"
        private const val KEY_ONION_ADDRESS = "onion_address"
        private const val KEY_TOR_INITIALIZED = "tor_initialized"
        private const val DEFAULT_SERVICE_PORT = 9150 // Ping-Pong protocol port

        @Volatile
        private var instance: TorManager? = null

        fun getInstance(context: Context): TorManager {
            return instance ?: synchronized(this) {
                instance ?: TorManager(context.applicationContext).also { instance = it }
            }
        }
    }

    /**
     * Initialize Tor client and create hidden service if needed
     * Should be called once on app startup (from Application class)
     */
    fun initializeAsync(onComplete: (Boolean, String?) -> Unit) {
        Thread {
            try {
                // Initialize Tor client
                Log.d(TAG, "Initializing Tor client...")
                val status = RustBridge.initializeTor()
                Log.d(TAG, "Tor initialized: $status")

                // Create hidden service if we don't have one yet
                val existingAddress = getOnionAddress()
                val onionAddress = if (existingAddress == null) {
                    Log.d(TAG, "Creating new hidden service...")
                    val address = RustBridge.createHiddenService(DEFAULT_SERVICE_PORT)
                    saveOnionAddress(address)
                    Log.d(TAG, "Hidden service created: $address")
                    address
                } else {
                    Log.d(TAG, "Using existing .onion address: $existingAddress")
                    existingAddress
                }

                // Mark as initialized
                prefs.edit().putBoolean(KEY_TOR_INITIALIZED, true).apply()

                onComplete(true, onionAddress)
            } catch (e: Exception) {
                Log.e(TAG, "Tor initialization failed", e)
                onComplete(false, null)
            }
        }.start()
    }

    /**
     * Get the device's .onion address for receiving messages
     * @return .onion address or null if not initialized
     */
    fun getOnionAddress(): String? {
        return prefs.getString(KEY_ONION_ADDRESS, null)
    }

    /**
     * Save the .onion address
     */
    private fun saveOnionAddress(address: String) {
        prefs.edit().putString(KEY_ONION_ADDRESS, address).apply()
    }

    /**
     * Check if Tor has been initialized
     */
    fun isInitialized(): Boolean {
        return prefs.getBoolean(KEY_TOR_INITIALIZED, false)
    }

    /**
     * Send a Ping token to a contact
     * @param contactPublicKey The contact's Ed25519 public key
     * @param contactOnionAddress The contact's .onion address
     * @return Ping ID for tracking
     */
    fun sendPing(contactPublicKey: ByteArray, contactOnionAddress: String): String {
        return RustBridge.sendPing(contactPublicKey, contactOnionAddress)
    }

    /**
     * Wait for Pong response
     * @param pingId The Ping ID
     * @param timeoutSeconds Timeout in seconds (default 60)
     * @return True if Pong received and user authenticated
     */
    fun waitForPong(pingId: String, timeoutSeconds: Int = 60): Boolean {
        return RustBridge.waitForPong(pingId, timeoutSeconds)
    }

    /**
     * Respond to incoming Ping with Pong
     * @param pingId The Ping ID
     * @param authenticated Whether user successfully authenticated
     * @return Pong token bytes
     */
    fun respondToPing(pingId: String, authenticated: Boolean): ByteArray {
        return RustBridge.respondToPing(pingId, authenticated)
    }

    /**
     * Clear all Tor data (for account wipe)
     */
    fun clearData() {
        prefs.edit().clear().apply()
    }
}
