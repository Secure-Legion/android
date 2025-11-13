package com.securelegion.crypto

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import okhttp3.OkHttpClient
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit

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

    @Volatile
    private var isInitializing = false

    @Volatile
    private var isInitialized = false

    private val initCallbacks = mutableListOf<(Boolean, String?) -> Unit>()

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
     * Prevents concurrent initializations - queues callbacks if already initializing
     */
    fun initializeAsync(onComplete: (Boolean, String?) -> Unit) {
        synchronized(this) {
            // If already initialized, immediately return cached result
            if (isInitialized) {
                Log.d(TAG, "Tor already initialized, returning cached result")
                onComplete(true, getOnionAddress())
                return
            }

            // If currently initializing, queue the callback
            if (isInitializing) {
                Log.d(TAG, "Tor initialization already in progress, queuing callback")
                initCallbacks.add(onComplete)
                return
            }

            // Start initialization
            isInitializing = true
            initCallbacks.add(onComplete)
        }

        Thread {
            try {
                // Initialize Tor client
                Log.d(TAG, "Initializing Tor client...")
                val status = RustBridge.initializeTor()
                Log.d(TAG, "Tor initialized: $status")

                // Create hidden service if we don't have one yet
                val existingAddress = getOnionAddress()
                val onionAddress = if (existingAddress == null) {
                    // Check if user has created an account (required for hidden service key)
                    val keyManager = KeyManager.getInstance(context)
                    if (keyManager.isInitialized()) {
                        Log.d(TAG, "Creating new hidden service...")
                        val address = RustBridge.createHiddenService(DEFAULT_SERVICE_PORT)
                        saveOnionAddress(address)
                        Log.d(TAG, "Hidden service created: $address")
                        address
                    } else {
                        Log.d(TAG, "Skipping hidden service creation - no account yet")
                        null
                    }
                } else {
                    Log.d(TAG, "Using existing .onion address: $existingAddress")
                    existingAddress
                }

                // Mark as initialized
                prefs.edit().putBoolean(KEY_TOR_INITIALIZED, true).apply()

                // Mark as complete and notify all queued callbacks
                synchronized(this) {
                    isInitializing = false
                    isInitialized = true
                    val callbacks = initCallbacks.toList()
                    initCallbacks.clear()
                    callbacks.forEach { it(true, onionAddress) }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Tor initialization failed", e)
                synchronized(this) {
                    isInitializing = false
                    val callbacks = initCallbacks.toList()
                    initCallbacks.clear()
                    callbacks.forEach { it(false, null) }
                }
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
     * @param contactEd25519PublicKey The contact's Ed25519 public key (for signature verification)
     * @param contactX25519PublicKey The contact's X25519 public key (for encryption)
     * @param contactOnionAddress The contact's .onion address
     * @return Ping ID for tracking
     */
    fun sendPing(
        contactEd25519PublicKey: ByteArray,
        contactX25519PublicKey: ByteArray,
        contactOnionAddress: String
    ): String {
        return RustBridge.sendPing(contactEd25519PublicKey, contactX25519PublicKey, contactOnionAddress)
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
     * @return Pong token bytes, or null if authentication denied
     */
    fun respondToPing(pingId: String, authenticated: Boolean): ByteArray? {
        return RustBridge.respondToPing(pingId, authenticated)
    }

    /**
     * Get an OkHttpClient configured to route traffic through Tor SOCKS proxy
     * Use this for all HTTP/HTTPS requests to preserve network anonymity
     *
     * @return OkHttpClient with Tor SOCKS proxy at 127.0.0.1:9050
     */
    fun getTorProxyClient(): OkHttpClient {
        return OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", 9050)))
            .connectTimeout(30, TimeUnit.SECONDS) // Tor routing is slower
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    /**
     * Clear all Tor data (for account wipe)
     */
    fun clearData() {
        prefs.edit().clear().apply()
    }
}
