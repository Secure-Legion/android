package com.securelegion.crypto

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.util.Log
import okhttp3.OkHttpClient
import org.torproject.jni.TorService
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import java.io.File

/**
 * Manages Tor network initialization and hidden service setup using TorService JNI
 *
 * Responsibilities:
 * - Initialize Tor client on app startup (in-process via JNI)
 * - Create hidden service for receiving messages
 * - Store/retrieve .onion address
 * - Provide access to Tor SOCKS proxy
 */
class TorManager(private val context: Context) {

    private val prefs: SharedPreferences by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    @Volatile
    private var isInitializing = false

    @Volatile
    private var isInitialized = false

    @Volatile
    private var listenerStarted = false

    private val initCallbacks = mutableListOf<(Boolean, String?) -> Unit>()

    private var torThread: Thread? = null
    private var torDataDir: File? = null

    companion object {
        private const val TAG = "TorManager"
        private const val PREFS_NAME = "tor_prefs"
        private const val KEY_ONION_ADDRESS = "onion_address"
        private const val KEY_TOR_INITIALIZED = "tor_initialized"
        private const val DEFAULT_SERVICE_PORT = 9150 // Virtual port on .onion address
        private const val DEFAULT_LOCAL_PORT = 8080 // Local port where app listens

        @Volatile
        private var instance: TorManager? = null

        fun getInstance(context: Context): TorManager {
            return instance ?: synchronized(this) {
                instance ?: TorManager(context.applicationContext).also { instance = it }
            }
        }
    }

    /**
     * Initialize Tor client using Tor_Onion_Proxy_Library
     * Should be called once on app startup (from Application class)
     * Prevents concurrent initializations - queues callbacks if already initializing
     */
    fun initializeAsync(onComplete: (Boolean, String?) -> Unit) {
        synchronized(this) {
            // If currently initializing, queue the callback
            if (isInitializing) {
                Log.d(TAG, "Tor initialization already in progress, queuing callback")
                initCallbacks.add(onComplete)
                return
            }

            // Start initialization (even if previously initialized, recheck bootstrap status)
            isInitializing = true
            initCallbacks.add(onComplete)
        }

        Thread {
            try {
                // Check if Tor control port is already accessible
                val alreadyRunning = try {
                    val testSocket = java.net.Socket()
                    testSocket.connect(java.net.InetSocketAddress("127.0.0.1", 9051), 500)
                    testSocket.close()
                    true
                } catch (e: Exception) {
                    false
                }

                // Create Tor data directory
                torDataDir = File(context.filesDir, "tor")
                torDataDir?.mkdirs()

                // Get the torrc file location that TorService expects
                val torrc = TorService.getTorrc(context)
                torrc.parentFile?.mkdirs()

                // Read bridge settings
                val bridgeConfig = getBridgeConfiguration()

                // ALWAYS write torrc configuration (even if Tor is running)
                // This ensures bridge configuration changes are applied on restart
                torrc.writeText("""
                    DataDirectory ${torDataDir!!.absolutePath}
                    SocksPort 127.0.0.1:9050
                    ControlPort 127.0.0.1:9051
                    CookieAuthentication 1
                    ClientOnly 1
                    AvoidDiskWrites 1
                    $bridgeConfig
                """.trimIndent())

                Log.d(TAG, "Torrc written to: ${torrc.absolutePath}")
                if (bridgeConfig.isNotEmpty()) {
                    Log.i(TAG, "Bridge configuration applied: ${bridgeConfig.lines().first()}")
                }

                if (!alreadyRunning) {
                    Log.d(TAG, "Starting TorService...")

                    // Start TorService as an Android Service
                    val intent = Intent(context, TorService::class.java)
                    intent.action = "org.torproject.android.intent.action.START"
                    context.startService(intent)

                    Log.d(TAG, "TorService started, waiting for control port to be ready...")
                } else {
                    Log.d(TAG, "Tor control port already accessible, torrc updated")
                }

                // Wait for Tor control port to be ready (poll until we can connect)
                var attempts = 0
                val maxAttempts = 60 // 60 seconds max
                var controlPortReady = false

                while (attempts < maxAttempts && !controlPortReady) {
                    try {
                        // Try to connect to control port
                        val testSocket = java.net.Socket()
                        testSocket.connect(java.net.InetSocketAddress("127.0.0.1", 9051), 1000)
                        testSocket.close()
                        controlPortReady = true
                        Log.d(TAG, "Tor control port ready after ${attempts + 1} attempts")
                    } catch (e: Exception) {
                        // Control port not ready yet
                        Thread.sleep(1000)
                        attempts++
                    }
                }

                if (!controlPortReady) {
                    throw Exception("Tor control port failed to become ready after $maxAttempts seconds")
                }

                Log.d(TAG, "Tor is ready and control port is accessible")

                // CRITICAL: Also wait for SOCKS port to be ready
                Log.d(TAG, "Waiting for Tor SOCKS proxy on port 9050...")
                var socksAttempts = 0
                val maxSocksAttempts = 30 // 30 seconds max
                var socksPortReady = false

                while (socksAttempts < maxSocksAttempts && !socksPortReady) {
                    try {
                        // Try to connect to SOCKS port
                        val testSocket = java.net.Socket()
                        testSocket.connect(java.net.InetSocketAddress("127.0.0.1", 9050), 1000)
                        testSocket.close()
                        socksPortReady = true
                        Log.i(TAG, "✓ Tor SOCKS proxy ready on 127.0.0.1:9050 after ${socksAttempts + 1} attempts")
                    } catch (e: Exception) {
                        // SOCKS port not ready yet
                        Thread.sleep(1000)
                        socksAttempts++
                    }
                }

                if (!socksPortReady) {
                    throw Exception("Tor SOCKS proxy failed to become ready after $maxSocksAttempts seconds")
                }

                Log.d(TAG, "Tor SOCKS proxy available at 127.0.0.1:9050")

                // Initialize Rust TorManager (connects to control port)
                Log.d(TAG, "Initializing Rust TorManager...")
                val rustStatus = RustBridge.initializeTor()
                Log.d(TAG, "Rust TorManager initialized: $rustStatus")

                // Re-register hidden service with Tor (must be done on every Tor start)
                val keyManager = KeyManager.getInstance(context)
                val onionAddress = if (keyManager.isInitialized()) {
                    Log.d(TAG, "Re-registering hidden service with Tor...")
                    val address = RustBridge.createHiddenService(DEFAULT_SERVICE_PORT, DEFAULT_LOCAL_PORT)
                    saveOnionAddress(address)
                    Log.d(TAG, "Hidden service re-registered: $address")
                    address
                } else {
                    Log.d(TAG, "Skipping hidden service creation - no account yet")
                    null
                }

                // Note: Listener startup is handled by TorService callback to avoid race condition
                // TorService will call startIncomingListener() after this callback completes

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
     * Create hidden service if account exists but service doesn't
     * Called after account creation to set up the hidden service
     */
    fun createHiddenServiceIfNeeded() {
        Thread {
            try {
                val existingAddress = getOnionAddress()
                if (existingAddress == null) {
                    val keyManager = KeyManager.getInstance(context)
                    if (keyManager.isInitialized()) {
                        // Wait for Tor to be fully bootstrapped before creating hidden service
                        Log.d(TAG, "Waiting for Tor to be ready before creating hidden service...")
                        val maxAttempts = 30 // 30 seconds max
                        var attempts = 0
                        while (attempts < maxAttempts) {
                            val status = RustBridge.getBootstrapStatus()
                            if (status >= 100) {
                                Log.d(TAG, "Tor bootstrapped - creating hidden service...")
                                break
                            }
                            Log.d(TAG, "Tor still bootstrapping ($status%)...")
                            Thread.sleep(1000)
                            attempts++
                        }

                        if (attempts >= maxAttempts) {
                            Log.e(TAG, "Timeout waiting for Tor to bootstrap")
                            return@Thread
                        }

                        Log.d(TAG, "Creating hidden service after account creation...")
                        val address = RustBridge.createHiddenService(DEFAULT_SERVICE_PORT, DEFAULT_LOCAL_PORT)
                        saveOnionAddress(address)
                        Log.d(TAG, "Hidden service created: $address")

                        // Start listener if not already started
                        if (!listenerStarted) {
                            Log.d(TAG, "Starting hidden service listener on port $DEFAULT_LOCAL_PORT...")
                            val started = RustBridge.startHiddenServiceListener(DEFAULT_LOCAL_PORT)
                            if (started) {
                                listenerStarted = true
                                Log.i(TAG, "Hidden service listener started successfully on port $DEFAULT_LOCAL_PORT")
                            } else {
                                Log.e(TAG, "Failed to start hidden service listener")
                            }
                        }
                    } else {
                        Log.w(TAG, "Account not initialized yet, cannot create hidden service")
                    }
                } else {
                    Log.d(TAG, "Hidden service already exists: $existingAddress")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to create hidden service", e)
            }
        }.start()
    }

    /**
     * Send a Ping token to a contact
     * @param contactEd25519PublicKey The contact's Ed25519 public key (for signature verification)
     * @param contactX25519PublicKey The contact's X25519 public key (for encryption)
     * @param contactOnionAddress The contact's .onion address
     * @param encryptedMessage The encrypted message payload
     * @param messageTypeByte The message type (0x03 = TEXT, 0x04 = VOICE)
     * @return Ping ID for tracking
     */
    fun sendPing(
        contactEd25519PublicKey: ByteArray,
        contactX25519PublicKey: ByteArray,
        contactOnionAddress: String,
        encryptedMessage: ByteArray,
        messageTypeByte: Byte
    ): String {
        return RustBridge.sendPing(contactEd25519PublicKey, contactX25519PublicKey, contactOnionAddress, encryptedMessage, messageTypeByte)
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
     * Get bridge configuration for torrc based on user settings
     * Uses IPtProxy library for obfs4proxy and snowflake pluggable transports
     */
    private fun getBridgeConfiguration(): String {
        val torSettings = context.getSharedPreferences("tor_settings", Context.MODE_PRIVATE)
        val bridgeType = torSettings.getString("bridge_type", "none") ?: "none"

        // Get path to native libraries (where IPtProxy binaries are located)
        val nativeLibDir = context.applicationInfo.nativeLibraryDir

        return when (bridgeType) {
            "snowflake" -> {
                // Snowflake bridge configuration using IPtProxy
                // IPtProxy provides libIPtProxy.so which includes snowflake
                """
                UseBridges 1
                ClientTransportPlugin snowflake exec $nativeLibDir/libIPtProxy.so -client
                Bridge snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.voip.blackberry.com:3478,stun:stun.altar.com.pl:3478,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.sonetel.net:3478,stun:stun.stunprotocol.org:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn
                """.trimIndent()
            }
            "obfs4" -> {
                // obfs4 bridge configuration using IPtProxy (Lyrebird/obfs4proxy)
                """
                UseBridges 1
                ClientTransportPlugin obfs4 exec $nativeLibDir/libIPtProxy.so
                Bridge obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1
                """.trimIndent()
            }
            "meek" -> {
                // Note: IPtProxy doesn't include meek - meek support removed from Tor Browser
                // Fall back to using obfs4 or document that meek is not supported
                Log.w(TAG, "Meek bridge requested but not supported by IPtProxy - using obfs4 instead")
                """
                UseBridges 1
                ClientTransportPlugin obfs4 exec $nativeLibDir/libIPtProxy.so
                Bridge obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1
                """.trimIndent()
            }
            "custom" -> {
                // Custom bridge provided by user
                val customBridge = torSettings.getString("custom_bridge", "")
                if (!customBridge.isNullOrEmpty()) {
                    """
                    UseBridges 1
                    $customBridge
                    """.trimIndent()
                } else {
                    "" // No custom bridge provided
                }
            }
            else -> "" // No bridges (default)
        }
    }

    /**
     * Clear all Tor data (for account wipe)
     */
    fun clearData() {
        prefs.edit().clear().apply()
    }
}
