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
import IPtProxy.Controller
import IPtProxy.IPtProxy
import com.securelegion.SecureLegionApplication

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
        private const val KEY_VOICE_ONION_ADDRESS = "voice_onion_address"
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

        // Start bootstrap event listener EARLY, before Tor even starts
        // This ensures it can capture progress from 0% onwards
        try {
            Log.i(TAG, "Starting bootstrap event listener early...")
            RustBridge.startBootstrapListener()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start bootstrap listener (may start later)", e)
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

                // Detect device performance to set appropriate initial timeouts
                // Slower devices (Android < 13 or low-end) need more conservative timeouts
                val sdkInt = android.os.Build.VERSION.SDK_INT
                val isSlowerDevice = sdkInt < 33 // Android 13+

                // Set initial CircuitBuildTimeout based on device
                // Tor will learn and adapt from this starting point
                val initialCircuitTimeout = if (isSlowerDevice) {
                    "CircuitBuildTimeout 45" // Slower devices: start with 45s
                } else {
                    "CircuitBuildTimeout 30" // Faster devices: start with 30s
                }

                Log.i(TAG, "Device: Android $sdkInt, using initial timeout: ${if (isSlowerDevice) "45s (slower device)" else "30s (faster device)"}")

                // ALWAYS write torrc configuration (even if Tor is running)
                // This ensures bridge configuration changes are applied on restart
                torrc.writeText("""
                    DataDirectory ${torDataDir!!.absolutePath}
                    SocksPort 127.0.0.1:9050
                    ControlPort 127.0.0.1:9051
                    CookieAuthentication 1
                    ClientOnly 1
                    AvoidDiskWrites 1
                    DormantCanceledByStartup 1
                    LearnCircuitBuildTimeout 1
                    $initialCircuitTimeout
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

                // Re-register hidden services with Tor (must be done on every Tor start)
                val keyManager = KeyManager.getInstance(context)
                val onionAddress = if (keyManager.isInitialized()) {
                    Log.d(TAG, "Re-registering messaging hidden service with Tor...")
                    val address = RustBridge.createHiddenService(DEFAULT_SERVICE_PORT, DEFAULT_LOCAL_PORT)
                    saveOnionAddress(address)
                    keyManager.storeMessagingOnion(address)  // Store in KeyManager too
                    Log.d(TAG, "Messaging hidden service re-registered: $address")

                    // Also re-register friend-request hidden service (v2.0)
                    Log.d(TAG, "Re-registering friend-request hidden service with Tor...")
                    val friendRequestOnion = RustBridge.createFriendRequestHiddenService(
                        servicePort = 9151,
                        localPort = 9151,
                        directory = "friend_requests"
                    )
                    Log.d(TAG, "Friend-request hidden service re-registered: $friendRequestOnion")

                    // Note: Voice hidden service is created later by TorService.startVoiceService()
                    // after the voice streaming listener is started on localhost:9152
                    Log.d(TAG, "Voice hidden service will be registered by TorService after voice listener starts")

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
    fun saveOnionAddress(address: String) {
        prefs.edit().putString(KEY_ONION_ADDRESS, address).apply()
    }

    /**
     * Get the device's voice .onion address for receiving voice calls
     * @return voice .onion address or null if not initialized
     */
    fun getVoiceOnionAddress(): String? {
        return prefs.getString(KEY_VOICE_ONION_ADDRESS, null)
    }

    /**
     * Save the voice .onion address
     */
    fun saveVoiceOnionAddress(address: String) {
        prefs.edit().putString(KEY_VOICE_ONION_ADDRESS, address).apply()
    }

    /**
     * Start VOICE Tor instance (port 9052) with Single Onion Service configuration
     * This is a separate Tor daemon specifically for voice hidden service
     * Runs with HiddenServiceNonAnonymousMode 1 for reduced latency (3-hop instead of 6-hop)
     * Should be called from TorService.startVoiceService() before creating voice hidden service
     */
    fun startVoiceTor(): Boolean {
        return try {
            Log.i(TAG, "Starting VOICE Tor instance (Single Onion Service mode)...")

            // Check if voice Tor control port is already accessible
            val alreadyRunning = try {
                val testSocket = java.net.Socket()
                testSocket.connect(java.net.InetSocketAddress("127.0.0.1", 9052), 500)
                testSocket.close()
                true
            } catch (e: Exception) {
                false
            }

            if (alreadyRunning) {
                Log.i(TAG, "Voice Tor already running on port 9052")
                // Initialize Rust voice control connection
                val status = RustBridge.initializeVoiceTorControl()
                Log.i(TAG, "Voice Tor control initialized: $status")
                return true
            }

            // Create voice Tor data directory (separate from main Tor)
            val voiceTorDataDir = File(context.filesDir, "voice_tor")
            voiceTorDataDir.mkdirs()

            // Create voice hidden service directory
            val voiceHiddenServiceDir = File(voiceTorDataDir, "voice_hidden_service")
            voiceHiddenServiceDir.mkdirs()

            // Create voice torrc file with HiddenServiceDir configuration
            val voiceTorrc = File(context.filesDir, "voice_torrc")
            voiceTorrc.writeText("""
                DataDirectory ${voiceTorDataDir.absolutePath}
                ControlPort 127.0.0.1:9052
                CookieAuthentication 1
                SOCKSPort 0
                AvoidDiskWrites 1
                HiddenServiceNonAnonymousMode 1
                HiddenServiceSingleHopMode 1
                LearnCircuitBuildTimeout 1
                CircuitBuildTimeout 30
                HiddenServiceDir ${voiceHiddenServiceDir.absolutePath}
                HiddenServicePort 9152 127.0.0.1:9152
            """.trimIndent())

            Log.i(TAG, "Voice torrc written to: ${voiceTorrc.absolutePath}")
            Log.i(TAG, "Voice Tor config: Single Onion Service (3-hop, service location visible)")

            // Start VoiceTorService (separate service for voice Tor)
            val voiceIntent = Intent(context, com.securelegion.services.VoiceTorService::class.java)
            voiceIntent.action = com.securelegion.services.VoiceTorService.ACTION_START
            context.startService(voiceIntent)

            Log.i(TAG, "VoiceTorService started, waiting for control port 9052...")

            // Wait for voice Tor control port to be ready
            var attempts = 0
            val maxAttempts = 60 // 60 seconds max
            var controlPortReady = false

            while (attempts < maxAttempts && !controlPortReady) {
                try {
                    val testSocket = java.net.Socket()
                    testSocket.connect(java.net.InetSocketAddress("127.0.0.1", 9052), 1000)
                    testSocket.close()
                    controlPortReady = true
                    Log.i(TAG, "Voice Tor control port 9052 ready after ${attempts + 1} attempts")
                } catch (e: Exception) {
                    Thread.sleep(1000)
                    attempts++
                }
            }

            if (!controlPortReady) {
                Log.e(TAG, "Voice Tor control port 9052 failed to become ready")
                return false
            }

            // Initialize Rust voice control connection
            val status = RustBridge.initializeVoiceTorControl()
            Log.i(TAG, "✓ Voice Tor initialized successfully: $status")
            true

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start voice Tor: ${e.message}", e)
            false
        }
    }

    /**
     * Check if Tor has been initialized
     */
    fun isInitialized(): Boolean {
        return prefs.getBoolean(KEY_TOR_INITIALIZED, false)
    }

    /**
     * Reset Tor initialization state to force re-initialization
     * Used when bridge configuration changes
     */
    fun resetInitializationState() {
        synchronized(this) {
            isInitializing = false
            isInitialized = false
            prefs.edit().putBoolean(KEY_TOR_INITIALIZED, false).apply()
            Log.i(TAG, "Tor initialization state reset - will re-initialize on next start")
        }
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
        messageTypeByte: Byte,
        pingId: String,
        pingTimestamp: Long
    ): String {
        return RustBridge.sendPing(contactEd25519PublicKey, contactX25519PublicKey, contactOnionAddress, encryptedMessage, messageTypeByte, pingId, pingTimestamp)
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
     * Start IPtProxy pluggable transports for the selected bridge type
     */
    private fun startIPtProxy(bridgeType: String) {
        try {
            val app = context.applicationContext as? SecureLegionApplication
            val controller = app?.let { SecureLegionApplication.iptProxyController }

            if (controller == null) {
                Log.e(TAG, "IPtProxy Controller not initialized - cannot start transport")
                return
            }

            when (bridgeType) {
                "obfs4" -> {
                    Log.d(TAG, "Starting obfs4 transport...")
                    controller.start(IPtProxy.Obfs4, null)

                    // Wait for obfs4 to start and bind to a port
                    var port = 0L
                    var attempts = 0
                    while (port == 0L && attempts < 30) {
                        Thread.sleep(1000)
                        port = controller.port(IPtProxy.Obfs4)
                        attempts++
                        if (port > 0) {
                            Log.i(TAG, "✓ obfs4 transport started on port $port after ${attempts}s")
                            break
                        }
                        Log.d(TAG, "Waiting for obfs4 to start... (${attempts}s)")
                    }

                    if (port == 0L) {
                        Log.e(TAG, "✗ obfs4 failed to start after 30 seconds")
                    }
                }
                "snowflake" -> {
                    Log.d(TAG, "Configuring snowflake transport...")
                    // Configure snowflake with default settings
                    controller.snowflakeBrokerUrl = "https://snowflake-broker.torproject.net.global.prod.fastly.net/"
                    controller.snowflakeFrontDomains = "cdn.sstatic.net,github.githubassets.com"
                    controller.snowflakeIceServers = "stun:stun.l.google.com:19302,stun:stun.altar.com.pl:3478,stun:stun.antisip.com:3478"
                    Log.d(TAG, "Starting snowflake transport...")
                    controller.start(IPtProxy.Snowflake, null)

                    // Wait for Snowflake to start and bind to a port
                    var port = 0L
                    var attempts = 0
                    while (port == 0L && attempts < 30) {
                        Thread.sleep(1000)
                        port = controller.port(IPtProxy.Snowflake)
                        attempts++
                        if (port > 0) {
                            Log.i(TAG, "✓ Snowflake transport started on port $port after ${attempts}s")
                            break
                        }
                        Log.d(TAG, "Waiting for Snowflake to start... (${attempts}s)")
                    }

                    if (port == 0L) {
                        Log.e(TAG, "✗ Snowflake failed to start after 30 seconds")
                    }
                }
                "meek" -> {
                    Log.d(TAG, "Starting meek_lite transport...")
                    controller.start(IPtProxy.MeekLite, null)

                    // Wait for meek_lite to start and bind to a port
                    var port = 0L
                    var attempts = 0
                    while (port == 0L && attempts < 30) {
                        Thread.sleep(1000)
                        port = controller.port(IPtProxy.MeekLite)
                        attempts++
                        if (port > 0) {
                            Log.i(TAG, "✓ meek_lite transport started on port $port after ${attempts}s")
                            break
                        }
                        Log.d(TAG, "Waiting for meek_lite to start... (${attempts}s)")
                    }

                    if (port == 0L) {
                        Log.e(TAG, "✗ meek_lite failed to start after 30 seconds")
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start IPtProxy transport for $bridgeType: ${e.message}", e)
            // Don't re-throw - allow Tor to start without bridges as fallback
        }
    }

    /**
     * Get bridge configuration for torrc based on user settings
     * Uses IPtProxy for obfs4 and snowflake pluggable transports
     */
    private fun getBridgeConfiguration(): String {
        val torSettings = context.getSharedPreferences("tor_settings", Context.MODE_PRIVATE)
        val bridgeType = torSettings.getString("bridge_type", "none") ?: "none"

        // Start IPtProxy if needed
        if (bridgeType in listOf("obfs4", "snowflake", "meek")) {
            startIPtProxy(bridgeType)
        }

        return when (bridgeType) {
            "snowflake" -> {
                // Snowflake - uses IPtProxy pluggable transport
                // Connects through volunteer WebRTC proxies via broker
                val app = context.applicationContext as? SecureLegionApplication
                val controller = app?.let { SecureLegionApplication.iptProxyController }
                val port = controller?.port(IPtProxy.Snowflake) ?: 0
                if (port == 0L) {
                    Log.e(TAG, "Snowflake transport failed to start - no SOCKS port available")
                    ""
                } else {
                    """
                    UseBridges 1
                    ClientTransportPlugin snowflake socks5 127.0.0.1:$port
                    Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.altar.com.pl:3478,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.stunprotocol.org:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn
                    """.trimIndent()
                }
            }
            "obfs4" -> {
                // obfs4 bridges from https://github.com/scriptzteam/Tor-Bridges-Collector
                // and https://bridges.torproject.org - uses IPtProxy pluggable transport
                val app = context.applicationContext as? SecureLegionApplication
                val controller = app?.let { SecureLegionApplication.iptProxyController }
                val port = controller?.port(IPtProxy.Obfs4) ?: 0
                if (port == 0L) {
                    Log.e(TAG, "obfs4 transport failed to start - no SOCKS port available")
                    ""
                } else {
                    """
                    UseBridges 1
                    ClientTransportPlugin obfs4 socks5 127.0.0.1:$port
                    Bridge obfs4 1.2.217.144:5987 DCE57AC308CB82958C56B1B5C9C3D08D225EC942 cert=Uemn6kep2gxo9J0P81geJV3gTWQtkrNHvEh1DL3wzhvLaUaIrn0/e0a1mvyB3T4c0jmHKg iat-mode=0
                    Bridge obfs4 2.35.113.108:9906 5A3E33D354B7B7BAE5D3873EF8A68E79B4194A2A cert=IJXo/z1hPSJ0Yr2bShs3UVnBS35rweyktBxY+azSyQwSwD2qAdrVpo8VSWhVxly6wIWkDg iat-mode=0
                    Bridge obfs4 2.37.211.221:9875 3A16586D003E32EE9798055C75D38498863FEC7A cert=afdvowWWudLtKXb3m5L9mQ/Ko9tm1Lu3rZDsb+rgEkHFEVKvuJihbfAyJlCUZbk42QwGZA iat-mode=0
                    Bridge obfs4 82.65.66.15:16380 4E08190BD91F309DD41CF5D6BE2AFFFF298C8A9F cert=+rOOVaQl8pO8zLKl4NNCEm+r1s2NAV55q/+INNaX4pHHvJg7wXfk8KFvTSK0NzgXfn7nFw iat-mode=0
                    Bridge obfs4 185.177.207.156:8443 85039DCAC3BBFB86A09BB0C58878FECD79AE33DA cert=9+nXWUOkB/vGawa21fYwAv8v66QvflMgsx3KExXhHInwU6GzBF/MdWtoAvIZ2YKThUCpdA iat-mode=0
                    """.trimIndent()
                }
            }
            "meek" -> {
                // Meek-azure bridge - uses IPtProxy pluggable transport
                // Uses Microsoft Azure CDN for domain fronting
                val app = context.applicationContext as? SecureLegionApplication
                val controller = app?.let { SecureLegionApplication.iptProxyController }
                val port = controller?.port(IPtProxy.MeekLite) ?: 0
                if (port == 0L) {
                    Log.e(TAG, "meek_lite transport failed to start - no SOCKS port available")
                    ""
                } else {
                    """
                    UseBridges 1
                    ClientTransportPlugin meek_lite socks5 127.0.0.1:$port
                    Bridge meek_lite 192.0.2.2:2 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com
                    """.trimIndent()
                }
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
