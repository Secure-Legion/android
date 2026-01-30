package com.securelegion.crypto

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.util.Log
import okhttp3.OkHttpClient
import org.torproject.jni.TorService
import com.securelegion.network.OkHttpProvider
import java.io.File
import IPtProxy.Controller
import IPtProxy.IPtProxy
import com.securelegion.SecureLegionApplication

/**
 * Thrown when a user-selected bridge transport fails to start.
 * Prevents silent fallback to direct Tor when bridges were explicitly requested.
 */
class BridgeTransportFailedException(message: String) : Exception(message)

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

        /**
         * Wait for Tor to generate hostname file and validate .onion address
         * Prevents timing bugs where we try to read before Tor finishes
         * @param hsDir Hidden service directory
         * @param timeoutMs Timeout in milliseconds (default 60s)
         * @return Valid .onion address
         * @throws RuntimeException if timeout or invalid address
         */
        private fun waitForValidHostname(hsDir: File, timeoutMs: Long = 60_000): String {
            val hostname = File(hsDir, "hostname")
            val start = System.currentTimeMillis()
            var lastBootstrapStatus = -1

            while (System.currentTimeMillis() - start < timeoutMs) {
                // Log Tor bootstrap progress while waiting
                try {
                    val status = RustBridge.getBootstrapStatus()
                    if (status != lastBootstrapStatus && status >= 0) {
                        Log.d(TAG, "Waiting for hidden service... Tor bootstrap: $status%")
                        lastBootstrapStatus = status
                    }
                } catch (e: Exception) {
                    // Ignore bootstrap status errors
                }

                if (hostname.exists()) {
                    try {
                        val txt = hostname.readText().trim()
                        // Validate: must end with .onion and be at least 20 chars (v3 onions are 56 chars)
                        if (txt.endsWith(".onion") && txt.length >= 20) {
                            Log.i(TAG, "✓ Valid .onion address found: $txt (after ${System.currentTimeMillis() - start}ms)")
                            return txt
                        } else {
                            Log.w(TAG, "Invalid .onion address format: $txt (length: ${txt.length})")
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Error reading hostname file: ${e.message}")
                    }
                }

                Thread.sleep(250) // Check every 250ms
            }

            throw RuntimeException("Hidden service hostname not ready after ${timeoutMs}ms: ${hsDir.absolutePath}")
        }
    }

    /**
     * Initialize Tor client using Tor_Onion_Proxy_Library
     * Should be called once on app startup (from Application class)
     * Prevents concurrent initializations - queues callbacks if already initializing
     */
    fun initializeAsync(onComplete: (Boolean, String?) -> Unit) {
        // LOG WHO IS CALLING THIS (stack trace)
        val caller = Thread.currentThread().stackTrace.getOrNull(3)?.let {
            "${it.className}.${it.methodName}:${it.lineNumber}"
        } ?: "unknown"
        Log.w(TAG, "========== initializeAsync() CALLED FROM: $caller ==========")

        synchronized(this) {
            // If currently initializing, queue the callback
            if (isInitializing) {
                Log.d(TAG, "Tor initialization already in progress, queuing callback (called from $caller)")
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

                // Create persistent hidden service directories (create-once, reuse forever)
                // This prevents "550 Onion address collision" errors on reconnect
                val messagingHiddenServiceDir = File(torDataDir, "messaging_hidden_service")
                messagingHiddenServiceDir.mkdirs()
                // Set explicit permissions for Android compatibility
                messagingHiddenServiceDir.setReadable(true, true)
                messagingHiddenServiceDir.setWritable(true, true)
                messagingHiddenServiceDir.setExecutable(true, true)

                val friendRequestHiddenServiceDir = File(torDataDir, "friend_request_hidden_service")
                friendRequestHiddenServiceDir.mkdirs()
                // Set explicit permissions for Android compatibility
                friendRequestHiddenServiceDir.setReadable(true, true)
                friendRequestHiddenServiceDir.setWritable(true, true)
                friendRequestHiddenServiceDir.setExecutable(true, true)

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

                // Generate torrc content
                // PERSISTENT HIDDEN SERVICES (not ephemeral):
                // Keys are generated once and stored in HiddenServiceDir
                // Tor reuses the same keys on every restart (no collision errors)
                //
                // NOTE: Guardian Project's TorService uses /app_TorService/data as DataDirectory
                // Do NOT specify DataDirectory here - let TorService manage it
                val torrcContent = """
                    CookieAuthentication 1
                    ControlPort 127.0.0.1:9051
                    MetricsPort 127.0.0.1:9035
                    MetricsPortPolicy accept 127.0.0.1
                    SocksPort 127.0.0.1:9050
                    ClientOnly 1
                    AvoidDiskWrites 1
                    DormantCanceledByStartup 1
                    LearnCircuitBuildTimeout 1
                    $initialCircuitTimeout
                    HiddenServiceDir ${messagingHiddenServiceDir.absolutePath}
                    HiddenServicePort $DEFAULT_SERVICE_PORT 127.0.0.1:$DEFAULT_LOCAL_PORT
                    HiddenServicePort 9153 127.0.0.1:9153
                    HiddenServiceDir ${friendRequestHiddenServiceDir.absolutePath}
                    HiddenServicePort 9151 127.0.0.1:9151
                    HiddenServicePort 9152 127.0.0.1:8081
                    $bridgeConfig
                """.trimIndent()

                // Only write torrc if content changed (avoid unnecessary rewrites)
                val needsUpdate = !torrc.exists() || torrc.readText() != torrcContent
                if (needsUpdate) {
                    torrc.writeText(torrcContent)
                    Log.d(TAG, "Torrc updated: ${torrc.absolutePath}")
                } else {
                    Log.d(TAG, "Torrc unchanged, skipping write: ${torrc.absolutePath}")
                }

                Log.d(TAG, "Torrc written to: ${torrc.absolutePath}")
                if (bridgeConfig.isNotEmpty()) {
                    Log.i(TAG, "Bridge configuration applied: ${bridgeConfig.lines().first()}")
                }

                if (!alreadyRunning || needsUpdate) {
                    // If Tor is running but torrc changed, restart it to pick up new config
                    if (alreadyRunning && needsUpdate) {
                        Log.i(TAG, "Torrc configuration changed - restarting Tor to apply changes...")
                        try {
                            // Stop TorService first
                            val stopIntent = Intent(context, TorService::class.java)
                            context.stopService(stopIntent)

                            // Give Tor time to shut down
                            Thread.sleep(2000)
                            Log.d(TAG, "TorService stopped")
                        } catch (e: Exception) {
                            Log.w(TAG, "Error stopping TorService: ${e.message}")
                        }
                    }

                    Log.w(TAG, "========== STARTING GUARDIAN PROJECT TOR DAEMON (org.torproject.jni.TorService) ==========")

                    // Start TorService as an Android Service
                    // NOTE: Guardian Project TorService is a third-party library that handles its own
                    // foreground service lifecycle. Use regular startService() to avoid crashes.
                    val intent = Intent(context, TorService::class.java)
                    intent.action = "org.torproject.android.intent.action.START"
                    context.startService(intent)

                    Log.w(TAG, "========== GUARDIAN PROJECT TOR DAEMON START COMMAND SENT ==========")
                    Log.d(TAG, "Waiting for control port to be ready...")
                } else {
                    Log.d(TAG, "Tor already running and torrc unchanged")
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

                // Read persistent hidden service .onion addresses from filesystem
                // Tor automatically creates/reuses keys in HiddenServiceDir on startup
                val keyManager = KeyManager.getInstance(context)
                val onionAddress = if (keyManager.isInitialized()) {
                    // Wait for Tor to generate/load hidden service keys with validation
                    Log.d(TAG, "Waiting for Tor to generate/load persistent hidden service keys...")

                    val address = try {
                        waitForValidHostname(messagingHiddenServiceDir, timeoutMs = 60_000)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to get messaging hidden service address", e)
                        throw e
                    }

                    // Sanity check: if we already had a stored onion, verify it matches
                    val storedOnion = getOnionAddress()
                    if (storedOnion != null && storedOnion != address) {
                        Log.w(TAG, "⚠️ Stored onion differs from filesystem! Stored: $storedOnion, Filesystem: $address")
                        Log.w(TAG, "Using filesystem onion (Tor's source of truth)")
                    }

                    saveOnionAddress(address)
                    keyManager.storeMessagingOnion(address)
                    Log.i(TAG, "✓ Messaging hidden service ready (persistent): $address")

                    // Read friend-request .onion address with validation
                    try {
                        val friendRequestOnion = waitForValidHostname(friendRequestHiddenServiceDir, timeoutMs = 60_000)
                        keyManager.storeFriendRequestOnion(friendRequestOnion)
                        Log.i(TAG, "✓ Friend-request hidden service ready (persistent): $friendRequestOnion")
                    } catch (e: Exception) {
                        Log.w(TAG, "Friend-request hidden service not ready: ${e.message}")
                    }

                    // Note: Voice hidden service is created later by TorService.startVoiceService()
                    // after the voice streaming listener is started on localhost:9152
                    Log.d(TAG, "Voice hidden service will be registered by TorService after voice listener starts")

                    address
                } else {
                    Log.d(TAG, "Skipping hidden service read - no account yet")
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
            } catch (e: BridgeTransportFailedException) {
                Log.e(TAG, "Bridge transport failed - Tor will NOT start without bridges: ${e.message}", e)
                // Broadcast bridge failure so UI can inform the user
                val failIntent = Intent("com.securelegion.BRIDGE_TRANSPORT_FAILED")
                failIntent.putExtra("error_message", e.message)
                context.sendBroadcast(failIntent)
                synchronized(this) {
                    isInitializing = false
                    val callbacks = initCallbacks.toList()
                    initCallbacks.clear()
                    callbacks.forEach { it(false, null) }
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
                val cookiePath = File(context.filesDir, "voice_tor/control_auth_cookie").absolutePath
                val status = RustBridge.initializeVoiceTorControl(cookiePath)
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
                CookieAuthentication 1
                CookieAuthFile ${voiceTorDataDir.absolutePath}/control_auth_cookie
                ControlPort 127.0.0.1:9052
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
            // CRITICAL: Use startForegroundService() for Android 8+ to avoid BackgroundServiceStartNotAllowedException
            val voiceIntent = Intent(context, com.securelegion.services.VoiceTorService::class.java)
            voiceIntent.action = com.securelegion.services.VoiceTorService.ACTION_START

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                context.startForegroundService(voiceIntent)
            } else {
                context.startService(voiceIntent)
            }

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
            val cookiePath = File(context.filesDir, "voice_tor/control_auth_cookie").absolutePath
            val status = RustBridge.initializeVoiceTorControl(cookiePath)
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
     *
     * With persistent hidden services (HiddenServiceDir in torrc), Tor automatically
     * creates and manages the keys. This function just reads the .onion address.
     */
    fun createHiddenServiceIfNeeded() {
        Thread {
            try {
                val existingAddress = getOnionAddress()
                if (existingAddress == null) {
                    val keyManager = KeyManager.getInstance(context)
                    if (keyManager.isInitialized()) {
                        // Wait for Tor to be fully bootstrapped before reading hidden service
                        Log.d(TAG, "Waiting for Tor to be ready before reading hidden service...")
                        val maxAttempts = 30 // 30 seconds max
                        var attempts = 0
                        while (attempts < maxAttempts) {
                            val status = RustBridge.getBootstrapStatus()
                            if (status >= 100) {
                                Log.d(TAG, "Tor bootstrapped - reading hidden service...")
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

                        // Read persistent hidden service .onion address from filesystem
                        val messagingHiddenServiceDir = File(torDataDir, "messaging_hidden_service")

                        val address = try {
                            waitForValidHostname(messagingHiddenServiceDir, timeoutMs = 60_000)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to get messaging hidden service address: ${e.message}")
                            return@Thread
                        }

                        // Sanity check: verify address matches stored onion
                        val storedOnion = getOnionAddress()
                        if (storedOnion != null && storedOnion != address) {
                            Log.w(TAG, "⚠️ Stored onion differs from filesystem! Stored: $storedOnion, Filesystem: $address")
                            Log.w(TAG, "Using filesystem onion (Tor's source of truth)")
                        }

                        saveOnionAddress(address)
                        keyManager.storeMessagingOnion(address)
                        Log.i(TAG, "✓ Messaging hidden service read (persistent): $address")

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
                        Log.w(TAG, "Account not initialized yet, cannot read hidden service")
                    }
                } else {
                    Log.d(TAG, "Hidden service already exists: $existingAddress")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to read hidden service", e)
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
     * Note: This returns a shared client instance from OkHttpProvider (supports connection reset)
     */
    fun getTorProxyClient(): OkHttpClient {
        return OkHttpProvider.getGenericClient()
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
                    // Match Tor Project circumvention API config for Iran (ir)
                    // CDN77 domain fronting with Iran-specific front domains
                    controller.snowflakeBrokerUrl = "https://1098762253.rsc.cdn77.org/"
                    controller.snowflakeFrontDomains = "www.phpmyadmin.net,cdn.zk.mk"
                    controller.snowflakeIceServers = "stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443"
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
                "webtunnel" -> {
                    Log.d(TAG, "Starting webtunnel transport...")
                    controller.start(IPtProxy.Webtunnel, "")

                    // Wait for webtunnel to start and bind to a port
                    var port = 0L
                    var attempts = 0
                    while (port == 0L && attempts < 30) {
                        Thread.sleep(1000)
                        port = controller.port(IPtProxy.Webtunnel)
                        attempts++
                        if (port > 0) {
                            Log.i(TAG, "✓ webtunnel transport started on port $port after ${attempts}s")
                            break
                        }
                        Log.d(TAG, "Waiting for webtunnel to start... (${attempts}s)")
                    }

                    if (port == 0L) {
                        Log.e(TAG, "✗ webtunnel failed to start after 30 seconds")
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start IPtProxy transport for $bridgeType: ${e.message}", e)
            throw BridgeTransportFailedException("Failed to start $bridgeType transport: ${e.message}")
        }
    }

    /**
     * Fetch bridge lines from Tor Project's circumvention map API.
     * Returns null if the API is unreachable (e.g. in censored regions before Tor is up).
     * API endpoint: https://bridges.torproject.org/moat/circumvention/map
     */
    private fun fetchCircumventionBridges(bridgeType: String): List<String>? {
        return try {
            Log.d(TAG, "Fetching bridges from circumvention API for type=$bridgeType...")
            val url = java.net.URL("https://bridges.torproject.org/moat/circumvention/map")
            val connection = url.openConnection() as java.net.HttpURLConnection
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.requestMethod = "GET"

            val responseCode = connection.responseCode
            if (responseCode != 200) {
                Log.w(TAG, "Circumvention API returned $responseCode")
                return null
            }

            val responseBody = connection.inputStream.bufferedReader().readText()
            connection.disconnect()

            val json = org.json.JSONObject(responseBody)

            // Try Iran first, then fallback to other regions
            val countryCode = "ir"
            val countryData = json.optJSONObject(countryCode) ?: run {
                Log.w(TAG, "No circumvention data for country=$countryCode")
                return null
            }

            val settings = countryData.optJSONArray("settings") ?: return null

            for (i in 0 until settings.length()) {
                val setting = settings.getJSONObject(i)
                val bridges = setting.optJSONObject("bridges") ?: continue
                val type = bridges.optString("type", "")

                if (type == bridgeType) {
                    val bridgeStrings = bridges.optJSONArray("bridge_strings") ?: continue
                    val result = mutableListOf<String>()
                    for (j in 0 until bridgeStrings.length()) {
                        result.add(bridgeStrings.getString(j))
                    }
                    if (result.isNotEmpty()) {
                        Log.i(TAG, "Circumvention API: got ${result.size} $bridgeType bridges for $countryCode")
                        // Cache the bridges for future use
                        try {
                            val prefs = context.getSharedPreferences("tor_settings", Context.MODE_PRIVATE)
                            prefs.edit()
                                .putString("cached_${bridgeType}_bridges", result.joinToString("\n"))
                                .putLong("cached_${bridgeType}_timestamp", System.currentTimeMillis())
                                .apply()
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to cache bridges: ${e.message}")
                        }
                        return result
                    }
                }
            }

            Log.w(TAG, "No $bridgeType bridges found in API response for $countryCode")
            // Try cached bridges
            getCachedBridges(bridgeType)
        } catch (e: Exception) {
            Log.w(TAG, "Circumvention API fetch failed: ${e.message}")
            // Try cached bridges
            getCachedBridges(bridgeType)
        }
    }

    /**
     * Get previously cached bridges from SharedPreferences.
     * Returns null if no cache exists or cache is older than 24 hours.
     */
    private fun getCachedBridges(bridgeType: String): List<String>? {
        return try {
            val prefs = context.getSharedPreferences("tor_settings", Context.MODE_PRIVATE)
            val cached = prefs.getString("cached_${bridgeType}_bridges", null) ?: return null
            val timestamp = prefs.getLong("cached_${bridgeType}_timestamp", 0)
            val ageMs = System.currentTimeMillis() - timestamp

            // Cache valid for 24 hours
            if (ageMs > 24 * 60 * 60 * 1000) {
                Log.d(TAG, "Cached $bridgeType bridges expired (${ageMs / 1000}s old)")
                return null
            }

            val bridges = cached.split("\n").filter { it.isNotBlank() }
            if (bridges.isNotEmpty()) {
                Log.i(TAG, "Using ${bridges.size} cached $bridgeType bridges (${ageMs / 1000}s old)")
                bridges
            } else null
        } catch (e: Exception) {
            Log.w(TAG, "Failed to read cached bridges: ${e.message}")
            null
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
        if (bridgeType in listOf("obfs4", "snowflake", "meek", "webtunnel")) {
            startIPtProxy(bridgeType)
        }

        return when (bridgeType) {
            "snowflake" -> {
                // Snowflake - uses IPtProxy pluggable transport
                // Bridge lines from Tor Project circumvention API: bridges.torproject.org/moat/circumvention/map
                // Iran (ir) specific config: CDN77 domain-fronted rendezvous, no SQS
                val app = context.applicationContext as? SecureLegionApplication
                val controller = app?.let { SecureLegionApplication.iptProxyController }
                val port = controller?.port(IPtProxy.Snowflake) ?: 0
                if (port == 0L) {
                    throw BridgeTransportFailedException("Snowflake transport failed to start - no SOCKS port available")
                } else {
                    // Try fetching fresh bridges from circumvention API first
                    val apiBridges = fetchCircumventionBridges("snowflake")
                    if (apiBridges != null) {
                        Log.i(TAG, "Using ${apiBridges.size} snowflake bridges from circumvention API")
                        val bridgeLines = apiBridges.joinToString("\n") { "Bridge $it" }
                        """
                        UseBridges 1
                        ClientTransportPlugin snowflake socks5 127.0.0.1:$port
                        $bridgeLines
                        """.trimIndent()
                    } else {
                        // Fallback: hardcoded bridges from Tor Project API + forum recommendations for Iran
                        // Includes 3 rendezvous methods: CDN77 domain-front, Netlify domain-front, Amazon SQS
                        Log.i(TAG, "Using hardcoded snowflake bridges (API unavailable)")
                        """
                        UseBridges 1
                        ClientTransportPlugin snowflake socks5 127.0.0.1:$port
                        Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org front=www.phpmyadmin.net,cdn.zk.mk ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
                        Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org front=www.phpmyadmin.net,cdn.zk.mk ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
                        Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://voluble-torrone-fc39bf.netlify.app/ fronts=vuejs.org ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
                        Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://voluble-torrone-fc39bf.netlify.app/ fronts=vuejs.org ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
                        Bridge snowflake 192.0.2.5:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net/ ampcache=https://cdn.ampproject.org/ front=www.google.com ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
                        Bridge snowflake 192.0.2.6:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net/ ampcache=https://cdn.ampproject.org/ front=www.google.com ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
                        Bridge snowflake 192.0.2.5:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 sqsqueue=https://sqs.us-east-1.amazonaws.com/893902434899/snowflake-broker sqscreds=eyJhd3MtYWNjZXNzLWtleS1pZCI6IkFLSUE1QUlGNFdKSlhTN1lIRUczIiwiYXdzLXNlY3JldC1rZXkiOiI3U0RNc0pBNHM1RitXZWJ1L3pMOHZrMFFXV0lsa1c2Y1dOZlVsQ0tRIn0= ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
                        Bridge snowflake 192.0.2.6:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA sqsqueue=https://sqs.us-east-1.amazonaws.com/893902434899/snowflake-broker sqscreds=eyJhd3MtYWNjZXNzLWtleS1pZCI6IkFLSUE1QUlGNFdKSlhTN1lIRUczIiwiYXdzLXNlY3JldC1rZXkiOiI3U0RNc0pBNHM1RitXZWJ1L3pMOHZrMFFXV0lsa1c2Y1dOZlVsQ0tRIn0= ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.nextcloud.com:3478,stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443 utls-imitate=hellorandomizedalpn
                        """.trimIndent()
                    }
                }
            }
            "obfs4" -> {
                // obfs4 bridges from https://github.com/scriptzteam/Tor-Bridges-Collector
                // and https://bridges.torproject.org - uses IPtProxy pluggable transport
                val app = context.applicationContext as? SecureLegionApplication
                val controller = app?.let { SecureLegionApplication.iptProxyController }
                val port = controller?.port(IPtProxy.Obfs4) ?: 0
                if (port == 0L) {
                    throw BridgeTransportFailedException("obfs4 transport failed to start - no SOCKS port available")
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
                    throw BridgeTransportFailedException("meek_lite transport failed to start - no SOCKS port available")
                } else {
                    """
                    UseBridges 1
                    ClientTransportPlugin meek_lite socks5 127.0.0.1:$port
                    Bridge meek_lite 192.0.2.2:2 97700DFE9F483596DDA6264C4D7DF7641E1E39CE url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com
                    """.trimIndent()
                }
            }
            "webtunnel" -> {
                // WebTunnel - disguises Tor traffic as HTTPS WebSocket connections
                // Iran priority #1 in Tor Project circumvention API
                val app = context.applicationContext as? SecureLegionApplication
                val controller = app?.let { SecureLegionApplication.iptProxyController }
                val port = controller?.port(IPtProxy.Webtunnel) ?: 0
                if (port == 0L) {
                    throw BridgeTransportFailedException("webtunnel transport failed to start - no SOCKS port available")
                } else {
                    // Try fetching fresh bridges from circumvention API first
                    val apiBridges = fetchCircumventionBridges("webtunnel")
                    if (apiBridges != null) {
                        Log.i(TAG, "Using ${apiBridges.size} webtunnel bridges from circumvention API")
                        val bridgeLines = apiBridges.joinToString("\n") { "Bridge $it" }
                        """
                        UseBridges 1
                        ClientTransportPlugin webtunnel socks5 127.0.0.1:$port
                        $bridgeLines
                        """.trimIndent()
                    } else {
                        // Fallback: hardcoded webtunnel bridges
                        Log.i(TAG, "Using hardcoded webtunnel bridges (API unavailable)")
                        """
                        UseBridges 1
                        ClientTransportPlugin webtunnel socks5 127.0.0.1:$port
                        Bridge webtunnel [2001:db8:1fc0:eebe:5e6e:d6ee:f53e:6889]:443 4A3859C089DF40A4FFADC10A79DFEBE4F8272535 url=https://verry.org/K2A2utQIMou4Ia2WjVseyDjV ver=0.0.1
                        Bridge webtunnel [2001:db8:2ae3:679a:856c:c72a:2746:1a1b]:443 8943BF53C9561C75A7302ED59575EF71E2B26562 url=https://allium.heelsn.eu/X1uzc7J4omPPBbqkJMDgBtXP ver=0.0.3
                        Bridge webtunnel [2001:db8:2b58:9764:2fcf:67a0:1d1d:b622]:443 9255D4ADB05B7F8792E49779E4DF382BF7B2BE01 url=https://3124.null-f.org/KFfqlXliDgBsyHEtT0SKO1i5 ver=0.0.1
                        Bridge webtunnel [2001:db8:2b84:8d:b5af:2b7c:2528:ecbc]:443 F99CFE52EDFF8EAA332CD73C1E638035210C0336 url=https://cdn-26.privacyguides.net/cFwsJGX85KZ4INwnDHvVxs0G ver=0.0.2
                        Bridge webtunnel [2001:db8:2c2a:de34:35ec:ef86:f18a:e2fc]:443 B2DD1165FE69D5E934002AF882D3397CFCE441DC url=https://doxy.ptnpnhcdn.net/ptnpnh/ ver=0.0.1
                        """.trimIndent()
                    }
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
     * Deletes persistent hidden service keys so new identity is created
     * IMPORTANT: Stop TorService before calling this to avoid file locks
     */
    fun clearData() {
        Log.i(TAG, "Clearing all Tor data for account wipe...")

        // Clear preferences first
        prefs.edit().clear().apply()

        // Stop listeners to release file handles
        try {
            RustBridge.stopListeners()
            Log.d(TAG, "Stopped Rust listeners")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to stop listeners: ${e.message}")
        }

        // Give Tor a moment to close file handles
        Thread.sleep(500)

        // Delete persistent hidden service directories
        // This ensures a fresh .onion address is generated on next account creation
        try {
            val messagingHiddenServiceDir = File(torDataDir, "messaging_hidden_service")
            if (messagingHiddenServiceDir.exists()) {
                val deleted = messagingHiddenServiceDir.deleteRecursively()
                if (deleted) {
                    Log.i(TAG, "✓ Deleted persistent messaging hidden service directory")
                } else {
                    Log.e(TAG, "✗ Failed to delete messaging hidden service directory (may be locked)")
                }
            }

            val friendRequestHiddenServiceDir = File(torDataDir, "friend_request_hidden_service")
            if (friendRequestHiddenServiceDir.exists()) {
                val deleted = friendRequestHiddenServiceDir.deleteRecursively()
                if (deleted) {
                    Log.i(TAG, "✓ Deleted persistent friend-request hidden service directory")
                } else {
                    Log.e(TAG, "✗ Failed to delete friend-request hidden service directory (may be locked)")
                }
            }

            // Also delete voice hidden service if it exists
            val voiceTorDataDir = File(context.filesDir, "voice_tor")
            if (voiceTorDataDir.exists()) {
                val deleted = voiceTorDataDir.deleteRecursively()
                if (deleted) {
                    Log.i(TAG, "✓ Deleted voice Tor data directory")
                } else {
                    Log.w(TAG, "✗ Failed to delete voice Tor directory (may be locked)")
                }
            }

            Log.i(TAG, "Tor data wipe complete - fresh .onion will be generated on next account creation")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete hidden service directories", e)
        }
    }
}
