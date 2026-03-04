package com.securelegion.crypto

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Build
import android.util.Log
import okhttp3.OkHttpClient
import com.securelegion.network.OkHttpProvider
import java.io.File
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
@Deprecated(
    message = "Legacy Kotlin Tor orchestrator. Migration target is Rust/Arti-owned lifecycle.",
    level = DeprecationLevel.WARNING
)
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
                            Log.i(TAG, "Valid .onion address found: $txt (after ${System.currentTimeMillis() - start}ms)")
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
     * Check if the :tor process (Guardian Project's TorService) is still alive.
     * Used to prevent double-starting GP TorService which causes SIGABRT on destroyed mutex.
     */
    private fun isTorProcessAlive(): Boolean {
        return try {
            // GP TorService runs in-process. Check file existence first (cheap),
            // then verify with a real control handshake (prevents stale socket traps).
            val controlSocket = java.io.File(context.dataDir, "app_TorService/data/ControlSocket")
            if (!controlSocket.exists()) return false
            val alive = probeTorControl()
            if (alive) {
                Log.d(TAG, "Tor is running (probe confirmed)")
            } else {
                Log.w(TAG, "ControlSocket exists but probe failed — stale")
                controlSocket.delete()
            }
            alive
        } catch (e: Exception) {
            Log.w(TAG, "Failed to check Tor status: ${e.message}")
            false
        }
    }

    /**
     * Probe the Tor ControlSocket to verify Tor is actually responsive.
     * A stale ControlSocket file can survive a crash — this verifies with a real
     * AUTHENTICATE + GETINFO handshake over the Unix domain socket.
     * @return true if Tor responds with 250 OK, false if dead/unreachable
     */
    private fun probeTorControl(): Boolean {
        // Arti: check bootstrap status via RustBridge instead of ControlSocket
        return try {
            val bootstrap = RustBridge.getBootstrapStatus()
            val alive = bootstrap >= 100
            Log.d(TAG, "probeTorControl: Arti bootstrap=$bootstrap% alive=$alive")
            alive
        } catch (e: Exception) {
            Log.w(TAG, "probeTorControl: failed — ${e.message}")
            false
        }
    }

    /**
     * Start Tor — now a no-op since Arti is initialized in Rust.
     * GP TorService removed.
     */
    private fun startGpTor() {
        Log.i(TAG, "startGpTor: no-op (Arti handles Tor in-process via Rust)")
    }

    /**
     * Search for the real ControlSocket path across all app-private directories.
     * GP TorService may create it in different locations depending on DataDir config.
     * @return File if found, null otherwise
     */
    private fun findControlSocket(): File? {
        val candidates = listOf(
            File(context.dataDir, "app_TorService/data/ControlSocket"),
            File(context.filesDir, "app_TorService/data/ControlSocket"),
            File(context.dataDir, "app_TorService/ControlSocket"),
            File(context.filesDir, "ControlSocket"),
        )
        candidates.firstOrNull { it.exists() }?.let {
            Log.i(TAG, "findControlSocket: found at ${it.absolutePath}")
            return it
        }

        // Recursive search under app private dirs (depth-capped)
        val roots = listOfNotNull(context.dataDir, context.filesDir, context.noBackupFilesDir, context.cacheDir)
        for (root in roots) {
            try {
                val found = root.walkTopDown()
                    .maxDepth(6)
                    .firstOrNull { it.isFile && it.name == "ControlSocket" }
                if (found != null) {
                    Log.i(TAG, "findControlSocket: found via search at ${found.absolutePath}")
                    return found
                }
            } catch (e: Exception) {
                // Permission denied on some dirs — skip
            }
        }
        return null
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
            val socketFile = File(context.dataDir, "app_TorService/data/ControlSocket")
            Log.i(TAG, "Starting bootstrap event listener early (socket path: ${socketFile.absolutePath})...")
            RustBridge.startBootstrapListener(socketFile.absolutePath)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to start bootstrap listener (may start later)", e)
        }

        Thread {
            try {
                // GP TorService runs in-process — any leftover ControlSocket on startup is stale.
                // Delete unconditionally so we never skip starting Tor due to a ghost file.
                val controlSocketFile = File(context.dataDir, "app_TorService/data/ControlSocket")
                if (controlSocketFile.exists()) {
                    Log.w(TAG, "Deleting stale ControlSocket on startup (in-process Tor guarantees stale)")
                    controlSocketFile.delete()
                }
                val alreadyRunning = false

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

                // Seed hidden service directories with deterministic keys BEFORE Tor starts.
                // This writes hs_ed25519_secret_key + hs_ed25519_public_key derived from the
                // BIP39 seed, so Tor loads our keys instead of generating random ones.
                // Result: the .onion address shown offline matches what Tor publishes.
                val keyManager = KeyManager.getInstance(context)
                if (keyManager.isInitialized()) {
                    try {
                        keyManager.seedHiddenServiceDir(messagingHiddenServiceDir, "tor_hs")
                        keyManager.seedHiddenServiceDir(friendRequestHiddenServiceDir, "friend_req")
                        Log.i(TAG, "Hidden service directories seeded with deterministic keys")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to seed hidden service directories — Tor may generate random keys", e)
                    }
                } else {
                    Log.d(TAG, "No account yet — skipping hidden service key seeding")
                }

                // Get the torrc file location (legacy — Arti uses its own config)
                val torrc = File(context.filesDir, "torrc")
                torrc.parentFile?.mkdirs()

                // Bridges removed — Arti uses direct Tor connections only.
                // Torrc is legacy (kept for reference only, Arti ignores it).
                val torrcContent = """
                    Log notice stdout
                    SocksPort 127.0.0.1:9050
                    ClientOnly 1
                    AvoidDiskWrites 1
                    DormantCanceledByStartup 1
                    DormantClientTimeout 525600 minutes
                    HiddenServiceDir ${messagingHiddenServiceDir.absolutePath}
                    HiddenServicePort $DEFAULT_SERVICE_PORT 127.0.0.1:$DEFAULT_LOCAL_PORT
                    HiddenServicePort 9153 127.0.0.1:9153
                    HiddenServiceDir ${friendRequestHiddenServiceDir.absolutePath}
                    HiddenServicePort 9151 127.0.0.1:9151
                    HiddenServicePort 9152 127.0.0.1:8081
                """.trimIndent()

                val needsUpdate = !torrc.exists() || torrc.readText() != torrcContent
                if (needsUpdate) {
                    torrc.writeText(torrcContent)
                    Log.d(TAG, "Torrc updated: ${torrc.absolutePath}")
                } else {
                    Log.d(TAG, "Torrc unchanged, skipping write: ${torrc.absolutePath}")
                }

                Log.d(TAG, "Torrc written to: ${torrc.absolutePath}")

                if (!alreadyRunning || needsUpdate) {
                    // If Tor is running but torrc changed, restart it to pick up new config
                    if (alreadyRunning && needsUpdate) {
                        Log.i(TAG, "Torrc configuration changed - restarting Tor to apply changes...")
                        try {
                            // Stop TorService first
                            val stopIntent = Intent(context, com.securelegion.services.TorService::class.java)
                            context.stopService(stopIntent)

                            // Give Tor time to shut down
                            Thread.sleep(2000)
                            Log.d(TAG, "TorService stopped")
                        } catch (e: Exception) {
                            Log.w(TAG, "Error stopping TorService: ${e.message}")
                        }
                    }

                    Log.w(TAG, "========== STARTING FOREGROUND SERVICE + TOR DAEMON ==========")

                    // Step 1: Start our custom TorService as foreground (keeps process alive)
                    // Uses KEEP_ALIVE action to avoid calling initializeAsync() again (circular dependency)
                    val keepAliveIntent = Intent(context, com.securelegion.services.TorService::class.java)
                    keepAliveIntent.action = com.securelegion.services.TorService.ACTION_KEEP_ALIVE
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                        context.startForegroundService(keepAliveIntent)
                    } else {
                        context.startService(keepAliveIntent)
                    }
                    Log.i(TAG, "Custom TorService started as foreground (KEEP_ALIVE)")

                    // Step 2: Arti handles Tor in-process — no external daemon needed
                    Log.i(TAG, "Arti in-process — no GP TorService to start")
                } else {
                    Log.d(TAG, "Tor already running and torrc unchanged")
                }

                // Initialize Rust TorManager + Arti (in-process Tor)
                Log.d(TAG, "Initializing Arti (in-process Rust Tor)...")
                val rustStatus = RustBridge.initializeTor()
                Log.d(TAG, "Arti initialized: $rustStatus")

                // Wait for Arti to bootstrap (up to 120s for slow networks)
                // Arti handles connections in-process — no ControlSocket or SOCKS proxy needed
                Log.d(TAG, "Waiting for Arti bootstrap...")
                var artiAttempts = 0
                val maxArtiAttempts = 120 // 120s to accommodate slow networks
                var artiReady = false

                while (artiAttempts < maxArtiAttempts && !artiReady) {
                    try {
                        val bootstrapStatus = RustBridge.getBootstrapStatus()
                        if (bootstrapStatus >= 95 || RustBridge.isSocksProxyRunning()) {
                            artiReady = true
                            Log.i(TAG, "Arti ready after ${artiAttempts + 1}s (bootstrap: $bootstrapStatus%)")
                        } else {
                            if (artiAttempts % 10 == 9) {
                                Log.d(TAG, "Arti bootstrap: $bootstrapStatus% (${artiAttempts + 1}s)")
                            }
                            Thread.sleep(1000)
                            artiAttempts++
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Bootstrap check error: ${e.message}")
                        Thread.sleep(1000)
                        artiAttempts++
                    }
                }

                if (!artiReady) {
                    throw Exception("Arti failed to bootstrap after $maxArtiAttempts seconds")
                }

                Log.d(TAG, "Arti bootstrapped and ready")

                // Read persistent hidden service .onion addresses from filesystem
                // Keys were seeded above — Tor should have loaded our deterministic keys
                val onionAddress = if (keyManager.isInitialized()) {
                    // Arti creates hidden services from the same Ed25519 keys
                    // Use KeyManager's pre-computed onion addresses (derived from BIP39 seed)
                    val address = keyManager.getMessagingOnion()
                    if (address != null) {
                        saveOnionAddress(address)
                        Log.i(TAG, "Messaging onion address (from KeyManager): $address")
                    } else {
                        Log.w(TAG, "No messaging onion address in KeyManager")
                    }

                    val friendRequestOnion = keyManager.getFriendRequestOnion()
                    if (friendRequestOnion != null) {
                        Log.i(TAG, "Friend-request onion address (from KeyManager): $friendRequestOnion")
                    } else {
                        Log.w(TAG, "No friend-request onion address in KeyManager")
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
        // Voice calling disabled in v1 — skip entire voice Tor daemon
        // Return true = "handled, not an error" to prevent retry/fatal paths
        Log.i(TAG, "startVoiceTor() — DISABLED (voice calling disabled in v1)")
        return true
        @Suppress("UNREACHABLE_CODE")
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
            Log.i(TAG, "Voice Tor initialized successfully: $status")
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
                        val maxAttempts = 120 // 120 seconds max (bridges on slow networks need more time)
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
                            Log.w(TAG, "Stored onion differs from filesystem!")
                            Log.w(TAG, "Using filesystem onion (Tor's source of truth)")
                        }

                        saveOnionAddress(address)
                        keyManager.storeMessagingOnion(address)
                        Log.i(TAG, "Messaging hidden service read (persistent)")

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
     * @param deviceProtection Whether Device Protection mode was used (M5 timing mitigation)
     * @return Pong token bytes, or null if authentication denied
     */
    fun respondToPing(pingId: String, authenticated: Boolean, deviceProtection: Boolean = false): ByteArray? {
        return RustBridge.respondToPing(pingId, authenticated, deviceProtection)
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

    // Bridges removed — Arti uses direct Tor connections only.

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
                    Log.i(TAG, "Deleted persistent messaging hidden service directory")
                } else {
                    Log.e(TAG, "Failed to delete messaging hidden service directory (may be locked)")
                }
            }

            val friendRequestHiddenServiceDir = File(torDataDir, "friend_request_hidden_service")
            if (friendRequestHiddenServiceDir.exists()) {
                val deleted = friendRequestHiddenServiceDir.deleteRecursively()
                if (deleted) {
                    Log.i(TAG, "Deleted persistent friend-request hidden service directory")
                } else {
                    Log.e(TAG, "Failed to delete friend-request hidden service directory (may be locked)")
                }
            }

            // Also delete voice hidden service if it exists
            val voiceTorDataDir = File(context.filesDir, "voice_tor")
            if (voiceTorDataDir.exists()) {
                val deleted = voiceTorDataDir.deleteRecursively()
                if (deleted) {
                    Log.i(TAG, "Deleted voice Tor data directory")
                } else {
                    Log.w(TAG, "Failed to delete voice Tor directory (may be locked)")
                }
            }

            Log.i(TAG, "Tor data wipe complete - fresh .onion will be generated on next account creation")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete hidden service directories", e)
        }
    }
}
