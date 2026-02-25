package com.securelegion

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.Spinner
import android.widget.AdapterView
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView

import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.securelegion.adapters.ChatAdapter
import com.securelegion.adapters.ContactAdapter
import com.securelegion.adapters.WalletAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import com.securelegion.models.Chat
import com.securelegion.models.Contact
import com.securelegion.services.SolanaService
import com.securelegion.services.TorService
import com.securelegion.services.ZcashService
import com.securelegion.utils.startActivityWithSlideAnimation
import com.securelegion.utils.BadgeUtils
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.crypto.VoiceCallCrypto
import com.securelegion.workers.SelfDestructWorker
import com.securelegion.workers.MessageRetryWorker
import com.securelegion.workers.SkippedKeyCleanupWorker
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.database.entities.x25519PublicKeyBytes
import java.util.UUID
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

class MainActivity : BaseActivity() {
    companion object {
        private const val TAG = "MainActivity"
        private const val PERMISSION_REQUEST_CALL = 100
    }

    private var currentTab = "messages" // Track current tab: "messages", "groups", "contacts", or "wallet"
    private var contactsSubTab = "contacts" // "contacts" or "requests"
    private var currentWallet: Wallet? = null // Track currently selected wallet
    private var isCallMode = false // Track if we're in call mode (Phone icon clicked)
    private var pendingCallContact: Contact? = null // Temporary storage for pending call after permission request
    private var isInitiatingCall = false // Prevent duplicate call initiations
    private var dbDeferred: Deferred<SecureLegionDatabase>? = null // Pre-warmed DB connection

    // BroadcastReceiver to listen for incoming Pings and message status updates
    private val pingReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                "com.securelegion.NEW_PING" -> {
                    Log.d("MainActivity", "Received NEW_PING broadcast - refreshing chat list")
                    runOnUiThread {
                        if (currentTab == "messages") {
                            setupChatList()
                        }
                        updateUnreadMessagesBadge()
                    }
                }
                "com.securelegion.MESSAGE_RECEIVED" -> {
                    val contactId = intent.getLongExtra("CONTACT_ID", -1)
                    Log.d("MainActivity", "Received MESSAGE_RECEIVED broadcast for contact $contactId")
                    runOnUiThread {
                        if (currentTab == "messages") {
                            setupChatList()
                        }
                        updateUnreadMessagesBadge()
                    }
                }
            }
        }
    }

    // BroadcastReceiver to listen for friend requests and update badge
    private val friendRequestReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.securelegion.FRIEND_REQUEST_RECEIVED") {
                Log.d("MainActivity", "Received FRIEND_REQUEST_RECEIVED broadcast - updating badges")
                runOnUiThread {
                    updateFriendRequestBadge()
                    // Also refresh the add friend page if on contacts tab
                    if (currentTab == "contacts") {
                        setupContactsList()
                    }
                }
            }
        }
    }

    // BroadcastReceiver to listen for group invites and group messages
    private val groupReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                "com.securelegion.GROUP_INVITE_RECEIVED" -> {
                    Log.d("MainActivity", "Received GROUP_INVITE_RECEIVED broadcast")
                    runOnUiThread {
                        // Always update badge regardless of current tab
                        updateGroupsBadge()
                        if (currentTab == "groups") {
                            setupGroupsList()
                        }
                    }
                }
                "com.securelegion.NEW_GROUP_MESSAGE" -> {
                    Log.d("MainActivity", "Received NEW_GROUP_MESSAGE broadcast")
                    runOnUiThread {
                        updateGroupsBadge()
                        if (currentTab == "groups") {
                            setupGroupsList()
                        }
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Verify account setup is complete before showing main screen
        val keyManager = KeyManager.getInstance(this)
        if (!keyManager.isAccountSetupComplete()) {
            Log.w("MainActivity", "Account setup incomplete - redirecting to CreateAccount")
            ThemedToast.showLong(this, "Please complete account setup")
            val intent = Intent(this, CreateAccountActivity::class.java)
            intent.putExtra("RESUME_SETUP", true)
            startActivity(intent)
            finish()
            return
        }

        // Pre-warm SQLCipher database while views inflate
        dbDeferred = lifecycleScope.async(Dispatchers.IO) {
            val dbPassphrase = keyManager.getDatabasePassphrase()
            SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)
        }

        setContentView(R.layout.activity_main)

        // Enable edge-to-edge display (important for display cutouts)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        // Handle window insets for top bar and bottom navigation
        val rootView = findViewById<View>(android.R.id.content)
        val topBar = findViewById<View>(R.id.topBar)
        val bottomNav = findViewById<View>(R.id.bottomNav)

        ViewCompat.setOnApplyWindowInsetsListener(rootView) { view, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                WindowInsetsCompat.Type.displayCutout()
            )

            // Apply top inset to top bar spacer (for status bar and display cutout)
            topBar.layoutParams = topBar.layoutParams.apply {
                height = insets.top
            }

            // Move bottom nav pill ABOVE system bars (margin, not padding)
            // Padding would squish icons inside the fixed-height pill;
            // margin moves the entire pill up while keeping content centered
            val navParams = bottomNav.layoutParams as androidx.constraintlayout.widget.ConstraintLayout.LayoutParams
            navParams.bottomMargin = (20 * resources.displayMetrics.density).toInt() + insets.bottom
            bottomNav.layoutParams = navParams

            Log.d("MainActivity", "Applied window insets - top: ${insets.top}, bottom: ${insets.bottom}, left: ${insets.left}, right: ${insets.right}")

            windowInsets
        }

        Log.d("MainActivity", "onCreate - initializing views")

        // Ensure messages tab is shown by default
        findViewById<View>(R.id.chatListContainer).visibility = View.VISIBLE
        findViewById<View>(R.id.groupsView).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.GONE

        // Show chat list (no empty state)
        val chatList = findViewById<RecyclerView>(R.id.chatList)
        chatList.visibility = View.VISIBLE

        setupClickListeners()
        scheduleSelfDestructWorker()
        scheduleMessageRetryWorker()
        scheduleSkippedKeyCleanupWorker()


        // Start Tor foreground service (shows notification and handles Ping-Pong protocol)
        startTorService()

        // Observe Tor state and update status dot next to "Chats"
        observeTorStatus()

        // Tap signal icon → Tor Health page
        findViewById<View>(R.id.torStatusIcon)?.setOnClickListener {
            startActivity(Intent(this, TorHealthActivity::class.java))
        }

        // Pull-down on chat list shows Tor status banner
        chatList.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                // Show banner when user scrolls past top (pull-down gesture)
                if (!recyclerView.canScrollVertically(-1) && dy < -10) {
                    val banner = findViewById<TextView>(R.id.torStatusBanner)
                    if (banner?.visibility != View.VISIBLE) {
                        showTorStatusBanner()
                    }
                }
            }
        })

        // Start contact exchange endpoint (v2.0)
        startFriendRequestServer()

        // Load data asynchronously to avoid blocking UI
        setupChatList()
        setupContactsList()

        // Update app icon badge with unread count
        updateAppBadge()

        // Wallet disabled — hidden until wallet feature is ready for release
        // if (intent.getBooleanExtra("SHOW_WALLET", false)) {
        //     val walletIntent = Intent(this, WalletActivity::class.java)
        //     startActivity(walletIntent)
        // }

        // Check if we should show groups tab (from group invite notification)
        if (intent.getBooleanExtra("SHOW_GROUPS", false)) {
            showGroupsTab()
        }

        // Phone/call tab — voice calling disabled in v1
        // if (intent.getBooleanExtra("SHOW_PHONE", false)) { isCallMode = true; showContactsTab() }

        // Register broadcast receiver for incoming Pings and message status updates
        val filter = IntentFilter().apply {
            addAction("com.securelegion.NEW_PING")
            addAction("com.securelegion.MESSAGE_RECEIVED")
        }
        registerReceiver(pingReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        Log.d("MainActivity", "Registered NEW_PING and MESSAGE_RECEIVED broadcast receiver in onCreate")

        // Register broadcast receiver for friend requests
        val friendRequestFilter = IntentFilter("com.securelegion.FRIEND_REQUEST_RECEIVED")
        registerReceiver(friendRequestReceiver, friendRequestFilter, Context.RECEIVER_NOT_EXPORTED)
        Log.d("MainActivity", "Registered FRIEND_REQUEST_RECEIVED broadcast receiver in onCreate")

        // Register broadcast receiver for group invites and messages
        val groupFilter = IntentFilter().apply {
            addAction("com.securelegion.GROUP_INVITE_RECEIVED")
            addAction("com.securelegion.NEW_GROUP_MESSAGE")
        }
        registerReceiver(groupReceiver, groupFilter, Context.RECEIVER_NOT_EXPORTED)
        Log.d("MainActivity", "Registered group broadcast receivers in onCreate")
    }

    private fun updateAppBadge() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                // Get total unread count across all contacts
                val unreadCount = database.messageDao().getTotalUnreadCount()

                Log.d("MainActivity", "Total unread messages: $unreadCount")

                withContext(Dispatchers.Main) {
                    // Update notification badge
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        val notificationManager = getSystemService(android.app.NotificationManager::class.java)

                        if (unreadCount > 0) {
                            // Create a simple badge notification
                            val notification = androidx.core.app.NotificationCompat.Builder(this@MainActivity, "badge_channel")
                                .setSmallIcon(R.drawable.ic_shield)
                                .setContentTitle("Secure Legion")
                                .setContentText("$unreadCount unread message${if (unreadCount > 1) "s" else ""}")
                                .setNumber(unreadCount)
                                .setBadgeIconType(androidx.core.app.NotificationCompat.BADGE_ICON_SMALL)
                                .setPriority(androidx.core.app.NotificationCompat.PRIORITY_LOW)
                                .setAutoCancel(true)
                                .build()

                            notificationManager.notify(999, notification)
                        } else {
                            // Clear badge
                            notificationManager.cancel(999)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to update app badge", e)
            }
        }
    }

    /**
     * Update the friend request badge on the Contacts nav icon and compose button
     */
    private fun updateFriendRequestBadge() {
        val rootView = findViewById<View>(android.R.id.content)
        BadgeUtils.updateFriendRequestBadge(this, rootView)

        // Also update compose button badge if on contacts tab
        val count = BadgeUtils.getPendingFriendRequestCount(this)
        if (currentTab == "contacts") {
            BadgeUtils.updateComposeBadge(rootView, count)
        } else {
            BadgeUtils.updateComposeBadge(rootView, 0)
        }
    }

    /**
     * Update the unread messages badge on the Chats nav icon
     */
    private fun updateUnreadMessagesBadge() {
        lifecycleScope.launch {
            try {
                val database = dbDeferred?.await() ?: return@launch
                val count = withContext(Dispatchers.IO) {
                    database.messageDao().getTotalUnreadCount()
                }
                val rootView = findViewById<View>(android.R.id.content)
                BadgeUtils.updateUnreadMessagesBadge(rootView, count)
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to update unread messages badge", e)
            }
        }
    }


    private fun scheduleSelfDestructWorker() {
        // Schedule periodic work to clean up expired self-destruct messages
        // Runs every 1 hour in background
        val workRequest = PeriodicWorkRequestBuilder<SelfDestructWorker>(
            1, TimeUnit.HOURS
        ).build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            SelfDestructWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP, // Don't restart if already scheduled
            workRequest
        )

        Log.d("MainActivity", "Self-destruct worker scheduled (hourly)")

        // Run cleanup in background - don't block app launch
        lifecycleScope.launch(Dispatchers.IO) {
            cleanupExpiredMessages()
        }
    }

    /**
     * Schedule message retry worker with exponential backoff
     * Retries pending Pings and polls for Pongs every 5 minutes
     */
    private fun scheduleMessageRetryWorker() {
        MessageRetryWorker.schedule(this)
        Log.d("MainActivity", "Message retry worker scheduled")
    }

    /**
     * Schedule skipped key cleanup worker
     * Runs daily to delete skipped message keys older than 30 days (TTL)
     */
    private fun scheduleSkippedKeyCleanupWorker() {
        // Schedule periodic work to clean up old skipped message keys
        // Runs every 24 hours in background
        val workRequest = PeriodicWorkRequestBuilder<SkippedKeyCleanupWorker>(
            24, TimeUnit.HOURS
        ).build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            SkippedKeyCleanupWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP, // Don't restart if already scheduled
            workRequest
        )

        Log.d("MainActivity", "Skipped key cleanup worker scheduled (daily)")
    }

    /**
     * Start the Tor foreground service
     * This shows the persistent notification and handles the Ping-Pong protocol
     */
    private fun startTorService() {
        // Check if service is already running to avoid race condition
        if (com.securelegion.services.TorService.isRunning()) {
            Log.d("MainActivity", "Tor service already running, skipping start")
            return
        }

        try {
            Log.d("MainActivity", "Starting Tor foreground service...")
            com.securelegion.services.TorService.start(this)
        } catch (e: Exception) {
            Log.e("MainActivity", "Failed to start Tor service", e)
        }
    }

    /**
     * Observe Tor state and update the signal strength icon next to "Chats"
     * Maps TorState + bootstrap percentage to 6 WiFi-style signal levels:
     *   OFF/ERROR/STOPPING → disconnected (slash icon)
     *   STARTING (0%)      → level 1 (dot only)
     *   BOOTSTRAPPING 1-33%  → level 2 (dot + 1 arc)
     *   BOOTSTRAPPING 34-66% → level 3 (dot + 2 arcs)
     *   BOOTSTRAPPING 67-99% → level 4 (dot + 3 arcs)
     *   RUNNING (100%)      → full signal (all arcs)
     */
    private fun observeTorStatus() {
        lifecycleScope.launch {
            while (isActive) {
                val icon = findViewById<ImageView>(R.id.torStatusIcon)
                val state = TorService.getCurrentTorState()
                val bootstrapPercent = TorService.getBootstrapPercent()
                val drawableRes = when (state) {
                    TorService.TorState.RUNNING -> {
                        // Proof-based signal: "receivable via onion" = HS self-test passed
                        // since last network change. Don't trust Tor's circuit-established
                        // (zombie circuits via local control socket).
                        val cm = getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
                        val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
                        val hasValidatedInternet = caps?.hasCapability(
                            android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED
                        ) == true

                        val lastProofMs = try { com.securelegion.crypto.RustBridge.getLastTorProofMs() } catch (_: Exception) { 0L }
                        val lastNetworkChangeMs = TorService.getLastNetworkChangeMs()
                        val hasFreshProof = lastProofMs > 0 && lastProofMs >= lastNetworkChangeMs
                        val circuitsEstablished = try { com.securelegion.crypto.RustBridge.getCircuitEstablished() } catch (_: Exception) { 0 }
                        val hasTransportReady = bootstrapPercent >= 100 && circuitsEstablished == 1

                        when {
                            !hasValidatedInternet -> R.drawable.ic_tor_signal_off  // offline
                            hasFreshProof -> R.drawable.ic_tor_signal_full         // receivable
                            hasTransportReady -> R.drawable.ic_tor_signal_4        // connected (outbound ready)
                            else -> R.drawable.ic_tor_signal_2                     // connecting
                        }
                    }
                    TorService.TorState.BOOTSTRAPPING -> when {
                        bootstrapPercent >= 67 -> R.drawable.ic_tor_signal_4
                        bootstrapPercent >= 34 -> R.drawable.ic_tor_signal_3
                        bootstrapPercent >= 1  -> R.drawable.ic_tor_signal_2
                        else -> R.drawable.ic_tor_signal_1
                    }
                    TorService.TorState.STARTING -> R.drawable.ic_tor_signal_1
                    else -> R.drawable.ic_tor_signal_off
                }
                icon?.setImageResource(drawableRes)
                delay(2000)
            }
        }
    }

    /**
     * Show the Tor status banner with a slide-down animation.
     * Auto-hides after 5 seconds. Tapping opens TorHealthActivity.
     */
    private fun showTorStatusBanner() {
        val banner = findViewById<TextView>(R.id.torStatusBanner) ?: return
        val state = TorService.getCurrentTorState()
        val bootstrapPercent = TorService.getBootstrapPercent()

        val torSettings = getSharedPreferences("tor_settings", MODE_PRIVATE)
        val bridgeType = torSettings.getString("bridge_type", "none") ?: "none"
        val usingBridges = bridgeType != "none"

        banner.text = when (state) {
            TorService.TorState.RUNNING -> {
                val cm = getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as? android.net.ConnectivityManager
                val caps = cm?.getNetworkCapabilities(cm.activeNetwork)
                val hasValidatedInternet = caps?.hasCapability(
                    android.net.NetworkCapabilities.NET_CAPABILITY_VALIDATED
                ) == true

                val lastProofMs = try { com.securelegion.crypto.RustBridge.getLastTorProofMs() } catch (_: Exception) { 0L }
                val lastNetworkChangeMs = TorService.getLastNetworkChangeMs()
                val hasFreshProof = lastProofMs > 0 && lastProofMs >= lastNetworkChangeMs
                val circuitsEstablished = try { com.securelegion.crypto.RustBridge.getCircuitEstablished() } catch (_: Exception) { 0 }
                val hasTransportReady = bootstrapPercent >= 100 && circuitsEstablished == 1

                when {
                    !hasValidatedInternet -> "Tor offline"
                    hasFreshProof -> if (usingBridges) "Tor receivable via bridges" else "Tor receivable"
                    hasTransportReady -> if (usingBridges) "Tor connected via bridges" else "Tor connected"
                    else -> "Connecting to Tor..."
                }
            }
            TorService.TorState.BOOTSTRAPPING -> "Connecting to Tor... ($bootstrapPercent%)"
            TorService.TorState.STARTING -> "Starting Tor..."
            TorService.TorState.ERROR -> "Tor reconnecting..."
            TorService.TorState.STOPPING -> "Tor stopping..."
            TorService.TorState.OFF -> "No internet connection"
        }

        banner.visibility = View.VISIBLE
        banner.alpha = 0f
        banner.animate().alpha(1f).setDuration(200).start()

        banner.setOnClickListener {
            try {
                val intent = Intent(this, TorHealthActivity::class.java)
                startActivity(intent)
            } catch (e: Exception) {
                Log.w(TAG, "TorHealthActivity not available: ${e.message}")
            }
        }

        // Auto-hide after 5 seconds
        Handler(Looper.getMainLooper()).postDelayed({
            banner.animate().alpha(0f).setDuration(200).withEndAction {
                banner.visibility = View.GONE
            }.start()
        }, 5000)
    }

    /**
     * Start the friend request HTTP server (v2.0)
     * This listens for incoming friend requests on the friend request .onion address
     */
    private fun startFriendRequestServer() {
        lifecycleScope.launch {
            try {
                Log.d("MainActivity", "Starting friend request HTTP server...")
                val friendRequestService = com.securelegion.services.FriendRequestService.getInstance(this@MainActivity)
                val result = friendRequestService.startServer()

                if (result.isSuccess) {
                    Log.i("MainActivity", "Friend request server started successfully")
                } else {
                    Log.w("MainActivity", "Failed to start friend request server: ${result.exceptionOrNull()?.message}")
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "Error starting friend request server", e)
            }
        }
    }

    private suspend fun cleanupExpiredMessages() {
        try {
            val keyManager = KeyManager.getInstance(this@MainActivity)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

            val deletedCount = database.messageDao().deleteExpiredMessages()

            if (deletedCount > 0) {
                Log.i("MainActivity", "Deleted $deletedCount expired messages on app launch")
            }
        } catch (e: Exception) {
            Log.e("MainActivity", "Failed to cleanup expired messages", e)
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent) // Update the activity's intent

        // Wallet disabled — hidden until wallet feature is ready for release
        // if (intent.getBooleanExtra("SHOW_WALLET", false)) {
        //     Log.d("MainActivity", "onNewIntent - opening wallet activity")
        //     val walletIntent = Intent(this, WalletActivity::class.java)
        //     startActivity(walletIntent)
        // }

        // Check if we should show groups tab (from group invite notification)
        if (intent.getBooleanExtra("SHOW_GROUPS", false)) {
            Log.d("MainActivity", "onNewIntent - showing groups tab from notification")
            showGroupsTab()
        } else if (intent.getBooleanExtra("SHOW_REQUESTS_TAB", false)) {
            Log.d("MainActivity", "onNewIntent - showing requests tab after QR send")
            isCallMode = false
            showContactsTab()
            showRequestsSubTab()
        } else if (intent.getBooleanExtra("SHOW_CONTACTS", false)) {
            Log.d("MainActivity", "onNewIntent - showing contacts tab")
            isCallMode = false
            showContactsTab()
        // } else if (intent.getBooleanExtra("SHOW_PHONE", false)) {
        //     Voice calling disabled in v1
        //     isCallMode = true
        //     showContactsTab()
        } else {
            // Default: show chats tab (e.g., navMessages pressed from another activity)
            Log.d("MainActivity", "onNewIntent - showing chats tab (default)")
            showAllChatsTab()
        }
    }

    override fun onResume() {
        super.onResume()
        Log.d("MainActivity", "onResume called - current tab: $currentTab")

        // Reset call initiation flag when returning from VoiceCallActivity
        // This allows subsequent call attempts after previous call ends/fails
        if (isInitiatingCall) {
            Log.d("MainActivity", "Resetting isInitiatingCall flag on resume")
            isInitiatingCall = false
        }

        // Notify TorService that app is in foreground (fast bandwidth updates)
        com.securelegion.services.TorService.setForegroundState(true)

        // Reload data when returning to MainActivity (receiver stays registered)
        if (currentTab == "messages") {
            setupChatList()
        } else if (currentTab == "groups") {
            // Reload groups list
            setupGroupsList()
        } else if (currentTab == "wallet") {
            // Reload wallet spinner to show newly created wallets
            setupWalletSpinner()
        } else if (currentTab == "contacts") {
            // Reload contacts list to show updates (e.g., after deleting a contact)
            setupContactsList()
        }

        // Update badge counts
        updateFriendRequestBadge()
        updateUnreadMessagesBadge()

        // Cancel non-Tor system notifications when user is actively in the app
        cancelStaleNotifications()
    }

    /**
     * Cancel non-Tor system bar notifications when user is actively in the app.
     * Keeps foreground service (1001) and download service (2002) notifications.
     * Cancels: friend-request-accepted (6000+), pending message summary (999),
     * and any stale message notifications the user hasn't tapped.
     */
    private fun cancelStaleNotifications() {
        try {
            val notificationManager = getSystemService(android.app.NotificationManager::class.java)
            for (sbn in notificationManager.activeNotifications) {
                val id = sbn.id
                val group = sbn.notification.group
                // Skip foreground service notifications (Tor=1001, Download=2002)
                if (id == 1001 || id == 2002) continue
                // Cancel friend-request-accepted (6000-15999)
                if (id in 6000..15999) {
                    notificationManager.cancel(id)
                    continue
                }
                // Cancel message notifications (grouped MESSAGES_*)
                if (group?.startsWith("MESSAGES_") == true) {
                    notificationManager.cancel(id)
                    continue
                }
                // Cancel pending message summary
                if (id == 999) {
                    notificationManager.cancel(id)
                }
            }
        } catch (e: Exception) {
            Log.e("MainActivity", "Failed to cancel stale notifications", e)
        }
    }

    override fun onPause() {
        super.onPause()
        Log.d("MainActivity", "onPause called")

        // Notify TorService that app is in background (slow bandwidth updates to save battery)
        com.securelegion.services.TorService.setForegroundState(false)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        if (requestCode == PERMISSION_REQUEST_CALL) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // Permission granted! Retry the call with stored contact
                pendingCallContact?.let { contact ->
                    Log.i(TAG, "Microphone permission granted - retrying call to ${contact.name}")
                    startVoiceCallWithContact(contact)
                    pendingCallContact = null // Clear after use
                }
            } else {
                // Permission denied
                pendingCallContact = null
                ThemedToast.show(this, "Microphone permission required for voice calls")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Unregister broadcast receivers when activity is destroyed
        try {
            unregisterReceiver(pingReceiver)
            Log.d("MainActivity", "Unregistered NEW_PING and MESSAGE_RECEIVED broadcast receiver in onDestroy")
        } catch (e: IllegalArgumentException) {
            Log.w("MainActivity", "Ping receiver was not registered during onDestroy")
        }

        try {
            unregisterReceiver(friendRequestReceiver)
            Log.d("MainActivity", "Unregistered FRIEND_REQUEST_RECEIVED broadcast receiver in onDestroy")
        } catch (e: IllegalArgumentException) {
            Log.w("MainActivity", "Friend request receiver was not registered during onDestroy")
        }

        try {
            unregisterReceiver(groupReceiver)
            Log.d("MainActivity", "Unregistered group broadcast receivers in onDestroy")
        } catch (e: IllegalArgumentException) {
            Log.w("MainActivity", "Group receiver was not registered during onDestroy")
        }
    }

    private fun setupChatList() {
        val chatList = findViewById<RecyclerView>(R.id.chatList)

        Log.d("MainActivity", "Loading message threads...")

        // Load real message threads from database
        lifecycleScope.launch {
            try {
                // Use pre-warmed DB if available, otherwise open fresh
                val database = dbDeferred?.await() ?: run {
                    val km = KeyManager.getInstance(this@MainActivity)
                    val pass = km.getDatabasePassphrase()
                    SecureLegionDatabase.getInstance(this@MainActivity, pass)
                }

                // Batch all DB queries (4 queries total instead of 3N+1)
                val chatsWithTimestamp = withContext(Dispatchers.IO) {
                    val allContacts = database.contactDao().getAllContacts()
                    Log.d("MainActivity", "Found ${allContacts.size} contacts")

                    // Batch: last message per contact, unread counts, pending pings
                    val lastMessages = database.messageDao().getLastMessagePerContact()
                    val lastMessageMap = lastMessages.associateBy { it.contactId }

                    val unreadCounts = database.messageDao().getUnreadCountsGrouped()
                    val unreadMap = unreadCounts.associate { it.contactId to it.cnt }

                    // Only count pending pings in device-protection mode (manual download).
                    // In auto-download mode, pings are transient — the badge will update
                    // after DownloadMessageService finishes via MESSAGE_RECEIVED broadcast.
                    val securityPrefs = getSharedPreferences("security", MODE_PRIVATE)
                    val deviceProtectionEnabled = securityPrefs.getBoolean(
                        com.securelegion.SecurityModeActivity.PREF_DEVICE_PROTECTION_ENABLED, false
                    )
                    val pendingCounts = if (deviceProtectionEnabled) {
                        database.pingInboxDao().countPendingPerContact()
                    } else {
                        emptyList()
                    }
                    val pendingMap = pendingCounts.associate { it.contactId to it.cnt }

                    val chatsList = mutableListOf<Pair<Chat, Long>>()

                    for (contact in allContacts) {
                        val lastMessage = lastMessageMap[contact.id]
                        val pendingPingCount = pendingMap[contact.id] ?: 0
                        val hasPendingPing = pendingPingCount > 0

                        if (lastMessage != null || hasPendingPing) {
                            val unreadCount = unreadMap[contact.id] ?: 0

                            val messageStatus = if (lastMessage != null && lastMessage.isSentByMe) lastMessage.status else 0
                            val isSent = lastMessage?.isSentByMe ?: false
                            val pingDelivered = lastMessage?.pingDelivered ?: false
                            val messageDelivered = lastMessage?.messageDelivered ?: false

                            // Show type-appropriate preview text
                            val previewText = when {
                                lastMessage == null -> "New message"
                                lastMessage.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE -> "Image"
                                lastMessage.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_STICKER -> "Sticker"
                                lastMessage.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE -> "Voice message"
                                lastMessage.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_REQUEST -> "Payment request"
                                lastMessage.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_SENT -> "Payment sent"
                                lastMessage.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> "Payment accepted"
                                else -> lastMessage.encryptedContent
                            }

                            val chatDisplayName = contact.nickname ?: contact.displayName
                            val chat = Chat(
                                id = contact.id.toString(),
                                nickname = chatDisplayName,
                                lastMessage = previewText,
                                time = if (lastMessage != null) formatTimestamp(lastMessage.timestamp) else formatTimestamp(System.currentTimeMillis()),
                                unreadCount = unreadCount + pendingPingCount,
                                isOnline = false,
                                avatar = chatDisplayName.firstOrNull()?.toString()?.uppercase() ?: "?",
                                securityBadge = "",
                                lastMessageStatus = messageStatus,
                                lastMessageIsSent = isSent,
                                lastMessagePingDelivered = pingDelivered,
                                lastMessageMessageDelivered = messageDelivered,
                                isPinned = contact.isPinned,
                                profilePictureBase64 = contact.profilePictureBase64
                            )
                            val timestamp = if (lastMessage != null) lastMessage.timestamp else System.currentTimeMillis()
                            chatsList.add(Pair(chat, timestamp))
                        }
                    }

                    // Also add pinned groups to the messages tab
                    val pinnedGroups = database.groupDao().getPinnedGroups()
                    for (group in pinnedGroups) {
                        val preview = when {
                            group.isPendingInvite -> "Pending invite - tap to accept"
                            !group.lastMessagePreview.isNullOrEmpty() -> group.lastMessagePreview
                            else -> "${group.memberCount} members"
                        }
                        val groupChat = Chat(
                            id = group.groupId,
                            nickname = group.name,
                            lastMessage = preview,
                            time = formatTimestamp(group.lastActivityTimestamp),
                            isPinned = true,
                            profilePictureBase64 = group.groupIcon,
                            isGroup = true,
                            groupId = group.groupId
                        )
                        chatsList.add(Pair(groupChat, group.lastActivityTimestamp))
                    }

                    chatsList
                }

                // Sort: pinned first, then by most recent message timestamp
                val chats = chatsWithTimestamp
                    .sortedWith(compareByDescending<Pair<Chat, Long>> { it.first.isPinned }.thenByDescending { it.second })
                    .map { it.first }

                Log.d("MainActivity", "Loaded ${chats.size} chat threads")
                chats.forEach { chat ->
                    Log.d("MainActivity", "Chat: ${chat.nickname} - ${chat.lastMessage}")
                }

                // Update UI on main thread
                val messagesEmptyState = findViewById<View>(R.id.messagesEmptyState)
                if (chats.isEmpty()) {
                    chatList.visibility = View.GONE
                    messagesEmptyState.visibility = View.VISIBLE
                } else {
                    chatList.visibility = View.VISIBLE
                    messagesEmptyState.visibility = View.GONE
                }

                Log.d("MainActivity", "Setting up RecyclerView adapter with ${chats.size} items")
                // Set adapter
                chatList.layoutManager = LinearLayoutManager(this@MainActivity)
                val chatAdapter = ChatAdapter(
                    chats = chats,
                    onChatClick = { chat ->
                        if (chat.isGroup && chat.groupId != null) {
                            // Pinned group — open GroupChatActivity
                            val intent = Intent(this@MainActivity, GroupChatActivity::class.java)
                            intent.putExtra(GroupChatActivity.EXTRA_GROUP_ID, chat.groupId)
                            intent.putExtra(GroupChatActivity.EXTRA_GROUP_NAME, chat.nickname)
                            startActivity(intent)
                            overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left)
                        } else {
                            lifecycleScope.launch {
                                val contact = withContext(Dispatchers.IO) {
                                    database.contactDao().getContactById(chat.id.toLong())
                                }
                                if (contact != null) {
                                    val intent = android.content.Intent(this@MainActivity, ChatActivity::class.java)
                                    intent.putExtra(ChatActivity.EXTRA_CONTACT_ID, contact.id)
                                    intent.putExtra(ChatActivity.EXTRA_CONTACT_NAME, contact.nickname ?: contact.displayName)
                                    intent.putExtra(ChatActivity.EXTRA_CONTACT_ADDRESS, contact.solanaAddress)
                                    startActivityWithSlideAnimation(intent)
                                }
                            }
                        }
                    },
                    onDownloadClick = { chat ->
                        handleMessageDownload(chat)
                    },
                    onDeleteClick = { chat ->
                        deleteThread(chat)
                    },
                    onMuteClick = { chat ->
                        ThemedToast.show(this@MainActivity, "${chat.nickname} muted")
                    },
                    onPinClick = { chat ->
                        togglePin(chat)
                    }
                )
                chatList.adapter = chatAdapter

                // Scroll gate: block taps while dragging or settling after fling
                chatList.addOnScrollListener(object : RecyclerView.OnScrollListener() {
                    override fun onScrollStateChanged(rv: RecyclerView, newState: Int) {
                        chatAdapter.listIsScrolling = newState != RecyclerView.SCROLL_STATE_IDLE
                    }
                })

                Log.d("MainActivity", "RecyclerView adapter set successfully")
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load message threads", e)
                withContext(Dispatchers.Main) {
                    // Keep chat list visible even on error
                    chatList.visibility = View.VISIBLE
                    findViewById<View>(R.id.messagesEmptyState).visibility = View.GONE
                }
            }
        }
    }

    private fun togglePin(chat: Chat) {
        lifecycleScope.launch {
            try {
                val database = dbDeferred?.await() ?: run {
                    val km = KeyManager.getInstance(this@MainActivity)
                    val pass = km.getDatabasePassphrase()
                    SecureLegionDatabase.getInstance(this@MainActivity, pass)
                }

                if (chat.isGroup && chat.groupId != null) {
                    // Toggle pin on a group chat
                    val newPinned = !chat.isPinned
                    withContext(Dispatchers.IO) {
                        database.groupDao().setPinned(chat.groupId, newPinned)
                    }
                    ThemedToast.show(this@MainActivity, "${chat.nickname} ${if (newPinned) "pinned" else "unpinned"}")
                } else {
                    val contactId = chat.id.toLong()
                    val newPinned = !chat.isPinned
                    withContext(Dispatchers.IO) {
                        database.contactDao().setPinned(contactId, newPinned)
                    }
                    ThemedToast.show(this@MainActivity, "${chat.nickname} ${if (newPinned) "pinned" else "unpinned"}")
                }
                setupChatList()
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to toggle pin", e)
            }
        }
    }

    private fun deleteThread(chat: Chat) {
        Log.d("MainActivity", "Delete button clicked for thread: ${chat.nickname}")

        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                withContext(Dispatchers.IO) {
                    // Lightweight projection: only fetch 4 small columns needed for cleanup
                    // Uses getDeleteInfoForContact instead of SELECT * to avoid CursorWindow overflow
                    val deleteInfos = database.messageDao().getDeleteInfoForContact(chat.id.toLong())
                    val messageIds = deleteInfos.map { it.messageId }

                    // ==================== PHASE 1: Clear All ACK State & Gap Buffers ====================
                    // CRITICAL: Prevent message resurrection via ACK state machine
                    // Must clear BEFORE deleting messages from database
                    try {
                        val messageService = com.securelegion.services.MessageService(this@MainActivity)
                        messageService.clearAckStateForThread(messageIds)
                        Log.d("MainActivity", "Cleared ACK state for ${messageIds.size} messages")

                        // Also clear gap timeout buffer to free memory
                        com.securelegion.services.MessageService.clearGapTimeoutBuffer(chat.id.toLong())
                        Log.d("MainActivity", "Cleared gap timeout buffer")
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Failed to clear ACK state or gap buffer", e)
                    }

                    // ==================== PHASE 2: Securely Wipe Files ====================
                    // Securely wipe any voice/image files
                    deleteInfos.forEach { info ->
                        if (info.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE &&
                            info.voiceFilePath != null) {
                            try {
                                val voiceFile = java.io.File(info.voiceFilePath)
                                if (voiceFile.exists()) {
                                    com.securelegion.utils.SecureWipe.secureDeleteFile(voiceFile)
                                    Log.d("MainActivity", "Securely wiped voice file: ${voiceFile.name}")
                                }
                            } catch (e: Exception) {
                                Log.e("MainActivity", "Failed to securely wipe voice file", e)
                            }
                        }
                        if (info.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_IMAGE) {
                            try {
                                val encFile = java.io.File(filesDir, "image_messages/${info.messageId}.enc")
                                val imgFile = java.io.File(filesDir, "image_messages/${info.messageId}.img")
                                val imageFile = if (encFile.exists()) encFile else imgFile
                                if (imageFile.exists()) {
                                    com.securelegion.utils.SecureWipe.secureDeleteFile(imageFile)
                                    Log.d("MainActivity", "Securely wiped image file: ${imageFile.name}")
                                }
                            } catch (e: Exception) {
                                Log.e("MainActivity", "Failed to securely wipe image file", e)
                            }
                        }
                    }

                    // ==================== PHASE 3: Clear Received ID Tracking ====================
                    // Clean up deduplication entries for all message types (Ping, Pong, Message)
                    try {
                        deleteInfos.forEach { info ->
                            if (info.pingId != null) {
                                // Delete tracking entries for this message's phases
                                database.receivedIdDao().deleteById(info.pingId) // Ping ID
                                database.receivedIdDao().deleteById("pong_${info.pingId}") // Pong ID
                                database.receivedIdDao().deleteById(info.messageId) // Message ID
                            }
                        }
                        Log.d("MainActivity", "Cleared ReceivedId entries for ${messageIds.size} messages")
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Failed to clear ReceivedId entries", e)
                    }

                    // ==================== PHASE 4: Delete Messages from Database ====================
                    // Delete all messages from database
                    database.messageDao().deleteMessagesForContact(chat.id.toLong())
                    Log.d("MainActivity", "Deleted ${deleteInfos.size} messages from database")

                    // ==================== PHASE 5: VACUUM Database ====================
                    // VACUUM database to compact and remove deleted records
                    try {
                        database.openHelper.writableDatabase.execSQL("VACUUM")
                        Log.d("MainActivity", "Database vacuumed after thread deletion")
                    } catch (e: Exception) {
                        Log.e("MainActivity", "Failed to vacuum database", e)
                    }
                }

                // Delete all ping_inbox entries for this contact
                database.pingInboxDao().deleteByContact(chat.id.toLong())
                Log.i("MainActivity", "Securely deleted all messages (DOD 3-pass) and pending Pings for contact: ${chat.nickname}")

                // Reload the chat list
                setupChatList()
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to delete thread", e)
                ThemedToast.show(
                    this@MainActivity,
                    "Failed to delete thread"
                )
                // Reload to restore UI
                setupChatList()
            }
        }
    }

    private fun formatTimestamp(timestamp: Long): String {
        val now = System.currentTimeMillis()
        val diff = now - timestamp

        return when {
            diff < 60_000 -> "Just now" // Less than 1 minute
            diff < 3600_000 -> "${diff / 60_000}m" // Less than 1 hour
            diff < 86400_000 -> "${diff / 3600_000}h" // Less than 1 day
            diff < 604800_000 -> "${diff / 86400_000}d" // Less than 1 week
            else -> "${diff / 604800_000}w" // Weeks
        }
    }

    private fun setupContactsList() {
        val contactsView = findViewById<View>(R.id.contactsView)
        val contactsList = contactsView.findViewById<RecyclerView>(R.id.contactsList)

        // Load contacts from encrypted database
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                // Load all contacts from database
                val dbContacts = withContext(Dispatchers.IO) {
                    database.contactDao().getAllContacts()
                }

                Log.i("MainActivity", "Loaded ${dbContacts.size} contacts from database")

                // Convert database entities to UI models
                val contacts = dbContacts.map { dbContact ->
                    Contact(
                        id = dbContact.id.toString(),
                        name = dbContact.displayName,
                        nickname = dbContact.nickname,
                        address = dbContact.solanaAddress,
                        friendshipStatus = dbContact.friendshipStatus,
                        profilePhotoBase64 = dbContact.profilePictureBase64
                    )
                }

                // Update UI on main thread
                withContext(Dispatchers.Main) {
                    val emptyContactsState = contactsView.findViewById<View>(R.id.emptyContactsState)

                    if (contacts.isEmpty()) {
                        contactsList.visibility = View.GONE
                        emptyContactsState.visibility = View.VISIBLE
                    } else {
                        contactsList.visibility = View.VISIBLE
                        emptyContactsState.visibility = View.GONE

                        contactsList.layoutManager = LinearLayoutManager(this@MainActivity)
                        contactsList.adapter = ContactAdapter(contacts) { contact ->
                            if (isCallMode) {
                                startVoiceCallWithContact(contact)
                            } else {
                                val intent = android.content.Intent(this@MainActivity, ContactOptionsActivity::class.java)
                                intent.putExtra("CONTACT_ID", contact.id.toLong())
                                intent.putExtra("CONTACT_NAME", contact.name)
                                intent.putExtra("CONTACT_ADDRESS", contact.address)
                                startActivityWithSlideAnimation(intent)
                            }
                        }
                    }
                    Log.i("MainActivity", "Displaying ${contacts.size} contacts in UI")
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load contacts from database", e)
                // Keep contacts list visible even on error
                withContext(Dispatchers.Main) {
                    contactsList.visibility = View.VISIBLE
                }
            }
        }
    }

    private fun setupGroupsList() {
        lifecycleScope.launch {
            try {
                val groupsWithCounts = withContext(Dispatchers.IO) {
                    val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@MainActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                    val groups = database.groupDao().getAllGroups()

                    groups.map { group ->
                        val preview = when {
                            group.isPendingInvite -> "Pending invite - tap to accept"
                            !group.lastMessagePreview.isNullOrEmpty() -> group.lastMessagePreview
                            else -> null
                        }
                        com.securelegion.adapters.GroupAdapter.GroupWithMemberCount(
                            group = group,
                            memberCount = group.memberCount,
                            lastMessagePreview = preview
                        )
                    }
                }

                withContext(Dispatchers.Main) {
                    val invitesHeader = findViewById<View>(R.id.invitesHeader)
                    val invitesRecyclerView = findViewById<androidx.recyclerview.widget.RecyclerView>(R.id.invitesRecyclerView)
                    val groupsRecyclerView = findViewById<androidx.recyclerview.widget.RecyclerView>(R.id.groupsRecyclerView)
                    val emptyState = findViewById<View>(R.id.emptyState)

                    // Hide invites — pending invites will arrive via CRDT sync (TODO)
                    invitesHeader.visibility = View.GONE
                    invitesRecyclerView.visibility = View.GONE

                    if (groupsWithCounts.isNotEmpty()) {
                        groupsRecyclerView.visibility = View.VISIBLE
                        emptyState.visibility = View.GONE

                        val groupAdapter = com.securelegion.adapters.GroupAdapter(
                            groups = groupsWithCounts,
                            onGroupClick = { group ->
                                val intent = Intent(this@MainActivity, GroupChatActivity::class.java)
                                intent.putExtra(GroupChatActivity.EXTRA_GROUP_ID, group.groupId)
                                intent.putExtra(GroupChatActivity.EXTRA_GROUP_NAME, group.name)
                                startActivity(intent)
                                overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left)
                            },
                            onMuteClick = { group ->
                                toggleGroupMute(group)
                            },
                            onLeaveClick = { group ->
                                confirmLeaveGroup(group)
                            },
                            onPinClick = { group ->
                                toggleGroupPin(group)
                            }
                        )

                        groupsRecyclerView.layoutManager = LinearLayoutManager(this@MainActivity)
                        groupsRecyclerView.adapter = groupAdapter

                        Log.d("MainActivity", "Loaded ${groupsWithCounts.size} groups")
                    } else {
                        groupsRecyclerView.visibility = View.GONE
                        emptyState.visibility = View.VISIBLE
                    }

                    // Update groups tab badge with count of pending invite groups
                    val pendingCount = groupsWithCounts.count { it.group.isPendingInvite }
                    val groupsBadge = findViewById<TextView>(R.id.groupsBadge)
                    if (pendingCount > 0) {
                        groupsBadge.text = pendingCount.toString()
                        groupsBadge.visibility = View.VISIBLE
                    } else {
                        groupsBadge.visibility = View.GONE
                    }
                }

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load groups", e)
            }
        }
    }

    /**
     * Lightweight badge-only update — queries pending invite count without refreshing the full groups list.
     * Safe to call from any tab.
     */
    private fun updateGroupsBadge() {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)
                val pendingCount = withContext(Dispatchers.IO) {
                    database.groupDao().countPendingInvites()
                }
                val groupsBadge = findViewById<TextView>(R.id.groupsBadge)
                if (pendingCount > 0) {
                    groupsBadge.text = pendingCount.toString()
                    groupsBadge.visibility = View.VISIBLE
                } else {
                    groupsBadge.visibility = View.GONE
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to update groups badge", e)
            }
        }
    }

    private fun toggleGroupMute(group: com.securelegion.database.entities.Group) {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                val newMuted = !group.isMuted
                withContext(Dispatchers.IO) {
                    database.groupDao().setMuted(group.groupId, newMuted)
                }
                ThemedToast.show(this@MainActivity, "${group.name} ${if (newMuted) "muted" else "unmuted"}")
                setupGroupsList()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to toggle group mute", e)
            }
        }
    }

    private fun toggleGroupPin(group: com.securelegion.database.entities.Group) {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                val newPinned = !group.isPinned
                withContext(Dispatchers.IO) {
                    database.groupDao().setPinned(group.groupId, newPinned)
                }
                ThemedToast.show(this@MainActivity, "${group.name} ${if (newPinned) "pinned" else "unpinned"}")
                setupGroupsList()
                // Also refresh messages tab since pinned groups show there
                if (currentTab == "messages") {
                    setupChatList()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to toggle group pin", e)
            }
        }
    }

    private fun confirmLeaveGroup(group: com.securelegion.database.entities.Group) {
        val dialog = GlassDialog.builder(this)
            .setTitle("Leave Group")
            .setMessage("Are you sure you want to leave \"${group.name}\"? This will remove you from the group and delete it from your device.")
            .setPositiveButton("Leave") { _, _ ->
                leaveGroup(group)
            }
            .setNegativeButton("Cancel", null)
            .create()
        GlassDialog.show(dialog)
    }

    private fun leaveGroup(group: com.securelegion.database.entities.Group) {
        lifecycleScope.launch {
            try {
                val mgr = com.securelegion.services.CrdtGroupManager.getInstance(this@MainActivity)
                val keyManager = KeyManager.getInstance(this@MainActivity)

                withContext(Dispatchers.IO) {
                    // Try to broadcast MemberRemove, but don't block local delete on failure
                    try {
                        mgr.loadGroup(group.groupId)
                        val localPubkeyHex = keyManager.getSigningPublicKey()
                            .joinToString("") { "%02x".format(it) }
                        val opBytes = mgr.removeMember(group.groupId, localPubkeyHex, "Leave")
                        mgr.broadcastOpToGroup(group.groupId, opBytes)
                    } catch (e: Exception) {
                        Log.w(TAG, "Could not broadcast leave op (deleting locally anyway): ${e.message}")
                    }

                    // Always delete group locally
                    mgr.deleteGroup(group.groupId)
                }

                ThemedToast.show(this@MainActivity, "Left group: ${group.name}")
                setupGroupsList()
                if (currentTab == "messages") {
                    setupChatList()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to leave group", e)
                ThemedToast.show(this@MainActivity, "Failed to leave group")
            }
        }
    }

    private fun setupClickListeners() {
        // Compose New Message / Add Friend Button
        findViewById<View>(R.id.newMessageBtn).setOnClickListener {
            when (currentTab) {
                "contacts" -> showAddContactBottomSheet()
                "groups" -> {
                    val intent = android.content.Intent(this, CreateGroupActivity::class.java)
                    startActivityWithSlideAnimation(intent)
                }
                else -> {
                    val intent = android.content.Intent(this, ComposeActivity::class.java)
                    startActivityWithSlideAnimation(intent)
                }
            }
        }

        // Bottom Navigation
        findViewById<View>(R.id.navMessages)?.setOnClickListener {
            Log.d("MainActivity", "Chats nav clicked")
            showAllChatsTab()
        }

        findViewById<View>(R.id.navContacts)?.setOnClickListener {
            Log.d("MainActivity", "Contacts nav clicked")
            isCallMode = false
            showContactsTab()
        }

        findViewById<View>(R.id.navProfile)?.setOnClickListener {
            Log.d("MainActivity", "Profile nav clicked")
            val intent = android.content.Intent(this, WalletIdentityActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }

        // Tabs
        findViewById<View>(R.id.tabMessages).setOnClickListener {
            if (currentTab == "contacts") {
                showContactsSubTab()
            } else {
                showAllChatsTab()
            }
        }

        findViewById<View>(R.id.tabGroups).setOnClickListener {
            if (currentTab == "contacts") {
                showRequestsSubTab()
            } else {
                showGroupsTab()
            }
        }
    }


    private fun setupWalletSpinner() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet - it's hidden (used only for encryption keys)
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    if (wallets.isNotEmpty()) {
                        // Set initial wallet (most recently used)
                        val initialWallet = wallets.firstOrNull()
                        if (initialWallet != null && currentWallet == null) {
                            currentWallet = initialWallet
                            Log.d("MainActivity", "Initial wallet set: ${initialWallet.name}")
                        }
                    }
                }

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load wallets", e)
            }
        }
    }

    private fun switchToWallet(wallet: Wallet) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("MainActivity", "Switching to wallet: ${wallet.walletId}")

                // Update current wallet
                currentWallet = wallet

                // Update last used timestamp
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)
                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())

                // Update UI on main thread
                withContext(Dispatchers.Main) {
                    Log.i("MainActivity", "Switched to wallet: ${wallet.walletId}")
                    // Wallet balance is now loaded in WalletActivity
                    updateWalletIdentity(wallet)
                }

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to switch wallet", e)
            }
        }
    }

    private fun updateWalletIdentity(wallet: Wallet) {
        // Wallet is now in separate activity - no UI updates needed here
        Log.i("MainActivity", "Wallet identity updated for: ${wallet.walletId}")
    }

    private fun showAllChatsTab() {
        Log.d("MainActivity", "Switching to messages tab")
        // Restore pill labels for chats mode
        findViewById<TextView>(R.id.tabMessages).text = "Messages"
        findViewById<TextView>(R.id.tabGroups).text = "Groups"
        currentTab = "messages"
        findViewById<View>(R.id.chatListContainer).visibility = View.VISIBLE
        findViewById<View>(R.id.groupsView).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.GONE

        // Show header and tabs
        findViewById<View>(R.id.tabsContainer).visibility = View.VISIBLE
        findViewById<TextView>(R.id.headerTitle).text = "Chats"

        // Restore compose icon and hide compose badge
        setNewMessageIcon(R.drawable.ic_compose)
        BadgeUtils.updateComposeBadge(findViewById(android.R.id.content), 0)

        // Update search bar hint
        findViewById<android.widget.EditText>(R.id.searchBar).hint = "Search"

        // Reload message threads when switching back to messages tab
        setupChatList()

        // Clear groups badge (friend request badge may be stale from contacts tab)
        findViewById<android.widget.TextView>(R.id.groupsBadge).visibility = View.GONE

        // Update tab pill styling - Messages active, Groups inactive
        findViewById<android.widget.TextView>(R.id.tabMessages).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_white))
            setBackgroundResource(R.drawable.tab_pill_active_bg)
        }

        findViewById<android.widget.TextView>(R.id.tabGroups).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_gray))
            setBackgroundResource(R.drawable.tab_pill_bg)
        }
    }

    private fun showGroupsTab() {
        Log.d("MainActivity", "Switching to groups tab")
        // Restore pill labels for chats mode
        findViewById<TextView>(R.id.tabMessages).text = "Messages"
        findViewById<TextView>(R.id.tabGroups).text = "Groups"
        currentTab = "groups"
        findViewById<View>(R.id.chatListContainer).visibility = View.GONE
        findViewById<View>(R.id.groupsView).visibility = View.VISIBLE
        findViewById<View>(R.id.contactsView).visibility = View.GONE

        // Show header and tabs
        findViewById<View>(R.id.tabsContainer).visibility = View.VISIBLE
        findViewById<TextView>(R.id.headerTitle).text = "Chats"

        // Restore compose icon and hide compose badge
        setNewMessageIcon(R.drawable.ic_compose)
        BadgeUtils.updateComposeBadge(findViewById(android.R.id.content), 0)

        // Update search bar hint
        findViewById<android.widget.EditText>(R.id.searchBar).hint = "Search"

        // Load groups and invites
        setupGroupsList()

        // Update tab pill styling - Groups active, Messages inactive
        findViewById<android.widget.TextView>(R.id.tabMessages).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_gray))
            setBackgroundResource(R.drawable.tab_pill_bg)
        }

        findViewById<android.widget.TextView>(R.id.tabGroups).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_white))
            setBackgroundResource(R.drawable.tab_pill_active_bg)
        }
    }

    private fun showContactsTab() {
        Log.d("MainActivity", "Switching to contacts tab")
        currentTab = "contacts"
        findViewById<View>(R.id.chatListContainer).visibility = View.GONE
        findViewById<View>(R.id.groupsView).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.VISIBLE

        // Show tabs and set to Contacts/Requests pills
        findViewById<View>(R.id.tabsContainer).visibility = View.VISIBLE
        findViewById<TextView>(R.id.headerTitle).text = "Contacts"

        // Relabel pills for contacts mode
        findViewById<TextView>(R.id.tabMessages).text = "Contacts"
        findViewById<TextView>(R.id.tabGroups).text = "Requests"

        // Update request badge count on Requests pill
        updateRequestsPillBadge()

        // Swap compose icon to + (add friend)
        setNewMessageIcon(R.drawable.ic_add_friend)
        BadgeUtils.updateComposeBadge(findViewById(android.R.id.content), 0)

        // Update search bar hint
        findViewById<android.widget.EditText>(R.id.searchBar).hint = "Search contacts..."

        // Show whichever sub-tab was last active
        if (contactsSubTab == "requests") {
            showRequestsSubTab()
        } else {
            showContactsSubTab()
        }
    }

    private fun showContactsSubTab() {
        contactsSubTab = "contacts"
        val contactsView = findViewById<View>(R.id.contactsView)

        contactsView.findViewById<View>(R.id.contactsList).visibility = View.VISIBLE
        contactsView.findViewById<View>(R.id.requestsList).visibility = View.GONE
        contactsView.findViewById<View>(R.id.emptyRequestsState).visibility = View.GONE

        // Update pill styling — Contacts active
        findViewById<android.widget.TextView>(R.id.tabMessages).apply {
            setTextColor(androidx.core.content.ContextCompat.getColor(context, R.color.text_white))
            setBackgroundResource(R.drawable.tab_pill_active_bg)
        }
        findViewById<android.widget.TextView>(R.id.tabGroups).apply {
            setTextColor(androidx.core.content.ContextCompat.getColor(context, R.color.text_gray))
            setBackgroundResource(R.drawable.tab_pill_bg)
        }

        // Update search bar hint
        findViewById<android.widget.EditText>(R.id.searchBar).hint = "Search contacts..."

        setupContactsList()
    }

    private fun showRequestsSubTab() {
        contactsSubTab = "requests"
        val contactsView = findViewById<View>(R.id.contactsView)

        contactsView.findViewById<View>(R.id.contactsList).visibility = View.GONE
        contactsView.findViewById<View>(R.id.emptyContactsState).visibility = View.GONE
        contactsView.findViewById<View>(R.id.requestsList).visibility = View.VISIBLE

        // Update pill styling — Requests active
        findViewById<android.widget.TextView>(R.id.tabMessages).apply {
            setTextColor(androidx.core.content.ContextCompat.getColor(context, R.color.text_gray))
            setBackgroundResource(R.drawable.tab_pill_bg)
        }
        findViewById<android.widget.TextView>(R.id.tabGroups).apply {
            setTextColor(androidx.core.content.ContextCompat.getColor(context, R.color.text_white))
            setBackgroundResource(R.drawable.tab_pill_active_bg)
        }

        // Update search bar hint
        findViewById<android.widget.EditText>(R.id.searchBar).hint = "Search requests..."

        setupRequestsList()
    }

    private fun setupRequestsList() {
        val contactsView = findViewById<View>(R.id.contactsView)
        val requestsList = contactsView.findViewById<androidx.recyclerview.widget.RecyclerView>(R.id.requestsList)
        val emptyRequestsState = contactsView.findViewById<View>(R.id.emptyRequestsState)

        val prefs = getSharedPreferences("friend_requests", android.content.Context.MODE_PRIVATE)
        val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

        val requests = mutableListOf<com.securelegion.models.PendingFriendRequest>()
        for (json in pendingRequestsSet) {
            try {
                requests.add(com.securelegion.models.PendingFriendRequest.fromJson(json))
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to parse friend request", e)
            }
        }

        if (requests.isEmpty()) {
            requestsList.visibility = View.GONE
            emptyRequestsState.visibility = View.VISIBLE
            return
        }

        requestsList.visibility = View.VISIBLE
        emptyRequestsState.visibility = View.GONE

        val adapter = com.securelegion.adapters.FriendRequestAdapter(
            onAccept = { request -> handleAcceptRequest(request) },
            onDecline = { request -> handleDeclineRequest(request) },
            onCancelSent = { request -> handleCancelSentRequest(request) }
        )
        requestsList.layoutManager = androidx.recyclerview.widget.LinearLayoutManager(this)
        requestsList.adapter = adapter
        adapter.updateRequests(requests)

        // After adapter filtering, check if there are actually visible items
        if (adapter.isEmpty()) {
            requestsList.visibility = View.GONE
            emptyRequestsState.visibility = View.VISIBLE
        }
    }

    private fun handleAcceptRequest(request: com.securelegion.models.PendingFriendRequest) {
        if (request.contactCardJson == null) {
            com.securelegion.utils.ThemedToast.show(this, "No Phase 1 data — cannot accept")
            return
        }

        lifecycleScope.launch {
            try {
                val phase1Obj = org.json.JSONObject(request.contactCardJson)
                val senderUsername = phase1Obj.getString("username")
                val senderFriendRequestOnion = phase1Obj.getString("friend_request_onion")
                val senderX25519PublicKeyBase64 = phase1Obj.getString("x25519_public_key")
                val senderX25519PublicKey = android.util.Base64.decode(senderX25519PublicKeyBase64, android.util.Base64.NO_WRAP)

                val senderKyberPublicKey = if (phase1Obj.has("kyber_public_key")) {
                    android.util.Base64.decode(phase1Obj.getString("kyber_public_key"), android.util.Base64.NO_WRAP)
                } else null

                // Verify Ed25519 signature if present
                if (phase1Obj.has("signature") && phase1Obj.has("ed25519_public_key")) {
                    val signature = android.util.Base64.decode(phase1Obj.getString("signature"), android.util.Base64.NO_WRAP)
                    val senderEd25519PubKey = android.util.Base64.decode(phase1Obj.getString("ed25519_public_key"), android.util.Base64.NO_WRAP)
                    val unsignedJson = org.json.JSONObject().apply {
                        put("username", senderUsername)
                        put("friend_request_onion", senderFriendRequestOnion)
                        put("x25519_public_key", senderX25519PublicKeyBase64)
                        put("kyber_public_key", phase1Obj.getString("kyber_public_key"))
                        put("phase", 1)
                    }.toString()
                    if (!com.securelegion.crypto.RustBridge.verifySignature(
                            unsignedJson.toByteArray(Charsets.UTF_8), signature, senderEd25519PubKey)) {
                        com.securelegion.utils.ThemedToast.show(this@MainActivity, "Invalid signature — rejecting")
                        return@launch
                    }
                }

                // Build own contact card
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val torManager = com.securelegion.crypto.TorManager.getInstance(applicationContext)
                val ownCard = com.securelegion.models.ContactCard(
                    displayName = keyManager.getUsername() ?: throw Exception("Username not set"),
                    solanaPublicKey = keyManager.getSolanaPublicKey(),
                    x25519PublicKey = keyManager.getEncryptionPublicKey(),
                    kyberPublicKey = keyManager.getKyberPublicKey(),
                    solanaAddress = keyManager.getSolanaAddress(),
                    friendRequestOnion = keyManager.getFriendRequestOnion() ?: throw Exception("FR onion not set"),
                    messagingOnion = keyManager.getMessagingOnion() ?: throw Exception("Messaging onion not set"),
                    voiceOnion = torManager.getVoiceOnionAddress().takeUnless { it.isNullOrBlank() }
                        ?: keyManager.getVoiceOnion().takeUnless { it.isNullOrBlank() } ?: "",
                    contactPin = keyManager.getContactPin() ?: throw Exception("Contact PIN not set"),
                    ipfsCid = keyManager.deriveContactListCID(),
                    timestamp = System.currentTimeMillis() / 1000
                )

                // Hybrid Kyber encapsulation
                var hybridSharedSecret: ByteArray? = null
                val kyberCiphertextBase64 = withContext(Dispatchers.IO) {
                    if (senderKyberPublicKey != null && senderKyberPublicKey.any { it != 0.toByte() }) {
                        val encapResult = com.securelegion.crypto.RustBridge.hybridEncapsulate(senderX25519PublicKey, senderKyberPublicKey)
                        hybridSharedSecret = encapResult.copyOfRange(0, 64)
                        android.util.Base64.encodeToString(encapResult.copyOfRange(64, encapResult.size), android.util.Base64.NO_WRAP)
                    } else null
                }

                // Build + sign Phase 2 payload
                val phase2UnsignedJson = org.json.JSONObject().apply {
                    put("contact_card", org.json.JSONObject(ownCard.toJson()))
                    if (kyberCiphertextBase64 != null) put("kyber_ciphertext", kyberCiphertextBase64)
                    put("phase", 2)
                }.toString()

                val phase2Signature = com.securelegion.crypto.RustBridge.signData(
                    phase2UnsignedJson.toByteArray(Charsets.UTF_8), keyManager.getSigningKeyBytes()
                )
                val phase2Payload = org.json.JSONObject(phase2UnsignedJson).apply {
                    put("ed25519_public_key", android.util.Base64.encodeToString(keyManager.getSigningPublicKey(), android.util.Base64.NO_WRAP))
                    put("signature", android.util.Base64.encodeToString(phase2Signature, android.util.Base64.NO_WRAP))
                }.toString()

                // Encrypt with sender's X25519 key
                val encryptedPhase2 = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.encryptMessage(phase2Payload, senderX25519PublicKey)
                }

                // Remove old incoming request, save new outgoing "sending" request
                removePendingRequest(request)
                val requestId = java.util.UUID.randomUUID().toString()
                val partialContactJson = org.json.JSONObject().apply {
                    put("username", senderUsername)
                    put("friend_request_onion", senderFriendRequestOnion)
                    put("x25519_public_key", senderX25519PublicKeyBase64)
                    if (senderKyberPublicKey != null)
                        put("kyber_public_key", android.util.Base64.encodeToString(senderKyberPublicKey, android.util.Base64.NO_WRAP))
                    if (hybridSharedSecret != null)
                        put("hybrid_shared_secret", android.util.Base64.encodeToString(hybridSharedSecret, android.util.Base64.NO_WRAP))
                }.toString()
                savePendingFriendRequest(com.securelegion.models.PendingFriendRequest(
                    displayName = senderUsername,
                    ipfsCid = senderFriendRequestOnion,
                    direction = com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING,
                    status = com.securelegion.models.PendingFriendRequest.STATUS_SENDING,
                    timestamp = System.currentTimeMillis(),
                    contactCardJson = partialContactJson,
                    id = requestId
                ))

                com.securelegion.utils.ThemedToast.show(this@MainActivity, "Accepting request from $senderUsername...")
                setupRequestsList()
                updateRequestsPillBadge()

                // Fire Phase 2 send via TorService background
                com.securelegion.services.TorService.acceptFriendRequestInBackground(
                    requestId, senderFriendRequestOnion, encryptedPhase2, applicationContext
                )

            } catch (e: Exception) {
                Log.e("MainActivity", "Phase 2 accept failed", e)
                com.securelegion.utils.ThemedToast.show(this@MainActivity, "Failed to accept: ${e.message}")
            }
        }
    }

    private fun handleDeclineRequest(request: com.securelegion.models.PendingFriendRequest) {
        removePendingRequest(request)
        com.securelegion.utils.ThemedToast.show(this, "Request declined")
        setupRequestsList()
        updateRequestsPillBadge()
    }

    private fun handleCancelSentRequest(request: com.securelegion.models.PendingFriendRequest) {
        removePendingRequest(request)
        com.securelegion.utils.ThemedToast.show(this, "Request cancelled")
        setupRequestsList()
        updateRequestsPillBadge()
    }

    private fun savePendingFriendRequest(request: com.securelegion.models.PendingFriendRequest) {
        val prefs = getSharedPreferences("friend_requests", android.content.Context.MODE_PRIVATE)
        val requestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        requestsSet.add(request.toJson())
        prefs.edit().putStringSet("pending_requests_v2", requestsSet).apply()
    }

    private fun removePendingRequest(request: com.securelegion.models.PendingFriendRequest) {
        val prefs = getSharedPreferences("friend_requests", android.content.Context.MODE_PRIVATE)
        val requestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        requestsSet.removeAll { json ->
            try {
                com.securelegion.models.PendingFriendRequest.fromJson(json).id == request.id
            } catch (e: Exception) { false }
        }
        prefs.edit().putStringSet("pending_requests_v2", requestsSet).apply()
    }

    private fun updateRequestsPillBadge() {
        val count = BadgeUtils.getPendingFriendRequestCount(this)
        val badge = findViewById<android.widget.TextView>(R.id.groupsBadge)
        if (currentTab == "contacts" && count > 0) {
            badge.text = count.toString()
            badge.visibility = View.VISIBLE
        } else if (currentTab == "contacts") {
            badge.visibility = View.GONE
        }
    }

    private fun showAddContactBottomSheet() {
        val bottomSheet = com.securelegion.utils.GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_add_contact, null)
        bottomSheet.setContentView(view)

        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        // Option 1: Scan QR Code — open camera scanner directly
        view.findViewById<View>(R.id.optionScanQr).setOnClickListener {
            bottomSheet.dismiss()
            val intent = Intent(this, AddFriendActivity::class.java)
            intent.putExtra("AUTO_SCAN", true)
            startActivityWithSlideAnimation(intent)
        }

        // Option 2: Add QR from Gallery — open gallery picker directly
        view.findViewById<View>(R.id.optionGalleryQr).setOnClickListener {
            bottomSheet.dismiss()
            val intent = Intent(this, AddFriendActivity::class.java)
            intent.putExtra("AUTO_GALLERY", true)
            startActivityWithSlideAnimation(intent)
        }

        // Option 3: Share Invite — open share bottom sheet (QR or manual)
        view.findViewById<View>(R.id.optionShareInvite).setOnClickListener {
            bottomSheet.dismiss()
            showShareInviteBottomSheet()
        }

        // Option 4: Add Manually — open manual .onion + PIN entry
        view.findViewById<View>(R.id.optionAddManually).setOnClickListener {
            bottomSheet.dismiss()
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }

        bottomSheet.show()
    }

    private fun shareInviteQrCode() {
        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.Default) {
                    val keyManager = KeyManager.getInstance(this@MainActivity)
                    val friendRequestOnion = keyManager.getFriendRequestOnion() ?: return@withContext null
                    val pin = keyManager.getContactPin() ?: ""
                    val username = keyManager.getUsername() ?: ""

                    val securityPrefs = getSharedPreferences("security_prefs", Context.MODE_PRIVATE)
                    val rotationIntervalMs = securityPrefs.getLong("pin_rotation_interval_ms", 24 * 60 * 60 * 1000L)
                    val rotationTimestamp = keyManager.getPinRotationTimestamp()
                    val expiryMs = if (rotationIntervalMs > 0 && rotationTimestamp > 0) {
                        rotationTimestamp + rotationIntervalMs
                    } else 0L

                    val expiryText = if (expiryMs > 0) {
                        val remainingMs = expiryMs - System.currentTimeMillis()
                        if (remainingMs > 0) {
                            val hours = remainingMs / (60 * 60 * 1000)
                            val minutes = (remainingMs % (60 * 60 * 1000)) / (60 * 1000)
                            "Expires ${hours}h ${minutes}m"
                        } else "Rotation pending"
                    } else null

                    val decryptCount = keyManager.getPinDecryptCount()
                    val maxUses = securityPrefs.getInt("pin_max_uses", 5)
                    val mintText = if (maxUses > 0) "$decryptCount/$maxUses" else null

                    val qrContent = buildString {
                        if (username.isNotEmpty()) append("$username@")
                        append(friendRequestOnion)
                        if (pin.isNotEmpty()) append("@$pin")
                        if (expiryMs > 0) append("@exp$expiryMs")
                    }

                    val bitmap = com.securelegion.utils.BrandedQrGenerator.generate(
                        this@MainActivity,
                        com.securelegion.utils.BrandedQrGenerator.QrOptions(
                            content = qrContent,
                            size = 512,
                            showLogo = true,
                            mintText = mintText,
                            expiryText = expiryText,
                            showWebsite = true
                        )
                    )
                    Pair(bitmap, friendRequestOnion)
                }

                if (result?.first == null) {
                    ThemedToast.show(this@MainActivity, "Failed to generate QR code")
                    return@launch
                }

                val bitmap = result.first!!
                val friendRequestOnion = result.second

                // Save bitmap to cache and share
                val cachePath = java.io.File(cacheDir, "images")
                cachePath.mkdirs()
                val file = java.io.File(cachePath, "invite_qr.png")
                java.io.FileOutputStream(file).use { stream ->
                    bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, stream)
                }

                val contentUri = androidx.core.content.FileProvider.getUriForFile(
                    this@MainActivity, "${packageName}.fileprovider", file
                )

                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "image/png"
                    putExtra(Intent.EXTRA_STREAM, contentUri)
                    putExtra(Intent.EXTRA_TEXT, "Add me on Secure!\nFriend Request Address: $friendRequestOnion")
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                }
                startActivity(Intent.createChooser(shareIntent, "Share Invite QR Code"))
            } catch (e: Exception) {
                Log.e(TAG, "Failed to share invite QR", e)
                ThemedToast.show(this@MainActivity, "Failed to share QR code")
            }
        }
    }

    private fun showShareInviteBottomSheet() {
        val bottomSheet = com.securelegion.utils.GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_share_invite, null)
        bottomSheet.setContentView(view)

        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        view.findViewById<View>(R.id.optionShareQrCode).setOnClickListener {
            bottomSheet.dismiss()
            shareInviteQrCode()
        }

        view.findViewById<View>(R.id.optionShareManually).setOnClickListener {
            bottomSheet.dismiss()
            shareManualInfo()
        }

        bottomSheet.show()
    }

    private fun shareManualInfo() {
        lifecycleScope.launch {
            try {
                val text = withContext(Dispatchers.Default) {
                    val keyManager = KeyManager.getInstance(this@MainActivity)
                    val friendRequestOnion = keyManager.getFriendRequestOnion() ?: return@withContext null
                    val pin = keyManager.getContactPin() ?: ""
                    val username = keyManager.getUsername() ?: ""

                    val securityPrefs = getSharedPreferences("security_prefs", Context.MODE_PRIVATE)
                    val rotationIntervalMs = securityPrefs.getLong("pin_rotation_interval_ms", 24 * 60 * 60 * 1000L)
                    val rotationTimestamp = keyManager.getPinRotationTimestamp()
                    val expiryMs = if (rotationIntervalMs > 0 && rotationTimestamp > 0) {
                        rotationTimestamp + rotationIntervalMs
                    } else 0L

                    buildString {
                        append("Add me on Secure!")
                        if (username.isNotEmpty()) append("\nUsername: $username")
                        append("\nAddress: $friendRequestOnion")
                        if (pin.isNotEmpty()) append("\nPIN: $pin")
                        if (expiryMs > 0) {
                            val remainingMs = expiryMs - System.currentTimeMillis()
                            if (remainingMs > 0) {
                                val hours = remainingMs / (60 * 60 * 1000)
                                val minutes = (remainingMs % (60 * 60 * 1000)) / (60 * 1000)
                                append("\nExpires in: ${hours}h ${minutes}m")
                            }
                        }
                    }
                }

                if (text == null) {
                    ThemedToast.show(this@MainActivity, "Failed to load identity info")
                    return@launch
                }

                val shareIntent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, text)
                }
                startActivity(Intent.createChooser(shareIntent, "Share Invite"))
            } catch (e: Exception) {
                Log.e(TAG, "Failed to share manual info", e)
                ThemedToast.show(this@MainActivity, "Failed to share")
            }
        }
    }

    private fun setNewMessageIcon(drawableRes: Int) {
        val btn = findViewById<android.view.ViewGroup>(R.id.newMessageBtn)
        val icon = btn.getChildAt(0) as? android.widget.ImageView
        icon?.setImageResource(drawableRes)
    }

    /**
     * Handle manual message download when user clicks download button
     */
    private fun handleMessageDownload(chat: Chat) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val contactId = chat.id.toLong()
                Log.i("MainActivity", "User clicked download for contact $contactId (${chat.nickname})")

                // Query ping_inbox DB for pending pings
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                val pendingPings = database.pingInboxDao().getPendingByContact(contactId)

                if (pendingPings.isEmpty()) {
                    Log.e("MainActivity", "No pending Ping found for contact $contactId")
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@MainActivity, "No pending message found")
                    }
                    return@launch
                }

                // Get the first pending ping
                val firstPing = pendingPings.first()
                val pingId = firstPing.pingId

                Log.i("MainActivity", "Delegating download to DownloadMessageService: pingId=${pingId.take(8)}")

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@MainActivity, "Downloading message from ${chat.nickname}...")
                }

                // Delegate to DownloadMessageService (handles PONG, polling, message save, ACK)
                com.securelegion.services.DownloadMessageService.start(
                    this@MainActivity,
                    contactId,
                    chat.nickname,
                    pingId
                )

                Log.i("MainActivity", "Download service started for contact $contactId")

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to download message", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@MainActivity, "Download failed: ${e.message}")
                }
            }
        }
    }

    /**
     * Start a voice call with the selected contact
     */
    private fun startVoiceCallWithContact(contact: Contact) {
        // Prevent duplicate call initiations
        if (isInitiatingCall) {
            Log.w(TAG, "Call initiation already in progress - ignoring duplicate request")
            return
        }
        isInitiatingCall = true

        lifecycleScope.launch {
            try {
                // Check RECORD_AUDIO permission
                if (ContextCompat.checkSelfPermission(
                        this@MainActivity,
                        Manifest.permission.RECORD_AUDIO
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    // Store contact for retry after permission granted
                    pendingCallContact = contact
                    ActivityCompat.requestPermissions(
                        this@MainActivity,
                        arrayOf(Manifest.permission.RECORD_AUDIO),
                        PERMISSION_REQUEST_CALL
                    )
                    return@launch
                }

                // Get full contact details from database
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                val fullContact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactById(contact.id.toLong())
                }

                if (fullContact == null) {
                    ThemedToast.show(this@MainActivity, "Contact not found")
                    isInitiatingCall = false
                    return@launch
                }

                if (fullContact.voiceOnion.isNullOrEmpty()) {
                    ThemedToast.show(this@MainActivity, "Contact has no voice address")
                    isInitiatingCall = false
                    return@launch
                }

                if (fullContact.messagingOnion == null) {
                    ThemedToast.show(this@MainActivity, "Contact has no messaging address")
                    isInitiatingCall = false
                    return@launch
                }

                // Generate call ID (use full UUID for proper matching)
                val callId = UUID.randomUUID().toString()

                // Generate ephemeral keypair
                val crypto = VoiceCallCrypto()
                val ephemeralKeypair = crypto.generateEphemeralKeypair()

                // Launch VoiceCallActivity immediately (shows "Calling..." screen)
                val intent = Intent(this@MainActivity, VoiceCallActivity::class.java)
                intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_ID, fullContact.id)
                intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_NAME, fullContact.nickname ?: fullContact.displayName)
                intent.putExtra(VoiceCallActivity.EXTRA_CALL_ID, callId)
                intent.putExtra(VoiceCallActivity.EXTRA_IS_OUTGOING, true)
                intent.putExtra(VoiceCallActivity.EXTRA_OUR_EPHEMERAL_SECRET_KEY, ephemeralKeypair.secretKey.asBytes)
                startActivity(intent)

                // Get voice onion once for reuse in retries
                val torManager = com.securelegion.crypto.TorManager.getInstance(this@MainActivity)
                val myVoiceOnion = torManager.getVoiceOnionAddress() ?: ""
                if (myVoiceOnion.isEmpty()) {
                    Log.w("MainActivity", "Voice onion address not yet created - call may fail")
                } else {
                    Log.i("MainActivity", "My voice onion: $myVoiceOnion")
                }

                // Get our X25519 public key for HTTP wire format (reuse existing keyManager from earlier)
                val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

                // Send CALL_OFFER (first attempt) to voice onion via HTTP POST
                Log.i("MainActivity", "CALL_OFFER_SEND attempt=1 call_id=$callId to voice onion via HTTP POST")
                val success = withContext(Dispatchers.IO) {
                    CallSignaling.sendCallOffer(
                        recipientX25519PublicKey = fullContact.x25519PublicKeyBytes,
                        recipientOnion = fullContact.voiceOnion!!,
                        callId = callId,
                        ephemeralPublicKey = ephemeralKeypair.publicKey.asBytes,
                        voiceOnion = myVoiceOnion,
                        ourX25519PublicKey = ourX25519PublicKey,
                        numCircuits = 1
                    )
                }

                if (!success) {
                    ThemedToast.show(this@MainActivity, "Failed to send call offer")
                    isInitiatingCall = false
                    return@launch
                }

                // Register pending call
                val callManager = VoiceCallManager.getInstance(this@MainActivity)

                // Create timeout checker
                val timeoutJob = lifecycleScope.launch {
                    while (isActive) {
                        delay(1000)
                        callManager.checkPendingCallTimeouts()
                    }
                }

                // CALL_OFFER retry timer per spec
                // Resend every 2 seconds until answered or 25-second deadline
                val offerRetryInterval = 2000L
                val callSetupDeadline = 25000L
                val setupStartTime = System.currentTimeMillis()
                var offerAttemptNum = 1

                val offerRetryJob = lifecycleScope.launch {
                    while (isActive) {
                        delay(offerRetryInterval)

                        val elapsed = System.currentTimeMillis() - setupStartTime
                        if (elapsed >= callSetupDeadline) {
                            Log.e("MainActivity", "CALL_SETUP_TIMEOUT call_id=$callId elapsed_ms=$elapsed")
                            break
                        }

                        offerAttemptNum++
                        Log.i("MainActivity", "CALL_OFFER_SEND attempt=$offerAttemptNum call_id=$callId (retry to voice onion via HTTP POST)")

                        withContext(Dispatchers.IO) {
                            CallSignaling.sendCallOffer(
                                recipientX25519PublicKey = fullContact.x25519PublicKeyBytes,
                                recipientOnion = fullContact.voiceOnion!!,
                                callId = callId,
                                ephemeralPublicKey = ephemeralKeypair.publicKey.asBytes,
                                voiceOnion = myVoiceOnion,
                                ourX25519PublicKey = ourX25519PublicKey,
                                numCircuits = 1
                            )
                        }
                    }
                }

                callManager.registerPendingOutgoingCall(
                    callId = callId,
                    contactOnion = fullContact.voiceOnion!!,
                    contactEd25519PublicKey = fullContact.ed25519PublicKeyBytes,
                    contactName = fullContact.nickname ?: fullContact.displayName,
                    ourEphemeralPublicKey = ephemeralKeypair.publicKey.asBytes,
                    onAnswered = { theirEphemeralKey ->
                        lifecycleScope.launch(Dispatchers.Main) {
                            val elapsed = System.currentTimeMillis() - setupStartTime
                            Log.i("MainActivity", "CALL_ANSWER_RECEIVED call_id=$callId elapsed_ms=$elapsed")
                            timeoutJob.cancel()
                            offerRetryJob.cancel()
                            // Notify the active VoiceCallActivity that CALL_ANSWER was received
                            VoiceCallActivity.onCallAnswered(callId, theirEphemeralKey)
                            Log.i("MainActivity", "Call answered, notified VoiceCallActivity")
                            isCallMode = false
                            isInitiatingCall = false
                        }
                    },
                    onTimeout = {
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            offerRetryJob.cancel()
                            VoiceCallActivity.onCallTimeout(callId)
                            isCallMode = false
                            isInitiatingCall = false
                        }
                    },
                    onRejected = { reason ->
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            offerRetryJob.cancel()
                            VoiceCallActivity.onCallRejected(callId, reason)
                            isCallMode = false
                            isInitiatingCall = false
                        }
                    },
                    onBusy = {
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            offerRetryJob.cancel()
                            VoiceCallActivity.onCallBusy(callId)
                            isCallMode = false
                            isInitiatingCall = false
                        }
                    }
                )

                Log.i("MainActivity", "Voice call initiated to ${fullContact.displayName} with call ID: $callId")

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to start voice call", e)
                ThemedToast.show(this@MainActivity, "Failed to start call: ${e.message}")
                isCallMode = false
                isInitiatingCall = false
            }
        }
    }
}
