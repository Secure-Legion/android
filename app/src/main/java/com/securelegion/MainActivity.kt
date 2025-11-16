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
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.Toast
import android.widget.Spinner
import android.widget.AdapterView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.recyclerview.widget.ItemTouchHelper
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
import com.securelegion.utils.startActivityWithSlideAnimation
import com.securelegion.workers.SelfDestructWorker
import com.securelegion.workers.MessageRetryWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {
    private var currentTab = "messages" // Track current tab: "messages", "contacts", or "wallet"
    private var currentWallet: Wallet? = null // Track currently selected wallet

    // BroadcastReceiver to listen for incoming Pings and refresh UI
    private val pingReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.securelegion.NEW_PING") {
                Log.d("MainActivity", "Received NEW_PING broadcast - refreshing chat list")
                // Update UI immediately on main thread
                runOnUiThread {
                    if (currentTab == "messages") {
                        Log.d("MainActivity", "Refreshing chat list from broadcast")
                        setupChatList()
                    } else {
                        Log.d("MainActivity", "Not on messages tab, skipping refresh")
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
            Toast.makeText(this, "Please complete account setup", Toast.LENGTH_LONG).show()
            val intent = Intent(this, CreateAccountActivity::class.java)
            intent.putExtra("RESUME_SETUP", true)
            startActivity(intent)
            finish()
            return
        }

        setContentView(R.layout.activity_main)

        Log.d("MainActivity", "onCreate - initializing views")

        // Ensure messages tab is shown by default
        findViewById<View>(R.id.chatListContainer).visibility = View.VISIBLE
        findViewById<View>(R.id.contactsView).visibility = View.GONE
        findViewById<View>(R.id.walletView).visibility = View.GONE

        // Show empty state initially while loading
        val chatList = findViewById<RecyclerView>(R.id.chatList)
        val emptyState = findViewById<View>(R.id.emptyState)
        chatList.visibility = View.GONE
        emptyState.visibility = View.VISIBLE

        setupClickListeners()
        scheduleSelfDestructWorker()
        scheduleMessageRetryWorker()

        // Request battery optimization exemption for wake lock
        requestBatteryOptimizationExemption()

        // Start Tor foreground service (shows notification and handles Ping-Pong protocol)
        startTorService()

        // Load data asynchronously to avoid blocking UI
        setupChatList()
        setupContactsList()

        // Update app icon badge with unread count
        updateAppBadge()

        // Check if we should show wallet tab
        if (intent.getBooleanExtra("SHOW_WALLET", false)) {
            showWalletTab()
        }

        // Register broadcast receiver for incoming Pings (stays registered even when paused)
        val filter = IntentFilter("com.securelegion.NEW_PING")
        registerReceiver(pingReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        Log.d("MainActivity", "Registered NEW_PING broadcast receiver in onCreate")
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

    private fun requestBatteryOptimizationExemption() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
            val packageName = packageName

            if (!powerManager.isIgnoringBatteryOptimizations(packageName)) {
                Log.i("MainActivity", "Requesting battery optimization exemption for wake lock")
                try {
                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = Uri.parse("package:$packageName")
                    }
                    startActivity(intent)
                } catch (e: Exception) {
                    Log.e("MainActivity", "Failed to request battery optimization exemption", e)
                    Toast.makeText(
                        this,
                        "Please disable battery optimization for Secure Legion in Settings",
                        Toast.LENGTH_LONG
                    ).show()
                }
            } else {
                Log.d("MainActivity", "App is already exempt from battery optimization")
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
     * Start the Tor foreground service
     * This shows the persistent notification and handles the Ping-Pong protocol
     */
    private fun startTorService() {
        try {
            Log.d("MainActivity", "Starting Tor foreground service...")
            com.securelegion.services.TorService.start(this)
        } catch (e: Exception) {
            Log.e("MainActivity", "Failed to start Tor service", e)
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

        // Check if we should show wallet tab
        if (intent.getBooleanExtra("SHOW_WALLET", false)) {
            Log.d("MainActivity", "onNewIntent - showing wallet tab")
            showWalletTab()
        }
    }

    override fun onResume() {
        super.onResume()
        Log.d("MainActivity", "onResume called - current tab: $currentTab")

        // Reload data when returning to MainActivity (receiver stays registered)
        if (currentTab == "messages") {
            setupChatList()
        } else if (currentTab == "wallet") {
            // Reload wallet spinner to show newly created wallets
            setupWalletSpinner()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Unregister broadcast receiver when activity is destroyed
        try {
            unregisterReceiver(pingReceiver)
            Log.d("MainActivity", "Unregistered NEW_PING broadcast receiver in onDestroy")
        } catch (e: IllegalArgumentException) {
            // Receiver wasn't registered, ignore
            Log.w("MainActivity", "Receiver was not registered during onDestroy")
        }
    }

    private fun setupChatList() {
        val chatList = findViewById<RecyclerView>(R.id.chatList)
        val emptyState = findViewById<View>(R.id.emptyState)

        Log.d("MainActivity", "Loading message threads...")

        // Load real message threads from database
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                // Do all database queries in one IO block for better performance
                val chatsWithTimestamp = withContext(Dispatchers.IO) {
                    val allContacts = database.contactDao().getAllContacts()
                    Log.d("MainActivity", "Found ${allContacts.size} contacts")

                    val chatsList = mutableListOf<Pair<Chat, Long>>()

                    // Check for pending Pings
                    val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)

                    // Process each contact
                    for (contact in allContacts) {
                        val lastMessage = database.messageDao().getLastMessage(contact.id)
                        val hasPendingPing = prefs.contains("ping_${contact.id}_id")

                        // Include contacts with messages OR pending Pings
                        if (lastMessage != null || hasPendingPing) {
                            val unreadCount = database.messageDao().getUnreadCount(contact.id)

                            val chat = Chat(
                                id = contact.id.toString(),
                                nickname = contact.displayName,
                                lastMessage = if (lastMessage != null) lastMessage.encryptedContent else "New message",
                                time = if (lastMessage != null) formatTimestamp(lastMessage.timestamp) else formatTimestamp(System.currentTimeMillis()),
                                unreadCount = unreadCount + (if (hasPendingPing) 1 else 0),
                                isOnline = false,
                                avatar = contact.displayName.firstOrNull()?.toString()?.uppercase() ?: "?",
                                securityBadge = "E2E"
                            )
                            val timestamp = if (lastMessage != null) lastMessage.timestamp else System.currentTimeMillis()
                            chatsList.add(Pair(chat, timestamp))
                        }
                    }

                    chatsList
                }

                // Sort by most recent message timestamp
                val chats = chatsWithTimestamp
                    .sortedByDescending { it.second }
                    .map { it.first }

                Log.d("MainActivity", "Loaded ${chats.size} chat threads")
                chats.forEach { chat ->
                    Log.d("MainActivity", "Chat: ${chat.nickname} - ${chat.lastMessage}")
                }

                // Update UI on main thread
                if (chats.isNotEmpty()) {
                    Log.d("MainActivity", "Showing chat list UI")
                    // Show chat list, hide empty state (but don't change tab visibility)
                    emptyState.visibility = View.GONE
                    chatList.visibility = View.VISIBLE

                    Log.d("MainActivity", "Setting up RecyclerView adapter with ${chats.size} items")
                    // Set adapter
                    chatList.layoutManager = LinearLayoutManager(this@MainActivity)
                    chatList.adapter = ChatAdapter(
                        chats = chats,
                        onChatClick = { chat ->
                            lifecycleScope.launch {
                                val contact = withContext(Dispatchers.IO) {
                                    database.contactDao().getContactById(chat.id.toLong())
                                }
                                if (contact != null) {
                                    val intent = android.content.Intent(this@MainActivity, ChatActivity::class.java)
                                    intent.putExtra(ChatActivity.EXTRA_CONTACT_ID, contact.id)
                                    intent.putExtra(ChatActivity.EXTRA_CONTACT_NAME, contact.displayName)
                                    intent.putExtra(ChatActivity.EXTRA_CONTACT_ADDRESS, contact.solanaAddress)
                                    startActivityWithSlideAnimation(intent)
                                }
                            }
                        },
                        onDownloadClick = { chat ->
                            handleMessageDownload(chat)
                        }
                    )
                    Log.d("MainActivity", "RecyclerView adapter set successfully")

                    // Add swipe-to-delete functionality
                    val swipeCallback = object : ItemTouchHelper.SimpleCallback(
                        0,
                        ItemTouchHelper.LEFT
                    ) {
                        override fun onMove(
                            recyclerView: RecyclerView,
                            viewHolder: RecyclerView.ViewHolder,
                            target: RecyclerView.ViewHolder
                        ): Boolean = false

                        override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                            val position = viewHolder.adapterPosition
                            val chat = chats[position]

                            Log.d("MainActivity", "Swiped to delete thread: ${chat.nickname}")

                            // Securely delete all messages for this contact using DOD 3-pass AND clear pending Pings
                            lifecycleScope.launch {
                                try {
                                    withContext(Dispatchers.IO) {
                                        // Get all messages for this contact to check for voice files
                                        val messages = database.messageDao().getMessagesForContact(chat.id.toLong())

                                        // Securely wipe any voice message audio files
                                        messages.forEach { message ->
                                            if (message.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE &&
                                                message.voiceFilePath != null) {
                                                try {
                                                    val voiceFile = java.io.File(message.voiceFilePath)
                                                    if (voiceFile.exists()) {
                                                        com.securelegion.utils.SecureWipe.secureDeleteFile(voiceFile)
                                                        Log.d("MainActivity", "✓ Securely wiped voice file: ${voiceFile.name}")
                                                    }
                                                } catch (e: Exception) {
                                                    Log.e("MainActivity", "Failed to securely wipe voice file", e)
                                                }
                                            }
                                        }

                                        // Delete all messages from database
                                        database.messageDao().deleteMessagesForContact(chat.id.toLong())

                                        // VACUUM database to compact and remove deleted records
                                        try {
                                            database.openHelper.writableDatabase.execSQL("VACUUM")
                                            Log.d("MainActivity", "✓ Database vacuumed after thread deletion")
                                        } catch (e: Exception) {
                                            Log.e("MainActivity", "Failed to vacuum database", e)
                                        }
                                    }

                                    // Clear pending Ping for this contact
                                    val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                                    prefs.edit()
                                        .remove("ping_${chat.id}_id")
                                        .remove("ping_${chat.id}_sender")
                                        .remove("ping_${chat.id}_timestamp")
                                        .remove("ping_${chat.id}_data")
                                        .apply()

                                    Log.i("MainActivity", "Securely deleted all messages (DOD 3-pass) and pending Pings for contact: ${chat.nickname}")

                                    // Reload the chat list
                                    setupChatList()
                                } catch (e: Exception) {
                                    Log.e("MainActivity", "Failed to delete thread", e)
                                    Toast.makeText(
                                        this@MainActivity,
                                        "Failed to delete thread",
                                        Toast.LENGTH_SHORT
                                    ).show()
                                    // Reload to restore UI
                                    setupChatList()
                                }
                            }
                        }
                    }

                    val itemTouchHelper = ItemTouchHelper(swipeCallback)
                    itemTouchHelper.attachToRecyclerView(chatList)
                } else {
                    Log.d("MainActivity", "No chats - showing empty state")
                    // Show empty state (but don't change tab visibility)
                    emptyState.visibility = View.VISIBLE
                    chatList.visibility = View.GONE
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load message threads", e)
                withContext(Dispatchers.Main) {
                    // Show empty state (but don't change tab visibility)
                    emptyState.visibility = View.VISIBLE
                    chatList.visibility = View.GONE
                }
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
        val emptyContactsState = contactsView.findViewById<View>(R.id.emptyContactsState)

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
                        address = dbContact.solanaAddress
                    )
                }

                // Update UI on main thread
                withContext(Dispatchers.Main) {
                    if (contacts.isNotEmpty()) {
                        Log.i("MainActivity", "Displaying ${contacts.size} contacts in UI")
                        contacts.forEach { contact ->
                            Log.i("MainActivity", "  - ${contact.name} (${contact.address})")
                        }
                        emptyContactsState.visibility = View.GONE
                        contactsList.visibility = View.VISIBLE
                        contactsList.layoutManager = LinearLayoutManager(this@MainActivity)
                        contactsList.adapter = ContactAdapter(contacts) { contact ->
                            // Open contact options screen
                            val intent = android.content.Intent(this@MainActivity, ContactOptionsActivity::class.java)
                            intent.putExtra("CONTACT_ID", contact.id.toLong())
                            intent.putExtra("CONTACT_NAME", contact.name)
                            intent.putExtra("CONTACT_ADDRESS", contact.address)
                            startActivityWithSlideAnimation(intent)
                        }
                        Log.i("MainActivity", "RecyclerView adapter set with ${contacts.size} items")
                    } else {
                        Log.w("MainActivity", "No contacts to display, showing empty state")
                        emptyContactsState.visibility = View.VISIBLE
                        contactsList.visibility = View.GONE
                    }
                }
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load contacts from database", e)
                // Show empty state on error
                withContext(Dispatchers.Main) {
                    emptyContactsState.visibility = View.VISIBLE
                    contactsList.visibility = View.GONE
                }
            }
        }
    }

    private fun setupClickListeners() {
        // New Message Button (in search bar)
        findViewById<View>(R.id.newMessageBtn).setOnClickListener {
            val intent = android.content.Intent(this, ComposeActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }

        // Bottom Navigation
        findViewById<View>(R.id.navMessages).setOnClickListener {
            showAllChatsTab()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            showWalletTab()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = android.content.Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = android.content.Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }

        // Tabs
        findViewById<View>(R.id.tabContacts).setOnClickListener {
            showContactsTab()
        }

        findViewById<View>(R.id.tabSettings).setOnClickListener {
            val intent = android.content.Intent(this, SettingsActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }
    }

    private fun setupWalletButtons() {
        // These buttons are in the included wallet_balance_card layout within walletView
        val walletView = findViewById<View>(R.id.walletView)

        val receiveButton = walletView?.findViewById<View>(R.id.receiveButton)
        val sendButton = walletView?.findViewById<View>(R.id.sendButton)
        val recentBtn = walletView?.findViewById<View>(R.id.recentBtn)
        val refreshButton = walletView?.findViewById<View>(R.id.refreshBalanceButton)
        val walletSettingsButton = walletView?.findViewById<View>(R.id.walletSettingsButton)

        receiveButton?.setOnClickListener {
            val intent = android.content.Intent(this, ReceiveActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        sendButton?.setOnClickListener {
            val intent = android.content.Intent(this, SendActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        recentBtn?.setOnClickListener {
            val intent = android.content.Intent(this, RecentTransactionsActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        refreshButton?.setOnClickListener {
            Log.d("MainActivity", "Refresh button clicked - reloading wallet balance")
            loadWalletBalance()
        }

        // Setup wallet spinner
        setupWalletSpinner()

        walletSettingsButton?.setOnClickListener {
            val intent = android.content.Intent(this, WalletSettingsActivity::class.java)
            intent.putExtra("WALLET_ID", "main")  // Default to main wallet
            intent.putExtra("IS_MAIN_WALLET", true)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }
    }

    private fun setupWalletSpinner() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)
                val wallets = database.walletDao().getAllWallets()

                withContext(Dispatchers.Main) {
                    val walletView = findViewById<View>(R.id.walletView)
                    val spinner = walletView?.findViewById<Spinner>(R.id.walletSpinner)

                    if (spinner != null && wallets.isNotEmpty()) {
                        val adapter = WalletAdapter(this@MainActivity, wallets)
                        spinner.adapter = adapter

                        // Set initial wallet (most recently used)
                        val initialWallet = wallets.firstOrNull()
                        if (initialWallet != null && currentWallet == null) {
                            currentWallet = initialWallet
                            updateWalletIdentity(initialWallet)
                        }

                        spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                                val selectedWallet = wallets[position]
                                switchToWallet(selectedWallet)
                            }

                            override fun onNothingSelected(parent: AdapterView<*>?) {
                                // Do nothing
                            }
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

                    // Reload wallet balance and identity
                    loadWalletBalance()
                    updateWalletIdentity(wallet)
                }

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to switch wallet", e)
            }
        }
    }

    private fun updateWalletIdentity(wallet: Wallet) {
        // Update wallet address and private key display
        val walletView = findViewById<View>(R.id.walletView)
        val addressText = walletView?.findViewById<android.widget.TextView>(R.id.walletAddress)

        // Update the displayed address
        addressText?.text = wallet.solanaAddress.take(12) + "..." + wallet.solanaAddress.takeLast(12)

        Log.i("MainActivity", "Wallet identity updated for: ${wallet.walletId}")
    }

    private fun showAllChatsTab() {
        Log.d("MainActivity", "Switching to messages tab")
        currentTab = "messages"
        findViewById<View>(R.id.chatListContainer).visibility = View.VISIBLE
        findViewById<View>(R.id.contactsView).visibility = View.GONE
        findViewById<View>(R.id.walletView).visibility = View.GONE

        // Show tabs (Contacts/Settings)
        findViewById<View>(R.id.tabsContainer).visibility = View.VISIBLE

        // Reload message threads when switching back to messages tab
        setupChatList()

        // Update tab styling
        findViewById<android.widget.TextView>(R.id.tabContacts).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_gray))
            setTypeface(null, android.graphics.Typeface.NORMAL)
        }

        // Update tab indicators
        findViewById<View>(R.id.indicatorContacts).setBackgroundColor(android.graphics.Color.TRANSPARENT)

        // Update bottom nav - highlight Messages
        findViewById<View>(R.id.navMessages)?.setBackgroundResource(R.drawable.nav_item_active_bg)
        findViewById<android.widget.TextView>(R.id.navMessagesLabel)?.setTextColor(ContextCompat.getColor(this, R.color.primary_blue))
        findViewById<View>(R.id.navWallet)?.setBackgroundResource(R.drawable.nav_item_ripple)
        findViewById<android.widget.TextView>(R.id.navWalletLabel)?.setTextColor(ContextCompat.getColor(this, R.color.text_gray))
    }

    private fun showContactsTab() {
        Log.d("MainActivity", "Switching to contacts tab")
        currentTab = "contacts"
        findViewById<View>(R.id.chatListContainer).visibility = View.GONE
        findViewById<View>(R.id.emptyState)?.visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.VISIBLE
        findViewById<View>(R.id.walletView).visibility = View.GONE

        // Show tabs (Contacts/Settings)
        findViewById<View>(R.id.tabsContainer).visibility = View.VISIBLE

        // Reload contacts list
        setupContactsList()

        // Update tab styling
        findViewById<android.widget.TextView>(R.id.tabContacts).apply {
            setTextColor(ContextCompat.getColor(context, R.color.primary_blue))
            setTypeface(null, android.graphics.Typeface.BOLD)
        }

        // Update tab indicators
        findViewById<View>(R.id.indicatorContacts).setBackgroundColor(ContextCompat.getColor(this, R.color.primary_blue))
    }

    private fun loadWalletBalance() {
        lifecycleScope.launch {
            try {
                Log.d("MainActivity", "Loading wallet balance from Solana blockchain")

                val walletView = findViewById<View>(R.id.walletView)
                val balanceText = walletView?.findViewById<android.widget.TextView>(R.id.balanceAmount)
                val balanceUSD = walletView?.findViewById<android.widget.TextView>(R.id.balanceUSD)

                // Show loading state
                withContext(Dispatchers.Main) {
                    balanceText?.text = "Loading..."
                    balanceUSD?.text = "..."
                }

                // Get wallet public key from currently selected wallet
                val solanaAddress = if (currentWallet != null) {
                    currentWallet!!.solanaAddress
                } else {
                    // Fallback to first wallet if none selected
                    val keyManager = KeyManager.getInstance(this@MainActivity)
                    keyManager.getSolanaAddress()
                }

                Log.d("MainActivity", "Fetching balance for address: $solanaAddress")

                // Fetch balance from blockchain (routes through Tor)
                val solanaService = SolanaService(this@MainActivity)
                val result = solanaService.getBalance(solanaAddress)

                withContext(Dispatchers.Main) {
                    if (result.isSuccess) {
                        val balanceSOL = result.getOrNull() ?: 0.0

                        // Format balance nicely
                        val formattedBalance = when {
                            balanceSOL >= 1.0 -> String.format("%.4f SOL", balanceSOL)
                            balanceSOL >= 0.0001 -> String.format("%.4f SOL", balanceSOL)
                            balanceSOL > 0 -> String.format("%.8f SOL", balanceSOL)
                            else -> "0 SOL"
                        }

                        balanceText?.text = formattedBalance
                        balanceUSD?.text = "..." // TODO: Add price conversion in Phase 4

                        Log.i("MainActivity", "Balance loaded: $formattedBalance")
                    } else {
                        balanceText?.text = "Error"
                        balanceUSD?.text = "Failed to load balance"
                        Log.e("MainActivity", "Failed to load balance: ${result.exceptionOrNull()?.message}")
                    }
                }

                // Also load SPL token balances
                loadTokenBalances(solanaService, solanaAddress)

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load wallet balance", e)
                withContext(Dispatchers.Main) {
                    val walletView = findViewById<View>(R.id.walletView)
                    val balanceText = walletView?.findViewById<android.widget.TextView>(R.id.balanceAmount)
                    balanceText?.text = "Error"
                }
            }
        }
    }

    private suspend fun loadTokenBalances(solanaService: SolanaService, solanaAddress: String) {
        try {
            Log.d("MainActivity", "Loading SPL token balances")

            // Fetch token accounts
            val result = solanaService.getTokenAccounts(solanaAddress)

            withContext(Dispatchers.Main) {
                val walletView = findViewById<View>(R.id.walletView)

                if (result.isSuccess) {
                    val tokenAccounts = result.getOrNull() ?: emptyList()
                    Log.i("MainActivity", "Token balances loaded: ${tokenAccounts.size} tokens")

                    Log.i("MainActivity", "Loaded ${tokenAccounts.size} token accounts")
                } else {
                    Log.e("MainActivity", "Failed to load token balances: ${result.exceptionOrNull()?.message}")
                }
            }

        } catch (e: Exception) {
            Log.e("MainActivity", "Failed to load token balances", e)
        }
    }

    private fun showWalletTab() {
        Log.d("MainActivity", "Switching to wallet tab")
        currentTab = "wallet"
        findViewById<View>(R.id.chatListContainer).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.GONE
        findViewById<View>(R.id.walletView).visibility = View.VISIBLE

        // Hide tabs (Contacts/Settings) - only for main page
        findViewById<View>(R.id.tabsContainer).visibility = View.GONE

        // Setup wallet buttons now that the view is visible
        setupWalletButtons()

        // Load wallet balance from blockchain
        loadWalletBalance()

        // Update tab styling - reset all top tabs to inactive
        findViewById<android.widget.TextView>(R.id.tabContacts).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_gray))
            setTypeface(null, android.graphics.Typeface.NORMAL)
        }

        // Update tab indicators - clear all
        findViewById<View>(R.id.indicatorContacts).setBackgroundColor(android.graphics.Color.TRANSPARENT)

        // Update bottom nav - highlight Wallet
        findViewById<View>(R.id.navMessages)?.setBackgroundResource(R.drawable.nav_item_ripple)
        findViewById<android.widget.TextView>(R.id.navMessagesLabel)?.setTextColor(ContextCompat.getColor(this, R.color.text_gray))
        findViewById<View>(R.id.navWallet)?.setBackgroundResource(R.drawable.nav_item_active_bg)
        findViewById<android.widget.TextView>(R.id.navWalletLabel)?.setTextColor(ContextCompat.getColor(this, R.color.primary_blue))
    }

    /**
     * Handle manual message download when user clicks download button
     */
    private fun handleMessageDownload(chat: Chat) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val contactId = chat.id.toLong()
                Log.i("MainActivity", "User clicked download for contact $contactId (${chat.nickname})")

                // Retrieve pending Ping info from SharedPreferences
                val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                val pingId = prefs.getString("ping_${contactId}_id", null)
                val senderOnionAddress = prefs.getString("ping_${contactId}_onion", null)
                val senderName = prefs.getString("ping_${contactId}_name", chat.nickname)
                val encryptedPingData = prefs.getString("ping_${contactId}_data", null)

                if (pingId == null || senderOnionAddress == null) {
                    Log.e("MainActivity", "No pending Ping found for contact $contactId")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "No pending message found", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                Log.i("MainActivity", "Downloading message: pingId=$pingId, sender=$senderOnionAddress")

                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Downloading message from $senderName...", Toast.LENGTH_SHORT).show()
                }

                // Step 1: Get contact info from database
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)
                val contact = database.contactDao().getContactById(contactId)

                if (contact == null) {
                    Log.e("MainActivity", "Contact $contactId not found in database")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Contact not found", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                // Step 2: Restore the Ping in Rust so respondToPing can find it
                Log.d("MainActivity", "Stored Ping ID from SharedPreferences: $pingId")

                val actualPingId: String
                if (encryptedPingData != null) {
                    val encryptedPingBytes = android.util.Base64.decode(encryptedPingData, android.util.Base64.NO_WRAP)
                    Log.d("MainActivity", "Restoring Ping from ${encryptedPingBytes.size} bytes of encrypted data")
                    val restoredPingId = com.securelegion.crypto.RustBridge.decryptIncomingPing(encryptedPingBytes)

                    if (restoredPingId == null) {
                        Log.e("MainActivity", "Failed to decrypt/restore Ping")
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@MainActivity, "Failed to restore message request", Toast.LENGTH_SHORT).show()
                        }
                        return@launch
                    }

                    Log.i("MainActivity", "Ping decrypted - stored ID: $pingId, restored ID: $restoredPingId")

                    if (restoredPingId != pingId) {
                        Log.w("MainActivity", "⚠️  Ping ID MISMATCH! Stored=$pingId, Restored=$restoredPingId")
                        Log.w("MainActivity", "Using restored ID (based on actual nonce) for Pong response")
                    }

                    actualPingId = restoredPingId
                    Log.i("MainActivity", "Ping restored successfully: $actualPingId")
                } else {
                    Log.e("MainActivity", "No encrypted Ping data stored - cannot restore")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Message data not found", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                // Step 3: Generate Pong response (user authenticated = true)
                Log.d("MainActivity", "Creating Pong with Ping ID: $actualPingId")
                val encryptedPongBytes = com.securelegion.crypto.RustBridge.respondToPing(actualPingId, authenticated = true)

                if (encryptedPongBytes == null) {
                    Log.e("MainActivity", "Failed to generate Pong response")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Failed to respond to message", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                Log.i("MainActivity", "Generated Pong response (${encryptedPongBytes.size} bytes)")

                // Step 4: Send Pong over NEW connection to sender (old connection is closed)
                val pongSent = com.securelegion.crypto.RustBridge.sendPongToNewConnection(senderOnionAddress, encryptedPongBytes)

                if (!pongSent) {
                    Log.e("MainActivity", "Failed to send Pong to $senderOnionAddress")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Failed to connect to sender", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                Log.i("MainActivity", "Pong sent to sender via new connection")

                // Step 5: Wait for the message blob to arrive via TorService listener
                // The message will be received by handleIncomingMessageBlob in TorService
                // and automatically saved to the database. We'll wait up to 30 seconds.
                Log.i("MainActivity", "Waiting for message blob from sender...")

                var messageReceived = false
                var attempts = 0
                val maxAttempts = 30  // 30 seconds total

                while (!messageReceived && attempts < maxAttempts) {
                    kotlinx.coroutines.delay(1000)  // Wait 1 second
                    attempts++

                    // Check if message has arrived by checking if Ping is still pending
                    val stillPending = prefs.contains("ping_${contactId}_id")
                    if (!stillPending) {
                        // Ping was cleared, meaning message was received and processed
                        messageReceived = true
                        break
                    }

                    // Also check database for new message from this contact
                    val lastMessage = database.messageDao().getLastMessage(contactId)
                    if (lastMessage != null && !lastMessage.isSentByMe &&
                        System.currentTimeMillis() - lastMessage.timestamp < 35000) {
                        // New received message within last 35 seconds
                        messageReceived = true
                        break
                    }
                }

                if (!messageReceived) {
                    Log.e("MainActivity", "Timeout waiting for message blob from sender")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Timeout: sender may be offline", Toast.LENGTH_LONG).show()
                    }
                    return@launch
                }

                Log.i("MainActivity", "Message blob received and processed by TorService")

                // Step 6: Remove pending Ping from SharedPreferences (TorService already saved the message)
                // Use commit() not apply() to ensure write completes immediately
                prefs.edit().apply {
                    remove("ping_${contactId}_id")
                    remove("ping_${contactId}_connection")
                    remove("ping_${contactId}_name")
                    remove("ping_${contactId}_data")
                    remove("ping_${contactId}_onion")
                    remove("ping_${contactId}_timestamp")
                    commit()  // Synchronous - guarantees persistence
                }

                Log.i("MainActivity", "Pending Ping cleared from SharedPreferences")

                // Step 7: Clear notification if no more pending Pings
                val remainingPings = prefs.all.filter { it.key.endsWith("_id") }.size
                if (remainingPings == 0) {
                    val notificationManager = getSystemService(android.app.NotificationManager::class.java)
                    notificationManager.cancel(999)
                }

                // Step 8: Update UI
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Message from $senderName downloaded!", Toast.LENGTH_SHORT).show()
                    // Refresh chat list to hide download button and show the new message
                    setupChatList()
                    // Update app badge
                    updateAppBadge()
                }

                Log.i("MainActivity", "Message download complete for contact $contactId")

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to download message", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Download failed: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}
