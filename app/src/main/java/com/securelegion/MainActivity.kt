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
import com.securelegion.services.TorService
import com.securelegion.services.ZcashService
import com.securelegion.utils.startActivityWithSlideAnimation
import com.securelegion.utils.BadgeUtils
import com.securelegion.utils.ThemedToast
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.crypto.VoiceCallCrypto
import com.securelegion.workers.SelfDestructWorker
import com.securelegion.workers.MessageRetryWorker
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.database.entities.x25519PublicKeyBytes
import java.util.UUID
import kotlinx.coroutines.Dispatchers
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
    private var currentWallet: Wallet? = null // Track currently selected wallet
    private var isCallMode = false // Track if we're in call mode (Phone icon clicked)
    private var pendingCallContact: Contact? = null // Temporary storage for pending call after permission request
    private var isInitiatingCall = false // Prevent duplicate call initiations

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

    // BroadcastReceiver to listen for friend requests and update badge
    private val friendRequestReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.securelegion.FRIEND_REQUEST_RECEIVED") {
                Log.d("MainActivity", "Received FRIEND_REQUEST_RECEIVED broadcast - updating badge")
                runOnUiThread {
                    updateFriendRequestBadge()
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
                        if (currentTab == "groups") {
                            setupGroupsList()
                        }
                        // Show toast notification
                        val groupName = intent.getStringExtra("GROUP_NAME")
                        val senderName = intent.getStringExtra("SENDER_NAME")
                        ThemedToast.show(this@MainActivity, "New group invite: $groupName from $senderName")
                    }
                }
                "com.securelegion.NEW_GROUP_MESSAGE" -> {
                    Log.d("MainActivity", "Received NEW_GROUP_MESSAGE broadcast")
                    runOnUiThread {
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

            // Apply top inset to top bar (for status bar and display cutout)
            topBar.setPadding(
                insets.left,
                insets.top + topBar.paddingTop,
                insets.right,
                topBar.paddingBottom
            )

            // Apply bottom inset to bottom navigation (for gesture bar)
            bottomNav.setPadding(
                bottomNav.paddingLeft,
                bottomNav.paddingTop,
                bottomNav.paddingRight,
                insets.bottom
            )

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


        // Start Tor foreground service (shows notification and handles Ping-Pong protocol)
        startTorService()

        // Start friend request HTTP server (v2.0)
        startFriendRequestServer()

        // Load data asynchronously to avoid blocking UI
        setupChatList()
        setupContactsList()

        // Update app icon badge with unread count
        updateAppBadge()

        // Check if we should show wallet tab - now opens separate WalletActivity
        if (intent.getBooleanExtra("SHOW_WALLET", false)) {
            val walletIntent = Intent(this, WalletActivity::class.java)
            startActivity(walletIntent)
        }

        // Register broadcast receiver for incoming Pings (stays registered even when paused)
        val filter = IntentFilter("com.securelegion.NEW_PING")
        registerReceiver(pingReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        Log.d("MainActivity", "Registered NEW_PING broadcast receiver in onCreate")

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
     * Update the friend request badge count on the Add Friend navigation icon
     */
    private fun updateFriendRequestBadge() {
        val rootView = findViewById<View>(android.R.id.content)
        BadgeUtils.updateFriendRequestBadge(this, rootView)
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

        // Check if we should show wallet tab - now opens separate WalletActivity
        if (intent.getBooleanExtra("SHOW_WALLET", false)) {
            Log.d("MainActivity", "onNewIntent - opening wallet activity")
            val walletIntent = Intent(this, WalletActivity::class.java)
            startActivity(walletIntent)
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

        // Update friend request badge count
        updateFriendRequestBadge()
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
            Log.d("MainActivity", "Unregistered NEW_PING broadcast receiver in onDestroy")
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
                        // Check for pending pings using new queue format
                        val pendingPings = com.securelegion.models.PendingPing.loadQueueForContact(prefs, contact.id)
                        val hasPendingPing = pendingPings.isNotEmpty()

                        // Include contacts with messages OR pending Pings
                        if (lastMessage != null || hasPendingPing) {
                            val unreadCount = database.messageDao().getUnreadCount(contact.id)

                            val chat = Chat(
                                id = contact.id.toString(),
                                nickname = contact.displayName,
                                lastMessage = if (lastMessage != null) lastMessage.encryptedContent else "New message",
                                time = if (lastMessage != null) formatTimestamp(lastMessage.timestamp) else formatTimestamp(System.currentTimeMillis()),
                                unreadCount = unreadCount + pendingPings.size,  // Add count of ALL pending pings
                                isOnline = false,
                                avatar = contact.displayName.firstOrNull()?.toString()?.uppercase() ?: "?",
                                securityBadge = ""
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
                Log.d("MainActivity", "Showing chat list UI")
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
                    },
                    onDeleteClick = { chat ->
                        deleteThread(chat)
                    }
                )
                Log.d("MainActivity", "RecyclerView adapter set successfully")

                // Don't use ItemTouchHelper - it's designed for swipe-to-dismiss, not swipe-to-reveal
                // Touch handling is done in ChatAdapter with the adapter tracking open items
            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load message threads", e)
                withContext(Dispatchers.Main) {
                    // Keep chat list visible even on error
                    chatList.visibility = View.VISIBLE
                }
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

                // Clear pending Pings for this contact (using new queue format)
                val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                com.securelegion.models.PendingPing.clearQueueForContact(prefs, chat.id.toLong())

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
                        address = dbContact.solanaAddress,
                        friendshipStatus = dbContact.friendshipStatus
                    )
                }

                // Update UI on main thread
                withContext(Dispatchers.Main) {
                    Log.i("MainActivity", "Displaying ${contacts.size} contacts in UI")
                    contacts.forEach { contact ->
                        Log.i("MainActivity", "  - ${contact.name} (${contact.address})")
                    }
                    contactsList.visibility = View.VISIBLE
                    contactsList.layoutManager = LinearLayoutManager(this@MainActivity)
                    contactsList.adapter = ContactAdapter(contacts) { contact ->
                        if (isCallMode) {
                            // Start voice call
                            startVoiceCallWithContact(contact)
                        } else {
                            // Open contact options screen
                            val intent = android.content.Intent(this@MainActivity, ContactOptionsActivity::class.java)
                            intent.putExtra("CONTACT_ID", contact.id.toLong())
                            intent.putExtra("CONTACT_NAME", contact.name)
                            intent.putExtra("CONTACT_ADDRESS", contact.address)
                            startActivityWithSlideAnimation(intent)
                        }
                    }
                    Log.i("MainActivity", "RecyclerView adapter set with ${contacts.size} items")

                    // Setup alphabet index click handlers
                    setupAlphabetIndex(contactsView, contactsList, contacts)
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

    private fun setupAlphabetIndex(contactsView: View, contactsList: RecyclerView, contacts: List<Contact>) {
        val alphabetIndex = contactsView.findViewById<android.widget.LinearLayout>(R.id.alphabetIndex)

        // Get all letter TextViews from the alphabet index
        val letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        for (i in 0 until alphabetIndex.childCount) {
            val letterView = alphabetIndex.getChildAt(i) as? android.widget.TextView
            letterView?.setOnClickListener {
                val letter = letterView.text.toString()
                scrollToLetter(contactsList, contacts, letter)
            }
        }
    }

    private fun scrollToLetter(contactsList: RecyclerView, contacts: List<Contact>, letter: String) {
        // Find the first contact that starts with this letter
        val position = contacts.indexOfFirst { contact ->
            contact.name.removePrefix("@").uppercase().startsWith(letter)
        }

        if (position != -1) {
            // Scroll to the position smoothly
            contactsList.smoothScrollToPosition(position)
            Log.i("MainActivity", "Scrolling to letter $letter at position $position")
        } else {
            Log.i("MainActivity", "No contacts found starting with letter $letter")
        }
    }

    private fun setupGroupsList() {
        lifecycleScope.launch {
            try {
                // Load groups from database with member counts
                val groupsWithCounts = withContext(Dispatchers.IO) {
                    val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@MainActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)

                    val groups = database.groupDao().getAllGroups()

                    // Get member count for each group
                    groups.map { group ->
                        val memberCount = database.groupMemberDao().getMemberCount(group.groupId)
                        com.securelegion.adapters.GroupAdapter.GroupWithMemberCount(
                            group = group,
                            memberCount = memberCount
                        )
                    }
                }

                // Load pending invites from SharedPreferences
                val invites = withContext(Dispatchers.IO) {
                    val prefs = getSharedPreferences("pending_group_invites", MODE_PRIVATE)
                    val invitesSet = prefs.getStringSet("invites", mutableSetOf()) ?: mutableSetOf()
                    invitesSet.toList()
                }

                withContext(Dispatchers.Main) {
                    // Get views
                    val invitesHeader = findViewById<View>(R.id.invitesHeader)
                    val inviteCountText = findViewById<android.widget.TextView>(R.id.inviteCount)
                    val invitesRecyclerView = findViewById<androidx.recyclerview.widget.RecyclerView>(R.id.invitesRecyclerView)
                    val groupsRecyclerView = findViewById<androidx.recyclerview.widget.RecyclerView>(R.id.groupsRecyclerView)
                    val emptyState = findViewById<View>(R.id.emptyState)

                    // Show/hide invites section
                    if (invites.isNotEmpty()) {
                        invitesHeader.visibility = View.VISIBLE
                        invitesRecyclerView.visibility = View.VISIBLE
                        inviteCountText.text = invites.size.toString()

                        // TODO: Setup invites adapter
                        // For now, just log
                        Log.d("MainActivity", "Found ${invites.size} pending group invites")
                    } else {
                        invitesHeader.visibility = View.GONE
                        invitesRecyclerView.visibility = View.GONE
                    }

                    // Show/hide groups list
                    if (groupsWithCounts.isNotEmpty()) {
                        groupsRecyclerView.visibility = View.VISIBLE
                        emptyState.visibility = View.GONE

                        // Setup groups adapter
                        val groupAdapter = com.securelegion.adapters.GroupAdapter(groupsWithCounts) { group ->
                            // Open group chat when clicked
                            val intent = Intent(this@MainActivity, GroupChatActivity::class.java)
                            intent.putExtra(GroupChatActivity.EXTRA_GROUP_ID, group.groupId)
                            intent.putExtra(GroupChatActivity.EXTRA_GROUP_NAME, group.name)
                            startActivity(intent)
                            overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left)
                        }

                        groupsRecyclerView.layoutManager = LinearLayoutManager(this@MainActivity)
                        groupsRecyclerView.adapter = groupAdapter

                        Log.d("MainActivity", "Loaded ${groupsWithCounts.size} groups")
                    } else if (invites.isEmpty()) {
                        // Show empty state only if no invites and no groups
                        groupsRecyclerView.visibility = View.GONE
                        emptyState.visibility = View.VISIBLE
                    }
                }

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to load groups", e)
            }
        }
    }

    private fun setupClickListeners() {
        // New Message/Group Button (in search bar)
        findViewById<View>(R.id.newMessageBtn).setOnClickListener {
            if (currentTab == "groups") {
                val intent = android.content.Intent(this, CreateGroupActivity::class.java)
                startActivityWithSlideAnimation(intent)
            } else {
                val intent = android.content.Intent(this, ComposeActivity::class.java)
                startActivityWithSlideAnimation(intent)
            }
        }

        // Bottom Navigation
        findViewById<View>(R.id.navMessages)?.setOnClickListener {
            Log.d("MainActivity", "Messages nav clicked")
            showAllChatsTab()
        }

        findViewById<View>(R.id.navWallet)?.setOnClickListener {
            Log.d("MainActivity", "Wallet nav clicked")
            val intent = Intent(this, WalletActivity::class.java)
            startActivity(intent)
        }

        findViewById<View>(R.id.navAddFriend)?.setOnClickListener {
            Log.d("MainActivity", "Add Friend nav clicked")
            val intent = android.content.Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        findViewById<View>(R.id.navPhone)?.setOnClickListener {
            Log.d("MainActivity", "Phone nav clicked")
            // Show contacts view in call mode
            isCallMode = true
            showContactsTab()
        }

        // Profile Icon (navigate to user profile)
        findViewById<View>(R.id.profileIcon).setOnClickListener {
            val intent = android.content.Intent(this, WalletIdentityActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }

        // Settings Icon
        findViewById<View>(R.id.settingsIcon).setOnClickListener {
            val intent = android.content.Intent(this, SettingsActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }

        // Tabs
        findViewById<View>(R.id.tabMessages).setOnClickListener {
            showAllChatsTab()
        }

        findViewById<View>(R.id.tabGroups).setOnClickListener {
            showGroupsTab()
        }

        findViewById<View>(R.id.tabContacts).setOnClickListener {
            isCallMode = false  // Regular contacts mode
            showContactsTab()
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
        currentTab = "messages"
        findViewById<View>(R.id.chatListContainer).visibility = View.VISIBLE
        findViewById<View>(R.id.groupsView).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.GONE

        // Show tabs
        findViewById<View>(R.id.tabsContainer).visibility = View.VISIBLE

        // Update search bar hint
        findViewById<android.widget.EditText>(R.id.searchBar).hint = "Search conversations..."

        // Reload message threads when switching back to messages tab
        setupChatList()

        // Update tab styling - Messages active, Groups and Contacts inactive
        findViewById<android.widget.TextView>(R.id.tabMessages).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_white))
            typeface = android.graphics.Typeface.create("@font/space_grotesk_bold", android.graphics.Typeface.BOLD)
        }

        findViewById<android.widget.TextView>(R.id.tabGroups).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_gray))
            typeface = android.graphics.Typeface.create("@font/space_grotesk_bold", android.graphics.Typeface.NORMAL)
        }

        findViewById<android.widget.ImageView>(R.id.tabContacts).apply {
            setColorFilter(ContextCompat.getColor(context, R.color.text_gray))
        }
    }

    private fun showGroupsTab() {
        Log.d("MainActivity", "Switching to groups tab")
        currentTab = "groups"
        findViewById<View>(R.id.chatListContainer).visibility = View.GONE
        findViewById<View>(R.id.groupsView).visibility = View.VISIBLE
        findViewById<View>(R.id.contactsView).visibility = View.GONE

        // Show tabs
        findViewById<View>(R.id.tabsContainer).visibility = View.VISIBLE

        // Update search bar hint
        findViewById<android.widget.EditText>(R.id.searchBar).hint = "Search your groups..."

        // Load groups and invites
        setupGroupsList()

        // Update tab styling - Groups active, Messages and Contacts inactive
        findViewById<android.widget.TextView>(R.id.tabMessages).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_gray))
            typeface = android.graphics.Typeface.create("@font/space_grotesk_bold", android.graphics.Typeface.NORMAL)
        }

        findViewById<android.widget.TextView>(R.id.tabGroups).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_white))
            typeface = android.graphics.Typeface.create("@font/space_grotesk_bold", android.graphics.Typeface.BOLD)
        }

        findViewById<android.widget.ImageView>(R.id.tabContacts).apply {
            setColorFilter(ContextCompat.getColor(context, R.color.text_gray))
        }
    }

    private fun showContactsTab() {
        Log.d("MainActivity", "Switching to contacts tab")
        currentTab = "contacts"
        findViewById<View>(R.id.chatListContainer).visibility = View.GONE
        findViewById<View>(R.id.groupsView).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.VISIBLE

        // Show tabs
        findViewById<View>(R.id.tabsContainer).visibility = View.VISIBLE

        // Update search bar hint
        findViewById<android.widget.EditText>(R.id.searchBar).hint = "Search contacts..."

        // Reload contacts list
        setupContactsList()

        // Update tab styling - Contacts active, Messages and Groups inactive
        findViewById<android.widget.TextView>(R.id.tabMessages).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_gray))
            typeface = android.graphics.Typeface.create("@font/poppins_medium", android.graphics.Typeface.NORMAL)
        }

        findViewById<android.widget.TextView>(R.id.tabGroups).apply {
            setTextColor(ContextCompat.getColor(context, R.color.text_gray))
            typeface = android.graphics.Typeface.create("@font/space_grotesk_bold", android.graphics.Typeface.NORMAL)
        }

        findViewById<android.widget.ImageView>(R.id.tabContacts).apply {
            setColorFilter(ContextCompat.getColor(context, R.color.text_white))
        }
    }

    /**
     * Handle manual message download when user clicks download button
     */
    private fun handleMessageDownload(chat: Chat) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val contactId = chat.id.toLong()
                Log.i("MainActivity", "User clicked download for contact $contactId (${chat.nickname})")

                // Retrieve pending Ping info from SharedPreferences (using new queue format)
                val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                val pendingPings = com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId)

                if (pendingPings.isEmpty()) {
                    Log.e("MainActivity", "No pending Ping found for contact $contactId")
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@MainActivity, "No pending message found")
                    }
                    return@launch
                }

                // Get the first pending ping from the queue
                val pendingPing = pendingPings.first()
                val pingId = pendingPing.pingId
                val senderOnionAddress = pendingPing.senderOnionAddress
                val senderName = pendingPing.senderName
                val encryptedPingData = pendingPing.encryptedPingData

                Log.i("MainActivity", "Downloading message: pingId=$pingId, sender=$senderOnionAddress")

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@MainActivity, "Downloading message from $senderName...")
                }

                // Step 1: Get contact info from database
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)
                val contact = database.contactDao().getContactById(contactId)

                if (contact == null) {
                    Log.e("MainActivity", "Contact $contactId not found in database")
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@MainActivity, "Contact not found")
                    }
                    return@launch
                }

                // Step 2: Restore the Ping in Rust so respondToPing can find it
                Log.d("MainActivity", "Stored Ping ID from SharedPreferences: $pingId")

                val encryptedPingBytes = android.util.Base64.decode(encryptedPingData, android.util.Base64.NO_WRAP)
                Log.d("MainActivity", "Restoring Ping from ${encryptedPingBytes.size} bytes of encrypted data")
                val restoredPingId = com.securelegion.crypto.RustBridge.decryptIncomingPing(encryptedPingBytes)

                if (restoredPingId == null) {
                    Log.e("MainActivity", "Failed to decrypt/restore Ping")
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@MainActivity, "Failed to restore message request")
                    }
                    return@launch
                }

                Log.i("MainActivity", "Ping decrypted - stored ID: $pingId, restored ID: $restoredPingId")

                if (restoredPingId != pingId) {
                    Log.w("MainActivity", "⚠️  Ping ID MISMATCH! Stored=$pingId, Restored=$restoredPingId")
                    Log.w("MainActivity", "Using restored ID (based on actual nonce) for Pong response")
                }

                val actualPingId = restoredPingId
                Log.i("MainActivity", "Ping restored successfully: $actualPingId")

                // Step 3: Generate Pong response (user authenticated = true)
                Log.d("MainActivity", "Creating Pong with Ping ID: $actualPingId")
                val encryptedPongBytes = com.securelegion.crypto.RustBridge.respondToPing(actualPingId, authenticated = true)

                if (encryptedPongBytes == null) {
                    Log.e("MainActivity", "Failed to generate Pong response")
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@MainActivity, "Failed to respond to message")
                    }
                    return@launch
                }

                Log.i("MainActivity", "Generated Pong response (${encryptedPongBytes.size} bytes)")

                // Step 4: Send Pong over NEW connection to sender (old connection is closed)
                val pongSent = com.securelegion.crypto.RustBridge.sendPongToNewConnection(senderOnionAddress, encryptedPongBytes)

                if (!pongSent) {
                    Log.e("MainActivity", "Failed to send Pong to $senderOnionAddress")
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@MainActivity, "Failed to connect to sender")
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

                    // Check if message has arrived by checking if Ping is still pending (using new queue format)
                    val currentPings = com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId)
                    val stillPending = currentPings.any { it.pingId == pingId }
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
                        ThemedToast.showLong(this@MainActivity, "Timeout: sender may be offline")
                    }
                    return@launch
                }

                Log.i("MainActivity", "Message blob received and processed by TorService")

                // Step 6: Remove pending Ping from queue (TorService already saved the message)
                com.securelegion.models.PendingPing.removeFromQueue(prefs, contactId, pingId)

                Log.i("MainActivity", "Pending Ping cleared from SharedPreferences")

                // Step 7: Clear notification if no more pending Pings (using new queue format)
                var totalRemainingPings = 0
                prefs.all.forEach { (key, value) ->
                    if (key.startsWith("ping_queue_") && value is String) {
                        try {
                            val jsonArray = org.json.JSONArray(value)
                            totalRemainingPings += jsonArray.length()
                        } catch (e: Exception) {
                            Log.w("MainActivity", "Failed to parse ping queue for key $key", e)
                        }
                    }
                }

                val notificationManager = getSystemService(android.app.NotificationManager::class.java)
                if (totalRemainingPings == 0) {
                    notificationManager.cancel(999)
                    Log.i("MainActivity", "All pings cleared - notification cancelled")
                } else {
                    // Update notification to show correct count
                    val openAppIntent = Intent(this@MainActivity, com.securelegion.LockActivity::class.java).apply {
                        putExtra("TARGET_ACTIVITY", "MainActivity")
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
                    }
                    val openAppPendingIntent = android.app.PendingIntent.getActivity(
                        this@MainActivity,
                        0,
                        openAppIntent,
                        android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
                    )

                    val notification = androidx.core.app.NotificationCompat.Builder(this@MainActivity, "auth_channel")
                        .setSmallIcon(R.drawable.ic_shield)
                        .setContentTitle("New Message")
                        .setContentText("You have $totalRemainingPings pending ${if (totalRemainingPings == 1) "message" else "messages"}")
                        .setPriority(androidx.core.app.NotificationCompat.PRIORITY_HIGH)
                        .setCategory(androidx.core.app.NotificationCompat.CATEGORY_MESSAGE)
                        .setAutoCancel(true)
                        .setContentIntent(openAppPendingIntent)
                        .setNumber(totalRemainingPings)
                        .build()

                    notificationManager.notify(999, notification)
                    Log.i("MainActivity", "Updated notification - $totalRemainingPings pending pings remaining")
                }

                // Step 8: Update UI
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@MainActivity, "Message from $senderName downloaded!")
                    // Refresh chat list to hide download button and show the new message
                    setupChatList()
                    // Update app badge
                    updateAppBadge()
                }

                Log.i("MainActivity", "Message download complete for contact $contactId")

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
            Log.w(TAG, "⚠️ Call initiation already in progress - ignoring duplicate request")
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
                intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_NAME, fullContact.displayName)
                intent.putExtra(VoiceCallActivity.EXTRA_CALL_ID, callId)
                intent.putExtra(VoiceCallActivity.EXTRA_IS_OUTGOING, true)
                intent.putExtra(VoiceCallActivity.EXTRA_OUR_EPHEMERAL_SECRET_KEY, ephemeralKeypair.secretKey.asBytes)
                startActivity(intent)

                // Get voice onion once for reuse in retries
                val torManager = com.securelegion.crypto.TorManager.getInstance(this@MainActivity)
                val myVoiceOnion = torManager.getVoiceOnionAddress() ?: ""
                if (myVoiceOnion.isEmpty()) {
                    Log.w("MainActivity", "⚠️ Voice onion address not yet created - call may fail")
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
                    contactName = fullContact.displayName,
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
