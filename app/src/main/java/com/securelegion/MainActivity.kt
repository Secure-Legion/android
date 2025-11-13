package com.securelegion

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
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
import com.securelegion.utils.startActivityWithSlideAnimation
import com.securelegion.workers.SelfDestructWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {
    private var currentTab = "messages" // Track current tab: "messages", "contacts", or "wallet"

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

    private fun startTorService() {
        // Start Tor foreground service for Ping-Pong protocol
        Log.i("MainActivity", "Starting Tor foreground service")
        TorService.start(this)
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
        // Only reload chat list if we're on the messages tab
        if (currentTab == "messages") {
            setupChatList()
        } else if (currentTab == "wallet") {
            // Reload wallet spinner to show newly created wallets
            setupWalletSpinner()
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

                    // Process each contact
                    for (contact in allContacts) {
                        val lastMessage = database.messageDao().getLastMessage(contact.id)

                        // Only include contacts with messages
                        if (lastMessage != null) {
                            val unreadCount = database.messageDao().getUnreadCount(contact.id)

                            val chat = Chat(
                                id = contact.id.toString(),
                                nickname = contact.displayName,
                                lastMessage = lastMessage.encryptedContent,
                                time = formatTimestamp(lastMessage.timestamp),
                                unreadCount = unreadCount,
                                isOnline = false,
                                avatar = contact.displayName.firstOrNull()?.toString()?.uppercase() ?: "?",
                                securityBadge = "E2E"
                            )
                            chatsList.add(Pair(chat, lastMessage.timestamp))
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
            overridePendingTransition(0, 0)
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
            overridePendingTransition(0, 0)
        }

        sendButton?.setOnClickListener {
            val intent = android.content.Intent(this, SendActivity::class.java)
            startActivity(intent)
            overridePendingTransition(0, 0)
        }

        recentBtn?.setOnClickListener {
            val intent = android.content.Intent(this, RecentTransactionsActivity::class.java)
            startActivity(intent)
            overridePendingTransition(0, 0)
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
            overridePendingTransition(0, 0)
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

                // Update last used timestamp
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@MainActivity, dbPassphrase)
                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())

                // Update UI on main thread
                withContext(Dispatchers.Main) {
                    Log.i("MainActivity", "Switched to wallet: ${wallet.walletId}")

                    // Reload wallet balance
                    loadWalletBalance()
                }

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to switch wallet", e)
            }
        }
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

                // Get wallet public key
                val keyManager = KeyManager.getInstance(this@MainActivity)
                val solanaAddress = keyManager.getSolanaAddress()

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
                val connectionId = prefs.getLong("ping_${contactId}_connection", -1L)
                val senderName = prefs.getString("ping_${contactId}_name", chat.nickname)

                if (pingId == null || connectionId == -1L) {
                    Log.e("MainActivity", "No pending Ping found for contact $contactId")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "No pending message found", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                Log.i("MainActivity", "Downloading message: pingId=$pingId, connectionId=$connectionId")

                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Downloading message from $senderName...", Toast.LENGTH_SHORT).show()
                }

                // Step 1: Generate Pong response (user authenticated = true)
                val encryptedPongBytes = com.securelegion.crypto.RustBridge.respondToPing(pingId, authenticated = true)

                if (encryptedPongBytes == null) {
                    Log.e("MainActivity", "Failed to generate Pong response")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Failed to respond to message", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                Log.i("MainActivity", "Generated Pong response (${encryptedPongBytes.size} bytes)")

                // Step 2: Send Pong back to sender
                com.securelegion.crypto.RustBridge.sendPongBytes(connectionId, encryptedPongBytes)
                Log.i("MainActivity", "Pong sent to sender")

                // Step 3: Receive the encrypted message
                val encryptedMessage = com.securelegion.crypto.RustBridge.receiveIncomingMessage(connectionId)

                if (encryptedMessage == null) {
                    Log.e("MainActivity", "Failed to receive message from sender")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Failed to receive message", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                Log.i("MainActivity", "Received encrypted message (${encryptedMessage.size} bytes)")

                // Step 4: Get contact info from database
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

                // Step 5: Decrypt the message
                val senderPublicKey = android.util.Base64.decode(contact.publicKeyBase64, android.util.Base64.NO_WRAP)
                val ourPrivateKey = keyManager.getSigningKeyBytes()
                val decryptedMessage = com.securelegion.crypto.RustBridge.decryptMessage(
                    encryptedMessage,
                    senderPublicKey,
                    ourPrivateKey
                )

                if (decryptedMessage == null) {
                    Log.e("MainActivity", "Failed to decrypt message from ${contact.displayName}")
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@MainActivity, "Failed to decrypt message", Toast.LENGTH_SHORT).show()
                    }
                    return@launch
                }

                Log.i("MainActivity", "Message decrypted successfully: \"$decryptedMessage\"")

                // Step 6: Store message in database
                val message = com.securelegion.database.entities.Message(
                    contactId = contactId,
                    messageId = java.util.UUID.randomUUID().toString(),
                    encryptedContent = decryptedMessage,
                    isSentByMe = false,
                    timestamp = System.currentTimeMillis(),
                    status = com.securelegion.database.entities.Message.STATUS_DELIVERED,
                    signatureBase64 = "", // No signature verification for now
                    nonceBase64 = "",
                    isRead = false,
                    selfDestructAt = null
                )
                database.messageDao().insertMessage(message)

                Log.i("MainActivity", "Message saved to database")

                // Step 7: Remove pending Ping from SharedPreferences
                prefs.edit().apply {
                    remove("ping_${contactId}_id")
                    remove("ping_${contactId}_connection")
                    remove("ping_${contactId}_name")
                    apply()
                }

                Log.i("MainActivity", "Pending Ping cleared")

                // Step 8: Clear notification if no more pending Pings
                val remainingPings = prefs.all.filter { it.key.endsWith("_id") }.size
                if (remainingPings == 0) {
                    val notificationManager = getSystemService(android.app.NotificationManager::class.java)
                    notificationManager.cancel(999)
                }

                // Step 9: Update UI
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Message from $senderName downloaded", Toast.LENGTH_SHORT).show()
                    // Refresh chat list to hide download button and show the new message
                    setupChatList()
                    // Update app badge
                    updateAppBadge()
                }

            } catch (e: Exception) {
                Log.e("MainActivity", "Failed to download message", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(this@MainActivity, "Download failed: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }
}
