package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.ChatAdapter
import com.securelegion.adapters.ContactAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.models.Chat
import com.securelegion.models.Contact
import com.securelegion.utils.startActivityWithSlideAnimation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        setupClickListeners()
        setupChatList()
        setupContactsList()

        // Check if we should show wallet tab
        if (intent.getBooleanExtra("SHOW_WALLET", false)) {
            showWalletTab()
        }
    }

    private fun setupChatList() {
        val chatList = findViewById<RecyclerView>(R.id.chatList)
        val emptyState = findViewById<View>(R.id.emptyState)

        // Sample chat data
        val chats = listOf(
            Chat(
                id = "1",
                nickname = "@nighthawk",
                lastMessage = "◆ Message ready to download",
                time = "2m",
                unreadCount = 2,
                isOnline = true,
                avatar = "A",
                securityBadge = "E2E"
            ),
            Chat(
                id = "2",
                nickname = "@cryptowolf",
                lastMessage = "▸ Downloading message...",
                time = "1h",
                unreadCount = 0,
                isOnline = false,
                avatar = "B",
                securityBadge = "E2E"
            ),
            Chat(
                id = "3",
                nickname = "@phantom",
                lastMessage = "◇ New Message",
                time = "3h",
                unreadCount = 1,
                isOnline = true,
                avatar = "C",
                securityBadge = "E2E"
            ),
            Chat(
                id = "4",
                nickname = "@shadowtech",
                lastMessage = "✓ Message decrypted",
                time = "5h",
                unreadCount = 0,
                isOnline = false,
                avatar = "D",
                securityBadge = ""
            ),
            Chat(
                id = "5",
                nickname = "@silentecho",
                lastMessage = "Meet at the secure location",
                time = "1d",
                unreadCount = 0,
                isOnline = false,
                avatar = "E",
                securityBadge = ""
            ),
            Chat(
                id = "6",
                nickname = "@stealthmode",
                lastMessage = "Got it, will proceed as planned",
                time = "2d",
                unreadCount = 0,
                isOnline = false,
                avatar = "F",
                securityBadge = ""
            )
        )

        if (chats.isNotEmpty()) {
            emptyState.visibility = View.GONE
            chatList.visibility = View.VISIBLE
            chatList.layoutManager = LinearLayoutManager(this)
            chatList.adapter = ChatAdapter(chats) { chat ->
                val intent = android.content.Intent(this, ChatActivity::class.java)
                intent.putExtra("CHAT_NAME", chat.nickname)
                intent.putExtra("IS_ONLINE", chat.isOnline)
                startActivityWithSlideAnimation(intent)
            }
        } else {
            emptyState.visibility = View.VISIBLE
            chatList.visibility = View.GONE
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
            startActivityWithSlideAnimation(intent)
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
        val manageTokensBtn = walletView?.findViewById<View>(R.id.manageTokensBtn)
        val viewAllBtn = walletView?.findViewById<View>(R.id.viewAllBtn)

        receiveButton?.setOnClickListener {
            val intent = android.content.Intent(this, ReceiveActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }

        sendButton?.setOnClickListener {
            val intent = android.content.Intent(this, SendActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }

        manageTokensBtn?.setOnClickListener {
            val intent = android.content.Intent(this, ManageTokensActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }

        viewAllBtn?.setOnClickListener {
            val intent = android.content.Intent(this, TransactionsActivity::class.java)
            startActivityWithSlideAnimation(intent)
        }
    }

    private fun showAllChatsTab() {
        findViewById<View>(R.id.chatListContainer).visibility = View.VISIBLE
        findViewById<View>(R.id.emptyState).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.GONE
        findViewById<View>(R.id.walletView).visibility = View.GONE

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
        findViewById<View>(R.id.chatListContainer).visibility = View.GONE
        findViewById<View>(R.id.emptyState).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.VISIBLE
        findViewById<View>(R.id.walletView).visibility = View.GONE

        // Update tab styling
        findViewById<android.widget.TextView>(R.id.tabContacts).apply {
            setTextColor(ContextCompat.getColor(context, R.color.primary_blue))
            setTypeface(null, android.graphics.Typeface.BOLD)
        }

        // Update tab indicators
        findViewById<View>(R.id.indicatorContacts).setBackgroundColor(ContextCompat.getColor(this, R.color.primary_blue))
    }

    private fun showWalletTab() {
        findViewById<View>(R.id.chatListContainer).visibility = View.GONE
        findViewById<View>(R.id.emptyState).visibility = View.GONE
        findViewById<View>(R.id.contactsView).visibility = View.GONE
        findViewById<View>(R.id.walletView).visibility = View.VISIBLE

        // Setup wallet buttons now that the view is visible
        setupWalletButtons()

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
}
