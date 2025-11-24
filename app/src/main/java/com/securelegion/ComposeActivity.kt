package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.ContactAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact as DbContact
import com.securelegion.models.Contact
import com.securelegion.services.MessageService
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ComposeActivity : BaseActivity() {

    companion object {
        private const val TAG = "ComposeActivity"
    }

    private lateinit var recipientInput: EditText
    private lateinit var contactSearchResults: RecyclerView
    private lateinit var contactAdapter: ContactAdapter

    private var allContacts: List<DbContact> = emptyList()
    private var selectedContact: DbContact? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_compose)

        recipientInput = findViewById(R.id.recipientInput)
        contactSearchResults = findViewById(R.id.contactSearchResults)

        setupContactSearch()
        loadContacts()
        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Send button
        findViewById<View>(R.id.sendButton).setOnClickListener {
            sendMessage()
        }
    }

    private fun setupContactSearch() {
        contactSearchResults.layoutManager = LinearLayoutManager(this)
        contactAdapter = ContactAdapter(emptyList()) { contact ->
            // Contact selected from search
            selectedContact = allContacts.find { it.id.toString() == contact.id }
            recipientInput.setText(contact.name)
            recipientInput.setSelection(contact.name.length)
            contactSearchResults.visibility = View.GONE
        }
        contactSearchResults.adapter = contactAdapter

        // Add text watcher for live search
        recipientInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}

            override fun afterTextChanged(s: Editable?) {
                val query = s?.toString() ?: ""
                filterContacts(query)
            }
        })
    }

    private fun loadContacts() {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@ComposeActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ComposeActivity, dbPassphrase)

                allContacts = withContext(Dispatchers.IO) {
                    // Only load CONFIRMED friends (not PENDING)
                    database.contactDao().getAllContacts()
                        .filter { it.friendshipStatus == DbContact.FRIENDSHIP_CONFIRMED }
                }

                Log.d(TAG, "Loaded ${allContacts.size} CONFIRMED friends for messaging")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contacts", e)
            }
        }
    }

    private fun filterContacts(query: String) {
        if (query.isBlank()) {
            contactSearchResults.visibility = View.GONE
            return
        }

        val filtered = allContacts.filter {
            it.displayName.contains(query, ignoreCase = true) ||
            it.solanaAddress.contains(query, ignoreCase = true)
        }

        if (filtered.isEmpty()) {
            contactSearchResults.visibility = View.GONE
        } else {
            val uiContacts = filtered.map { dbContact ->
                Contact(
                    id = dbContact.id.toString(),
                    name = dbContact.displayName,
                    address = dbContact.solanaAddress,
                    friendshipStatus = dbContact.friendshipStatus
                )
            }
            contactAdapter.updateContacts(uiContacts)
            contactSearchResults.visibility = View.VISIBLE
        }
    }

    private fun sendMessage() {
        val message = findViewById<EditText>(R.id.messageInput).text.toString()
        val sendButton = findViewById<View>(R.id.sendButton)

        if (selectedContact == null) {
            ThemedToast.show(this, "Please select a contact")
            return
        }

        // Verify friendship status - only allow messaging CONFIRMED friends
        if (selectedContact!!.friendshipStatus != DbContact.FRIENDSHIP_CONFIRMED) {
            ThemedToast.show(this, "Can only message confirmed friends")
            Log.w(TAG, "Blocked message to ${selectedContact!!.displayName} - friendship status: ${selectedContact!!.friendshipStatus}")
            return
        }

        if (message.isBlank()) {
            ThemedToast.show(this, "Please enter a message")
            return
        }

        // Disable button to prevent multiple sends
        sendButton.isEnabled = false
        sendButton.alpha = 0.5f

        // Send message in background and return to main screen immediately
        lifecycleScope.launch {
            val messageService = MessageService(this@ComposeActivity)

            // Send message with callback - navigate back as soon as it's saved to DB
            messageService.sendMessage(
                contactId = selectedContact!!.id,
                plaintext = message,
                selfDestructDurationMs = null,
                enableReadReceipt = true,
                onMessageSaved = { savedMessage ->
                    // Message saved to DB - navigate back immediately
                    // Tor send continues in background
                    lifecycleScope.launch(Dispatchers.Main) {
                        val intent = Intent(this@ComposeActivity, MainActivity::class.java)
                        intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
                        startActivity(intent)
                        finish()
                    }
                }
            )
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
