package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.Toast
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ComposeActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "ComposeActivity"
    }

    private lateinit var recipientInput: EditText
    private lateinit var contactSearchResults: RecyclerView
    private lateinit var contactAdapter: ContactAdapter

    private var allContacts: List<DbContact> = emptyList()
    private var selectedContact: DbContact? = null

    // Security options state
    private var isSelfDestructEnabled = false
    private var isReadReceiptEnabled = true // Default enabled

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_compose)

        recipientInput = findViewById(R.id.recipientInput)
        contactSearchResults = findViewById(R.id.contactSearchResults)

        setupContactSearch()
        loadContacts()
        setupBottomNavigation()
        setupSecurityOptions()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Send button
        findViewById<View>(R.id.sendButton).setOnClickListener {
            sendMessage()
        }
    }

    private fun setupSecurityOptions() {
        val selfDestructOption = findViewById<View>(R.id.selfDestructOption)
        val readReceiptOption = findViewById<View>(R.id.readReceiptOption)

        // Update initial states
        updateSecurityOptionUI(selfDestructOption, isSelfDestructEnabled)
        updateSecurityOptionUI(readReceiptOption, isReadReceiptEnabled)

        // Self-destruct toggle
        selfDestructOption.setOnClickListener {
            isSelfDestructEnabled = !isSelfDestructEnabled
            updateSecurityOptionUI(selfDestructOption, isSelfDestructEnabled)

            val message = if (isSelfDestructEnabled) {
                "Self-destruct enabled (24h)"
            } else {
                "Self-destruct disabled"
            }
            com.securelegion.utils.ToastUtils.showCustomToast(this, message)
        }

        // Read receipt toggle
        readReceiptOption.setOnClickListener {
            isReadReceiptEnabled = !isReadReceiptEnabled
            updateSecurityOptionUI(readReceiptOption, isReadReceiptEnabled)

            val message = if (isReadReceiptEnabled) {
                "Read receipts enabled"
            } else {
                "Read receipts disabled"
            }
            com.securelegion.utils.ToastUtils.showCustomToast(this, message)
        }
    }

    private fun updateSecurityOptionUI(view: View, isEnabled: Boolean) {
        if (isEnabled) {
            view.setBackgroundResource(R.drawable.metallic_button_bg)
            view.alpha = 1.0f
        } else {
            view.setBackgroundResource(R.drawable.settings_item_bg)
            view.alpha = 0.5f
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
                    database.contactDao().getAllContacts()
                }

                Log.d(TAG, "Loaded ${allContacts.size} contacts for search")
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
                    address = dbContact.solanaAddress
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
            Toast.makeText(this, "Please select a contact", Toast.LENGTH_SHORT).show()
            return
        }

        if (message.isBlank()) {
            Toast.makeText(this, "Please enter a message", Toast.LENGTH_SHORT).show()
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
                enableSelfDestruct = isSelfDestructEnabled,
                enableReadReceipt = isReadReceiptEnabled,
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
