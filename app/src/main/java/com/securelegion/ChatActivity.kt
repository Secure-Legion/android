package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.MessageAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.MessageService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ChatActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "ChatActivity"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "CONTACT_NAME"
        const val EXTRA_CONTACT_ADDRESS = "CONTACT_ADDRESS"
    }

    private lateinit var messagesRecyclerView: RecyclerView
    private lateinit var messageAdapter: MessageAdapter
    private lateinit var messageService: MessageService
    private lateinit var messageInput: EditText
    private lateinit var sendButton: ImageView

    private var contactId: Long = -1
    private var contactName: String = "@user"
    private var contactAddress: String = ""
    private var isShowingSendButton = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        // Get contact info from intent
        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)
        contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: "@user"
        contactAddress = intent.getStringExtra(EXTRA_CONTACT_ADDRESS) ?: ""

        if (contactId == -1L) {
            Toast.makeText(this, "Error: Invalid contact", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        Log.d(TAG, "Opening chat with: $contactName (ID: $contactId)")

        // Initialize services
        messageService = MessageService(this)

        // Setup UI
        findViewById<TextView>(R.id.chatName).text = contactName
        findViewById<TextView>(R.id.chatStatus).text = "● Offline" // TODO: Add online status

        setupRecyclerView()
        setupClickListeners()
        setupBottomNavigation()

        // Check for pre-filled message from ComposeActivity
        val preFilledMessage = intent.getStringExtra("PRE_FILL_MESSAGE")
        if (!preFilledMessage.isNullOrBlank()) {
            messageInput.setText(preFilledMessage)
            // Get security options
            val enableSelfDestruct = intent.getBooleanExtra("ENABLE_SELF_DESTRUCT", false)
            val enableReadReceipt = intent.getBooleanExtra("ENABLE_READ_RECEIPT", true)
            // Automatically send the message with security options (will load messages after sending)
            sendMessage(enableSelfDestruct, enableReadReceipt)
        } else {
            // Only load messages if there's no pre-filled message (sendMessage will load them)
            loadMessages()
        }
    }

    private fun setupRecyclerView() {
        messagesRecyclerView = findViewById(R.id.messagesRecyclerView)
        messageAdapter = MessageAdapter()

        messagesRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@ChatActivity)
            adapter = messageAdapter
        }
    }

    private fun setupClickListeners() {
        // Initialize views
        messageInput = findViewById(R.id.messageInput)
        sendButton = findViewById(R.id.sendButton)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Options button
        findViewById<View>(R.id.optionsButton).setOnClickListener {
            Toast.makeText(this, "Options menu", Toast.LENGTH_SHORT).show()
            // TODO: Show options menu
        }

        // Send/Mic button - dynamically switches based on text
        sendButton.setOnClickListener {
            if (isShowingSendButton) {
                // Send button - send text message
                sendMessage(enableSelfDestruct = false, enableReadReceipt = true)
            } else {
                // Mic button - start voice recording
                startVoiceRecording()
            }
        }

        // Monitor text input to switch between mic and send button
        messageInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                val hasText = !s.isNullOrBlank()

                if (hasText && !isShowingSendButton) {
                    // Switch to send button
                    sendButton.setImageResource(R.drawable.ic_send)
                    isShowingSendButton = true
                } else if (!hasText && isShowingSendButton) {
                    // Switch to mic button
                    sendButton.setImageResource(R.drawable.ic_mic)
                    isShowingSendButton = false
                }
            }

            override fun afterTextChanged(s: Editable?) {}
        })
    }

    private fun startVoiceRecording() {
        // TODO: Implement voice recording
        Toast.makeText(this, "Voice recording coming soon", Toast.LENGTH_SHORT).show()
        Log.d(TAG, "Voice recording feature - to be implemented")
    }

    private fun loadMessages() {
        lifecycleScope.launch {
            try {
                Log.d(TAG, "Loading messages for contact: $contactId")
                val messages = messageService.getMessagesForContact(contactId)
                Log.d(TAG, "Loaded ${messages.size} messages")

                withContext(Dispatchers.Main) {
                    messageAdapter.updateMessages(messages)
                    if (messages.isNotEmpty()) {
                        messagesRecyclerView.scrollToPosition(messages.size - 1)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load messages", e)
                withContext(Dispatchers.Main) {
                    Toast.makeText(
                        this@ChatActivity,
                        "Failed to load messages: ${e.message}",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }
    }

    private fun sendMessage(enableSelfDestruct: Boolean = false, enableReadReceipt: Boolean = true) {
        val messageText = messageInput.text.toString().trim()

        if (messageText.isBlank()) {
            return
        }

        Log.d(TAG, "Sending message: $messageText (self-destruct=$enableSelfDestruct, read-receipt=$enableReadReceipt)")

        lifecycleScope.launch {
            try {
                // Clear input immediately
                withContext(Dispatchers.Main) {
                    messageInput.text.clear()
                }

                // Send message with security options
                val result = messageService.sendMessage(contactId, messageText, enableSelfDestruct, enableReadReceipt)

                if (result.isSuccess) {
                    Log.i(TAG, "Message sent successfully")

                    // Reload messages to show the new message
                    loadMessages()
                } else {
                    throw result.exceptionOrNull() ?: Exception("Unknown error")
                }
            } catch (e: Exception) {
                // Silent failure - message saved to database, will retry later
                Log.e(TAG, "Failed to send message (will retry later)", e)

                // Still reload messages to show the pending message
                loadMessages()
            }
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
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
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
