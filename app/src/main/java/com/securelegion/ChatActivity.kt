package com.securelegion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
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
import com.securelegion.crypto.TorManager
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
    private var isDownloadInProgress = false

    // BroadcastReceiver for instant message display and new Pings
    private val messageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                "com.securelegion.MESSAGE_RECEIVED" -> {
                    val receivedContactId = intent.getLongExtra("CONTACT_ID", -1L)
                    Log.d(TAG, "MESSAGE_RECEIVED broadcast: received contactId=$receivedContactId, current contactId=$contactId")
                    if (receivedContactId == contactId) {
                        Log.i(TAG, "New message for current contact - reloading messages")
                        // Verify pending ping is cleared before resetting flag
                        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                        if (!prefs.contains("ping_${contactId}_id")) {
                            isDownloadInProgress = false  // Download complete, ping cleared
                        }
                        runOnUiThread {
                            lifecycleScope.launch {
                                loadMessages()
                            }
                        }
                    } else {
                        Log.d(TAG, "Message for different contact, ignoring")
                    }
                }
                "com.securelegion.NEW_PING" -> {
                    val receivedContactId = intent.getLongExtra("CONTACT_ID", -1L)
                    Log.d(TAG, "NEW_PING broadcast: received contactId=$receivedContactId, current contactId=$contactId")

                    if (receivedContactId == contactId) {
                        // NEW_PING for current contact
                        if (!isDownloadInProgress) {
                            // Not downloading - this is a legitimate new ping, show lock icon
                            Log.i(TAG, "New Ping for current contact - reloading to show lock icon")
                            runOnUiThread {
                                lifecycleScope.launch {
                                    loadMessages()
                                }
                            }
                        } else {
                            Log.d(TAG, "NEW_PING for current contact during download - ignoring to prevent ghost")
                        }
                    } else if (receivedContactId != -1L) {
                        // NEW_PING for different contact - reload to update UI
                        Log.i(TAG, "New Ping for different contact - reloading")
                        runOnUiThread {
                            lifecycleScope.launch {
                                loadMessages()
                            }
                        }
                    }
                }
            }
        }
    }

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

        setupRecyclerView()
        setupClickListeners()

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
            lifecycleScope.launch {
                loadMessages()
            }
        }

        // Register broadcast receiver for instant message display and new Pings (stays registered even when paused)
        val filter = IntentFilter().apply {
            addAction("com.securelegion.MESSAGE_RECEIVED")
            addAction("com.securelegion.NEW_PING")
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(messageReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(messageReceiver, filter)
        }
        Log.d(TAG, "Message receiver registered in onCreate for MESSAGE_RECEIVED and NEW_PING")
    }

    override fun onDestroy() {
        super.onDestroy()
        // Unregister broadcast receiver when activity is destroyed
        try {
            unregisterReceiver(messageReceiver)
            Log.d(TAG, "Message receiver unregistered in onDestroy")
        } catch (e: IllegalArgumentException) {
            // Receiver was not registered, ignore
            Log.w(TAG, "Receiver was not registered during onDestroy")
        }
    }

    private fun setupRecyclerView() {
        messagesRecyclerView = findViewById(R.id.messagesRecyclerView)
        messageAdapter = MessageAdapter(
            onDownloadClick = {
                handleDownloadClick()
            }
        )

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

    private suspend fun loadMessages() {
        try {
            Log.d(TAG, "Loading messages for contact: $contactId")
            val messages = withContext(Dispatchers.IO) {
                messageService.getMessagesForContact(contactId)
            }
            Log.d(TAG, "Loaded ${messages.size} messages")
            messages.forEach { msg ->
                Log.d(TAG, "Message: ${msg.encryptedContent.take(20)}... status=${msg.status}")
            }

            // Mark all received messages as read (updates unread count)
            val markedCount = withContext(Dispatchers.IO) {
                val keyManager = KeyManager.getInstance(this@ChatActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                val unreadMessages = messages.filter { !it.isSentByMe && !it.isRead }
                unreadMessages.forEach { message ->
                    val updatedMessage = message.copy(isRead = true)
                    database.messageDao().updateMessage(updatedMessage)
                }
                unreadMessages.size
            }

            if (markedCount > 0) {
                Log.d(TAG, "Marked $markedCount messages as read")
                // Notify MainActivity to refresh unread counts (explicit broadcast)
                val intent = Intent("com.securelegion.NEW_PING")
                intent.setPackage(packageName) // Make it explicit
                sendBroadcast(intent)
            }

            // Check for pending Ping (but not if download is in progress to prevent ghost)
            val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
            val hasPendingPing = prefs.contains("ping_${contactId}_id") && !isDownloadInProgress
            val pendingSenderName = if (hasPendingPing) contactName else null
            val pendingTimestamp = if (hasPendingPing) prefs.getLong("ping_${contactId}_timestamp", System.currentTimeMillis()) else null

            withContext(Dispatchers.Main) {
                Log.d(TAG, "Updating adapter with ${messages.size} messages" +
                    if (hasPendingPing) " + 1 pending" else "")
                messageAdapter.updateMessages(
                    messages,
                    pendingSenderName,
                    pendingTimestamp
                )
                messagesRecyclerView.post {
                    val totalItems = messages.size + (if (hasPendingPing) 1 else 0)
                    if (totalItems > 0) {
                        messagesRecyclerView.scrollToPosition(totalItems - 1)
                    }
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
                // Use callback to update UI immediately when message is saved (before Tor send)
                val result = messageService.sendMessage(
                    contactId = contactId,
                    plaintext = messageText,
                    enableSelfDestruct = enableSelfDestruct,
                    enableReadReceipt = enableReadReceipt,
                    onMessageSaved = { savedMessage ->
                        // Message saved to DB - update UI immediately to show PENDING message
                        Log.d(TAG, "Message saved to DB, updating UI immediately")
                        lifecycleScope.launch {
                            loadMessages()
                        }
                    }
                )

                // Reload again after Tor send completes to update status indicator
                loadMessages()

                if (result.isFailure) {
                    Log.e(TAG, "Failed to send message", result.exceptionOrNull())
                }
            } catch (e: Exception) {
                // Silent failure - message saved to database, will retry later
                Log.e(TAG, "Failed to send message (will retry later)", e)

                // Reload messages to show the pending message
                loadMessages()
            }
        }
    }


    private fun handleDownloadClick() {
        Log.i(TAG, "Download button clicked for contact $contactId")

        // Check if we have a pending Ping
        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
        val pingId = prefs.getString("ping_${contactId}_id", null)

        if (pingId == null) {
            Toast.makeText(this, "No pending message", Toast.LENGTH_SHORT).show()
            return
        }

        // Set flag to prevent showing pending message again during download
        isDownloadInProgress = true

        // Start the download service
        com.securelegion.services.DownloadMessageService.start(this, contactId, contactName)

        // DON'T reload messages here - let the "downloading" text stay visible
        // The service will broadcast MESSAGE_RECEIVED when done, which will trigger a reload
    }

}
