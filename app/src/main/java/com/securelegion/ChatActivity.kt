package com.securelegion

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.MotionEvent
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.MessageAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.TorManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
import com.securelegion.services.MessageService
import com.securelegion.utils.SecureWipe
import com.securelegion.utils.VoiceRecorder
import com.securelegion.utils.VoicePlayer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class ChatActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "ChatActivity"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "CONTACT_NAME"
        const val EXTRA_CONTACT_ADDRESS = "CONTACT_ADDRESS"
        private const val PERMISSION_REQUEST_CODE = 100
    }

    private lateinit var messagesRecyclerView: RecyclerView
    private lateinit var messageAdapter: MessageAdapter
    private lateinit var messageService: MessageService
    private lateinit var messageInput: EditText
    private lateinit var sendButton: ImageView
    private lateinit var textInputLayout: LinearLayout
    private lateinit var voiceRecordingLayout: LinearLayout
    private lateinit var recordingTimer: TextView
    private lateinit var cancelRecordingButton: ImageView
    private lateinit var sendVoiceButton: ImageView

    private var contactId: Long = -1
    private var contactName: String = "@user"
    private var contactAddress: String = ""
    private var isShowingSendButton = false
    private var isDownloadInProgress = false
    private var isSelectionMode = false

    // Voice recording
    private lateinit var voiceRecorder: VoiceRecorder
    private lateinit var voicePlayer: VoicePlayer
    private var recordingFile: File? = null
    private var recordingHandler: Handler? = null
    private var currentlyPlayingMessageId: String? = null

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
                        // Check if pending ping exists - if cleared during download, allow refresh
                        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                        val hasPendingPing = prefs.contains("ping_${contactId}_id")

                        if (!isDownloadInProgress || !hasPendingPing) {
                            // Either not downloading, OR download completed (ping cleared) - refresh UI
                            if (isDownloadInProgress && !hasPendingPing) {
                                Log.i(TAG, "Download completed (ping cleared) - resetting flag and refreshing UI")
                                isDownloadInProgress = false
                            } else {
                                Log.i(TAG, "New Ping for current contact - reloading to show lock icon")
                            }
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
                "com.securelegion.DOWNLOAD_FAILED" -> {
                    val receivedContactId = intent.getLongExtra("CONTACT_ID", -1L)
                    Log.w(TAG, "DOWNLOAD_FAILED broadcast: received contactId=$receivedContactId, current contactId=$contactId")

                    if (receivedContactId == contactId) {
                        // Download failed for current contact - reset flag and refresh UI
                        Log.w(TAG, "Download failed - resetting download flag and refreshing UI")
                        isDownloadInProgress = false
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
        voiceRecorder = VoiceRecorder(this)
        voicePlayer = VoicePlayer(this)

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
            addAction("com.securelegion.DOWNLOAD_FAILED")
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(messageReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(messageReceiver, filter)
        }
        Log.d(TAG, "Message receiver registered in onCreate for MESSAGE_RECEIVED, NEW_PING, and DOWNLOAD_FAILED")
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

        // Cleanup voice player
        voicePlayer.release()
        recordingHandler?.removeCallbacksAndMessages(null)
    }

    private fun setupRecyclerView() {
        messagesRecyclerView = findViewById(R.id.messagesRecyclerView)
        messageAdapter = MessageAdapter(
            onDownloadClick = {
                handleDownloadClick()
            },
            onVoicePlayClick = { message ->
                playVoiceMessage(message)
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
        textInputLayout = findViewById(R.id.textInputLayout)
        voiceRecordingLayout = findViewById(R.id.voiceRecordingLayout)
        recordingTimer = findViewById(R.id.recordingTimer)
        cancelRecordingButton = findViewById(R.id.cancelRecordingButton)
        sendVoiceButton = findViewById(R.id.sendVoiceButton)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            if (isSelectionMode) {
                // Exit selection mode
                toggleSelectionMode()
            } else {
                finish()
            }
        }

        // Delete button
        findViewById<View>(R.id.deleteButton).setOnClickListener {
            if (isSelectionMode) {
                // If messages are selected, delete them
                // If no messages selected, exit selection mode
                val selectedIds = messageAdapter.getSelectedMessageIds()
                if (selectedIds.isEmpty()) {
                    toggleSelectionMode()
                } else {
                    deleteSelectedMessages()
                }
            } else {
                // Enter selection mode
                toggleSelectionMode()
            }
        }

        // Send/Mic button - dynamically switches based on text
        // Use OnTouchListener to detect hold down for voice recording
        sendButton.setOnTouchListener { view, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    if (isShowingSendButton) {
                        // Has text - let click handler send it
                        false
                    } else {
                        // Empty text - start voice recording on hold
                        startVoiceRecording()
                        true
                    }
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    if (isShowingSendButton) {
                        // Has text - let click handler process it
                        false
                    } else {
                        // Recording mode - do nothing on release
                        true
                    }
                }
                else -> false
            }
        }

        // Fallback click handler for sending text
        sendButton.setOnClickListener {
            if (isShowingSendButton) {
                sendMessage(enableSelfDestruct = false, enableReadReceipt = true)
            }
        }

        // Cancel recording button
        cancelRecordingButton.setOnClickListener {
            cancelVoiceRecording()
        }

        // Send voice message button
        sendVoiceButton.setOnClickListener {
            sendVoiceMessage()
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
        // Check permission
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this,
                arrayOf(Manifest.permission.RECORD_AUDIO), PERMISSION_REQUEST_CODE)
            return
        }

        try {
            recordingFile = voiceRecorder.startRecording()
            Log.d(TAG, "Voice recording started")

            // Switch UI to recording mode
            textInputLayout.visibility = View.GONE
            voiceRecordingLayout.visibility = View.VISIBLE

            // Start timer
            startRecordingTimer()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start recording", e)
            Toast.makeText(this, "Failed to start recording: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun startRecordingTimer() {
        recordingHandler = Handler(Looper.getMainLooper())
        val timerRunnable = object : Runnable {
            override fun run() {
                val duration = voiceRecorder.getCurrentDuration()
                recordingTimer.text = String.format("%d:%02d",
                    duration / 60, duration % 60)
                recordingHandler?.postDelayed(this, 1000)
            }
        }
        recordingHandler?.post(timerRunnable)
    }

    private fun cancelVoiceRecording() {
        Log.d(TAG, "Voice recording cancelled")
        recordingHandler?.removeCallbacksAndMessages(null)
        voiceRecorder.cancelRecording()
        recordingFile = null

        // Switch back to text input mode
        voiceRecordingLayout.visibility = View.GONE
        textInputLayout.visibility = View.VISIBLE
    }

    private fun sendVoiceMessage() {
        recordingHandler?.removeCallbacksAndMessages(null)

        try {
            val (file, duration) = voiceRecorder.stopRecording()
            val audioBytes = voiceRecorder.readAudioFile(file)

            Log.d(TAG, "Sending voice message: ${audioBytes.size} bytes, ${duration}s")

            // Switch back to text input mode
            voiceRecordingLayout.visibility = View.GONE
            textInputLayout.visibility = View.VISIBLE

            // Send voice message
            lifecycleScope.launch {
                try {
                    val result = messageService.sendVoiceMessage(
                        contactId = contactId,
                        audioBytes = audioBytes,
                        durationSeconds = duration,
                        selfDestructDurationMs = null
                    ) { savedMessage ->
                        // Message saved to DB - update UI immediately
                        Log.d(TAG, "Voice message saved to DB, updating UI")
                        runOnUiThread {
                            lifecycleScope.launch {
                                loadMessages()
                            }
                        }
                    }

                    if (result.isSuccess) {
                        Log.i(TAG, "Voice message sent successfully")
                        withContext(Dispatchers.Main) {
                            loadMessages()
                        }
                    } else {
                        Log.e(TAG, "Failed to send voice message: ${result.exceptionOrNull()?.message}")
                        withContext(Dispatchers.Main) {
                            Toast.makeText(this@ChatActivity,
                                "Failed to send voice message", Toast.LENGTH_SHORT).show()
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending voice message", e)
                    withContext(Dispatchers.Main) {
                        Toast.makeText(this@ChatActivity,
                            "Error: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }

            // Cleanup temp file
            file.delete()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send voice message", e)
            Toast.makeText(this, "Failed to send voice message: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // Permission granted, start recording
                startVoiceRecording()
            } else {
                Toast.makeText(this, "Microphone permission required for voice messages",
                    Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun playVoiceMessage(message: com.securelegion.database.entities.Message) {
        val filePath = message.voiceFilePath
        if (filePath == null) {
            Log.e(TAG, "Voice message has no file path")
            Toast.makeText(this, "Voice file not found", Toast.LENGTH_SHORT).show()
            return
        }

        val file = File(filePath)
        if (!file.exists()) {
            Log.e(TAG, "Voice file does not exist: $filePath")
            Toast.makeText(this, "Voice file not found", Toast.LENGTH_SHORT).show()
            return
        }

        Log.d(TAG, "Playing voice message: ${message.messageId}")

        // Check if this message is already playing
        if (currentlyPlayingMessageId == message.messageId) {
            // Pause playback
            voicePlayer.pause()
            currentlyPlayingMessageId = null
            messageAdapter.setCurrentlyPlayingMessageId(null)
            Log.d(TAG, "Paused voice message")
        } else {
            // Stop any currently playing message
            if (currentlyPlayingMessageId != null) {
                voicePlayer.stop()
            }

            // Start playing
            voicePlayer.play(
                filePath = filePath,
                onCompletion = {
                    Log.d(TAG, "Voice message playback completed")
                    currentlyPlayingMessageId = null
                    runOnUiThread {
                        messageAdapter.setCurrentlyPlayingMessageId(null)
                    }
                },
                onProgress = { currentPos, duration ->
                    // Optionally update progress bar in real-time
                    // Would need to pass ViewHolder reference to update progress
                }
            )
            currentlyPlayingMessageId = message.messageId
            messageAdapter.setCurrentlyPlayingMessageId(message.messageId)
            Log.d(TAG, "Started playing voice message")
        }
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
                    selfDestructDurationMs = if (enableSelfDestruct) 24 * 60 * 60 * 1000L else null,
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

    private fun toggleSelectionMode() {
        isSelectionMode = !isSelectionMode
        messageAdapter.setSelectionMode(isSelectionMode)

        // Update delete button appearance based on mode
        val deleteButton = findViewById<ImageView>(R.id.deleteButton)
        if (isSelectionMode) {
            deleteButton.setColorFilter(ContextCompat.getColor(this, R.color.accent_blue))
        } else {
            deleteButton.clearColorFilter()
        }

        Log.d(TAG, "Selection mode: $isSelectionMode")
    }

    private fun deleteSelectedMessages() {
        val selectedIds = messageAdapter.getSelectedMessageIds()

        if (selectedIds.isEmpty()) {
            return
        }

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@ChatActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                    // Securely delete each selected message
                    selectedIds.forEach { messageId ->
                        // Get the message to check if it's a voice message
                        val message = database.messageDao().getMessageById(messageId)

                        // If it's a voice message, securely wipe the audio file using DOD 3-pass
                        if (message?.messageType == Message.MESSAGE_TYPE_VOICE && message.voiceFilePath != null) {
                            try {
                                val voiceFile = File(message.voiceFilePath)
                                if (voiceFile.exists()) {
                                    SecureWipe.secureDeleteFile(voiceFile)
                                    Log.d(TAG, "✓ Securely wiped voice file: ${voiceFile.name}")
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to securely wipe voice file", e)
                            }
                        }

                        // Delete from database
                        database.messageDao().deleteMessageById(messageId)
                    }

                    // VACUUM database to compact and remove deleted records
                    try {
                        database.openHelper.writableDatabase.execSQL("VACUUM")
                        Log.d(TAG, "✓ Database vacuumed after message deletion")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to vacuum database", e)
                    }
                }

                Log.d(TAG, "Securely deleted ${selectedIds.size} messages using DOD 3-pass wiping")

                // Exit selection mode and reload messages
                toggleSelectionMode()
                loadMessages()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete messages", e)
            }
        }
    }

}
