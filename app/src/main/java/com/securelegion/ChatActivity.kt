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
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
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
import com.securelegion.utils.ThemedToast
import com.securelegion.utils.VoiceRecorder
import com.securelegion.utils.VoicePlayer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class ChatActivity : BaseActivity() {

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
    private lateinit var sendButton: View
    private lateinit var sendButtonIcon: ImageView
    private lateinit var plusButton: View
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

    // Track which specific pings are currently being downloaded
    private val downloadingPingIds = mutableSetOf<String>()

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

                        // Launch coroutine immediately to avoid blocking broadcast receiver
                        lifecycleScope.launch(Dispatchers.Main) {
                            // Clean up downloading set - check queue in background
                            val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                            val pendingPings = withContext(Dispatchers.IO) {
                                com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId)
                            }

                            // Remove completed downloads from tracking set
                            val stillPendingIds = pendingPings.map { it.pingId }.toSet()
                            val completedDownloads = downloadingPingIds.filter { it !in stillPendingIds }
                            completedDownloads.forEach { downloadingPingIds.remove(it) }
                            if (completedDownloads.isNotEmpty()) {
                                Log.d(TAG, "✓ Cleared ${completedDownloads.size} completed downloads from UI tracking")
                            }

                            if (pendingPings.isEmpty()) {
                                isDownloadInProgress = false  // Download complete, pings cleared
                            }

                            // Now reload messages (which will reflect the cleared downloadingPingIds)
                            loadMessages()
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
                        // Check if pending pings exist - if cleared during download, allow refresh (using new queue format)
                        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                        val pendingPings = com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId)
                        val hasPendingPing = pendingPings.isNotEmpty()

                        if (!isDownloadInProgress || !hasPendingPing) {
                            // Either not downloading, OR download completed (pings cleared) - refresh UI
                            if (isDownloadInProgress && !hasPendingPing) {
                                Log.i(TAG, "Download completed (pings cleared) - resetting flag and refreshing UI")
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

        // Enable edge-to-edge display (important for display cutouts)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        // Handle window insets for header and message input container
        val rootView = findViewById<View>(android.R.id.content)
        val chatHeader = findViewById<View>(R.id.chatHeader)
        val messageInputContainer = findViewById<View>(R.id.messageInputContainer)

        ViewCompat.setOnApplyWindowInsetsListener(rootView) { view, windowInsets ->
            val systemInsets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                WindowInsetsCompat.Type.displayCutout()
            )

            // Get IME (keyboard) insets
            val imeInsets = windowInsets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = windowInsets.isVisible(WindowInsetsCompat.Type.ime())

            // Apply top inset to header (for status bar and display cutout)
            chatHeader.setPadding(
                systemInsets.left,
                systemInsets.top,
                systemInsets.right,
                chatHeader.paddingBottom
            )

            // Apply bottom inset to message input container
            // Use IME insets when keyboard is visible, otherwise use system insets
            // Add extra spacing (48px ≈ 16dp) when keyboard is visible for breathing room
            val extraKeyboardSpacing = if (imeVisible) 48 else 0
            val bottomInset = if (imeVisible) {
                imeInsets.bottom + extraKeyboardSpacing
            } else {
                systemInsets.bottom
            }

            messageInputContainer.setPadding(
                messageInputContainer.paddingLeft,
                messageInputContainer.paddingTop,
                messageInputContainer.paddingRight,
                bottomInset
            )

            Log.d("ChatActivity", "Insets - System bottom: ${systemInsets.bottom}, IME bottom: ${imeInsets.bottom}, IME visible: $imeVisible, Applied bottom: $bottomInset")

            windowInsets
        }

        // Get contact info from intent
        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)
        contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: "@user"
        contactAddress = intent.getStringExtra(EXTRA_CONTACT_ADDRESS) ?: ""

        if (contactId == -1L) {
            ThemedToast.show(this, "Error: Invalid contact")
            finish()
            return
        }

        Log.d(TAG, "Opening chat with: $contactName (ID: $contactId)")

        // Migrate old pending ping format to queue format (one-time)
        com.securelegion.utils.PendingPingMigration.migrateIfNeeded(this)

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
        @Suppress("UnspecifiedRegisterReceiverFlag")
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
            onDownloadClick = { pingId ->
                handleDownloadClick(pingId)
            },
            onVoicePlayClick = { message ->
                playVoiceMessage(message)
            },
            onMessageLongClick = {
                // Enter selection mode on long-press
                if (!isSelectionMode) {
                    toggleSelectionMode()
                }
            }
        )

        messagesRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@ChatActivity)
            adapter = messageAdapter

            // Add scroll listener to hide revealed timestamps when scrolling
            addOnScrollListener(object : RecyclerView.OnScrollListener() {
                override fun onScrollStateChanged(recyclerView: RecyclerView, newState: Int) {
                    if (newState == RecyclerView.SCROLL_STATE_DRAGGING) {
                        // User started scrolling - hide any revealed timestamps
                        messageAdapter.resetSwipeState()
                    }
                }
            })
        }
    }

    private fun setupClickListeners() {
        // Initialize views
        messageInput = findViewById(R.id.messageInput)
        sendButton = findViewById(R.id.sendButton)
        sendButtonIcon = findViewById(R.id.sendButtonIcon)
        plusButton = findViewById(R.id.plusButton)
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

        // Trash button (enter selection mode or delete selected)
        findViewById<View>(R.id.settingsButton).setOnClickListener {
            if (isSelectionMode) {
                // In selection mode: delete selected messages
                deleteSelectedMessages()
            } else {
                // Normal mode: enter selection mode
                toggleSelectionMode()
            }
        }

        // Plus button (shows chat actions bottom sheet)
        plusButton.setOnClickListener {
            showChatActionsBottomSheet()
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
                    sendButtonIcon.setImageResource(R.drawable.ic_send)
                    isShowingSendButton = true
                } else if (!hasText && isShowingSendButton) {
                    // Switch to mic button
                    sendButtonIcon.setImageResource(R.drawable.ic_mic)
                    isShowingSendButton = false
                }
            }

            override fun afterTextChanged(s: Editable?) {}
        })
    }

    private fun showChatActionsBottomSheet() {
        val bottomSheet = com.google.android.material.bottomsheet.BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_chat_actions, null)

        bottomSheet.setContentView(view)

        // Configure bottom sheet behavior
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Make all backgrounds transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        // Remove the white background box
        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Send Money option
        view.findViewById<View>(R.id.sendMoneyOption).setOnClickListener {
            bottomSheet.dismiss()
            ThemedToast.show(this, "Send Money - Coming soon")
            // TODO: Implement send money functionality
        }

        // Request Money option
        view.findViewById<View>(R.id.requestMoneyOption).setOnClickListener {
            bottomSheet.dismiss()
            ThemedToast.show(this, "Request Money - Coming soon")
            // TODO: Implement request money functionality
        }

        // Send File option
        view.findViewById<View>(R.id.sendFileOption).setOnClickListener {
            bottomSheet.dismiss()
            ThemedToast.show(this, "Send File - Coming soon")
            // TODO: Implement send file functionality
        }

        // Send Image option
        view.findViewById<View>(R.id.sendImageOption).setOnClickListener {
            bottomSheet.dismiss()
            ThemedToast.show(this, "Send Image - Coming soon")
            // TODO: Implement send image functionality
        }

        // Send Video option
        view.findViewById<View>(R.id.sendVideoOption).setOnClickListener {
            bottomSheet.dismiss()
            ThemedToast.show(this, "Send Video - Coming soon")
            // TODO: Implement send video functionality
        }

        bottomSheet.show()
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
            ThemedToast.show(this, "Failed to start recording: ${e.message}")
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
                            ThemedToast.show(this@ChatActivity,
                                "Failed to send voice message")
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending voice message", e)
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@ChatActivity,
                            "Error: ${e.message}")
                    }
                }
            }

            // Cleanup temp file
            file.delete()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to send voice message", e)
            ThemedToast.show(this, "Failed to send voice message: ${e.message}")
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
                ThemedToast.show(this, "Microphone permission required for voice messages")
            }
        }
    }

    private fun playVoiceMessage(message: com.securelegion.database.entities.Message) {
        val encryptedFilePath = message.voiceFilePath
        if (encryptedFilePath == null) {
            Log.e(TAG, "Voice message has no file path")
            ThemedToast.show(this, "Voice file not found")
            return
        }

        val encryptedFile = File(encryptedFilePath)
        if (!encryptedFile.exists()) {
            Log.e(TAG, "Encrypted voice file does not exist: $encryptedFilePath")
            ThemedToast.show(this, "Voice file not found")
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

            try {
                // Read and decrypt the encrypted voice file
                val encryptedBytes = encryptedFile.readBytes()
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this)
                val decryptedAudio = keyManager.decryptVoiceFile(encryptedBytes)

                // Create temporary playable file from decrypted audio
                val tempPlayablePath = voicePlayer.loadFromBytes(decryptedAudio, message.messageId)

                // Start playing the decrypted temp file
                voicePlayer.play(
                    filePath = tempPlayablePath,
                    onCompletion = {
                        Log.d(TAG, "Voice message playback completed")
                        currentlyPlayingMessageId = null
                        runOnUiThread {
                            messageAdapter.setCurrentlyPlayingMessageId(null)
                        }
                        // Securely delete temporary playable file
                        try {
                            com.securelegion.utils.SecureWipe.secureDeleteFile(File(tempPlayablePath))
                            Log.d(TAG, "Securely deleted temp voice file")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to delete temp voice file", e)
                        }
                    },
                    onProgress = { currentPos, duration ->
                        // Optionally update progress bar in real-time
                        // Would need to pass ViewHolder reference to update progress
                    }
                )
                currentlyPlayingMessageId = message.messageId
                messageAdapter.setCurrentlyPlayingMessageId(message.messageId)
                Log.d(TAG, "Started playing decrypted voice message")

            } catch (e: SecurityException) {
                Log.e(TAG, "Voice file decryption failed - authentication error", e)
                ThemedToast.show(this, "Voice file corrupted or tampered")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to play voice message", e)
                ThemedToast.show(this, "Failed to play voice message")
            }
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

            // Load all pending pings from queue (don't filter - let adapter handle downloading state)
            val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
            val allPendingPings = com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId.toLong())

            // Clean up pings that match existing messages (ghost pings from completed downloads)
            val keyManager = KeyManager.getInstance(this@ChatActivity)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

            val ghostPings = mutableListOf<String>()
            allPendingPings.forEach { ping ->
                // Check if this ping was already processed into a message
                val existingMessage = database.messageDao().getMessageByPingId(ping.pingId)
                if (existingMessage != null) {
                    Log.w(TAG, "Found ghost ping ${ping.pingId} that matches existing message - removing")
                    ghostPings.add(ping.pingId)
                }
            }

            // Remove ghost pings from queue
            ghostPings.forEach { pingId ->
                com.securelegion.models.PendingPing.removeFromQueue(prefs, contactId.toLong(), pingId)
            }

            val pendingPings = allPendingPings.filter { it.pingId !in ghostPings }

            if (ghostPings.isNotEmpty()) {
                Log.i(TAG, "Cleaned up ${ghostPings.size} ghost pings")
            }

            withContext(Dispatchers.Main) {
                Log.d(TAG, "Updating adapter with ${messages.size} messages + ${pendingPings.size} pending (${downloadingPingIds.size} downloading)")
                messageAdapter.updateMessages(
                    messages,
                    pendingPings,
                    downloadingPingIds  // Pass downloading state to adapter
                )
                messagesRecyclerView.post {
                    val totalItems = messages.size + pendingPings.size
                    if (totalItems > 0) {
                        messagesRecyclerView.scrollToPosition(totalItems - 1)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load messages", e)
            withContext(Dispatchers.Main) {
                ThemedToast.show(
                    this@ChatActivity,
                    "Failed to load messages: ${e.message}"
                )
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


    private fun handleDownloadClick(pingId: String) {
        Log.i(TAG, "Download button clicked for contact $contactId, ping $pingId")

        // Set flag to prevent showing pending message again during download
        isDownloadInProgress = true

        // Track this specific ping as being downloaded
        downloadingPingIds.add(pingId)
        Log.d(TAG, "Added $pingId to downloading set (now tracking ${downloadingPingIds.size} downloads)")

        // Start the download service with specific ping ID
        com.securelegion.services.DownloadMessageService.start(this, contactId, contactName, pingId)

        // DON'T reload here - the MessageAdapter already shows "downloading..." text
        // The service will broadcast MESSAGE_RECEIVED when done, which will trigger a reload
    }

    private fun toggleSelectionMode() {
        isSelectionMode = !isSelectionMode
        messageAdapter.setSelectionMode(isSelectionMode)

        Log.d(TAG, "Selection mode: $isSelectionMode")
    }

    private fun deleteSelectedMessages() {
        val selectedIds = messageAdapter.getSelectedMessageIds()

        if (selectedIds.isEmpty()) {
            return
        }

        lifecycleScope.launch {
            try {
                // Track if we deleted the pending message (needs to be accessible in Main context)
                var deletedPendingMessage = false

                withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@ChatActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                    // Separate selected IDs into ping IDs and message IDs
                    val pingIds = selectedIds.filter { it.startsWith("ping:") }.map { it.removePrefix("ping:") }
                    val messageIds = selectedIds.filter { !it.startsWith("ping:") }.mapNotNull { it.toLongOrNull() }

                    // Delete pending pings by pingId (no formula needed!)
                    if (pingIds.isNotEmpty()) {
                        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)

                        pingIds.forEach { pingId ->
                            // Direct removal by pingId - simple and reliable!
                            com.securelegion.models.PendingPing.removeFromQueue(prefs, contactId.toLong(), pingId)
                            Log.d(TAG, "✓ Deleted pending ping $pingId from queue")
                            deletedPendingMessage = true
                        }

                        // Also clean up outgoing ping keys (fix for ghost messages)
                        prefs.edit().apply {
                            remove("outgoing_ping_${contactId}_id")
                            remove("outgoing_ping_${contactId}_name")
                            remove("outgoing_ping_${contactId}_timestamp")
                            remove("outgoing_ping_${contactId}_onion")
                            apply()
                        }
                        Log.d(TAG, "✓ Cleaned up outgoing ping keys to prevent ghost messages")
                    }

                    // Delete regular messages from database
                    val regularMessageIds = messageIds
                    regularMessageIds.forEach { messageId ->
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
                    if (regularMessageIds.isNotEmpty()) {
                        try {
                            database.openHelper.writableDatabase.execSQL("VACUUM")
                            Log.d(TAG, "✓ Database vacuumed after message deletion")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to vacuum database", e)
                        }
                    }
                }

                Log.d(TAG, "Securely deleted ${selectedIds.size} messages using DOD 3-pass wiping")

                // Update UI on main thread
                withContext(Dispatchers.Main) {
                    // Exit selection mode and reload messages
                    // (loadMessages will reload from SharedPreferences, so deleted pending message won't show)
                    toggleSelectionMode()
                    loadMessages()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete messages", e)
            }
        }
    }

    /**
     * Delete entire chat thread and return to main activity
     */
    private fun deleteThread() {
        androidx.appcompat.app.AlertDialog.Builder(this, R.style.CustomAlertDialog)
            .setTitle("Delete Chat")
            .setMessage("Delete this entire conversation? This cannot be undone.")
            .setPositiveButton("Delete") { _, _ ->
                lifecycleScope.launch {
                    try {
                        val keyManager = KeyManager.getInstance(this@ChatActivity)
                        val dbPassphrase = keyManager.getDatabasePassphrase()
                        val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                        withContext(Dispatchers.IO) {
                            // Get all messages for this contact to check for voice files
                            val messages = database.messageDao().getMessagesForContact(contactId.toLong())

                            // Securely wipe any voice message audio files
                            messages.forEach { message ->
                                if (message.messageType == Message.MESSAGE_TYPE_VOICE &&
                                    message.voiceFilePath != null) {
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
                            }

                            // Delete all messages for this contact
                            database.messageDao().deleteMessagesForContact(contactId.toLong())

                            // Delete any pending messages from SharedPreferences
                            val prefs = getSharedPreferences("pending_messages", Context.MODE_PRIVATE)
                            val allPending = prefs.all
                            val keysToRemove = mutableListOf<String>()

                            allPending.forEach { (key, _) ->
                                if (key.startsWith("ping_") && key.endsWith("_onion")) {
                                    val savedContactAddress = prefs.getString(key, null)
                                    if (savedContactAddress == contactAddress) {
                                        keysToRemove.add(key)
                                    }
                                }
                            }

                            if (keysToRemove.isNotEmpty()) {
                                prefs.edit().apply {
                                    keysToRemove.forEach { remove(it) }
                                    apply()
                                }
                            }

                            // VACUUM database to compact and remove deleted records
                            database.openHelper.writableDatabase.execSQL("VACUUM")
                            Log.d(TAG, "✓ Thread deleted and database vacuumed")
                        }

                        withContext(Dispatchers.Main) {
                            ThemedToast.show(this@ChatActivity, "Chat deleted")
                            finish()
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to delete thread", e)
                        withContext(Dispatchers.Main) {
                            ThemedToast.show(this@ChatActivity, "Failed to delete chat")
                        }
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

}
