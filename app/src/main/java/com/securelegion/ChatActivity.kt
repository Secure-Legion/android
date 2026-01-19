package com.securelegion

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.text.Editable
import android.text.TextWatcher
import android.util.Base64
import android.util.Log
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.MessageAdapter
import com.securelegion.crypto.KeyChainManager
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.TorManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
import com.securelegion.services.MessageService
import com.securelegion.utils.SecureWipe
import com.securelegion.utils.ThemedToast
import com.securelegion.utils.VoiceRecorder
import com.securelegion.utils.VoicePlayer
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.crypto.VoiceCallCrypto
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.database.entities.x25519PublicKeyBytes
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ChatActivity : BaseActivity() {

    companion object {
        private const val TAG = "ChatActivity"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "CONTACT_NAME"
        const val EXTRA_CONTACT_ADDRESS = "CONTACT_ADDRESS"
        private const val PERMISSION_REQUEST_CODE = 100
        private const val CAMERA_PERMISSION_REQUEST_CODE = 101
        private const val MAX_IMAGE_WIDTH = 1920  // 1080p width
        private const val MAX_IMAGE_HEIGHT = 1080 // 1080p height
        private const val JPEG_QUALITY = 85       // Good quality, reasonable size
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
    private lateinit var contactAvatar: com.securelegion.views.AvatarView

    private var contactId: Long = -1
    private var contactName: String = "@user"
    private var contactAddress: String = ""
    private var isShowingSendButton = false
    private var isDownloadInProgress = false
    private var isSelectionMode = false

    // Track which specific pings are currently being downloaded
    private val downloadingPingIds = mutableSetOf<String>()

    // Auto-download: Track if user has manually downloaded at least one message this session
    private var hasDownloadedOnce = false

    // Track pings that are being auto-downloaded (hide from UI for seamless experience)
    private val autoPongPingIds = mutableSetOf<String>()

    // Debouncing for loadMessages() to prevent rapid refresh bursts (coalesce within 150ms)
    private val loadMessagesHandler = Handler(Looper.getMainLooper())
    private var pendingLoadMessagesRunnable: Runnable? = null
    private val LOAD_MESSAGES_DEBOUNCE_MS = 150L

    // Voice recording
    private lateinit var voiceRecorder: VoiceRecorder
    private lateinit var voicePlayer: VoicePlayer
    private var recordingFile: File? = null
    private var recordingHandler: Handler? = null
    private var currentlyPlayingMessageId: String? = null

    // Image capture
    private var cameraPhotoUri: Uri? = null
    private var cameraPhotoFile: File? = null
    private var isWaitingForCameraGallery = false  // Prevent auto-lock during external camera/gallery

    // Voice call
    private var isInitiatingCall = false  // Prevent duplicate call initiations

    // Media picking
    private var isWaitingForMediaResult = false  // Track if waiting for media picker result

    // Activity result launchers for image picking
    private val galleryLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        isWaitingForMediaResult = false  // Clear flag
        // DON'T clear isWaitingForCameraGallery here - let onResume() clear it
        // after preventing auto-lock (callback runs before onResume)

        uri?.let { handleSelectedImage(it) }
    }

    private val cameraLauncher = registerForActivityResult(
        ActivityResultContracts.TakePicture()
    ) { success: Boolean ->
        isWaitingForMediaResult = false  // Clear flag
        // DON'T clear isWaitingForCameraGallery here - let onResume() clear it
        // after preventing auto-lock (callback runs before onResume)

        if (success && cameraPhotoUri != null) {
            handleSelectedImage(cameraPhotoUri!!)
        }
    }

    // Contact photo picker launchers
    private val contactPhotoGalleryLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            val uri = result.data?.data
            val base64 = com.securelegion.utils.ImagePicker.processImageUri(this, uri)
            if (base64 != null) {
                saveContactPhoto(base64)
                contactAvatar.setPhotoBase64(base64)
                ThemedToast.show(this, "Contact photo updated")
            } else {
                ThemedToast.show(this, "Failed to process image")
            }
        }
    }

    private val contactPhotoCameraLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == android.app.Activity.RESULT_OK) {
            val bitmap = result.data?.extras?.get("data") as? Bitmap
            val base64 = com.securelegion.utils.ImagePicker.processImageBitmap(bitmap)
            if (base64 != null) {
                saveContactPhoto(base64)
                contactAvatar.setPhotoBase64(base64)
                ThemedToast.show(this, "Contact photo updated")
            } else {
                ThemedToast.show(this, "Failed to process image")
            }
        }
    }

    // BroadcastReceiver for instant message display and new Pings
    private val messageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                "com.securelegion.MESSAGE_RECEIVED" -> {
                    val receivedContactId = intent.getLongExtra("CONTACT_ID", -1L)
                    Log.d(TAG, "MESSAGE_RECEIVED broadcast: received contactId=$receivedContactId, current contactId=$contactId")
                    if (receivedContactId == contactId) {
                        Log.i(TAG, "New message for current contact - reloading messages (debounced)")

                        // Use debounced reload to coalesce rapid messages
                        loadMessagesDebounced()
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
                                    // AUTO-PONG: Check BEFORE loadMessages to prevent lock icon flash
                                    if (hasDownloadedOnce) {
                                        val currentPings = com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId)
                                        val pendingPings = currentPings.filter { it.state == com.securelegion.models.PingState.PENDING }

                                        if (pendingPings.isNotEmpty()) {
                                            Log.i(TAG, "⚡ Auto-sending PONG for ${pendingPings.size} new message(s) (user is active in thread)")
                                            pendingPings.forEach { ping ->
                                                Log.d(TAG, "  Auto-PONGing ping: ${ping.pingId.take(8)}")

                                                // Mark this ping as auto-download FIRST (prevents lock icon flash)
                                                autoPongPingIds.add(ping.pingId)

                                                // Update state to DOWNLOADING immediately to prevent duplicate sends
                                                com.securelegion.models.PendingPing.updateState(
                                                    prefs,
                                                    contactId,
                                                    ping.pingId,
                                                    com.securelegion.models.PingState.DOWNLOADING,
                                                    synchronous = true
                                                )

                                                // Start download service which will send PONG and receive message
                                                com.securelegion.services.DownloadMessageService.start(
                                                    this@ChatActivity,
                                                    contactId,
                                                    contactName,
                                                    ping.pingId
                                                )
                                            }
                                        }
                                    }

                                    // Load messages (auto-downloading pings are already hidden) - use debounced to coalesce
                                    loadMessagesDebounced()
                                }
                            }
                        } else {
                            Log.d(TAG, "NEW_PING for current contact during download - ignoring to prevent ghost")
                        }
                    } else if (receivedContactId != -1L) {
                        // NEW_PING for different contact - reload to update UI (debounced)
                        Log.i(TAG, "New Ping for different contact - reloading (debounced)")
                        loadMessagesDebounced()
                    }
                }
                "com.securelegion.DOWNLOAD_FAILED" -> {
                    val receivedContactId = intent.getLongExtra("CONTACT_ID", -1L)
                    Log.w(TAG, "DOWNLOAD_FAILED broadcast: received contactId=$receivedContactId, current contactId=$contactId")

                    if (receivedContactId == contactId) {
                        // Download failed for current contact - reset flag and refresh UI (debounced)
                        Log.w(TAG, "Download failed - resetting download flag and refreshing UI (debounced)")
                        isDownloadInProgress = false
                        loadMessagesDebounced()
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

        // Download state will be determined from database (pending pings with DOWNLOADING/DECRYPTING state)
        // No need to check SharedPreferences - database is source of truth

        // Migrate old pending ping format to queue format (one-time)
        com.securelegion.utils.PendingPingMigration.migrateIfNeeded(this)

        // Initialize services
        messageService = MessageService(this)
        voiceRecorder = VoiceRecorder(this)
        voicePlayer = VoicePlayer(this)

        // Setup UI
        val chatNameView = findViewById<TextView>(R.id.chatName)
        chatNameView.text = contactName

        // DEBUG: Long-press contact name to reset key chain counters
        chatNameView.setOnLongClickListener {
            Log.d(TAG, "🔍 DEBUG: Long-press detected on contact name!")
            ThemedToast.show(this, "Long-press detected - showing reset dialog")

            AlertDialog.Builder(this)
                .setTitle("Reset Key Chain?")
                .setMessage("This will reset send/receive counters to 0 for this contact.\n\n⚠️ WARNING: Both devices must reset at the same time!")
                .setPositiveButton("Reset") { _, _ ->
                    Log.d(TAG, "🔍 DEBUG: User tapped RESET button in dialog")
                    ThemedToast.show(this@ChatActivity, "Resetting key chain counters...")
                    lifecycleScope.launch {
                        try {
                            Log.d(TAG, "🔍 DEBUG: Calling KeyChainManager.resetKeyChainCounters for contactId=$contactId")
                            KeyChainManager.resetKeyChainCounters(this@ChatActivity, contactId)
                            Log.d(TAG, "🔍 DEBUG: Reset completed successfully!")
                            ThemedToast.show(this@ChatActivity, "✓ Key chain counters reset to 0")
                        } catch (e: Exception) {
                            Log.e(TAG, "🔍 DEBUG: Reset failed with exception", e)
                            ThemedToast.show(this@ChatActivity, "Failed to reset: ${e.message}")
                        }
                    }
                }
                .setNegativeButton("Cancel") { _, _ ->
                    Log.d(TAG, "🔍 DEBUG: User tapped CANCEL button in dialog")
                }
                .show()
            Log.d(TAG, "🔍 DEBUG: Reset dialog shown to user")
            true
        }

        setupContactAvatar()

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

    override fun onResume() {
        // Check persistent flag first (survives activity recreation)
        val lifecyclePrefs = getSharedPreferences("app_lifecycle", MODE_PRIVATE)
        val wasWaitingForCameraGallery = lifecyclePrefs.getBoolean("waiting_for_camera_gallery", false)

        // Clear pause timestamp if returning from camera/gallery to prevent auto-lock
        // Camera/gallery are EXTERNAL apps, so they're not detected by BaseActivity
        if (isWaitingForCameraGallery || wasWaitingForCameraGallery) {
            lifecyclePrefs.edit()
                .putLong("last_pause_timestamp", 0L)
                .putBoolean("waiting_for_camera_gallery", false)
                .commit()  // Intentional: must be synchronous before onResume() completes
            Log.d(TAG, "Cleared pause timestamp after camera/gallery - preventing auto-lock")
            isWaitingForCameraGallery = false
        }

        // Reset call initiation flag when returning from VoiceCallActivity
        // This allows subsequent call attempts after previous call ends/fails
        if (isInitiatingCall) {
            Log.d(TAG, "Resetting isInitiatingCall flag on resume")
            isInitiatingCall = false
        }

        super.onResume()
        Log.d(TAG, "onResume called")

        // Download state is derived from database on loadMessages() - no need to check SharedPreferences

        // Notify TorService that app is in foreground (fast bandwidth updates)
        com.securelegion.services.TorService.setForegroundState(true)
    }

    override fun onPause() {
        super.onPause()
        Log.d(TAG, "onPause called")

        // Notify TorService that app is in background (slow bandwidth updates to save battery)
        com.securelegion.services.TorService.setForegroundState(false)
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

        // Stop all animations in adapter before destroying
        if (::messageAdapter.isInitialized) {
            messageAdapter.stopAllAnimations()
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
            },
            onImageClick = { imageBase64 ->
                showFullImage(imageBase64)
            },
            onPaymentRequestClick = { message ->
                // User clicked "Pay" on a payment request
                handlePaymentRequestClick(message)
            },
            onPaymentDetailsClick = { message ->
                // User clicked to view payment details
                handlePaymentDetailsClick(message)
            },
            onPriceRefreshClick = { message, usdView, cryptoView ->
                // Refresh price when crypto amount is clicked
                refreshPaymentPrice(message, usdView, cryptoView)
            },
            onDeleteMessage = { message ->
                // Delete single message from long-press menu
                deleteSingleMessage(message)
            }
        )

        // Fetch initial prices
        fetchCryptoPrices()

        // Enable stable IDs BEFORE attaching adapter (must be done before observers register)
        messageAdapter.setHasStableIds(true)

        messagesRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@ChatActivity)
            adapter = messageAdapter

            // PHASE 1.1/1.2: Stable IDs now working, re-enable animations
            // DiffUtil with stable messageIds = smooth item transitions
            itemAnimator = androidx.recyclerview.widget.DefaultItemAnimator()

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
            finish()
        }

        // Call button - start voice call
        findViewById<View>(R.id.callButton).setOnClickListener {
            Log.d(TAG, "Call button clicked - starting voice call")
            ThemedToast.show(this, "Starting call...")
            startVoiceCall()
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
            val intent = Intent(this, SendMoneyActivity::class.java).apply {
                putExtra(SendMoneyActivity.EXTRA_RECIPIENT_NAME, contactName)
                putExtra(SendMoneyActivity.EXTRA_RECIPIENT_ADDRESS, contactAddress)
                putExtra(SendMoneyActivity.EXTRA_CONTACT_ID, contactId)
            }
            startActivity(intent)
        }

        // Request Money option
        view.findViewById<View>(R.id.requestMoneyOption).setOnClickListener {
            bottomSheet.dismiss()
            val intent = Intent(this, RequestMoneyActivity::class.java).apply {
                putExtra(RequestMoneyActivity.EXTRA_RECIPIENT_NAME, contactName)
                putExtra(RequestMoneyActivity.EXTRA_RECIPIENT_ADDRESS, contactAddress)
                putExtra(RequestMoneyActivity.EXTRA_CONTACT_ID, contactId)
            }
            startActivity(intent)
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
            showImageSourceDialog()
        }

        // Send Video option
        view.findViewById<View>(R.id.sendVideoOption).setOnClickListener {
            bottomSheet.dismiss()
            ThemedToast.show(this, "Send Video - Coming soon")
            // TODO: Implement send video functionality
        }

        bottomSheet.show()
    }

    // ==================== IMAGE SENDING ====================

    private fun showImageSourceDialog() {
        val bottomSheet = com.google.android.material.bottomsheet.BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_image_source, null)
        bottomSheet.setContentView(view)

        // Make background transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Take Photo option
        view.findViewById<View>(R.id.takePhotoOption).setOnClickListener {
            bottomSheet.dismiss()
            openCamera()
        }

        // Choose from Gallery option
        view.findViewById<View>(R.id.chooseGalleryOption).setOnClickListener {
            bottomSheet.dismiss()
            openGallery()
        }

        bottomSheet.show()
    }

    private fun openCamera() {
        // Check camera permission
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.CAMERA),
                CAMERA_PERMISSION_REQUEST_CODE
            )
            return
        }

        try {
            // Create temp file for camera photo
            val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val imageFileName = "JPEG_${timeStamp}_"
            val storageDir = getExternalFilesDir(Environment.DIRECTORY_PICTURES)
            cameraPhotoFile = File.createTempFile(imageFileName, ".jpg", storageDir)

            cameraPhotoUri = FileProvider.getUriForFile(
                this,
                "${packageName}.fileprovider",
                cameraPhotoFile!!
            )

            // Set flag to prevent auto-lock when returning from external camera app
            isWaitingForCameraGallery = true

            // Persist flag to survive activity recreation
            getSharedPreferences("app_lifecycle", MODE_PRIVATE)
                .edit()
                .putBoolean("waiting_for_camera_gallery", true)
                .apply()

            cameraLauncher.launch(cameraPhotoUri)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to open camera", e)
            ThemedToast.show(this, "Failed to open camera")
        }
    }

    private fun openGallery() {
        // Check storage permission for older Android versions
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
                    CAMERA_PERMISSION_REQUEST_CODE
                )
                return
            }
        }

        // Set flag to prevent auto-lock when returning from external gallery app
        isWaitingForCameraGallery = true

        // Persist flag to survive activity recreation
        getSharedPreferences("app_lifecycle", MODE_PRIVATE)
            .edit()
            .putBoolean("waiting_for_camera_gallery", true)
            .apply()

        galleryLauncher.launch("image/*")
    }

    private fun handleSelectedImage(uri: Uri) {
        lifecycleScope.launch {
            try {
                ThemedToast.show(this@ChatActivity, "Processing image...")

                val compressedImageData = withContext(Dispatchers.IO) {
                    compressImage(uri)
                }

                if (compressedImageData == null) {
                    ThemedToast.show(this@ChatActivity, "Failed to process image")
                    return@launch
                }

                val imageSizeKB = compressedImageData.size / 1024
                Log.d(TAG, "Compressed image size: ${imageSizeKB}KB")

                if (imageSizeKB > 500) {
                    ThemedToast.show(this@ChatActivity, "Image too large (${imageSizeKB}KB). Max 500KB.")
                    return@launch
                }

                // Send the image message
                sendImageMessage(compressedImageData)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to handle image", e)
                ThemedToast.show(this@ChatActivity, "Failed to send image: ${e.message}")
            }
        }
    }

    private fun compressImage(uri: Uri): ByteArray? {
        try {
            // Get input stream
            val inputStream = contentResolver.openInputStream(uri) ?: return null

            // Decode bounds first
            val options = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeStream(inputStream, null, options)
            inputStream.close()

            // Calculate sample size for downscaling (use minimal downsampling)
            val (width, height) = options.outWidth to options.outHeight
            var sampleSize = 1
            // Only downsample if image is significantly larger than target
            // Use sampleSize that keeps image at least as large as target dimensions
            while (width / (sampleSize * 2) >= MAX_IMAGE_WIDTH && height / (sampleSize * 2) >= MAX_IMAGE_HEIGHT) {
                sampleSize *= 2
            }

            // Decode with sample size
            val decodeOptions = BitmapFactory.Options().apply {
                inSampleSize = sampleSize
            }
            val newInputStream = contentResolver.openInputStream(uri) ?: return null
            var bitmap = BitmapFactory.decodeStream(newInputStream, null, decodeOptions)
            newInputStream.close()

            if (bitmap == null) return null

            // Handle EXIF rotation
            bitmap = rotateImageIfRequired(uri, bitmap)

            // Scale to exact 720p if needed
            bitmap = scaleBitmap(bitmap, MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT)

            // Compress to JPEG
            // SECURITY: Bitmap.compress() creates a fresh JPEG with NO EXIF metadata.
            // All sensitive metadata (GPS, device info, timestamps) from the original
            // image is stripped. Only pixel data is transmitted over Tor.
            val outputStream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, outputStream)
            bitmap.recycle()

            return outputStream.toByteArray()
        } catch (e: Exception) {
            Log.e(TAG, "Image compression failed", e)
            return null
        }
    }

    private fun rotateImageIfRequired(uri: Uri, bitmap: Bitmap): Bitmap {
        try {
            val inputStream = contentResolver.openInputStream(uri) ?: return bitmap
            val exif = ExifInterface(inputStream)
            inputStream.close()

            val orientation = exif.getAttributeInt(
                ExifInterface.TAG_ORIENTATION,
                ExifInterface.ORIENTATION_NORMAL
            )

            val rotationDegrees = when (orientation) {
                ExifInterface.ORIENTATION_ROTATE_90 -> 90f
                ExifInterface.ORIENTATION_ROTATE_180 -> 180f
                ExifInterface.ORIENTATION_ROTATE_270 -> 270f
                else -> return bitmap
            }

            val matrix = Matrix()
            matrix.postRotate(rotationDegrees)
            val rotatedBitmap = Bitmap.createBitmap(
                bitmap, 0, 0, bitmap.width, bitmap.height, matrix, true
            )
            if (rotatedBitmap != bitmap) {
                bitmap.recycle()
            }
            return rotatedBitmap
        } catch (e: Exception) {
            Log.w(TAG, "Failed to check EXIF rotation", e)
            return bitmap
        }
    }

    private fun scaleBitmap(bitmap: Bitmap, maxWidth: Int, maxHeight: Int): Bitmap {
        val width = bitmap.width
        val height = bitmap.height

        if (width <= maxWidth && height <= maxHeight) {
            return bitmap
        }

        val ratio = minOf(maxWidth.toFloat() / width, maxHeight.toFloat() / height)
        val newWidth = (width * ratio).toInt()
        val newHeight = (height * ratio).toInt()

        // Use high-quality scaling with FILTER_BITMAP flag
        val scaledBitmap = Bitmap.createScaledBitmap(bitmap, newWidth, newHeight, true)
        if (scaledBitmap != bitmap) {
            bitmap.recycle()
        }

        Log.d(TAG, "Scaled image from ${width}x${height} to ${newWidth}x${newHeight}")
        return scaledBitmap
    }

    private fun sendImageMessage(imageData: ByteArray) {
        lifecycleScope.launch {
            try {
                val imageBase64 = Base64.encodeToString(imageData, Base64.NO_WRAP)

                Log.d(TAG, "Sending image message, base64 length: ${imageBase64.length}")

                // Send as IMAGE message type
                val result = messageService.sendImageMessage(
                    contactId = contactId,
                    imageBase64 = imageBase64,
                    onMessageSaved = { savedMessage ->
                        // Update UI immediately when message is saved
                        runOnUiThread {
                            lifecycleScope.launch {
                                loadMessages()
                            }
                        }
                    }
                )

                if (result.isSuccess) {
                    Log.i(TAG, "Image message sent successfully")
                } else {
                    ThemedToast.show(this@ChatActivity, "Failed to send image")
                }
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Job cancelled but WorkManager will retry sending - this is normal when activity is killed for memory
                Log.d(TAG, "Image message coroutine cancelled, but WorkManager will handle retry")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send image message", e)
                ThemedToast.show(this@ChatActivity, "Failed to send image: ${e.message}")
            }
        }
    }

    private fun showFullImage(imageBase64: String) {
        if (imageBase64.isEmpty()) {
            ThemedToast.show(this, "Image not available")
            return
        }

        try {
            // Decode image
            val imageBytes = Base64.decode(imageBase64, Base64.DEFAULT)
            val bitmap = android.graphics.BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size)

            // Create full-screen dialog to show image
            val dialog = android.app.Dialog(this, android.R.style.Theme_Black_NoTitleBar_Fullscreen)
            val view = layoutInflater.inflate(R.layout.dialog_full_image, null)

            // Set the image
            val imageView = view.findViewById<ImageView>(R.id.fullImageView)
            imageView.setImageBitmap(bitmap)

            // Close button
            view.findViewById<View>(R.id.closeButton).setOnClickListener {
                dialog.dismiss()
            }

            // Save button
            view.findViewById<View>(R.id.saveImageButton).setOnClickListener {
                saveImageToGallery(bitmap)
            }

            dialog.setContentView(view)
            dialog.show()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show full image", e)
            ThemedToast.show(this, "Failed to open image")
        }
    }

    private fun saveImageToGallery(bitmap: android.graphics.Bitmap) {
        try {
            val filename = "SecureLegion_${System.currentTimeMillis()}.jpg"
            val contentValues = android.content.ContentValues().apply {
                put(android.provider.MediaStore.Images.Media.DISPLAY_NAME, filename)
                put(android.provider.MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
                put(android.provider.MediaStore.Images.Media.RELATIVE_PATH, android.os.Environment.DIRECTORY_PICTURES + "/SecureLegion")
            }

            val resolver = contentResolver
            val imageUri = resolver.insert(android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI, contentValues)

            if (imageUri != null) {
                resolver.openOutputStream(imageUri)?.use { outputStream ->
                    bitmap.compress(android.graphics.Bitmap.CompressFormat.JPEG, 95, outputStream)
                }
                ThemedToast.show(this, "Image saved to gallery")
                Log.i(TAG, "Image saved to gallery: $filename")
            } else {
                ThemedToast.show(this, "Failed to save image")
                Log.e(TAG, "Failed to create MediaStore entry")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save image to gallery", e)
            ThemedToast.show(this, "Failed to save image: ${e.message}")
        }
    }

    // ==================== VOICE RECORDING ====================

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
            messageAdapter.resetVoiceProgress(message.messageId)
            Log.d(TAG, "Paused voice message")
        } else {
            // Stop any currently playing message
            if (currentlyPlayingMessageId != null) {
                val previousMessageId = currentlyPlayingMessageId
                voicePlayer.stop()
                messageAdapter.resetVoiceProgress(previousMessageId!!)
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
                        val completedMessageId = currentlyPlayingMessageId
                        currentlyPlayingMessageId = null
                        runOnUiThread {
                            messageAdapter.setCurrentlyPlayingMessageId(null)
                            if (completedMessageId != null) {
                                messageAdapter.resetVoiceProgress(completedMessageId)
                            }
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
                        // Update waveform progress in real-time
                        runOnUiThread {
                            messageAdapter.updateVoiceProgress(message.messageId, currentPos, duration)
                        }
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

    /**
     * Debounced wrapper for loadMessages() - coalesces rapid calls into a single refresh within 150ms
     * Prevents flicker from multiple loadMessages() triggers (broadcasts, callbacks, etc.)
     */
    private fun loadMessagesDebounced() {
        // Cancel any pending loadMessages call
        pendingLoadMessagesRunnable?.let {
            loadMessagesHandler.removeCallbacks(it)
        }

        // Create new runnable that calls loadMessages in a coroutine
        val runnable = Runnable {
            lifecycleScope.launch {
                loadMessages()
            }
        }

        // Store reference and schedule with debounce delay
        pendingLoadMessagesRunnable = runnable
        loadMessagesHandler.postDelayed(runnable, LOAD_MESSAGES_DEBOUNCE_MS)
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

            // Get database instance (reuse for multiple operations)
            val keyManager = KeyManager.getInstance(this@ChatActivity)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

            // Mark all received messages as read (updates unread count)
            val markedCount = withContext(Dispatchers.IO) {
                val unreadMessages = messages.filter { !it.isSentByMe && !it.isRead }
                unreadMessages.forEach { message ->
                    // Use markAsRead() to only update isRead field - prevents timestamp changes
                    database.messageDao().markAsRead(message.id)
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

            // Load all pending pings from DATABASE (source of truth, restart-safe)
            // Falls back to SharedPreferences for backward compatibility
            val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
            var allPendingPings = com.securelegion.models.PendingPing.loadQueueFromDatabase(database, prefs, contactId.toLong())

            // Don't auto-reset DOWNLOADING/DECRYPTING states - let database guide the UI
            // If download service restarts, it will update the state
            // If it stays stuck, user can manually trigger download again
            if (false) {  // Disabled stale state reset
                val staleStates = allPendingPings.filter {
                    it.state == com.securelegion.models.PingState.DOWNLOADING ||
                    it.state == com.securelegion.models.PingState.DECRYPTING
                }
                if (staleStates.isNotEmpty()) {
                    Log.i(TAG, "Found ${staleStates.size} pings with stale download states - resetting to PENDING")
                    staleStates.forEach { ping ->
                        com.securelegion.models.PendingPing.updateState(
                            prefs,
                            contactId.toLong(),
                            ping.pingId,
                            com.securelegion.models.PingState.PENDING,
                            synchronous = true
                        )
                        Log.d(TAG, "  Reset ping ${ping.pingId.take(8)} from ${ping.state} to PENDING")
                    }
                    // Reload pings after reset (from database)
                    allPendingPings = com.securelegion.models.PendingPing.loadQueueFromDatabase(database, prefs, contactId.toLong())
                }
            } else {
                Log.d(TAG, "Download service is running - preserving DOWNLOADING/DECRYPTING states")
            }

            // Clean up pings that match existing messages (ghost pings from completed downloads)
            // Database instance already initialized above

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

            // ATOMIC SWAP: Remove pings in READY state ONLY if message is confirmed in DB
            Log.d(TAG, "Checking for READY pings. Total pings: ${pendingPings.size}")
            pendingPings.forEachIndexed { index, ping ->
                Log.d(TAG, "  Ping $index: ${ping.pingId.take(8)} - state=${ping.state}")
            }

            // Get set of pingIds that have messages in the database
            val existingMessagePingIds = messages.mapNotNull { it.pingId }.toSet()

            val readyPings = pendingPings.filter { it.state == com.securelegion.models.PingState.READY }
            if (readyPings.isNotEmpty()) {
                Log.i(TAG, "⚡ ATOMIC SWAP: Found ${readyPings.size} READY pings")
                readyPings.forEach { ping ->
                    // Only remove if message is confirmed in database
                    if (ping.pingId in existingMessagePingIds) {
                        com.securelegion.models.PendingPing.removeFromQueue(prefs, contactId.toLong(), ping.pingId, synchronous = true)
                        Log.d(TAG, "  ✓ Removed READY ping ${ping.pingId.take(8)} - message confirmed in DB")
                    } else {
                        Log.d(TAG, "  ⏳ Keeping READY ping ${ping.pingId.take(8)} - message not in DB yet (will show as Downloading)")
                    }
                }
            } else {
                Log.d(TAG, "No READY pings found")
            }

            // Filter out pings whose messages already exist in DB
            // Pings are removed from queue when message arrives, but check DB as safety net
            val pendingPingsToShow = pendingPings.filter { ping ->
                ping.pingId !in existingMessagePingIds
            }

            // Clean up autoPongPingIds - remove completed auto-downloads
            val completedAutoPongs = autoPongPingIds.filter { pingId ->
                pingId in existingMessagePingIds  // Message arrived
            }
            completedAutoPongs.forEach { autoPongPingIds.remove(it) }
            if (completedAutoPongs.isNotEmpty()) {
                Log.d(TAG, "Cleaned up ${completedAutoPongs.size} completed auto-downloads")
            }

            // GHOST TYPING FIX: Also remove pings from autoPongPingIds if they're not in pending queue
            // This handles cases where download completed but ping wasn't cleaned up from autoPongPingIds
            val pendingPingIds = pendingPings.map { it.pingId }.toSet()
            val ghostAutoPongs = autoPongPingIds.filter { pingId ->
                pingId !in pendingPingIds  // No longer in pending queue
            }
            ghostAutoPongs.forEach { autoPongPingIds.remove(it) }
            if (ghostAutoPongs.isNotEmpty()) {
                Log.d(TAG, "Cleaned up ${ghostAutoPongs.size} ghost auto-pong indicators")
            }

            // Clean up downloadingPingIds - remove any pingIds that are no longer actually pending
            // OR that already have messages in the database
            // This handles failed downloads, completed downloads (safety net), and activity recreation scenarios
            val stillPendingIds = pendingPingsToShow.map { it.pingId }.toSet()

            // A download is stale if: (1) not in pending queue OR (2) message already exists in DB
            val staleDownloadIds = downloadingPingIds.filter {
                it !in stillPendingIds || it in existingMessagePingIds
            }
            staleDownloadIds.forEach {
                Log.d(TAG, "Removing stale download indicator for ping ${it.take(8)}")
                downloadingPingIds.remove(it)
            }
            if (staleDownloadIds.isNotEmpty()) {
                Log.i(TAG, "Cleaned up ${staleDownloadIds.size} stale download indicators from UI")
                Log.d(TAG, "  Remaining in downloadingPingIds: ${downloadingPingIds.size}")
            }

            // GHOST TYPING FIX: Reset isDownloadInProgress if no pending pings in DATABASE and no active downloads
            // Query ping_inbox directly (SOURCE OF TRUTH) with COUNT optimization
            // Wrapped in IO dispatcher to avoid main thread violations
            val pendingCount = withContext(Dispatchers.IO) {
                database.pingInboxDao().countPendingByContact(
                    contactId = contactId,
                    msgStoredState = com.securelegion.database.entities.PingInbox.STATE_MSG_STORED
                )
            }

            if (pendingCount == 0 && downloadingPingIds.isEmpty() && isDownloadInProgress) {
                Log.d(TAG, "All downloads complete (ping_inbox confirms no pending) - resetting isDownloadInProgress")
                isDownloadInProgress = false
            }

            withContext(Dispatchers.Main) {
                Log.d(TAG, "Updating adapter with ${messages.size} messages + ${pendingPingsToShow.size} pending (${downloadingPingIds.size} downloading, ${autoPongPingIds.size} auto-downloading)")
                if (autoPongPingIds.isNotEmpty()) {
                    Log.i(TAG, "🔵 Auto-PONG pings for typing indicator: ${autoPongPingIds.map { it.take(8) }}")
                }
                // Check if user is at bottom before updating (to avoid force-scrolling)
                // Use findLastVisibleItemPosition() for more reliable detection - treats partially visible items as "at bottom"
                val layoutManager = messagesRecyclerView.layoutManager as? LinearLayoutManager
                val lastVisiblePosition = layoutManager?.findLastVisibleItemPosition() ?: -1
                val oldItemCount = messageAdapter.itemCount
                val wasAtBottom = lastVisiblePosition >= (oldItemCount - 1)

                messageAdapter.updateMessages(
                    messages,
                    pendingPingsToShow,
                    downloadingPingIds,  // Pass downloading state to adapter
                    autoPongPingIds      // Pass auto-downloading pings to show typing indicator
                )

                // Only auto-scroll if user was already at bottom (prevents force-scroll during reading)
                if (wasAtBottom) {
                    messagesRecyclerView.post {
                        val totalItems = messages.size + pendingPingsToShow.size
                        if (totalItems > 0) {
                            messagesRecyclerView.scrollToPosition(totalItems - 1)
                        }
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

        // Check if already downloading this specific ping
        if (downloadingPingIds.contains(pingId)) {
            Log.d(TAG, "Ping $pingId is already being downloaded, ignoring duplicate click")
            return
        }

        // Mark that user has downloaded at least once (enables auto-download for future messages)
        hasDownloadedOnce = true
        Log.d(TAG, "User has downloaded a message - auto-download enabled for this session")

        // Mark this specific ping as downloading
        downloadingPingIds.add(pingId)
        Log.d(TAG, "Added pingId ${pingId.take(8)} to downloadingPingIds - now tracking ${downloadingPingIds.size} downloads")

        // Set flag to prevent showing pending message again during download
        isDownloadInProgress = true

        // CRITICAL FIX: Update ping state to DOWNLOADING in SharedPreferences IMMEDIATELY
        // This ensures loadMessages() will show "Downloading..." instead of the lock icon
        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
        com.securelegion.models.PendingPing.updateState(
            prefs,
            contactId,
            pingId,
            com.securelegion.models.PingState.DOWNLOADING,
            synchronous = true  // Synchronous to ensure it's written before loadMessages()
        )
        Log.d(TAG, "Updated ping state to DOWNLOADING in SharedPreferences before UI refresh")

        // Mark that a download is in progress (in-memory tracking only, no SharedPreferences)
        downloadingPingIds.add(pingId)

        // Immediately update UI to show "Downloading..." status
        lifecycleScope.launch {
            loadMessages()
        }

        // Start the download service with specific ping ID
        // The service will update the ping state (PENDING → DOWNLOADING → DECRYPTING → READY)
        com.securelegion.services.DownloadMessageService.start(this, contactId, contactName, pingId)
    }

    private fun toggleSelectionMode() {
        isSelectionMode = !isSelectionMode
        messageAdapter.setSelectionMode(isSelectionMode)

        Log.d(TAG, "Selection mode: $isSelectionMode")
    }

    /**
     * Delete a single message (from long-press popup menu)
     */
    private fun deleteSingleMessage(message: Message) {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@ChatActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                    // If it's a voice message, securely wipe the audio file using DOD 3-pass
                    if (message.messageType == Message.MESSAGE_TYPE_VOICE && message.voiceFilePath != null) {
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

                    // Note: Image messages are stored as Base64 in attachmentData, not as files
                    // No file cleanup needed for images

                    // Delete from database
                    database.messageDao().deleteMessageById(message.id)
                    Log.d(TAG, "✓ Deleted message ${message.id}")

                    // VACUUM database to compact and remove deleted records
                    try {
                        database.openHelper.writableDatabase.execSQL("VACUUM")
                        Log.d(TAG, "✓ Database vacuumed after message deletion")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to vacuum database", e)
                    }
                }

                // Update UI on main thread
                withContext(Dispatchers.Main) {
                    loadMessages()
                    ThemedToast.show(this@ChatActivity, "Message deleted")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete message", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@ChatActivity, "Failed to delete message")
                }
            }
        }
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

    // ==================== PAYMENT HANDLERS ====================

    /**
     * Handle click on "Pay" or "Accept" button for a received payment request
     *
     * Two flows:
     * 1. Request Money: They put their wallet as recipient → I pay to their wallet → SendMoneyActivity
     * 2. Send Money: Recipient is empty → They want to send to me → AcceptPaymentActivity
     */
    private fun handlePaymentRequestClick(message: Message) {
        Log.d(TAG, "Payment request clicked: ${message.messageId}")

        // Extract quote JSON and parse it
        val quoteJson = message.paymentQuoteJson
        if (quoteJson == null) {
            ThemedToast.show(this, "Invalid payment request")
            return
        }

        // Parse quote to check if this is a "Request Money" or "Send Money" offer
        val quote = com.securelegion.crypto.NLx402Manager.PaymentQuote.fromJson(quoteJson)
        if (quote == null) {
            ThemedToast.show(this, "Failed to parse payment request")
            return
        }

        // Check recipient field to determine flow type
        if (quote.recipient.isNullOrEmpty()) {
            // Empty recipient = "Send Money" offer → They want to send me money
            // Open AcceptPaymentActivity so I can provide my wallet address
            Log.d(TAG, "Send Money offer detected - opening AcceptPaymentActivity")
            val intent = Intent(this, AcceptPaymentActivity::class.java).apply {
                putExtra(AcceptPaymentActivity.EXTRA_SENDER_NAME, contactName)
                putExtra(AcceptPaymentActivity.EXTRA_CONTACT_ID, contactId)
                putExtra(AcceptPaymentActivity.EXTRA_PAYMENT_AMOUNT, message.paymentAmount ?: 0L)
                putExtra(AcceptPaymentActivity.EXTRA_PAYMENT_TOKEN, message.paymentToken ?: "SOL")
                putExtra(AcceptPaymentActivity.EXTRA_PAYMENT_QUOTE_JSON, quoteJson)
                putExtra(AcceptPaymentActivity.EXTRA_MESSAGE_ID, message.messageId)
                putExtra(AcceptPaymentActivity.EXTRA_EXPIRY_TIME, quote.expiresAt * 1000) // Convert to millis
            }
            startActivity(intent)
        } else {
            // Has recipient = "Request Money" → They're requesting money from me
            // Open SendMoneyActivity to pay them
            Log.d(TAG, "Request Money detected - opening SendMoneyActivity")
            val intent = Intent(this, SendMoneyActivity::class.java).apply {
                putExtra(SendMoneyActivity.EXTRA_RECIPIENT_NAME, contactName)
                putExtra(SendMoneyActivity.EXTRA_RECIPIENT_ADDRESS, quote.recipient)
                putExtra(SendMoneyActivity.EXTRA_CONTACT_ID, contactId.toLong())
                putExtra(SendMoneyActivity.EXTRA_PAYMENT_QUOTE_JSON, quoteJson)
                putExtra(SendMoneyActivity.EXTRA_PAYMENT_AMOUNT, message.paymentAmount ?: 0L)
                putExtra(SendMoneyActivity.EXTRA_PAYMENT_TOKEN, message.paymentToken ?: "SOL")
                putExtra(SendMoneyActivity.EXTRA_IS_PAYMENT_REQUEST, true)
            }
            startActivity(intent)
        }
    }

    /**
     * Handle click on a payment card to view details
     * Opens TransferDetailsActivity or RequestDetailsActivity based on message type
     */
    private fun handlePaymentDetailsClick(message: Message) {
        Log.d(TAG, "Payment details clicked: ${message.messageId}")

        when (message.messageType) {
            Message.MESSAGE_TYPE_PAYMENT_REQUEST -> {
                // Show request details (I requested money)
                val intent = Intent(this, RequestDetailsActivity::class.java).apply {
                    putExtra(RequestDetailsActivity.EXTRA_RECIPIENT_NAME, contactName)
                    putExtra(RequestDetailsActivity.EXTRA_QUOTE_JSON, message.paymentQuoteJson)
                    putExtra(RequestDetailsActivity.EXTRA_AMOUNT, (message.paymentAmount ?: 0L).toDouble() / getTokenDivisor(message.paymentToken))
                    putExtra(RequestDetailsActivity.EXTRA_CURRENCY, message.paymentToken ?: "SOL")
                    putExtra(RequestDetailsActivity.EXTRA_TRANSACTION_NUMBER, message.messageId)
                    putExtra(RequestDetailsActivity.EXTRA_TIME, formatTime(message.timestamp))
                    putExtra(RequestDetailsActivity.EXTRA_DATE, formatDate(message.timestamp))
                    putExtra(RequestDetailsActivity.EXTRA_PAYMENT_STATUS, message.paymentStatus ?: Message.PAYMENT_STATUS_PENDING)
                }
                startActivity(intent)
            }
            Message.MESSAGE_TYPE_PAYMENT_SENT -> {
                // Show transfer details (I paid or they paid me)
                lifecycleScope.launch {
                    try {
                        val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@ChatActivity)
                        val myAddress = keyManager.getSolanaAddress()

                        // Get contact's address
                        val database = com.securelegion.database.SecureLegionDatabase.getInstance(
                            this@ChatActivity,
                            keyManager.getDatabasePassphrase()
                        )
                        val contact = database.contactDao().getContactById(contactId)
                        val contactAddress = contact?.solanaAddress ?: ""

                        val (fromAddress, toAddress) = if (message.isSentByMe) {
                            // I sent money: from me, to them
                            Pair(myAddress, contactAddress)
                        } else {
                            // They sent money: from them, to me
                            Pair(contactAddress, myAddress)
                        }

                        val intent = Intent(this@ChatActivity, TransferDetailsActivity::class.java).apply {
                            putExtra(TransferDetailsActivity.EXTRA_RECIPIENT_NAME, contactName)
                            putExtra(TransferDetailsActivity.EXTRA_AMOUNT, (message.paymentAmount ?: 0L).toDouble() / getTokenDivisor(message.paymentToken))
                            putExtra(TransferDetailsActivity.EXTRA_CURRENCY, message.paymentToken ?: "SOL")
                            putExtra(TransferDetailsActivity.EXTRA_FROM_ADDRESS, fromAddress)
                            putExtra(TransferDetailsActivity.EXTRA_TO_ADDRESS, toAddress)
                            putExtra(TransferDetailsActivity.EXTRA_TRANSACTION_NUMBER, message.txSignature ?: message.messageId)
                            putExtra(TransferDetailsActivity.EXTRA_TIME, formatTime(message.timestamp))
                            putExtra(TransferDetailsActivity.EXTRA_DATE, formatDate(message.timestamp))
                            putExtra(TransferDetailsActivity.EXTRA_IS_OUTGOING, message.isSentByMe)
                        }
                        startActivity(intent)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to get addresses for payment details", e)
                        // Fallback: show details without addresses
                        val intent = Intent(this@ChatActivity, TransferDetailsActivity::class.java).apply {
                            putExtra(TransferDetailsActivity.EXTRA_RECIPIENT_NAME, contactName)
                            putExtra(TransferDetailsActivity.EXTRA_AMOUNT, (message.paymentAmount ?: 0L).toDouble() / getTokenDivisor(message.paymentToken))
                            putExtra(TransferDetailsActivity.EXTRA_CURRENCY, message.paymentToken ?: "SOL")
                            putExtra(TransferDetailsActivity.EXTRA_TRANSACTION_NUMBER, message.txSignature ?: message.messageId)
                            putExtra(TransferDetailsActivity.EXTRA_TIME, formatTime(message.timestamp))
                            putExtra(TransferDetailsActivity.EXTRA_DATE, formatDate(message.timestamp))
                            putExtra(TransferDetailsActivity.EXTRA_IS_OUTGOING, message.isSentByMe)
                        }
                        startActivity(intent)
                    }
                }
            }
        }
    }

    private fun getTokenDivisor(token: String?): Double {
        return when (token?.uppercase()) {
            "SOL" -> 1_000_000_000.0  // 9 decimals
            "ZEC" -> 100_000_000.0    // 8 decimals
            "USDC", "USDT" -> 1_000_000.0  // 6 decimals
            else -> 1_000_000_000.0   // Default to SOL
        }
    }

    private fun formatTime(timestamp: Long): String {
        val sdf = SimpleDateFormat("hh:mm a", Locale.getDefault())
        return sdf.format(Date(timestamp))
    }

    private fun formatDate(timestamp: Long): String {
        val sdf = SimpleDateFormat("dd MMM, yyyy", Locale.getDefault())
        return sdf.format(Date(timestamp))
    }

    /**
     * Fetch live crypto prices and cache them in the adapter
     */
    private fun fetchCryptoPrices() {
        lifecycleScope.launch {
            try {
                val solanaService = com.securelegion.services.SolanaService(this@ChatActivity)
                val zcashService = com.securelegion.services.ZcashService.getInstance(this@ChatActivity)

                // Fetch SOL price
                val solResult = solanaService.getSolPrice()
                if (solResult.isSuccess) {
                    MessageAdapter.cachedSolPrice = solResult.getOrNull() ?: 0.0
                    Log.d(TAG, "Cached SOL price: ${MessageAdapter.cachedSolPrice}")
                }

                // Fetch ZEC price
                val zecResult = zcashService.getZecPrice()
                if (zecResult.isSuccess) {
                    MessageAdapter.cachedZecPrice = zecResult.getOrNull() ?: 0.0
                    Log.d(TAG, "Cached ZEC price: ${MessageAdapter.cachedZecPrice}")
                }

                // Refresh adapter to show updated prices
                withContext(Dispatchers.Main) {
                    messageAdapter.notifyDataSetChanged()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch crypto prices", e)
            }
        }
    }

    /**
     * Refresh price for a specific payment card when clicked
     */
    private fun refreshPaymentPrice(message: Message, usdView: TextView, cryptoView: TextView) {
        val token = message.paymentToken ?: "SOL"

        lifecycleScope.launch {
            try {
                ThemedToast.show(this@ChatActivity, "Refreshing price...")

                val price = when (token.uppercase()) {
                    "SOL" -> {
                        val solanaService = com.securelegion.services.SolanaService(this@ChatActivity)
                        val result = solanaService.getSolPrice()
                        if (result.isSuccess) {
                            MessageAdapter.cachedSolPrice = result.getOrNull() ?: 0.0
                            MessageAdapter.cachedSolPrice
                        } else 0.0
                    }
                    "ZEC" -> {
                        val zcashService = com.securelegion.services.ZcashService.getInstance(this@ChatActivity)
                        val result = zcashService.getZecPrice()
                        if (result.isSuccess) {
                            MessageAdapter.cachedZecPrice = result.getOrNull() ?: 0.0
                            MessageAdapter.cachedZecPrice
                        } else 0.0
                    }
                    else -> 0.0
                }

                if (price > 0) {
                    // Calculate and update USD amount
                    val amount = message.paymentAmount ?: 0L
                    val decimals = when (token.uppercase()) {
                        "SOL" -> 9
                        "ZEC" -> 8
                        "USDC", "USDT" -> 6
                        else -> 9
                    }
                    val divisor = java.math.BigDecimal.TEN.pow(decimals)
                    val cryptoAmount = java.math.BigDecimal(amount).divide(divisor).toDouble()
                    val usdValue = cryptoAmount * price

                    withContext(Dispatchers.Main) {
                        usdView.text = String.format("$%.2f", usdValue)
                        ThemedToast.show(this@ChatActivity, "Price updated")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to refresh price", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@ChatActivity, "Failed to refresh price")
                }
            }
        }
    }

    /**
     * Start voice call with this contact
     */
    private fun startVoiceCall() {
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
                        this@ChatActivity,
                        Manifest.permission.RECORD_AUDIO
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    ActivityCompat.requestPermissions(
                        this@ChatActivity,
                        arrayOf(Manifest.permission.RECORD_AUDIO),
                        PERMISSION_REQUEST_CODE
                    )
                    isInitiatingCall = false
                    return@launch
                }

                // Get contact info from database
                val keyManager = KeyManager.getInstance(this@ChatActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val db = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)
                val contact = withContext(Dispatchers.IO) {
                    db.contactDao().getContactById(contactId)
                }

                if (contact == null) {
                    ThemedToast.show(this@ChatActivity, "Contact not found")
                    isInitiatingCall = false
                    return@launch
                }

                if (contact.voiceOnion.isNullOrEmpty()) {
                    ThemedToast.show(this@ChatActivity, "Contact has no voice address")
                    isInitiatingCall = false
                    return@launch
                }

                if (contact.messagingOnion == null) {
                    ThemedToast.show(this@ChatActivity, "Contact has no messaging address")
                    isInitiatingCall = false
                    return@launch
                }

                // Generate call ID (use full UUID for proper matching)
                val callId = UUID.randomUUID().toString()

                // Generate ephemeral keypair
                val crypto = VoiceCallCrypto()
                val ephemeralKeypair = crypto.generateEphemeralKeypair()

                // Launch VoiceCallActivity immediately (shows "Calling..." screen)
                val intent = Intent(this@ChatActivity, VoiceCallActivity::class.java)
                intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_ID, contactId)
                intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_NAME, contactName)
                intent.putExtra(VoiceCallActivity.EXTRA_CALL_ID, callId)
                intent.putExtra(VoiceCallActivity.EXTRA_IS_OUTGOING, true)
                intent.putExtra(VoiceCallActivity.EXTRA_OUR_EPHEMERAL_SECRET_KEY, ephemeralKeypair.secretKey.asBytes)
                startActivity(intent)

                // Get voice onion once for reuse in retries
                val torManager = com.securelegion.crypto.TorManager.getInstance(this@ChatActivity)
                val myVoiceOnion = torManager.getVoiceOnionAddress() ?: ""

                // Get our X25519 public key for HTTP wire format (reuse existing keyManager from earlier)
                val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

                // Send CALL_OFFER (first attempt) to voice onion via HTTP POST
                Log.i(TAG, "CALL_OFFER_SEND attempt=1 call_id=$callId to voice onion via HTTP POST")
                val success = withContext(Dispatchers.IO) {
                    CallSignaling.sendCallOffer(
                        recipientX25519PublicKey = contact.x25519PublicKeyBytes,
                        recipientOnion = contact.voiceOnion!!,
                        callId = callId,
                        ephemeralPublicKey = ephemeralKeypair.publicKey.asBytes,
                        voiceOnion = myVoiceOnion,
                        ourX25519PublicKey = ourX25519PublicKey,
                        numCircuits = 1
                    )
                }

                if (!success) {
                    ThemedToast.show(this@ChatActivity, "Failed to send call offer")
                    // VoiceCallActivity will handle timeout
                    isInitiatingCall = false
                    return@launch
                }

                // Register pending call and wait for CALL_ANSWER with 30-second timeout
                val callManager = VoiceCallManager.getInstance(this@ChatActivity)

                // Create a countdown timer to check for timeout
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
                            Log.e(TAG, "CALL_SETUP_TIMEOUT call_id=$callId elapsed_ms=$elapsed")
                            break
                        }

                        offerAttemptNum++
                        Log.i(TAG, "CALL_OFFER_SEND attempt=$offerAttemptNum call_id=$callId (retry to voice onion via HTTP POST)")

                        withContext(Dispatchers.IO) {
                            CallSignaling.sendCallOffer(
                                recipientX25519PublicKey = contact.x25519PublicKeyBytes,
                                recipientOnion = contact.voiceOnion!!,
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
                    contactOnion = contact.voiceOnion!!,
                    contactEd25519PublicKey = contact.ed25519PublicKeyBytes,
                    contactName = contactName,
                    ourEphemeralPublicKey = ephemeralKeypair.publicKey.asBytes,
                    onAnswered = { theirEphemeralKey ->
                        lifecycleScope.launch(Dispatchers.Main) {
                            val elapsed = System.currentTimeMillis() - setupStartTime
                            Log.i(TAG, "CALL_ANSWER_RECEIVED call_id=$callId elapsed_ms=$elapsed")
                            timeoutJob.cancel()
                            offerRetryJob.cancel()
                            // Notify the active VoiceCallActivity that CALL_ANSWER was received
                            VoiceCallActivity.onCallAnswered(callId, theirEphemeralKey)
                            Log.i(TAG, "Call answered, notified VoiceCallActivity")
                            isInitiatingCall = false
                        }
                    },
                    onRejected = { reason ->
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            offerRetryJob.cancel()
                            VoiceCallActivity.onCallRejected(callId, reason)
                            isInitiatingCall = false
                        }
                    },
                    onBusy = {
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            offerRetryJob.cancel()
                            VoiceCallActivity.onCallBusy(callId)
                            isInitiatingCall = false
                        }
                    },
                    onTimeout = {
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            offerRetryJob.cancel()
                            VoiceCallActivity.onCallTimeout(callId)
                            isInitiatingCall = false
                        }
                    }
                )

                Log.i(TAG, "Voice call initiated to $contactName with call ID: $callId")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to start voice call", e)
                ThemedToast.show(this@ChatActivity, "Failed to start call: ${e.message}")
                isInitiatingCall = false
            }
        }
    }

    // ==================== CONTACT PHOTO ====================

    private fun setupContactAvatar() {
        contactAvatar = findViewById(R.id.contactAvatar)

        // Load contact photo from database
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@ChatActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                val contact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactById(contactId)
                }

                if (contact != null) {
                    // Set photo if available, otherwise use name for initials
                    if (!contact.profilePictureBase64.isNullOrEmpty()) {
                        contactAvatar.setPhotoBase64(contact.profilePictureBase64)
                    }
                    contactAvatar.setName(contact.displayName)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error loading contact photo", e)
                contactAvatar.setName(contactName)
            }
        }

        // Click listener to change contact photo
        contactAvatar.setOnClickListener {
            showContactPhotoPickerDialog()
        }
    }

    private fun showContactPhotoPickerDialog() {
        AlertDialog.Builder(this)
            .setTitle("Change Contact Photo")
            .setItems(arrayOf("Take Photo", "Choose from Gallery", "Remove Photo")) { _, which ->
                when (which) {
                    0 -> com.securelegion.utils.ImagePicker.pickFromCamera(contactPhotoCameraLauncher)
                    1 -> com.securelegion.utils.ImagePicker.pickFromGallery(contactPhotoGalleryLauncher)
                    2 -> removeContactPhoto()
                }
            }
            .show()
    }

    private fun saveContactPhoto(base64: String) {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@ChatActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                withContext(Dispatchers.IO) {
                    database.contactDao().updateContactPhoto(contactId, base64)
                }
                Log.d(TAG, "Contact photo saved to database")
            } catch (e: Exception) {
                Log.e(TAG, "Error saving contact photo", e)
            }
        }
    }

    private fun removeContactPhoto() {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@ChatActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                withContext(Dispatchers.IO) {
                    database.contactDao().updateContactPhoto(contactId, null)
                }
                contactAvatar.clearPhoto()
                ThemedToast.show(this@ChatActivity, "Contact photo removed")
                Log.d(TAG, "Contact photo removed from database")
            } catch (e: Exception) {
                Log.e(TAG, "Error removing contact photo", e)
            }
        }
    }

}
