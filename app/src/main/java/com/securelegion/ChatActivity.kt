package com.securelegion

import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.GlassDialog

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
import android.view.Gravity
import android.view.LayoutInflater
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.contract.ActivityResultContracts
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
import com.securelegion.services.TorService
import com.securelegion.network.TransportGate
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
import com.vanniktech.emoji.google.GoogleEmojiProvider
import com.vanniktech.emoji.EmojiManager
import com.securelegion.views.MediaKeyboardView

class ChatActivity : BaseActivity() {

    companion object {
        private const val TAG = "ChatActivity"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "CONTACT_NAME"
        const val EXTRA_CONTACT_ADDRESS = "CONTACT_ADDRESS"
        private const val PERMISSION_REQUEST_CODE = 100
        private const val CAMERA_PERMISSION_REQUEST_CODE = 101
        private const val GALLERY_PERMISSION_REQUEST_CODE = 102
        private const val MAX_IMAGE_WIDTH = 1920 // 1080p width
        private const val MAX_IMAGE_HEIGHT = 1080 // 1080p height
        private const val JPEG_QUALITY = 85 // Good quality, reasonable size

        /** Contact ID currently visible in ChatActivity, or -1 if not open. */
        @Volatile
        var visibleContactId: Long = -1L
            private set
    }

    private lateinit var messagesRecyclerView: RecyclerView
    private lateinit var messageAdapter: MessageAdapter
    private lateinit var messageService: MessageService
    private lateinit var messageInput: EditText
    private lateinit var sendButton: View
    private lateinit var sendButtonIcon: ImageView
    private lateinit var plusButton: View
    private lateinit var emojiButton: View
    private lateinit var emojiButtonIcon: ImageView
    private lateinit var mediaKeyboardPanel: MediaKeyboardView
    private var isMediaKeyboardVisible = false
    private lateinit var attachmentPanel: View
    private var isAttachmentPanelVisible = false
    private var isFirstLoad = true
    private var keyboardHeight = 0
    private lateinit var textInputLayout: LinearLayout
    private lateinit var voiceRecordingLayout: LinearLayout
    private lateinit var recordingTimer: TextView
    private lateinit var cancelRecordingButton: ImageView
    private lateinit var sendVoiceButton: ImageView
    private lateinit var contactAvatar: com.securelegion.views.AvatarView
    private lateinit var pinnedBanner: View
    private lateinit var pinnedBannerText: TextView
    private lateinit var pinnedBannerClose: ImageView
    private var pinnedMessagePosition: Int = -1
    private var pinnedMessageId: Long = -1

    private var contactId: Long = -1
    private var contactName: String = "@user"
    private var contactAddress: String = ""
    private var myPubKeyBase64: String = ""
    private var myReactionByMessageId: Map<String, String> = emptyMap()
    private var isShowingSendButton = false
    private var isSelectionMode = false

    // Auto-download: Track if user has manually downloaded at least one message this session
    // (Device Protection ON only - enables auto-PONG for subsequent pings in same session)
    private var hasDownloadedOnce = false

    // Lazy DB reference - avoids reconstructing KeyManager + passphrase on every call
    private val database by lazy {
        val keyManager = KeyManager.getInstance(this)
        val dbPassphrase = keyManager.getDatabasePassphrase()
        SecureLegionDatabase.getInstance(this, dbPassphrase)
    }

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
    private var isWaitingForCameraGallery = false // Prevent auto-lock during external camera/gallery

    // Voice call
    private var isInitiatingCall = false // Prevent duplicate call initiations

    // Media picking
    private var isWaitingForMediaResult = false // Track if waiting for media picker result

    // Image preview/edit result
    private val imagePreviewLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val filePath = result.data?.getStringExtra(ImagePreviewActivity.RESULT_IMAGE_URI)
            if (filePath != null) {
                handleEditedImage(filePath)
            }
        }
    }

    // Activity result launchers for image picking
    private val galleryLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        isWaitingForMediaResult = false // Clear flag
        // DON'T clear isWaitingForCameraGallery here - let onResume() clear it
        // after preventing auto-lock (callback runs before onResume)

        uri?.let { launchImagePreview(it) }
    }

    private val cameraLauncher = registerForActivityResult(
        ActivityResultContracts.TakePicture()
    ) { success: Boolean ->
        isWaitingForMediaResult = false // Clear flag
        // DON'T clear isWaitingForCameraGallery here - let onResume() clear it
        // after preventing auto-lock (callback runs before onResume)

        if (success && cameraPhotoUri != null) {
            launchImagePreview(cameraPhotoUri!!)
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
                    Log.d(TAG, "NEW_PING broadcast: receivedContactId=$receivedContactId, state=${com.securelegion.services.DownloadStateManager.getState(receivedContactId)}")

                    if (receivedContactId == contactId) {
                        // NEW_PING for current contact - DownloadStateManager drives the UI,
                        // just refresh to pick up the latest state.
                        runOnUiThread {
                            lifecycleScope.launch {
                                // Device Protection ON + user active: auto-PONG new pings
                                val securityPrefs = getSharedPreferences("security", MODE_PRIVATE)
                                val deviceProtectionEnabled = securityPrefs.getBoolean(
                                    com.securelegion.SecurityModeActivity.PREF_DEVICE_PROTECTION_ENABLED, false
                                )
                                if (deviceProtectionEnabled && hasDownloadedOnce) {
                                    val pingSeen = withContext(kotlinx.coroutines.Dispatchers.IO) {
                                        database.pingInboxDao().getPendingByContact(contactId)
                                            .filter { it.state == com.securelegion.database.entities.PingInbox.STATE_PING_SEEN }
                                            .filter { ping ->
                                                val wireBytes = ping.pingWireBytesBase64?.let {
                                                    try { android.util.Base64.decode(it, android.util.Base64.NO_WRAP) } catch (_: Exception) { null }
                                                }
                                                wireBytes == null || wireBytes.isEmpty() || wireBytes[0] != 0x0F.toByte()
                                            }
                                    }
                                    if (pingSeen.isNotEmpty()) {
                                        Log.i(TAG, "Device Protection ON but user active - auto-PONGing ${pingSeen.size} ping(s)")
                                        pingSeen.forEach { ping ->
                                            Log.d(TAG, "Auto-PONGing ping: ${ping.pingId.take(8)}")
                                            com.securelegion.services.DownloadMessageService.start(
                                                this@ChatActivity, contactId, contactName, ping.pingId
                                            )
                                        }
                                    }
                                }
                                loadMessagesDebounced()
                            }
                        }
                    } else if (receivedContactId != -1L) {
                        loadMessagesDebounced()
                    }
                }
                "com.securelegion.DOWNLOAD_FAILED" -> {
                    val receivedContactId = intent.getLongExtra("CONTACT_ID", -1L)
                    Log.d(TAG, "DOWNLOAD_FAILED broadcast: receivedContactId=$receivedContactId, state=${com.securelegion.services.DownloadStateManager.getState(receivedContactId)}")
                    if (receivedContactId == contactId) {
                        // DownloadStateManager already transitioned to BACKOFF - just refresh UI
                        loadMessagesDebounced()
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Install Google emoji provider (must be called before any emoji rendering)
        EmojiManager.install(GoogleEmojiProvider())

        setContentView(R.layout.activity_chat)

        // Back press closes open panels first
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (isMediaKeyboardVisible) {
                    hideMediaKeyboard()
                } else if (isAttachmentPanelVisible) {
                    hideAttachmentPanel()
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })

        // Enable edge-to-edge display (important for display cutouts)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        // Handle window insets for header and message input container
        val rootView = findViewById<View>(android.R.id.content)
        val chatHeader = findViewById<View>(R.id.chatHeader)
        pinnedBanner = findViewById(R.id.pinnedBanner)
        pinnedBannerText = findViewById(R.id.pinnedBannerText)
        pinnedBannerClose = findViewById(R.id.pinnedBannerClose)
        val messageInputContainer = findViewById<View>(R.id.messageInputContainer)
        val recyclerView = findViewById<RecyclerView>(R.id.messagesRecyclerView)
        var wasImeVisible = false
        val headerBasePaddingLeft = chatHeader.paddingLeft
        val headerBasePaddingTop = chatHeader.paddingTop
        val headerBasePaddingRight = chatHeader.paddingRight
        val headerBasePaddingBottom = chatHeader.paddingBottom

        // Header floats above messages for glass effect
        chatHeader.elevation = 8 * resources.displayMetrics.density

        // Track current keyboard inset so the layout listener can use it
        var currentBottomInset = 0

        // Update RecyclerView padding based on header + input bar + any visible bottom panel
        fun updateRecyclerPadding() {
            val inputContentHeight = messageInputContainer.height - messageInputContainer.paddingBottom
            val bottomMargin = (28 * resources.displayMetrics.density).toInt() // 12dp margin + 16dp breathing
            val panelHeight = if (isAttachmentPanelVisible && ::attachmentPanel.isInitialized) attachmentPanel.height
                              else if (isMediaKeyboardVisible) findViewById<View>(R.id.mediaKeyboardPanel)?.height ?: 0
                              else 0
            val pinnedHeight = if (pinnedBanner.visibility == View.VISIBLE) pinnedBanner.height else 0
            recyclerView.setPadding(
                recyclerView.paddingLeft,
                chatHeader.height + pinnedHeight,
                recyclerView.paddingRight,
                currentBottomInset + inputContentHeight + bottomMargin + panelHeight
            )
        }

        // Recalculate RV padding whenever the header or input bar is laid out
        chatHeader.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
            updateRecyclerPadding()
        }
        pinnedBanner.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
            updateRecyclerPadding()
        }
        messageInputContainer.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
            updateRecyclerPadding()
        }

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
                headerBasePaddingLeft + systemInsets.left,
                headerBasePaddingTop + systemInsets.top,
                headerBasePaddingRight + systemInsets.right,
                headerBasePaddingBottom
            )

            // Apply bottom inset to message input container
            // Use IME inset when keyboard is visible, system nav bar inset otherwise
            currentBottomInset = if (imeVisible) {
                imeInsets.bottom
            } else {
                systemInsets.bottom
            }

            messageInputContainer.setPadding(
                messageInputContainer.paddingLeft,
                messageInputContainer.paddingTop,
                messageInputContainer.paddingRight,
                currentBottomInset
            )

            // Also update RV padding immediately (layout listener will refine after measure)
            updateRecyclerPadding()

            // Scroll to bottom when keyboard just appeared
            if (imeVisible && !wasImeVisible) {
                recyclerView.post { scrollToBottom(smooth = true) }
            }
            wasImeVisible = imeVisible

            Log.d("ChatActivity", "Insets - System bottom: ${systemInsets.bottom}, IME bottom: ${imeInsets.bottom}, IME visible: $imeVisible, Applied bottom: $currentBottomInset")

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

        // SharedPrefs migration removed - ping_inbox DB is single source of truth

        // Initialize services
        messageService = MessageService(this)
        voiceRecorder = VoiceRecorder(this)
        voicePlayer = VoicePlayer(this)

        // Setup UI
        val chatNameView = findViewById<TextView>(R.id.chatName)
        chatNameView.text = contactName
        com.securelegion.utils.TextGradient.apply(chatNameView)

        // Tap contact name to open contact profile
        chatNameView.setOnClickListener {
            val intent = Intent(this, ContactOptionsActivity::class.java).apply {
                putExtra("CONTACT_ID", contactId)
                putExtra("CONTACT_NAME", contactName)
                putExtra("CONTACT_ADDRESS", contactAddress)
            }
            startActivity(intent)
        }

        // DEBUG: Long-press contact name to reset key chain counters
        chatNameView.setOnLongClickListener {
            Log.d(TAG, "DEBUG: Long-press detected on contact name!")
            ThemedToast.show(this, "Long-press detected - showing reset dialog")

            val resetDialog = GlassDialog.builder(this)
                .setTitle("Reset Key Chain?")
                .setMessage("This will reset send/receive counters to 0 for this contact.\n\n WARNING: Both devices must reset at the same time!")
                .setPositiveButton("Reset") { _, _ ->
                    Log.d(TAG, "DEBUG: User tapped RESET button in dialog")
                    ThemedToast.show(this@ChatActivity, "Resetting key chain counters...")
                    lifecycleScope.launch {
                        try {
                            Log.d(TAG, "DEBUG: Calling KeyChainManager.resetKeyChainCounters for contactId=$contactId")
                            KeyChainManager.resetKeyChainCounters(this@ChatActivity, contactId)
                            Log.d(TAG, "DEBUG: Reset completed successfully!")
                            ThemedToast.show(this@ChatActivity, "Key chain counters reset to 0")
                        } catch (e: Exception) {
                            Log.e(TAG, "DEBUG: Reset failed with exception", e)
                            ThemedToast.show(this@ChatActivity, "Failed to reset: ${e.message}")
                        }
                    }
                }
                .setNegativeButton("Cancel") { _, _ ->
                    Log.d(TAG, "DEBUG: User tapped CANCEL button in dialog")
                }
                .create()
            GlassDialog.show(resetDialog)
            Log.d(TAG, "DEBUG: Reset dialog shown to user")
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
        visibleContactId = contactId

        // Check persistent flag first (survives activity recreation)
        val lifecyclePrefs = getSharedPreferences("app_lifecycle", MODE_PRIVATE)
        val wasWaitingForCameraGallery = lifecyclePrefs.getBoolean("waiting_for_camera_gallery", false)

        // Clear pause timestamp if returning from camera/gallery to prevent auto-lock
        // Camera/gallery are EXTERNAL apps, so they're not detected by BaseActivity
        if (isWaitingForCameraGallery || wasWaitingForCameraGallery) {
            lifecyclePrefs.edit()
                .putLong("last_pause_timestamp", 0L)
                .putBoolean("waiting_for_camera_gallery", false)
                .commit() // Intentional: must be synchronous before onResume() completes
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

        // Cancel system bar notifications for this contact
        cancelNotificationsForContact()

        // Download state is derived from database on loadMessages() - no need to check SharedPreferences

        // Refresh messages when returning to the screen (ensures fresh data even if broadcast was missed)
        lifecycleScope.launch {
            loadMessages()
        }

        // Notify TorService that app is in foreground (fast bandwidth updates)
        com.securelegion.services.TorService.setForegroundState(true)

    }

    /**
     * Cancel all system bar notifications related to this contact:
     * - Message notifications (grouped under MESSAGES_{contactId})
     * - Friend-request-accepted notification (ID 6000 + hash)
     * - Global pending summary (999) if no message notifications remain
     */
    private fun cancelNotificationsForContact() {
        try {
            val notificationManager = getSystemService(android.app.NotificationManager::class.java)
            val messageGroup = "MESSAGES_${contactId}"

            // Cancel all message notifications for this contact
            for (sbn in notificationManager.activeNotifications) {
                if (sbn.notification.group == messageGroup) {
                    notificationManager.cancel(sbn.id)
                }
            }

            // Cancel friend-request-accepted notification for this contact
            if (contactName.isNotEmpty()) {
                val acceptedNotificationId = 6000 + Math.abs(contactName.hashCode() % 10000)
                notificationManager.cancel(acceptedNotificationId)
            }

            // If no message notifications remain, cancel the global summary too
            val hasRemainingMessages = notificationManager.activeNotifications.any {
                it.notification.group?.startsWith("MESSAGES_") == true
            }
            if (!hasRemainingMessages) {
                notificationManager.cancel(999)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to cancel notifications for contact", e)
        }
    }

    override fun onPause() {
        super.onPause()
        visibleContactId = -1L
        Log.d(TAG, "onPause called")

        // Notify TorService that app is in background (slow bandwidth updates to save battery)
        com.securelegion.services.TorService.setForegroundState(false)
    }

    override fun onStop() {
        super.onStop()
        hideMediaKeyboard()
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

    /**
     * Scroll to bottom of messages
     * Use smooth scroll when user is actively interacting (typing/receiving),
     * instant scroll for data loads
     */
    private fun scrollToBottom(smooth: Boolean = true) {
        val itemCount = messageAdapter.itemCount
        if (itemCount > 0) {
            messagesRecyclerView.post {
                val layoutManager = messagesRecyclerView.layoutManager as? LinearLayoutManager
                val lastVisible = layoutManager?.findLastVisibleItemPosition() ?: 0
                val distance = itemCount - 1 - lastVisible

                // Only smooth-scroll if within 15 items of the bottom.
                // Smooth-scrolling 1000+ items locks the UI for ages.
                if (smooth && distance in 1..15) {
                    messagesRecyclerView.smoothScrollToPosition(itemCount - 1)
                } else {
                    messagesRecyclerView.scrollToPosition(itemCount - 1)
                }
            }
        }
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
            },
            onResendMessage = { message ->
                // Resend failed message (user-triggered via long-press menu)
                resendFailedMessage(message)
            },
            decryptImageFile = { encryptedBytes ->
                KeyManager.getInstance(this).decryptImageFile(encryptedBytes)
            },
            onPinMessage = { message ->
                pinMessage(message)
            },
            onReactMessage = { message ->
                showReactionPicker(message)
            },
            decryptContent = { stored ->
                KeyManager.getInstance(this).decryptMessageContent(stored)
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
        emojiButton = findViewById(R.id.emojiButton)
        emojiButtonIcon = findViewById(R.id.emojiButtonIcon)
        textInputLayout = findViewById(R.id.textInputLayout)
        voiceRecordingLayout = findViewById(R.id.voiceRecordingLayout)
        recordingTimer = findViewById(R.id.recordingTimer)
        cancelRecordingButton = findViewById(R.id.cancelRecordingButton)
        sendVoiceButton = findViewById(R.id.sendVoiceButton)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Call button - voice calling disabled in v1
        findViewById<View>(R.id.callButton).visibility = View.GONE

        // Attachment panel (inline - replaces keyboard like media panel)
        attachmentPanel = findViewById(R.id.attachmentPanel)
        setupAttachmentPanel()

        // Plus button toggles inline attachment panel
        plusButton.setOnClickListener {
            if (isAttachmentPanelVisible) {
                hideAttachmentPanel()
            } else {
                val imm = getSystemService(INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
                val keyboardVisible = imm.isAcceptingText
                if (keyboardVisible) {
                    hideSoftKeyboard()
                    plusButton.postDelayed({ showAttachmentPanel() }, 200)
                } else {
                    showAttachmentPanel()
                }
            }
        }

        // Media keyboard panel (emoji/sticker/GIF)
        mediaKeyboardPanel = findViewById(R.id.mediaKeyboardPanel)
        setupMediaKeyboard()

        // Track keyboard height for panel sizing
        val rootView = findViewById<View>(android.R.id.content)
        rootView.viewTreeObserver.addOnGlobalLayoutListener {
            val rect = android.graphics.Rect()
            rootView.getWindowVisibleDisplayFrame(rect)
            val screenHeight = rootView.rootView.height
            val kbHeight = screenHeight - rect.bottom
            if (kbHeight > 200) {
                keyboardHeight = kbHeight
                // If keyboard appeared while any panel is showing, hide it
                if (isMediaKeyboardVisible) {
                    hideMediaKeyboard()
                }
                if (isAttachmentPanelVisible) {
                    hideAttachmentPanel()
                }
            }
        }

        // Emoji button toggles media keyboard panel
        emojiButton.setOnClickListener {
            if (isMediaKeyboardVisible) {
                hideMediaKeyboard()
                showSoftKeyboard()
            } else {
                if (isAttachmentPanelVisible) hideAttachmentPanel()
                hideSoftKeyboard()
                // Delay slightly so keyboard hides before panel appears
                emojiButton.postDelayed({ showMediaKeyboard() }, 100)
            }
        }

        // Tapping the text input hides any panel and shows keyboard
        messageInput.setOnClickListener {
            if (isMediaKeyboardVisible) {
                hideMediaKeyboard()
            }
            if (isAttachmentPanelVisible) {
                hideAttachmentPanel()
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

    private fun setupAttachmentPanel() {
        // Close/collapse arrow
        attachmentPanel.findViewById<View>(R.id.closeAttachmentPanel).setOnClickListener {
            hideAttachmentPanel()
        }

        // Setup photo previews
        val photoPreviewGrid = attachmentPanel.findViewById<RecyclerView>(R.id.photoPreviewGrid)
        val allowAccessButton = attachmentPanel.findViewById<View>(R.id.allowAccessButton)
        setupPhotoPreviewGrid(photoPreviewGrid, allowAccessButton, null)

        // Gallery action
        attachmentPanel.findViewById<View>(R.id.actionGallery).setOnClickListener {
            flashAttachmentIcon(it)
            hideAttachmentPanel()
            openGallery()
        }

        // Camera action
        attachmentPanel.findViewById<View>(R.id.actionCamera).setOnClickListener {
            flashAttachmentIcon(it)
            hideAttachmentPanel()
            openCamera()
        }

        // File action
        attachmentPanel.findViewById<View>(R.id.actionFile).setOnClickListener {
            flashAttachmentIcon(it)
            hideAttachmentPanel()
            ThemedToast.show(this, "File sharing coming soon")
        }

        // SecurePay action
        attachmentPanel.findViewById<View>(R.id.actionSecurePay).setOnClickListener {
            flashAttachmentIcon(it)
            hideAttachmentPanel()
            ThemedToast.show(this, "SecurePay coming soon")
        }

        // Location action
        attachmentPanel.findViewById<View>(R.id.actionLocation).setOnClickListener {
            flashAttachmentIcon(it)
            hideAttachmentPanel()
            ThemedToast.show(this, "Location sharing coming soon")
        }
    }

    private fun flashAttachmentIcon(actionView: View) {
        val iconBg = (actionView as ViewGroup).getChildAt(0) as android.widget.FrameLayout
        iconBg.setBackgroundResource(R.drawable.attachment_icon_circle_bg_active)
        iconBg.postDelayed({
            iconBg.setBackgroundResource(R.drawable.attachment_icon_circle_bg)
        }, 300)
    }

    private fun showAttachmentPanel() {
        if (isMediaKeyboardVisible) hideMediaKeyboard()
        val minHeight = (380 * resources.displayMetrics.density).toInt()
        val height = if (keyboardHeight > minHeight) keyboardHeight else minHeight
        attachmentPanel.layoutParams.height = height
        attachmentPanel.visibility = View.VISIBLE
        attachmentPanel.requestLayout()
        isAttachmentPanelVisible = true

        // Refresh photo previews each time panel opens
        val photoPreviewGrid = attachmentPanel.findViewById<RecyclerView>(R.id.photoPreviewGrid)
        val allowAccessButton = attachmentPanel.findViewById<View>(R.id.allowAccessButton)
        setupPhotoPreviewGrid(photoPreviewGrid, allowAccessButton, null)

        // Scroll messages up so last message is visible above the panel
        messagesRecyclerView.post { scrollToBottom(smooth = true) }
    }

    private fun hideAttachmentPanel() {
        if (!isAttachmentPanelVisible) return
        attachmentPanel.visibility = View.GONE
        isAttachmentPanelVisible = false
    }

    private fun setupPhotoPreviewGrid(
        recyclerView: RecyclerView,
        allowAccessButton: View,
        bottomSheet: GlassBottomSheetDialog?
    ) {
        // Check permission (READ_MEDIA_IMAGES for full access, READ_MEDIA_VISUAL_USER_SELECTED
        // for partial "Select photos" on Android 14+, READ_EXTERNAL_STORAGE for pre-13)
        val hasPermission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // Android 14+: either full or partial photo access is enough to show previews
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_IMAGES) ==
                PackageManager.PERMISSION_GRANTED ||
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_VISUAL_USER_SELECTED) ==
                PackageManager.PERMISSION_GRANTED
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_MEDIA_IMAGES) ==
                PackageManager.PERMISSION_GRANTED
        } else {
            ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) ==
                PackageManager.PERMISSION_GRANTED
        }

        if (!hasPermission) {
            recyclerView.visibility = View.GONE
            allowAccessButton.visibility = View.VISIBLE
            allowAccessButton.setOnClickListener {
                bottomSheet?.dismiss()
                hideAttachmentPanel()
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    ActivityCompat.requestPermissions(
                        this, arrayOf(
                            Manifest.permission.READ_MEDIA_IMAGES,
                            Manifest.permission.READ_MEDIA_VISUAL_USER_SELECTED
                        ), GALLERY_PERMISSION_REQUEST_CODE
                    )
                } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    ActivityCompat.requestPermissions(
                        this, arrayOf(Manifest.permission.READ_MEDIA_IMAGES), GALLERY_PERMISSION_REQUEST_CODE
                    )
                } else {
                    ActivityCompat.requestPermissions(
                        this, arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE), GALLERY_PERMISSION_REQUEST_CODE
                    )
                }
            }
            return
        }

        // Load recent photos from MediaStore
        recyclerView.visibility = View.VISIBLE
        allowAccessButton.visibility = View.GONE

        recyclerView.layoutManager = LinearLayoutManager(this, LinearLayoutManager.HORIZONTAL, false)

        lifecycleScope.launch {
            val photos = withContext(Dispatchers.IO) { loadRecentPhotos(20) }
            recyclerView.adapter = com.securelegion.adapters.PhotoPreviewAdapter(photos) { uri ->
                bottomSheet?.dismiss()
                hideAttachmentPanel()
                launchImagePreview(uri)
            }
        }
    }

    private fun loadRecentPhotos(limit: Int): List<Uri> {
        val photos = mutableListOf<Uri>()
        val collection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL)
        } else {
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI
        }

        val projection = arrayOf(MediaStore.Images.Media._ID)
        val sortOrder = "${MediaStore.Images.Media.DATE_ADDED} DESC"

        contentResolver.query(collection, projection, null, null, sortOrder)?.use { cursor ->
            val idColumn = cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
            var count = 0
            while (cursor.moveToNext() && count < limit) {
                val id = cursor.getLong(idColumn)
                val contentUri = android.content.ContentUris.withAppendedId(collection, id)
                photos.add(contentUri)
                count++
            }
        }
        return photos
    }

    // ==================== MEDIA KEYBOARD (Emoji / Sticker / GIF) ====================

    private fun setupMediaKeyboard() {
        mediaKeyboardPanel.setOnEmojiSelectedListener { emoji ->
            // Insert emoji at cursor position in EditText
            val start = messageInput.selectionStart.coerceAtLeast(0)
            val end = messageInput.selectionEnd.coerceAtLeast(0)
            messageInput.text.replace(start.coerceAtMost(end), start.coerceAtLeast(end), emoji)
        }

        mediaKeyboardPanel.setOnStickerSelectedListener { assetPath ->
            hideMediaKeyboard()
            sendStickerMessage(assetPath)
        }

        mediaKeyboardPanel.setOnGifSelectedListener { gifAssetPath ->
            hideMediaKeyboard()
            // System GIFs are bundled assets - send as text code like stickers
            sendStickerMessage(gifAssetPath)
        }
    }

    private fun showMediaKeyboard() {
        if (isAttachmentPanelVisible) hideAttachmentPanel()
        val height = if (keyboardHeight > 200) keyboardHeight
            else (300 * resources.displayMetrics.density).toInt()
        mediaKeyboardPanel.layoutParams.height = height
        mediaKeyboardPanel.visibility = View.VISIBLE
        mediaKeyboardPanel.requestLayout()
        isMediaKeyboardVisible = true
        emojiButtonIcon.setImageResource(R.drawable.ic_keyboard)
    }

    private fun hideMediaKeyboard() {
        if (!isMediaKeyboardVisible) return
        mediaKeyboardPanel.visibility = View.GONE
        isMediaKeyboardVisible = false
        emojiButtonIcon.setImageResource(R.drawable.ic_emoji)
    }

    private fun hideSoftKeyboard() {
        val imm = getSystemService(INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
        imm.hideSoftInputFromWindow(messageInput.windowToken, 0)
    }

    private fun showSoftKeyboard() {
        messageInput.requestFocus()
        val imm = getSystemService(INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
        imm.showSoftInput(messageInput, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
    }

    private fun sendStickerMessage(assetPath: String) {
        lifecycleScope.launch {
            try {
                val result = messageService.sendStickerMessage(
                    contactId = contactId,
                    assetPath = assetPath,
                    onMessageSaved = { savedMessage ->
                        runOnUiThread {
                            lifecycleScope.launch { loadMessages() }
                        }
                    }
                )
                if (result.isSuccess) {
                    Log.i(TAG, "Sticker sent: $assetPath")
                } else {
                    ThemedToast.show(this@ChatActivity, "Failed to send sticker")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send sticker", e)
                ThemedToast.show(this@ChatActivity, "Failed to send sticker")
            }
        }
    }

    // ==================== IMAGE SENDING ====================

    private fun showImageSourceDialog() {
        val bottomSheet = GlassBottomSheetDialog(this)
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

            val uri = cameraPhotoUri
            if (uri == null) {
                Log.e(TAG, "cameraPhotoUri is null - cannot launch camera")
                ThemedToast.show(this, "Camera unavailable. Please try again.")
                return
            }
            cameraLauncher.launch(uri)
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

    private fun launchImagePreview(uri: Uri) {
        val intent = ImagePreviewActivity.createIntent(this, uri)
        imagePreviewLauncher.launch(intent)
    }

    private fun handleEditedImage(filePath: String) {
        lifecycleScope.launch {
            try {
                ThemedToast.show(this@ChatActivity, "Sending image...")

                val compressedImageData = withContext(Dispatchers.IO) {
                    compressImageFromFile(filePath)
                }

                if (compressedImageData == null) {
                    ThemedToast.show(this@ChatActivity, "Failed to process image")
                    return@launch
                }

                val imageSizeKB = compressedImageData.size / 1024
                Log.d(TAG, "Edited image size: ${imageSizeKB}KB")

                if (imageSizeKB > 500) {
                    ThemedToast.show(this@ChatActivity, "Image too large (${imageSizeKB}KB). Max 500KB.")
                    return@launch
                }

                sendImageMessage(compressedImageData)

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send edited image", e)
                ThemedToast.show(this@ChatActivity, "Failed to send image: ${e.message}")
            }
        }
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

    private fun compressImageFromFile(filePath: String): ByteArray? {
        try {
            val file = java.io.File(filePath)
            if (!file.exists() || file.length() == 0L) {
                Log.e(TAG, "Edited image file missing or empty: $filePath")
                return null
            }
            Log.d(TAG, "compressImageFromFile: path=$filePath, size=${file.length()}")

            // Decode bounds
            val boundsOptions = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeFile(filePath, boundsOptions)

            val (width, height) = boundsOptions.outWidth to boundsOptions.outHeight
            if (width <= 0 || height <= 0) {
                Log.e(TAG, "Failed to decode bounds from file: ${width}x${height}")
                return null
            }

            var sampleSize = 1
            while (width / (sampleSize * 2) >= MAX_IMAGE_WIDTH && height / (sampleSize * 2) >= MAX_IMAGE_HEIGHT) {
                sampleSize *= 2
            }

            // Decode actual bitmap
            val decodeOptions = BitmapFactory.Options().apply { inSampleSize = sampleSize }
            var bitmap = BitmapFactory.decodeFile(filePath, decodeOptions) ?: return null

            // Scale if needed
            bitmap = scaleBitmap(bitmap, MAX_IMAGE_WIDTH, MAX_IMAGE_HEIGHT)

            // Compress to JPEG (strips EXIF metadata)
            val outputStream = java.io.ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, JPEG_QUALITY, outputStream)
            bitmap.recycle()

            val result = outputStream.toByteArray()
            Log.d(TAG, "compressImageFromFile: output ${result.size} bytes")
            return result
        } catch (e: Exception) {
            Log.e(TAG, "compressImageFromFile failed", e)
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

    private fun showFullImage(imageData: String) {
        if (imageData.isEmpty()) {
            ThemedToast.show(this, "Image not available")
            return
        }

        try {
            // Decode image (handle file path or inline base64)
            val rawBytes = if (imageData.startsWith("/")) {
                val file = java.io.File(imageData)
                if (file.exists()) file.readBytes() else null
            } else {
                Base64.decode(imageData, Base64.DEFAULT)
            }
            if (rawBytes == null) {
                ThemedToast.show(this, "Image file not found")
                return
            }

            // Decrypt if encrypted (.enc = AES-256-GCM at rest)
            val imageBytes = if (imageData.endsWith(".enc")) {
                KeyManager.getInstance(this).decryptImageFile(rawBytes)
            } else {
                rawBytes // Legacy .img or inline base64
            }
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
        val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
        when (requestCode) {
            PERMISSION_REQUEST_CODE -> {
                if (granted) {
                    startVoiceRecording()
                } else {
                    ThemedToast.show(this, "Microphone permission required for voice messages")
                }
            }
            GALLERY_PERMISSION_REQUEST_CODE -> {
                if (granted) {
                    // Re-open the attachment panel so user immediately sees their photos
                    showAttachmentPanel()
                }
            }
            CAMERA_PERMISSION_REQUEST_CODE -> {
                if (granted) {
                    // Camera permission was granted, retry camera action
                }
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

    private fun pinnedPreviewFor(message: Message): String {
        return when (message.messageType) {
            Message.MESSAGE_TYPE_IMAGE -> "Photo"
            Message.MESSAGE_TYPE_VOICE -> "Voice message"
            Message.MESSAGE_TYPE_STICKER -> "Sticker"
            Message.MESSAGE_TYPE_PAYMENT_REQUEST -> "Payment request"
            Message.MESSAGE_TYPE_PAYMENT_SENT -> "Payment sent"
            Message.MESSAGE_TYPE_PAYMENT_ACCEPTED -> "Payment accepted"
            else -> try {
                KeyManager.getInstance(this).decryptMessageContent(message.encryptedContent).ifBlank { "Pinned message" }
            } catch (_: Exception) { "Pinned message" }
        }
    }

    private fun updatePinnedBanner(messages: List<Message>) {
        val pinnedMessage = messages.lastOrNull { it.isPinned }
        if (pinnedMessage == null) {
            pinnedBanner.visibility = View.GONE
            pinnedMessagePosition = -1
            pinnedMessageId = -1
            return
        }

        pinnedBannerText.text = pinnedPreviewFor(pinnedMessage)
        pinnedMessagePosition = messages.indexOfLast { it.id == pinnedMessage.id }
        pinnedMessageId = pinnedMessage.id
        pinnedBanner.visibility = View.VISIBLE

        pinnedBanner.setOnClickListener {
            val position = pinnedMessagePosition
            if (position >= 0) {
                messagesRecyclerView.smoothScrollToPosition(position)
            }
        }

        pinnedBannerClose.setOnClickListener {
            val messageId = pinnedMessageId
            if (messageId <= 0) return@setOnClickListener
            pinnedBanner.visibility = View.GONE
            pinnedMessagePosition = -1
            pinnedMessageId = -1
            lifecycleScope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        database.messageDao().setPinned(messageId, false)
                    }
                    loadMessages()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to unpin message", e)
                }
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
                Log.d(TAG, "Message: [${msg.encryptedContent.length}B] status=${msg.status}")
            }

            // Get database instance (reuse for multiple operations)
            val keyManager = KeyManager.getInstance(this@ChatActivity)
            val dbPassphrase = keyManager.getDatabasePassphrase()
            val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)
            if (myPubKeyBase64.isBlank()) {
                myPubKeyBase64 = Base64.encodeToString(keyManager.getSigningPublicKey(), Base64.NO_WRAP)
            }

            // Mark all received messages as read (updates unread count)
            // TODO(ghost-badge): Replace per-message loop with bulk markAllAsRead(contactId)
            // to avoid races where new messages arrive between filter and markAsRead calls.
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

            // Load renderable pings from ping_inbox DB (single source of truth)
            // Only states that need a UI row: PING_SEEN(0), DOWNLOAD_QUEUED(10), FAILED_TEMP(11), MANUAL_REQUIRED(12)
            // Excludes PONG_SENT(1) and MSG_STORED(2) to prevent message+downloading overlap
            val pingInboxEntries = withContext(Dispatchers.IO) {
                database.pingInboxDao().getRenderableByContact(contactId.toLong())
            }

            // Get set of pingIds that already have messages in the database
            val existingMessagePingIds = messages.mapNotNull { it.pingId }.toSet()

            // Transition ghost pings (message exists but ping not yet MSG_STORED) to MSG_STORED
            val ghostPings = pingInboxEntries.filter { it.pingId in existingMessagePingIds }
            if (ghostPings.isNotEmpty()) {
                Log.i(TAG, "Transitioning ${ghostPings.size} ghost pings to MSG_STORED")
                withContext(Dispatchers.IO) {
                    val now = System.currentTimeMillis()
                    ghostPings.forEach { ping ->
                        database.pingInboxDao().transitionToMsgStored(ping.pingId, now)
                    }
                }
            }

            // Only show pings that don't have messages yet
            val activePingEntries = pingInboxEntries.filter { it.pingId !in existingMessagePingIds }

            Log.d(TAG, "Pending pings from DB: ${activePingEntries.size} (${ghostPings.size} ghost cleaned)")
            activePingEntries.forEachIndexed { index, ping ->
                Log.d(TAG, "Ping $index: ${ping.pingId.take(8)} - state=${ping.state}")
            }

            // Suppress silent pings (0x0F profile updates, 0x10 reactions) -- no lock icon or typing dots
            // Wire format: [type_byte][X25519_pubkey_32][encrypted_payload] -- first byte is unencrypted content type
            val silentWireTypes = setOf(0x0F.toByte(), 0x10.toByte())
            val pendingPingsToShow = activePingEntries.filter { ping ->
                val wireBytes = ping.pingWireBytesBase64?.let {
                    try { android.util.Base64.decode(it, android.util.Base64.NO_WRAP) } catch (_: Exception) { null }
                }
                wireBytes == null || wireBytes.isEmpty() || wireBytes[0] !in silentWireTypes
            }

            // â”€â”€ State machine drives UI â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            // DownloadStateManager is the single source of truth for typing/lock.
            // Typing indicator = DOWNLOADING only (active network I/O)
            // Lock icon        = PAUSED only (device protection ON, no retries)
            // IDLE/BACKOFF     = invisible (pending pings hidden from UI)
            val contactState = com.securelegion.services.DownloadStateManager.getState(contactId.toLong())
            val secPrefs = getSharedPreferences("security", MODE_PRIVATE)
            val devProtection = secPrefs.getBoolean(
                com.securelegion.SecurityModeActivity.PREF_DEVICE_PROTECTION_ENABLED, false
            )

            // Decide which pending pings to show and whether to display typing dots
            val (pingsForAdapter, showTyping) = if (!devProtection) {
                // Instant mode: typing = DOWNLOADING, lock = never, hidden otherwise
                when (contactState) {
                    com.securelegion.services.DownloadStateManager.State.DOWNLOADING -> {
                        // Show 1 typing indicator (first pending ping is the visual anchor)
                        if (pendingPingsToShow.isNotEmpty()) {
                            listOf(pendingPingsToShow.first()) to true
                        } else {
                            emptyList<com.securelegion.database.entities.PingInbox>() to false
                        }
                    }
                    else -> {
                        // IDLE, BACKOFF, or PAUSED - everything invisible, retries happen silently
                        emptyList<com.securelegion.database.entities.PingInbox>() to false
                    }
                }
            } else {
                // Manual mode (Device Protection ON): show all pending pings as lock icons
                // User taps lock -> DownloadMessageService starts -> state flips to DOWNLOADING -> typing
                when (contactState) {
                    com.securelegion.services.DownloadStateManager.State.DOWNLOADING -> {
                        // Show 1 typing indicator (cap at 1 to avoid duplicate dots)
                        if (pendingPingsToShow.isNotEmpty()) {
                            listOf(pendingPingsToShow.first()) to true
                        } else {
                            emptyList<com.securelegion.database.entities.PingInbox>() to false
                        }
                    }
                    else -> {
                        // Show lock icons for all pending pings (manual download required)
                        pendingPingsToShow to false
                    }
                }
            }

            Log.d(TAG, "State machine: contact=$contactId state=$contactState devProtection=$devProtection -> showing ${pingsForAdapter.size} pings (typing=$showTyping)")

            val reactionAgg = withContext(Dispatchers.IO) {
                database.messageReactionDao().getAggregatesForContact(contactId, myPubKeyBase64)
            }
            val reactionSummaryByMessageId = mutableMapOf<String, MutableList<String>>()
            val myReactionMap = mutableMapOf<String, String>()
            reactionAgg.forEach { row ->
                val display = if (row.count > 1) "${row.emoji} ${row.count}" else row.emoji
                reactionSummaryByMessageId.getOrPut(row.targetMessageId) { mutableListOf() }.add(display)
                if (row.mine == 1) {
                    myReactionMap[row.targetMessageId] = row.emoji
                }
            }
            myReactionByMessageId = myReactionMap

            withContext(Dispatchers.Main) {
                Log.d(TAG, "Updating adapter with ${messages.size} messages + ${pingsForAdapter.size} pending")
                updatePinnedBanner(messages)
                messageAdapter.setReactionSummaries(
                    reactionSummaryByMessageId.mapValues { (_, list) -> list.joinToString("  ") }
                )
                val layoutManager = messagesRecyclerView.layoutManager as? LinearLayoutManager
                val lastVisiblePosition = layoutManager?.findLastVisibleItemPosition() ?: -1
                val oldItemCount = messageAdapter.itemCount
                val wasAtBottom = lastVisiblePosition >= (oldItemCount - 1)

                val totalItems = messages.size + pingsForAdapter.size
                // Always scroll on first load (opening chat), otherwise only if at bottom or new items
                val shouldScroll = isFirstLoad || wasAtBottom || oldItemCount < totalItems

                messageAdapter.updateMessages(
                    messages,
                    pingsForAdapter,
                    showTyping
                ) {
                    // Runs AFTER DiffUtil commits - adapter itemCount is now correct
                    if (shouldScroll) {
                        scrollToBottom(smooth = !isFirstLoad)
                    }
                    isFirstLoad = false
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

    private fun showReactionPicker(message: Message) {
        val choices = listOf("👍", "❤️", "😂", "😮", "😢", "🔥", "🙏", "👎")
        val currentMine = myReactionByMessageId[message.messageId]
        val dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_reaction_picker, null)
        val emojiContainer = dialogView.findViewById<LinearLayout>(R.id.reactionEmojiContainer)
        val removeButton = dialogView.findViewById<TextView>(R.id.reactionRemoveButton)

        val dialog = GlassDialog.builder(this)
            .setView(dialogView)
            .create()

        fun sendReaction(emoji: String, present: Boolean) {
            lifecycleScope.launch {
                val (targetMessageId, targetBlobMessageId) = withContext(Dispatchers.IO) {
                    resolveReactionTargetIds(message)
                }
                val result = withContext(Dispatchers.IO) {
                    messageService.sendReactionMessage(
                        contactId = contactId,
                        targetMessageId = targetMessageId,
                        targetBlobMessageId = targetBlobMessageId,
                        emoji = emoji,
                        present = present
                    )
                }
                if (result.isFailure) {
                    ThemedToast.show(this@ChatActivity, "Failed to send reaction")
                }
                loadMessagesDebounced()
            }
            dialog.dismiss()
        }

        choices.forEach { emoji ->
            val chip = TextView(this).apply {
                text = emoji
                textSize = 22f
                gravity = Gravity.CENTER
                background = ContextCompat.getDrawable(this@ChatActivity, R.drawable.glass_circle_bg)
                layoutParams = LinearLayout.LayoutParams(dp(44), dp(44)).apply {
                    marginEnd = dp(8)
                }
                setOnClickListener {
                    sendReaction(emoji, present = true)
                }
            }
            emojiContainer.addView(chip)
        }

        if (currentMine != null) {
            removeButton.visibility = View.VISIBLE
            removeButton.setOnClickListener {
                sendReaction(currentMine, present = false)
            }
        } else {
            removeButton.visibility = View.GONE
        }

        dialog.show()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private suspend fun resolveReactionTargetIds(message: Message): Pair<String, String?> {
        val localTargetId = message.messageId
        if (localTargetId.startsWith("blob_")) {
            return localTargetId to localTargetId
        }

        return try {
            val encryptedPayload = message.encryptedPayload
                ?: database.messageDao().getEncryptedPayload(message.id)
            val blobId = encryptedPayload?.let { computeBlobMessageId(it) }
            localTargetId to blobId
        } catch (e: Exception) {
            Log.w(TAG, "Failed to resolve blob message id for reaction target", e)
            localTargetId to null
        }
    }

    private fun computeBlobMessageId(encryptedPayloadBase64: String): String? {
        return try {
            val encryptedBytes = Base64.decode(encryptedPayloadBase64, Base64.NO_WRAP)
            val hash = java.security.MessageDigest.getInstance("SHA-256").digest(encryptedBytes)
            "blob_" + Base64.encodeToString(hash, Base64.NO_WRAP).take(28)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to compute blob message id from encrypted payload", e)
            null
        }
    }

    private fun sendMessage(enableSelfDestruct: Boolean = false, enableReadReceipt: Boolean = true) {
        val messageText = messageInput.text.toString().trim()

        if (messageText.isBlank()) {
            return
        }

        Log.d(TAG, "Sending message: $messageText (self-destruct=$enableSelfDestruct, read-receipt=$enableReadReceipt)")

        // Clear input synchronously on main thread before any async work
        messageInput.text.clear()

        // Post to ensure the cleared-text frame renders before the send coroutine
        // runs on Main.immediate (which would otherwise delay the draw pass)
        messageInput.post {
        lifecycleScope.launch {
            try {

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
                            // scrollToBottom is now handled inside loadMessages() via commit callback
                        }
                    }
                )

                if (result.isFailure) {
                    Log.e(TAG, "Failed to send message", result.exceptionOrNull())
                }
            } catch (e: Exception) {
                // Silent failure - message saved to database, will retry later
                Log.e(TAG, "Failed to send message (will retry later)", e)

                // Reload messages to show the pending message (scroll handled by commit callback)
                loadMessages()
            }
        }
        } // messageInput.post
    }


    private fun handleDownloadClick(pingId: String) {
        Log.i(TAG, "Download button clicked for contact $contactId, ping $pingId")

        // Ignore if already downloading for this contact (DownloadStateManager is the guard)
        if (com.securelegion.services.DownloadStateManager.isDownloading(contactId)) {
            Log.d(TAG, "Already downloading for contact $contactId, ignoring duplicate click")
            return
        }

        // Atomic DB claim - prevents double-click race
        lifecycleScope.launch {
            val claimed = withContext(Dispatchers.IO) {
                database.pingInboxDao().claimForManualDownload(pingId, System.currentTimeMillis())
            }

            if (claimed == 0) {
                Log.w(TAG, "Ping ${pingId.take(8)} claim failed - already claimed or past DOWNLOAD_QUEUED")
                return@launch
            }

            Log.d(TAG, "Ping ${pingId.take(8)} claimed (DB -> DOWNLOAD_QUEUED)")

            // Mark that user has downloaded at least once (enables auto-PONG for future pings)
            hasDownloadedOnce = true

            // Refresh UI (DownloadStateManager will flip to DOWNLOADING when I/O starts)
            loadMessages()

            // Start the download service - it calls DownloadStateManager.onDownloadStarted()
            com.securelegion.services.DownloadMessageService.start(this@ChatActivity, contactId, contactName, pingId)
        }
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
                                Log.d(TAG, "Securely wiped voice file: ${voiceFile.name}")
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to securely wipe voice file", e)
                        }
                    }

                    // Note: Image messages are stored as Base64 in attachmentData, not as files
                    // No file cleanup needed for images

                    // Delete from database
                    database.messageDao().deleteMessageById(message.id)
                    Log.d(TAG, "Deleted message ${message.id}")
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

    private fun pinMessage(message: Message) {
        val newPinned = !message.isPinned
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    database.messageDao().setPinned(message.id, newPinned)
                }
                loadMessages()
                ThemedToast.show(
                    this@ChatActivity,
                    if (newPinned) "Message pinned" else "Message unpinned"
                )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to pin/unpin message", e)
            }
        }
    }

    /**
     * Resend a failed message (from long-press popup menu)
     * Triggers immediate retry via MessageService
     */
    private fun resendFailedMessage(message: Message) {
        lifecycleScope.launch {
            try {
                Log.i(TAG, "User requested resend for message ${message.messageId} (id=${message.id})")

                val messageService = MessageService(this@ChatActivity)
                val result = messageService.retryMessageNow(message.id)

                if (result.isSuccess) {
                    withContext(Dispatchers.Main) {
                        loadMessages() // Refresh UI to show updated status
                    }
                } else {
                    // Message remains queued; retry worker will handle it
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to resend message", e)
                // Message remains queued; retry worker will handle it
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

                    // Delete pending pings from ping_inbox DB
                    if (pingIds.isNotEmpty()) {
                        pingIds.forEach { pingId ->
                            database.pingInboxDao().delete(pingId)
                            Log.d(TAG, "Deleted pending ping $pingId from ping_inbox")
                            deletedPendingMessage = true
                        }
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
                                    Log.d(TAG, "Securely wiped voice file: ${voiceFile.name}")
                                }
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to securely wipe voice file", e)
                            }
                        }

                        // Delete from database
                        database.messageDao().deleteMessageById(messageId)
                    }

                    Log.d(TAG, "Deleted ${regularMessageIds.size} messages")
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
        val deleteDialog = GlassDialog.builder(this)
            .setTitle("Delete Chat")
            .setMessage("Delete this entire conversation? This cannot be undone.")
            .setPositiveButton("Delete") { _, _ ->
                lifecycleScope.launch {
                    try {
                        val keyManager = KeyManager.getInstance(this@ChatActivity)
                        val dbPassphrase = keyManager.getDatabasePassphrase()
                        val database = SecureLegionDatabase.getInstance(this@ChatActivity, dbPassphrase)

                        withContext(Dispatchers.IO) {
                            // Lightweight projection: only fetch the 4 small columns needed for cleanup
                            // Uses getDeleteInfoForContact instead of SELECT * to avoid CursorWindow overflow
                            val deleteInfos = database.messageDao().getDeleteInfoForContact(contactId.toLong())

                            // Securely wipe any voice/image files
                            deleteInfos.forEach { info ->
                                if (info.messageType == Message.MESSAGE_TYPE_VOICE &&
                                    info.voiceFilePath != null) {
                                    try {
                                        val voiceFile = File(info.voiceFilePath)
                                        if (voiceFile.exists()) {
                                            SecureWipe.secureDeleteFile(voiceFile)
                                            Log.d(TAG, "Securely wiped voice file: ${voiceFile.name}")
                                        }
                                    } catch (e: Exception) {
                                        Log.e(TAG, "Failed to securely wipe voice file", e)
                                    }
                                }
                                // Wipe image files (stored as image_messages/$messageId.img)
                                if (info.messageType == Message.MESSAGE_TYPE_IMAGE) {
                                    try {
                                        // Check both .enc (encrypted) and .img (legacy) files
                                        val encFile = File(filesDir, "image_messages/${info.messageId}.enc")
                                        val imgFile = File(filesDir, "image_messages/${info.messageId}.img")
                                        val imageFile = if (encFile.exists()) encFile else imgFile
                                        if (imageFile.exists()) {
                                            SecureWipe.secureDeleteFile(imageFile)
                                            Log.d(TAG, "Securely wiped image file: ${imageFile.name}")
                                        }
                                    } catch (e: Exception) {
                                        Log.e(TAG, "Failed to securely wipe image file", e)
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

                            Log.d(TAG, "Thread deleted successfully")
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
            .create()
        GlassDialog.show(deleteDialog)
    }

    // ==================== PAYMENT HANDLERS ====================

    /**
     * Handle click on "Pay" or "Accept" button for a received payment request
     *
     * Two flows:
     * 1. Request Money: They put their wallet as recipient -> I pay to their wallet -> SendMoneyActivity
     * 2. Send Money: Recipient is empty -> They want to send to me -> AcceptPaymentActivity
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
            // Empty recipient = "Send Money" offer -> They want to send me money
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
            // Has recipient = "Request Money" -> They're requesting money from me
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
                putExtra(SendMoneyActivity.EXTRA_MESSAGE_ID, message.messageId)
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
            "SOL" -> 1_000_000_000.0 // 9 decimals
            "ZEC" -> 100_000_000.0 // 8 decimals
            "USDC", "USDT" -> 1_000_000.0 // 6 decimals
            else -> 1_000_000_000.0 // Default to SOL
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
            Log.w(TAG, "Call initiation already in progress - ignoring duplicate request")
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
        val dialog = GlassDialog.builder(this)
            .setTitle("Change Contact Photo")
            .setItems(arrayOf("Take Photo", "Choose from Gallery", "Remove Photo")) { _, which ->
                when (which) {
                    0 -> com.securelegion.utils.ImagePicker.pickFromCamera(contactPhotoCameraLauncher)
                    1 -> com.securelegion.utils.ImagePicker.pickFromGallery(contactPhotoGalleryLauncher)
                    2 -> removeContactPhoto()
                }
            }
            .create()
        GlassDialog.show(dialog)
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


