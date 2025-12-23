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

    // Image capture
    private var cameraPhotoUri: Uri? = null
    private var cameraPhotoFile: File? = null
    private var isWaitingForMediaResult = false  // Prevent auto-lock during camera/gallery

    // Activity result launchers for image picking
    private val galleryLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        isWaitingForMediaResult = false  // Clear flag
        uri?.let { handleSelectedImage(it) }
    }

    private val cameraLauncher = registerForActivityResult(
        ActivityResultContracts.TakePicture()
    ) { success: Boolean ->
        isWaitingForMediaResult = false  // Clear flag
        if (success && cameraPhotoUri != null) {
            handleSelectedImage(cameraPhotoUri!!)
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
                        Log.i(TAG, "New message for current contact - reloading messages")

                        // Launch coroutine immediately to avoid blocking broadcast receiver
                        lifecycleScope.launch(Dispatchers.Main) {
                            // Check if download complete
                            val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                            val pendingPings = withContext(Dispatchers.IO) {
                                com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId)
                            }

                            if (pendingPings.isEmpty()) {
                                isDownloadInProgress = false  // Download complete, pings cleared
                            }

                            // Reload messages - state machine handles atomic swap automatically
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

    override fun onResume() {
        // Reset pause timestamp if returning from camera/gallery to prevent auto-lock
        if (isWaitingForMediaResult) {
            val lifecyclePrefs = getSharedPreferences("app_lifecycle", MODE_PRIVATE)
            lifecyclePrefs.edit().putLong("last_pause_timestamp", 0L).apply()
            Log.d(TAG, "Cleared pause timestamp to prevent auto-lock after camera/gallery")
        }

        super.onResume()
        Log.d(TAG, "onResume called (isWaitingForMediaResult=$isWaitingForMediaResult)")

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

            isWaitingForMediaResult = true  // Prevent auto-lock during camera
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
        isWaitingForMediaResult = true  // Prevent auto-lock during gallery
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
            var allPendingPings = com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId.toLong())

            // Reset stale DOWNLOADING/DECRYPTING states back to PENDING
            // This handles cases where the download service was killed (device shutdown, force stop, etc.)
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
                // Reload pings after reset
                allPendingPings = com.securelegion.models.PendingPing.loadQueueForContact(prefs, contactId.toLong())
            }

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

            // ATOMIC SWAP: Remove pings in READY state (message already saved to DB)
            Log.d(TAG, "Checking for READY pings. Total pings: ${pendingPings.size}")
            pendingPings.forEachIndexed { index, ping ->
                Log.d(TAG, "  Ping $index: ${ping.pingId.take(8)} - state=${ping.state}")
            }

            val readyPings = pendingPings.filter { it.state == com.securelegion.models.PingState.READY }
            if (readyPings.isNotEmpty()) {
                Log.i(TAG, "⚡ ATOMIC SWAP: Removing ${readyPings.size} READY pings")
                readyPings.forEach { ping ->
                    com.securelegion.models.PendingPing.removeFromQueue(prefs, contactId.toLong(), ping.pingId, synchronous = true)
                    Log.d(TAG, "  ✓ Removed READY ping ${ping.pingId.take(8)} - message already in DB")
                }
            } else {
                Log.d(TAG, "No READY pings found")
            }

            // Filter out READY pings from display (they're now messages)
            val pendingPingsToShow = pendingPings.filter { it.state != com.securelegion.models.PingState.READY }

            // Clean up downloadingPingIds - remove any pingIds that are no longer actually pending
            // OR that already have messages in the database
            // This handles failed downloads, completed downloads (safety net), and activity recreation scenarios
            val stillPendingIds = pendingPingsToShow.map { it.pingId }.toSet()
            val existingPingIds = messages.mapNotNull { it.pingId }.toSet()

            // A download is stale if: (1) not in pending queue OR (2) message already exists in DB
            val staleDownloadIds = downloadingPingIds.filter {
                it !in stillPendingIds || it in existingPingIds
            }
            staleDownloadIds.forEach { downloadingPingIds.remove(it) }
            if (staleDownloadIds.isNotEmpty()) {
                Log.i(TAG, "Cleaned up ${staleDownloadIds.size} stale download indicators from UI")
            }

            withContext(Dispatchers.Main) {
                Log.d(TAG, "Updating adapter with ${messages.size} messages + ${pendingPingsToShow.size} pending (${downloadingPingIds.size} downloading)")
                messageAdapter.updateMessages(
                    messages,
                    pendingPingsToShow,
                    downloadingPingIds  // Pass downloading state to adapter
                )
                messagesRecyclerView.post {
                    val totalItems = messages.size + pendingPingsToShow.size
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

        // Start the download service with specific ping ID
        // The service will update the ping state (PENDING → DOWNLOADING → DECRYPTING → READY)
        com.securelegion.services.DownloadMessageService.start(this, contactId, contactName, pingId)

        // DON'T reload here - the MessageAdapter already shows state-based UI
        // The service will broadcast MESSAGE_RECEIVED when state changes, which will trigger a reload
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
                val intent = Intent(this, TransferDetailsActivity::class.java).apply {
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
                    return@launch
                }

                if (contact.messagingOnion == null) {
                    ThemedToast.show(this@ChatActivity, "Contact has no messaging address")
                    return@launch
                }

                // Show "Calling..." dialog
                val callingDialog = AlertDialog.Builder(this@ChatActivity)
                    .setTitle("Calling")
                    .setMessage("Calling $contactName...")
                    .setCancelable(false)
                    .create()
                callingDialog.show()

                // Generate call ID
                val callId = UUID.randomUUID().toString().replace("-", "").take(16)

                // Generate ephemeral keypair
                val crypto = VoiceCallCrypto()
                val ephemeralKeypair = crypto.generateEphemeralKeypair()

                // Send CALL_OFFER
                val success = withContext(Dispatchers.IO) {
                    CallSignaling.sendCallOffer(
                        recipientX25519PublicKey = contact.x25519PublicKeyBytes,
                        recipientOnion = contact.messagingOnion!!,
                        callId = callId,
                        ephemeralPublicKey = ephemeralKeypair.publicKey.asBytes,
                        numCircuits = 1 // Phase 1: single circuit
                    )
                }

                if (!success) {
                    callingDialog.dismiss()
                    ThemedToast.show(this@ChatActivity, "Failed to send call offer")
                    return@launch
                }

                // Register pending call and wait for CALL_ANSWER with 30-second timeout
                val callManager = VoiceCallManager.getInstance(this@ChatActivity)

                // Create a countdown timer to check for timeout
                val timeoutJob = lifecycleScope.launch {
                    while (isActive) {
                        delay(1000) // Check every second
                        callManager.checkPendingCallTimeouts()
                    }
                }

                callManager.registerPendingOutgoingCall(
                    callId = callId,
                    contactOnion = contact.messagingOnion!!,
                    contactEd25519PublicKey = contact.ed25519PublicKeyBytes,
                    contactName = contactName,
                    ourEphemeralPublicKey = ephemeralKeypair.publicKey.asBytes,
                    onAnswered = { theirEphemeralKey ->
                        // Call answered! Launch VoiceCallActivity
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            callingDialog.dismiss()

                            Log.i(TAG, "Call answered by $contactName - launching VoiceCallActivity")

                            val intent = Intent(this@ChatActivity, VoiceCallActivity::class.java)
                            intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_ID, contactId)
                            intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_NAME, contactName)
                            intent.putExtra(VoiceCallActivity.EXTRA_CALL_ID, callId)
                            intent.putExtra(VoiceCallActivity.EXTRA_IS_OUTGOING, true)
                            intent.putExtra(VoiceCallActivity.EXTRA_THEIR_EPHEMERAL_KEY, theirEphemeralKey)
                            startActivity(intent)
                        }
                    },
                    onRejected = { reason ->
                        // Call rejected
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            callingDialog.dismiss()
                            ThemedToast.show(this@ChatActivity, "$contactName declined the call")
                            Log.i(TAG, "Call rejected by $contactName: $reason")
                        }
                    },
                    onBusy = {
                        // Contact is busy
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            callingDialog.dismiss()
                            ThemedToast.show(this@ChatActivity, "$contactName is on another call")
                            Log.i(TAG, "Call to $contactName - busy")
                        }
                    },
                    onTimeout = {
                        // Call timed out (30 seconds, no response)
                        lifecycleScope.launch(Dispatchers.Main) {
                            timeoutJob.cancel()
                            callingDialog.dismiss()
                            ThemedToast.show(this@ChatActivity, "No response from $contactName")
                            Log.w(TAG, "Call to $contactName timed out")
                        }
                    }
                )

            } catch (e: Exception) {
                Log.e(TAG, "Failed to start voice call", e)
                ThemedToast.show(this@ChatActivity, "Failed to start call: ${e.message}")
            }
        }
    }

}
