package com.securelegion

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.media.Ringtone
import android.media.RingtoneManager
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import android.view.animation.AnimationUtils
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.CallHistory
import com.securelegion.database.entities.CallType
import com.securelegion.services.TorService
import com.securelegion.utils.BiometricAuthHelper
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.crypto.VoiceCallCrypto
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job

/**
 * IncomingCallActivity - Full-screen incoming call notification
 *
 * Shows when someone calls you:
 * - Contact name and avatar
 * - Incoming call status
 * - Answer/Decline buttons
 *
 * Receives data from:
 * - Intent extras (callId, contactId, contactName, contactOnion, etc.)
 */
class IncomingCallActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "IncomingCallActivity"
        private const val PERMISSION_REQUEST_CODE = 100
        const val EXTRA_CALL_ID = "CALL_ID"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "CONTACT_NAME"
        const val EXTRA_CONTACT_ONION = "CONTACT_ONION"
        const val EXTRA_CONTACT_ED25519_PUBLIC_KEY = "CONTACT_ED25519_PUBLIC_KEY"
        const val EXTRA_CONTACT_X25519_PUBLIC_KEY = "CONTACT_X25519_PUBLIC_KEY"
        const val EXTRA_EPHEMERAL_PUBLIC_KEY = "EPHEMERAL_PUBLIC_KEY"
    }

    // UI elements
    private lateinit var animatedRing: ImageView
    private lateinit var contactAvatar: ImageView
    private lateinit var contactNameText: TextView
    private lateinit var callStatusText: TextView
    private lateinit var declineButton: FloatingActionButton
    private lateinit var answerButton: FloatingActionButton
    private lateinit var slideHintText: TextView
    private lateinit var slideToAnswerContainer: android.view.ViewGroup

    // Unlock overlay elements
    private lateinit var unlockOverlay: android.view.ViewGroup
    private lateinit var timeoutCountdown: TextView
    private lateinit var quickUnlockButton: com.google.android.material.button.MaterialButton
    private lateinit var passwordEntryContainer: android.widget.LinearLayout
    private lateinit var quickPasswordInput: android.widget.EditText
    private lateinit var submitPasswordButton: com.google.android.material.button.MaterialButton

    // Slide-to-answer state
    private var initialX = 0f
    private var buttonStartX = 0f
    private var containerWidth = 0f
    private var isSliding = false

    // Data
    private var callId: String = ""
    private var contactId: Long = -1
    private var contactName: String = "@Contact"
    private var contactOnion: String = ""
    private var contactEd25519PublicKey: ByteArray = ByteArray(0)
    private var contactX25519PublicKey: ByteArray = ByteArray(0)
    private var theirEphemeralPublicKey: ByteArray = ByteArray(0)

    // Call manager
    private lateinit var callManager: VoiceCallManager
    private val crypto = VoiceCallCrypto()

    // Ringtone
    private var ringtone: Ringtone? = null

    // Track if call was answered (to prevent rejecting in onDestroy)
    private var callWasAnswered = false

    // Quick unlock support
    private lateinit var biometricHelper: BiometricAuthHelper
    private var timeoutJob: Job? = null
    private var remainingSeconds = 30
    private var isAppLocked = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Check if app is locked - if so, show quick unlock overlay
        // Also check if we can verify the password (if we can, app has been set up and should be unlocked)
        val keyManager = KeyManager.getInstance(this)
        val hasBeenUnlocked = com.securelegion.utils.SessionManager.isUnlocked(this)

        // If session says unlocked OR account is not set up yet (first run), don't show lock overlay
        isAppLocked = !hasBeenUnlocked && keyManager.isAccountSetupComplete()

        Log.d(TAG, "Incoming call - SessionManager unlocked: $hasBeenUnlocked, Account complete: ${keyManager.isAccountSetupComplete()}, Will show lock overlay: $isAppLocked")

        // Show over lock screen
        window.addFlags(
            WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
            WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD or
            WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
        )

        setContentView(R.layout.activity_incoming_call)

        // Get data from intent
        callId = intent.getStringExtra(EXTRA_CALL_ID) ?: ""
        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)
        contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: "@Contact"
        contactOnion = intent.getStringExtra(EXTRA_CONTACT_ONION) ?: ""
        contactEd25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_ED25519_PUBLIC_KEY) ?: ByteArray(0)
        contactX25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_X25519_PUBLIC_KEY) ?: ByteArray(0)
        theirEphemeralPublicKey = intent.getByteArrayExtra(EXTRA_EPHEMERAL_PUBLIC_KEY) ?: ByteArray(0)

        // Initialize UI
        initializeViews()
        setupClickListeners()

        // Initialize biometric helper
        biometricHelper = BiometricAuthHelper(this)

        // Get call manager
        callManager = VoiceCallManager.getInstance(this)

        // Update UI
        contactNameText.text = contactName
        callStatusText.text = "Incoming Call"

        // Start ring rotation animation
        val rotateAnimation = AnimationUtils.loadAnimation(this, R.anim.rotate_ring)
        animatedRing.startAnimation(rotateAnimation)

        // If app is locked, show unlock overlay
        if (isAppLocked) {
            Log.w(TAG, "App is locked - showing quick unlock overlay")
            showQuickUnlockOverlay()
        } else {
            Log.i(TAG, "App is unlocked - normal incoming call flow")
        }

        // Check RECORD_AUDIO permission early (while activity window is valid)
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            // Request permission immediately when activity starts
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), PERMISSION_REQUEST_CODE)
        }

        // Play ringtone
        startRingtone()
    }

    private fun initializeViews() {
        animatedRing = findViewById(R.id.animatedRing)
        contactAvatar = findViewById(R.id.contactAvatar)
        contactNameText = findViewById(R.id.contactName)
        callStatusText = findViewById(R.id.callStatus)
        declineButton = findViewById(R.id.declineButton)
        answerButton = findViewById(R.id.answerButton)
        slideHintText = findViewById(R.id.slideHintText)
        slideToAnswerContainer = findViewById(R.id.slideToAnswerContainer)

        // Unlock overlay views
        unlockOverlay = findViewById(R.id.unlockOverlay)
        timeoutCountdown = findViewById(R.id.timeoutCountdown)
        quickUnlockButton = findViewById(R.id.quickUnlockButton)
        passwordEntryContainer = findViewById(R.id.passwordEntryContainer)
        quickPasswordInput = findViewById(R.id.quickPasswordInput)
        submitPasswordButton = findViewById(R.id.submitPasswordButton)

        // Apply 3D press effect to decline button
        val pressAnimator = android.animation.AnimatorInflater.loadStateListAnimator(
            this,
            R.animator.button_press_effect
        )
        declineButton.stateListAnimator = pressAnimator
    }

    private fun setupClickListeners() {
        // Decline button
        declineButton.setOnClickListener {
            declineCall()
        }

        // Slide-to-answer gesture (replaces simple click)
        setupSlideToAnswer()

        // Quick unlock button
        quickUnlockButton.setOnClickListener {
            attemptQuickUnlock()
        }

        // Password submission
        submitPasswordButton.setOnClickListener {
            val password = quickPasswordInput.text.toString()
            if (password.isBlank()) {
                ThemedToast.show(this, "Please enter password")
                return@setOnClickListener
            }
            verifyPasswordAndUnlock(password)
        }

        // Submit on Enter key
        quickPasswordInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == android.view.inputmethod.EditorInfo.IME_ACTION_DONE) {
                submitPasswordButton.performClick()
                true
            } else {
                false
            }
        }
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun setupSlideToAnswer() {
        answerButton.setOnTouchListener { view, event ->
            // Wait for layout to complete to get accurate measurements
            if (containerWidth == 0f) {
                containerWidth = slideToAnswerContainer.width.toFloat()
                buttonStartX = 4f * resources.displayMetrics.density  // 4dp margin
            }

            when (event.action) {
                android.view.MotionEvent.ACTION_DOWN -> {
                    // Start dragging
                    initialX = event.rawX
                    isSliding = true

                    // Slightly enlarge button to show feedback
                    view.animate()
                        .scaleX(1.1f)
                        .scaleY(1.1f)
                        .setDuration(100)
                        .start()

                    true
                }

                android.view.MotionEvent.ACTION_MOVE -> {
                    if (isSliding) {
                        // Calculate new X position
                        val deltaX = event.rawX - initialX
                        var newX = view.x + deltaX

                        // Constrain to container bounds
                        val maxX = containerWidth - view.width - (4f * resources.displayMetrics.density)
                        newX = newX.coerceIn(buttonStartX, maxX)

                        // Update position
                        view.x = newX
                        initialX = event.rawX

                        // Fade out hint text as user slides
                        val progress = (newX - buttonStartX) / (maxX - buttonStartX)
                        slideHintText.alpha = (1f - progress) * 0.7f

                        // Change button color as user slides (green → brighter green)
                        val greenProgress = (0xFF00C853.toInt() + (progress * 0x003300).toInt())
                        answerButton.backgroundTintList = android.content.res.ColorStateList.valueOf(greenProgress)
                    }
                    true
                }

                android.view.MotionEvent.ACTION_UP, android.view.MotionEvent.ACTION_CANCEL -> {
                    isSliding = false

                    // Reset scale
                    view.animate()
                        .scaleX(1f)
                        .scaleY(1f)
                        .setDuration(100)
                        .start()

                    // Check if slid far enough (80% threshold)
                    val maxX = containerWidth - view.width - (4f * resources.displayMetrics.density)
                    val slideProgress = (view.x - buttonStartX) / (maxX - buttonStartX)

                    if (slideProgress >= 0.8f) {
                        // SUCCESS - Answer the call!
                        Log.d(TAG, "Slide-to-answer gesture completed (${(slideProgress * 100).toInt()}%)")

                        // Animate button to end
                        view.animate()
                            .x(maxX)
                            .setDuration(150)
                            .withEndAction {
                                answerCall()
                            }
                            .start()

                        // Fade out hint
                        slideHintText.animate()
                            .alpha(0f)
                            .setDuration(150)
                            .start()
                    } else {
                        // Not far enough - snap back to start
                        Log.d(TAG, "Slide-to-answer gesture incomplete (${(slideProgress * 100).toInt()}%) - resetting")

                        view.animate()
                            .x(buttonStartX)
                            .setDuration(200)
                            .start()

                        slideHintText.animate()
                            .alpha(0.7f)
                            .setDuration(200)
                            .start()

                        // Reset button color
                        answerButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF00C853.toInt())
                    }
                    true
                }

                else -> false
            }
        }
    }

    private fun declineCall() {
        // Stop ringtone
        stopRingtone()

        // Cancel timeout if running
        timeoutJob?.cancel()

        // Send CALL_REJECT
        lifecycleScope.launch {
            CallSignaling.sendCallReject(
                contactX25519PublicKey,
                contactOnion,
                callId,
                "User declined"
            )
        }

        // Reject in call manager
        callManager.rejectCall(callId)

        // Close activity
        finish()
    }

    private fun answerCall() {
        // Disable buttons immediately to prevent double-tap
        answerButton.isEnabled = false
        declineButton.isEnabled = false

        // Check microphone permission (should have been granted in onCreate)
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            ThemedToast.show(this, "Microphone permission required for voice calls")
            answerButton.isEnabled = true
            declineButton.isEnabled = true
            return
        }

        // Permission granted, proceed with answering
        proceedWithAnswer()
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // Permission granted, proceed with answering
                proceedWithAnswer()
            } else {
                // Permission denied, decline the call
                ThemedToast.show(this, "Microphone permission required for calls")
                declineCall()
            }
        }
    }

    private fun proceedWithAnswer() {
        // Stop ringtone immediately when answering
        stopRingtone()

        // Check if there's already an active call
        if (callManager.hasActiveCall()) {
            Log.e(TAG, "Cannot answer - call already in progress")
            ThemedToast.show(this, "Call already in progress")
            // Send rejection to caller
            lifecycleScope.launch {
                CallSignaling.sendCallReject(
                    contactX25519PublicKey,
                    contactOnion,
                    callId,
                    "Call already in progress"
                )
            }
            finish()
            return
        }

        // Mark call as answered BEFORE launching VoiceCallActivity
        // This prevents onDestroy from rejecting the call
        callWasAnswered = true

        // IMMEDIATELY launch VoiceCallActivity (shows "Connecting" screen)
        // VoiceCallActivity will handle all the connection logic
        val intent = Intent(this, VoiceCallActivity::class.java)
        intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_ID, contactId)
        intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_NAME, contactName)
        intent.putExtra(VoiceCallActivity.EXTRA_CALL_ID, callId)
        intent.putExtra(VoiceCallActivity.EXTRA_IS_OUTGOING, false)
        intent.putExtra(VoiceCallActivity.EXTRA_THEIR_EPHEMERAL_KEY, theirEphemeralPublicKey)
        intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_ONION, contactOnion)
        intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_X25519_PUBLIC_KEY, contactX25519PublicKey)
        startActivity(intent)
        finish() // Close incoming call screen immediately
    }

    override fun onBackPressed() {
        // Decline call on back press
        declineCall()
    }

    override fun onDestroy() {
        super.onDestroy()
        // Stop animation
        animatedRing.clearAnimation()

        // Stop ringtone
        stopRingtone()

        // Cancel timeout job if running
        timeoutJob?.cancel()

        // Only reject call if it wasn't answered
        // If callWasAnswered is true, VoiceCallActivity is handling it
        if (!callWasAnswered) {
            Log.d(TAG, "IncomingCallActivity destroyed without answer - rejecting call")
            callManager.rejectCall(callId)
        } else {
            Log.d(TAG, "IncomingCallActivity destroyed after answer - VoiceCallActivity handling call")
        }
    }

    /**
     * Start playing ringtone
     */
    private fun startRingtone() {
        try {
            val ringtoneUri: Uri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE)
            ringtone = RingtoneManager.getRingtone(applicationContext, ringtoneUri)

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                ringtone?.isLooping = true
                ringtone?.audioAttributes = AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                    .build()
            }

            ringtone?.play()
            Log.d(TAG, "Ringtone started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start ringtone", e)
        }
    }

    /**
     * Stop playing ringtone
     */
    private fun stopRingtone() {
        try {
            ringtone?.stop()
            ringtone = null
            Log.d(TAG, "Ringtone stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop ringtone", e)
        }
    }

    /**
     * Show quick unlock overlay with 30-second timeout
     */
    private fun showQuickUnlockOverlay() {
        // Show overlay
        unlockOverlay.visibility = android.view.View.VISIBLE

        // Disable slide-to-answer button until unlocked
        answerButton.isEnabled = false
        answerButton.alpha = 0.5f

        // Update icon based on biometric availability
        if (biometricHelper.isBiometricEnabled()) {
            quickUnlockButton.setIconResource(R.drawable.ic_fingerprint)
        } else {
            quickUnlockButton.setIconResource(R.drawable.ic_lock)
        }

        // Start timeout countdown (30 seconds)
        startTimeoutCountdown()
    }

    /**
     * Start 30-second countdown - auto-reject if not unlocked in time
     */
    private fun startTimeoutCountdown() {
        timeoutJob?.cancel()
        remainingSeconds = 30

        timeoutJob = lifecycleScope.launch {
            while (remainingSeconds > 0) {
                withContext(Dispatchers.Main) {
                    timeoutCountdown.text = "Call will be missed in ${remainingSeconds}s"
                }
                delay(1000)
                remainingSeconds--
            }

            // Timeout reached - reject call and save as missed
            withContext(Dispatchers.Main) {
                Log.w(TAG, "Quick unlock timeout - rejecting call")
                handleUnlockTimeout()
            }
        }
    }

    /**
     * Attempt to authenticate with biometric or show password field
     */
    private fun attemptQuickUnlock() {
        Log.d(TAG, "Quick unlock button pressed")

        // Try biometric authentication first if enabled
        if (biometricHelper.isBiometricEnabled()) {
            Log.d(TAG, "Attempting biometric authentication")
            biometricHelper.authenticateWithBiometric(
                activity = this,
                onSuccess = { passwordHash ->
                    Log.i(TAG, "Biometric authentication successful")

                    // Verify the decrypted password hash matches stored hash
                    val keyManager = KeyManager.getInstance(this)
                    if (keyManager.verifyPasswordHash(passwordHash)) {
                        Log.i(TAG, "Password hash verified from biometric")
                        handleUnlockSuccess()
                    } else {
                        Log.e(TAG, "Biometric decrypted hash does not match stored hash")
                        ThemedToast.show(this, "Authentication failed")
                        showPasswordField()
                    }
                },
                onError = { errorMsg ->
                    Log.w(TAG, "Biometric authentication error: $errorMsg")
                    // Show password field if user cancels or biometric fails
                    if (errorMsg.contains("Cancel") || errorMsg.contains("Use Password")) {
                        showPasswordField()
                    } else {
                        ThemedToast.show(this, errorMsg)
                        showPasswordField()
                    }
                }
            )
        } else {
            // No biometric - show password field immediately
            Log.d(TAG, "No biometric enabled - showing password field")
            showPasswordField()
        }
    }

    /**
     * Show password entry field
     */
    private fun showPasswordField() {
        // Hide the quick unlock button
        quickUnlockButton.visibility = android.view.View.GONE

        // Show password entry
        passwordEntryContainer.visibility = android.view.View.VISIBLE

        // Focus on password input and show keyboard
        quickPasswordInput.requestFocus()
        val imm = getSystemService(android.content.Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
        imm.showSoftInput(quickPasswordInput, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
    }

    /**
     * Verify password and unlock if correct
     */
    private fun verifyPasswordAndUnlock(password: String) {
        val keyManager = KeyManager.getInstance(this)

        if (keyManager.verifyDevicePassword(password)) {
            Log.i(TAG, "Password verified successfully")
            handleUnlockSuccess()
        } else {
            Log.w(TAG, "Incorrect password entered")
            ThemedToast.show(this, "Incorrect password")
            quickPasswordInput.text.clear()
            quickPasswordInput.requestFocus()
        }
    }

    /**
     * Handle successful authentication - hide overlay and enable answering
     */
    private fun handleUnlockSuccess() {
        Log.i(TAG, "Quick unlock successful - enabling call answer")

        // Cancel timeout
        timeoutJob?.cancel()

        // Mark app as unlocked
        com.securelegion.utils.SessionManager.setUnlocked(this)
        isAppLocked = false

        // Hide unlock overlay with animation
        unlockOverlay.animate()
            .alpha(0f)
            .setDuration(300)
            .withEndAction {
                unlockOverlay.visibility = android.view.View.GONE
                unlockOverlay.alpha = 1f
            }
            .start()

        // Enable slide-to-answer button
        answerButton.isEnabled = true
        answerButton.animate()
            .alpha(1f)
            .setDuration(300)
            .start()

        // Update status text
        callStatusText.text = "Incoming Call"

        ThemedToast.show(this, "Unlocked - you can now answer")
    }

    /**
     * Handle unlock timeout or failure - reject call and save as missed
     */
    private fun handleUnlockTimeout() {
        Log.w(TAG, "Quick unlock failed/timeout - rejecting call")

        // Cancel timeout job
        timeoutJob?.cancel()

        // Save missed call to database
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@IncomingCallActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val db = SecureLegionDatabase.getInstance(this@IncomingCallActivity, dbPassphrase)
                val callHistory = CallHistory(
                    contactId = contactId,
                    contactName = contactName,
                    callId = callId,
                    timestamp = System.currentTimeMillis(),
                    type = CallType.MISSED,
                    duration = 0,
                    missedReason = "App was locked - not unlocked in time"
                )
                db.callHistoryDao().insert(callHistory)
                Log.d(TAG, "Saved missed call to database: $contactName")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to save missed call", e)
            }

            // Reject the call
            CallSignaling.sendCallReject(
                contactX25519PublicKey,
                contactOnion,
                callId,
                "App locked - user did not unlock in time"
            )
        }

        // Show persistent notification
        showMissedCallNotification(contactId, contactName)

        // Close activity
        finish()
    }

    /**
     * Show persistent notification for missed call when app is locked
     */
    private fun showMissedCallNotification(contactId: Long, contactName: String) {
        try {
            // Create intent to open LockActivity (which will then navigate to MainActivity)
            val intent = Intent(this, LockActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                putExtra("from_missed_call", true)
                putExtra("contact_id", contactId)
                putExtra("contact_name", contactName)
            }

            val pendingIntent = PendingIntent.getActivity(
                this,
                contactId.toInt(), // Use contactId as unique request code
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            // Build notification
            val notification = NotificationCompat.Builder(this, SecureLegionApplication.CHANNEL_ID_CALLS)
                .setSmallIcon(R.drawable.ic_call)
                .setContentTitle("Missed Call")
                .setContentText("Missed call from $contactName")
                .setStyle(NotificationCompat.BigTextStyle()
                    .bigText("Missed call from $contactName\nApp was locked - Tap to unlock and call back"))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setCategory(NotificationCompat.CATEGORY_CALL)
                .setAutoCancel(true)
                .setContentIntent(pendingIntent)
                .setVibrate(longArrayOf(0, 250, 250, 250))
                .build()

            // Show notification
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.notify(contactId.toInt(), notification)

            Log.d(TAG, "Shown missed call notification for $contactName")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to show missed call notification", e)
        }
    }
}
