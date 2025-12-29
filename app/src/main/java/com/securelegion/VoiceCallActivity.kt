package com.securelegion

import android.media.AudioManager
import android.media.ToneGenerator
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.WindowManager
import android.view.animation.AnimationUtils
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.securelegion.ui.WaveformView
import com.securelegion.utils.ThemedToast
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.VoiceCallSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.database.entities.x25519PublicKeyBytes
import java.util.Locale

/**
 * VoiceCallActivity - In-call screen for active voice calls
 *
 * Shows:
 * - Contact name and avatar
 * - Call timer
 * - Mute/Speaker/More controls
 * - End call button
 *
 * Receives data from:
 * - Intent extras (contactId, contactName, callId, isOutgoing)
 */
class VoiceCallActivity : BaseActivity() {

    companion object {
        private const val TAG = "VoiceCallActivity"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "CONTACT_NAME"
        const val EXTRA_CALL_ID = "CALL_ID"
        const val EXTRA_IS_OUTGOING = "IS_OUTGOING"
        const val EXTRA_THEIR_EPHEMERAL_KEY = "THEIR_EPHEMERAL_KEY"
        const val EXTRA_OUR_EPHEMERAL_SECRET_KEY = "OUR_EPHEMERAL_SECRET_KEY"
        const val EXTRA_CONTACT_ONION = "CONTACT_ONION"
        const val EXTRA_CONTACT_X25519_PUBLIC_KEY = "CONTACT_X25519_PUBLIC_KEY"
        const val EXTRA_NEEDS_CONNECTIVITY_TEST = "NEEDS_CONNECTIVITY_TEST"
        const val EXTRA_CONTACT_VOICE_ONION = "CONTACT_VOICE_ONION"

        // Callback for when CALL_ANSWER is received for outgoing calls
        private var activeInstance: VoiceCallActivity? = null

        fun onCallAnswered(callId: String, theirEphemeralKey: ByteArray) {
            activeInstance?.handleCallAnswered(callId, theirEphemeralKey)
        }

        fun onCallTimeout(callId: String) {
            activeInstance?.handleCallTimeout(callId)
        }

        fun onCallRejected(callId: String, reason: String) {
            activeInstance?.handleCallRejected(callId, reason)
        }

        fun onCallBusy(callId: String) {
            activeInstance?.handleCallBusy(callId)
        }

        fun onConnectivityTestPassed() {
            activeInstance?.handleConnectivityTestPassed()
        }

        fun onConnectivityTestFailed(error: String) {
            activeInstance?.handleConnectivityTestFailed(error)
        }
    }

    // UI elements
    private lateinit var backButton: View
    private lateinit var animatedRing: ImageView
    private lateinit var lockIcon: ImageView
    private lateinit var waveformView: WaveformView
    private lateinit var contactNameText: TextView
    private lateinit var callTimerText: TextView
    private lateinit var callStatusText: TextView
    private lateinit var connectionProgressBar: ProgressBar
    private lateinit var timerContainer: View
    private lateinit var muteButton: FloatingActionButton
    private lateinit var speakerButton: FloatingActionButton
    private lateinit var endCallButton: FloatingActionButton

    // Hidden compatibility views
    private lateinit var contactAvatar: ImageView
    private lateinit var muteIcon: ImageView
    private lateinit var speakerIcon: ImageView

    // Data
    private var contactId: Long = -1
    private var contactName: String = "@Contact"
    private var callId: String = ""
    private var isOutgoing: Boolean = true
    private var theirEphemeralKey: ByteArray? = null
    private var needsConnectivityTest: Boolean = false
    private var contactVoiceOnion: String? = null
    private var contactX25519PublicKey: ByteArray? = null

    // State
    private var isMuted = false
    private var isSpeakerOn = false
    private var callStartTime = 0L
    private val timerHandler = Handler(Looper.getMainLooper())
    private var timerRunnable: Runnable? = null
    private var waitingForAnswer = false

    // Ringback tone (plays while waiting for answer on outgoing calls)
    private var toneGenerator: ToneGenerator? = null
    private var isPlayingRingback = false

    // Call manager
    private lateinit var callManager: VoiceCallManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_voice_call)

        // Register as active instance
        activeInstance = this

        // Keep screen on during call and show on lock screen
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        // Show activity on lock screen (deprecated but still works on most devices)
        @Suppress("DEPRECATION")
        window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED)
        @Suppress("DEPRECATION")
        window.addFlags(WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD)
        @Suppress("DEPRECATION")
        window.addFlags(WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON)

        // Use modern APIs for Android O and above
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        }

        // Get data from intent
        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)
        contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: "@Contact"
        callId = intent.getStringExtra(EXTRA_CALL_ID) ?: ""
        isOutgoing = intent.getBooleanExtra(EXTRA_IS_OUTGOING, true)
        theirEphemeralKey = intent.getByteArrayExtra(EXTRA_THEIR_EPHEMERAL_KEY)
        needsConnectivityTest = intent.getBooleanExtra(EXTRA_NEEDS_CONNECTIVITY_TEST, false)
        contactVoiceOnion = intent.getStringExtra(EXTRA_CONTACT_VOICE_ONION)
        contactX25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_X25519_PUBLIC_KEY)

        // Initialize UI
        initializeViews()
        setupClickListeners()

        // Get call manager
        callManager = VoiceCallManager.getInstance(this)

        // Set up call state observer
        callManager.onCallStateChanged = { state ->
            handleCallStateChanged(state)
        }

        callManager.onCallEnded = { reason ->
            handleCallEnded(reason)
        }

        // Start call timer
        callStartTime = System.currentTimeMillis()
        startCallTimer()

        // Update UI
        contactNameText.text = contactName

        // Check if we need to show connectivity test UI
        if (needsConnectivityTest && isOutgoing) {
            // Show "Testing Connection..." status with progress bar
            // The caller (ChatActivity/MainActivity) will run the actual test and call
            // onConnectivityTestPassed() or onConnectivityTestFailed()
            lockIcon.visibility = View.VISIBLE
            animatedRing.visibility = View.VISIBLE
            waveformView.visibility = View.GONE
            connectionProgressBar.visibility = View.VISIBLE
            updateCallStatus("Testing Connection...")
            android.util.Log.i(TAG, "Showing connectivity test UI, waiting for caller to run test")
        } else if (isOutgoing && theirEphemeralKey == null) {
            // Outgoing call - waiting for CALL_ANSWER (connectivity test already passed)
            waitingForAnswer = true
            // Show animated ring and "Calling..." status
            lockIcon.visibility = View.VISIBLE
            animatedRing.visibility = View.VISIBLE
            waveformView.visibility = View.GONE
            connectionProgressBar.visibility = View.GONE
            updateCallStatus("Calling...")
            android.util.Log.i(TAG, "Waiting for CALL_ANSWER from $contactName")
            // Start ringback tone for outgoing calls
            startRingbackTone()
        } else {
            // Incoming call or outgoing call with answer already received
            connectionProgressBar.visibility = View.GONE
            updateCallStatus("Encrypted voice call")
            // Start the call immediately
            startActualCall()
        }
    }

    /**
     * Called by companion object when CALL_ANSWER is received
     */
    private fun handleCallAnswered(receivedCallId: String, receivedTheirEphemeralKey: ByteArray) {
        if (receivedCallId != callId) {
            android.util.Log.w(TAG, "Received CALL_ANSWER for different call ID: $receivedCallId (expected $callId)")
            return
        }

        if (!waitingForAnswer) {
            android.util.Log.w(TAG, "Received CALL_ANSWER but not waiting for answer")
            return
        }

        android.util.Log.i(TAG, "Received CALL_ANSWER for our outgoing call")
        waitingForAnswer = false
        theirEphemeralKey = receivedTheirEphemeralKey

        // Stop ringback tone
        stopRingbackTone()

        // Now start the actual call
        runOnUiThread {
            updateCallStatus("Connecting...")
            startActualCall()
        }
    }

    private fun handleCallTimeout(receivedCallId: String) {
        if (receivedCallId != callId) return

        runOnUiThread {
            handleCallEnded("No answer")
        }
    }

    private fun handleCallRejected(receivedCallId: String, reason: String) {
        if (receivedCallId != callId) return

        runOnUiThread {
            handleCallEnded("Call rejected")
        }
    }

    private fun handleCallBusy(receivedCallId: String) {
        if (receivedCallId != callId) return

        runOnUiThread {
            handleCallEnded("Contact is busy")
        }
    }

    private fun handleConnectivityTestPassed() {
        runOnUiThread {
            // Hide progress bar and update status
            connectionProgressBar.visibility = View.GONE
            updateCallStatus("Calling...")
            android.util.Log.i(TAG, "✓ Connectivity test passed - updated UI to 'Calling...'")
            // The caller will now send CALL_OFFER and we'll wait for CALL_ANSWER
            waitingForAnswer = true
        }
    }

    private fun handleConnectivityTestFailed(error: String) {
        runOnUiThread {
            // Hide progress bar and show error
            connectionProgressBar.visibility = View.GONE
            updateCallStatus("Connection failed")
            android.util.Log.e(TAG, "✗ Connectivity test failed: $error")

            // Show toast and close activity
            ThemedToast.show(this, "Cannot reach $contactName\n$error")

            // Close after a short delay
            Handler(Looper.getMainLooper()).postDelayed({
                finish()
            }, 2000)
        }
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        animatedRing = findViewById(R.id.animatedRing)
        lockIcon = findViewById(R.id.lockIcon)
        waveformView = findViewById(R.id.waveformView)
        contactNameText = findViewById(R.id.contactName)
        callTimerText = findViewById(R.id.callTimer)
        callStatusText = findViewById(R.id.callStatus)
        connectionProgressBar = findViewById(R.id.connectionProgressBar)
        timerContainer = findViewById(R.id.timerContainer)
        muteButton = findViewById(R.id.muteButton)
        speakerButton = findViewById(R.id.speakerButton)
        endCallButton = findViewById(R.id.endCallButton)

        // Hidden compatibility views
        contactAvatar = findViewById(R.id.contactAvatar)
        muteIcon = findViewById(R.id.muteIcon)
        speakerIcon = findViewById(R.id.speakerIcon)

        // Apply 3D press effect to call control buttons
        val pressAnimator = android.animation.AnimatorInflater.loadStateListAnimator(
            this,
            R.animator.button_press_effect
        )
        endCallButton.stateListAnimator = pressAnimator
        muteButton.stateListAnimator = pressAnimator
        speakerButton.stateListAnimator = pressAnimator

        // Start ring animation
        val pulseAnimation = AnimationUtils.loadAnimation(this, R.anim.pulse_ring)
        animatedRing.startAnimation(pulseAnimation)
    }

    private fun setupClickListeners() {
        // Back button
        backButton.setOnClickListener {
            confirmEndCall()
        }

        // Mute button
        muteButton.setOnClickListener {
            toggleMute()
        }

        // Speaker button
        speakerButton.setOnClickListener {
            toggleSpeaker()
        }

        // End call button
        endCallButton.setOnClickListener {
            confirmEndCall()
        }
    }

    private fun toggleMute() {
        isMuted = !isMuted
        callManager.setMuted(isMuted)

        if (isMuted) {
            muteButton.setImageResource(R.drawable.ic_mic_off)
            muteButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFFFF6B6B.toInt())
        } else {
            muteButton.setImageResource(R.drawable.ic_mic)
            muteButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF2C2C2C.toInt())
        }
    }

    private fun toggleSpeaker() {
        isSpeakerOn = !isSpeakerOn
        callManager.setSpeakerEnabled(isSpeakerOn)

        if (isSpeakerOn) {
            speakerButton.setImageResource(R.drawable.ic_speaker_on)
            speakerButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF4A9EFF.toInt())
        } else {
            speakerButton.setImageResource(R.drawable.ic_speaker)
            speakerButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF2C2C2C.toInt())
        }
    }


    private fun confirmEndCall() {
        // If waiting for answer or no active call, just end immediately
        if (waitingForAnswer || !callManager.hasActiveCall()) {
            endCall()
            return
        }

        // If call is still connecting/ringing, just end immediately without confirmation
        val currentState = callManager.getCurrentCallState()
        if (currentState == VoiceCallSession.Companion.CallState.CONNECTING ||
            currentState == VoiceCallSession.Companion.CallState.RINGING) {
            endCall()
            return
        }

        // For active calls, show confirmation dialog
        AlertDialog.Builder(this)
            .setTitle("End Call")
            .setMessage("Are you sure you want to end this call?")
            .setPositiveButton("End Call") { _, _ ->
                endCall()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun endCall() {
        // Stop waiting if we're in waiting state
        waitingForAnswer = false

        // Stop ringback tone
        stopRingbackTone()

        // Always try to end the call, even if it's not fully active
        try {
            if (callManager.hasActiveCall()) {
                callManager.endCall("User ended call")
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Error ending call", e)
        }
        stopCallTimer()
        finish()
    }

    private fun handleCallStateChanged(state: VoiceCallSession.Companion.CallState) {
        runOnUiThread {
            when (state) {
                VoiceCallSession.Companion.CallState.CONNECTING -> {
                    showConnectingState()
                }
                VoiceCallSession.Companion.CallState.RINGING -> {
                    showConnectingState()
                    updateCallStatus("Ringing...")
                }
                VoiceCallSession.Companion.CallState.ACTIVE -> {
                    showConnectedState()
                }
                VoiceCallSession.Companion.CallState.ENDING -> {
                    updateCallStatus("Ending call...")
                }
                VoiceCallSession.Companion.CallState.ENDED -> {
                    updateCallStatus("Call ended")
                }
                else -> {}
            }
        }
    }

    /**
     * Show connecting state: lock icon with ring, progress bar
     */
    private fun showConnectingState() {
        updateCallStatus("Connecting")

        // Show lock icon and ring
        lockIcon.visibility = View.VISIBLE
        animatedRing.visibility = View.VISIBLE
        waveformView.visibility = View.GONE

        // Show progress bar, hide timer
        connectionProgressBar.visibility = View.VISIBLE
        timerContainer.visibility = View.GONE

        // Animate progress bar
        animateProgressBar()
    }

    /**
     * Show connected state: waveform visualization, timer
     */
    private fun showConnectedState() {
        updateCallStatus("Connected")

        // Hide lock icon and ring, show waveform
        lockIcon.visibility = View.GONE
        animatedRing.visibility = View.GONE
        waveformView.visibility = View.VISIBLE

        // Hide progress bar, show timer
        connectionProgressBar.visibility = View.GONE
        timerContainer.visibility = View.VISIBLE
    }

    /**
     * Animate progress bar during connecting state
     */
    private fun animateProgressBar() {
        connectionProgressBar.progress = 0
        val progressRunnable = object : Runnable {
            override fun run() {
                if (connectionProgressBar.visibility == View.VISIBLE && connectionProgressBar.progress < 90) {
                    connectionProgressBar.progress += 5
                    timerHandler.postDelayed(this, 200)
                }
            }
        }
        timerHandler.post(progressRunnable)
    }

    private fun handleCallEnded(reason: String) {
        // Don't show dialog if activity is already finishing (user pressed End)
        if (isFinishing) {
            return
        }

        // Stop ringback tone if it's playing
        stopRingbackTone()

        runOnUiThread {
            updateCallStatus(reason)
            stopCallTimer()

            // Show dialog only if activity is still active
            if (!isFinishing) {
                AlertDialog.Builder(this)
                    .setTitle("Call Ended")
                    .setMessage(reason)
                    .setPositiveButton("OK") { _, _ ->
                        finish()
                    }
                    .setCancelable(false)
                    .show()
            }
        }
    }

    private fun updateCallStatus(status: String) {
        callStatusText.text = status
    }

    private fun startRingbackTone() {
        if (isPlayingRingback) return

        try {
            // Create ToneGenerator for ringback tone
            // Use STREAM_VOICE_CALL for proper audio routing during calls
            toneGenerator = ToneGenerator(AudioManager.STREAM_VOICE_CALL, 80) // 80% volume

            // Play standard DTMF ringback tone in a loop
            // This sounds like the standard "ringing" tone during outgoing calls
            toneGenerator?.startTone(ToneGenerator.TONE_SUP_RINGTONE, -1) // -1 = continuous
            isPlayingRingback = true

            android.util.Log.d(TAG, "Started ringback tone")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to start ringback tone", e)
        }
    }

    private fun stopRingbackTone() {
        if (!isPlayingRingback) return

        try {
            toneGenerator?.stopTone()
            toneGenerator?.release()
            toneGenerator = null
            isPlayingRingback = false

            android.util.Log.d(TAG, "Stopped ringback tone")
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to stop ringback tone", e)
        }
    }

    private fun startCallTimer() {
        timerRunnable = object : Runnable {
            override fun run() {
                val elapsedMillis = System.currentTimeMillis() - callStartTime
                val seconds = (elapsedMillis / 1000).toInt()
                val minutes = seconds / 60
                val secs = seconds % 60

                callTimerText.text = String.format(Locale.US, "%02d:%02d", minutes, secs)

                timerHandler.postDelayed(this, 1000)
            }
        }
        timerHandler.post(timerRunnable!!)
    }

    private fun stopCallTimer() {
        timerRunnable?.let {
            timerHandler.removeCallbacks(it)
        }
    }

    /**
     * Start the actual voice call with VoiceCallManager
     * Called from onCreate() after UI is set up
     * Handles both outgoing and incoming calls
     */
    private fun startActualCall() {
        lifecycleScope.launch {
            try {
                // Get contact info from database
                val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@VoiceCallActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val db = com.securelegion.database.SecureLegionDatabase.getInstance(this@VoiceCallActivity, dbPassphrase)

                val contact = withContext(kotlinx.coroutines.Dispatchers.IO) {
                    db.contactDao().getContactById(contactId)
                }

                if (contact == null) {
                    android.util.Log.e(TAG, "Contact not found: $contactId")
                    handleCallEnded("Contact not found")
                    return@launch
                }

                if (contact.messagingOnion == null) {
                    android.util.Log.e(TAG, "Contact has no messaging address")
                    handleCallEnded("Contact has no messaging address")
                    return@launch
                }

                // Get their ephemeral public key (from intent or from handleCallAnswered)
                val theirEphKey = theirEphemeralKey
                if (theirEphKey == null) {
                    android.util.Log.e(TAG, "No ephemeral key available")
                    handleCallEnded("Missing encryption key")
                    return@launch
                }

                if (isOutgoing) {
                    // OUTGOING CALL: Start the call
                    android.util.Log.i(TAG, "Starting outgoing voice call to ${contact.displayName}")
                    updateCallStatus("Connecting...")

                    // Check if contact has voice onion
                    val contactVoiceOnion = contact.voiceOnion ?: ""
                    if (contactVoiceOnion.isEmpty()) {
                        android.util.Log.e(TAG, "Contact has no voice onion address - cannot establish voice call")
                        handleCallEnded("Contact has no voice address - voice calls not yet set up")
                        return@launch
                    }

                    // Get our ephemeral secret key from intent (generated in MainActivity)
                    val ourEphemeralSecretKey = intent.getByteArrayExtra(EXTRA_OUR_EPHEMERAL_SECRET_KEY)
                    if (ourEphemeralSecretKey == null) {
                        android.util.Log.e(TAG, "No our ephemeral secret key provided")
                        handleCallEnded("Missing encryption key")
                        return@launch
                    }

                    val result = callManager.startCall(
                        contactOnion = contact.messagingOnion!!,
                        contactVoiceOnion = contactVoiceOnion,
                        contactEd25519PublicKey = contact.ed25519PublicKeyBytes,
                        contactName = contact.displayName,
                        theirEphemeralPublicKey = theirEphKey,
                        ourEphemeralSecretKey = ourEphemeralSecretKey,
                        callId = callId,
                        contactX25519PublicKey = contact.x25519PublicKeyBytes
                    )

                    if (result.isFailure) {
                        android.util.Log.e(TAG, "Failed to start call", result.exceptionOrNull())
                        handleCallEnded("Failed to connect: ${result.exceptionOrNull()?.message}")
                    } else {
                        android.util.Log.i(TAG, "Voice call started successfully")
                        showConnectedState()
                    }
                } else {
                    // INCOMING CALL: Answer the call
                    android.util.Log.i(TAG, "Answering incoming voice call from ${contact.displayName}")
                    updateCallStatus("Connecting...")

                    val contactVoiceOnion = contact.voiceOnion ?: ""
                    android.util.Log.i(TAG, "Contact ${contact.displayName} voiceOnion from DB: '${contactVoiceOnion}'")

                    if (contactVoiceOnion.isEmpty()) {
                        android.util.Log.e(TAG, "❌ Contact has no voice onion address - cannot establish voice call")
                        android.util.Log.e(TAG, "   This means the contact never sent their voice.onion in CALL_OFFER")
                        android.util.Log.e(TAG, "   OR the auto-population failed")

                        // Get contact info from intent for rejection
                        val contactOnion = intent.getStringExtra(EXTRA_CONTACT_ONION) ?: ""
                        val contactX25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_X25519_PUBLIC_KEY) ?: ByteArray(0)

                        com.securelegion.voice.CallSignaling.sendCallReject(
                            contactX25519PublicKey,
                            contactOnion,
                            callId,
                            "Voice onion not available"
                        )
                        handleCallEnded("Contact's voice address missing - please try calling again")
                        return@launch
                    }

                    android.util.Log.i(TAG, "✓ Contact has voice onion: ${contactVoiceOnion}")

                    // CRITICAL: Generate ephemeral keypair ONCE before answering call
                    // This keypair must be used for BOTH encryption AND in CALL_ANSWER message
                    val crypto = com.securelegion.voice.crypto.VoiceCallCrypto()
                    val ourEphemeralKeypair = crypto.generateEphemeralKeypair()
                    android.util.Log.d(TAG, "Generated single ephemeral keypair for incoming call")

                    // IMMEDIATELY send CALL_ANSWER to notify caller (before creating Tor circuits)
                    // This allows the calling device to transition from "Calling..." to "Connecting..." right away
                    val torManager = com.securelegion.crypto.TorManager.getInstance(this@VoiceCallActivity)
                    val myVoiceOnion = torManager.getVoiceOnionAddress() ?: ""
                    if (myVoiceOnion.isEmpty()) {
                        android.util.Log.w(TAG, "Voice onion address not yet created - call may fail")
                    }

                    val contactOnion = intent.getStringExtra(EXTRA_CONTACT_ONION) ?: ""
                    val contactX25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_X25519_PUBLIC_KEY) ?: ByteArray(0)

                    android.util.Log.i(TAG, "Sending CALL_ANSWER via HTTP POST immediately (before creating Tor circuits)...")
                    android.util.Log.d(TAG, "  contactOnion: $contactOnion")
                    android.util.Log.d(TAG, "  contactX25519PublicKey size: ${contactX25519PublicKey.size}")
                    android.util.Log.d(TAG, "  callId: $callId")
                    android.util.Log.d(TAG, "  myVoiceOnion: $myVoiceOnion")
                    android.util.Log.d(TAG, "  ourEphemeralKeypair.publicKey size: ${ourEphemeralKeypair.publicKey.asBytes.size}")

                    // Get our X25519 public key for HTTP wire format
                    val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@VoiceCallActivity)
                    val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

                    // Update UI to show we're sending the answer
                    updateCallStatus("Sending call response...")

                    // Send CALL_ANSWER on IO thread via HTTP POST to voice .onion
                    // This will retry up to 5 times with 15-second timeout each
                    val success = withContext(kotlinx.coroutines.Dispatchers.IO) {
                        com.securelegion.voice.CallSignaling.sendCallAnswer(
                            contactX25519PublicKey,
                            contactOnion,
                            callId,
                            ourEphemeralKeypair.publicKey.asBytes,
                            myVoiceOnion,
                            ourX25519PublicKey
                        )
                    }

                    if (!success) {
                        android.util.Log.e(TAG, "Failed to send CALL_ANSWER after all retries")
                        handleCallEnded("Failed to establish connection - please try again")
                        return@launch
                    }
                    android.util.Log.i(TAG, "✓ CALL_ANSWER sent successfully")

                    // Now answer call in call manager (this will create Tor circuits - takes 5-10s)
                    android.util.Log.d(TAG, "Calling answerCall with callId: $callId")
                    val result = callManager.answerCall(
                        callId = callId,
                        contactVoiceOnion = contactVoiceOnion,
                        ourEphemeralSecretKey = ourEphemeralKeypair.secretKey.asBytes,
                        contactX25519PublicKey = contactX25519PublicKey,
                        contactMessagingOnion = contactOnion,
                        ourEphemeralPublicKey = ourEphemeralKeypair.publicKey.asBytes,
                        myVoiceOnion = myVoiceOnion
                    )

                    if (result.isFailure) {
                        // Failed to create call session - send rejection to caller
                        android.util.Log.e(TAG, "Failed to answer call: ${result.exceptionOrNull()?.message}")

                        com.securelegion.voice.CallSignaling.sendCallReject(
                            contactX25519PublicKey,
                            contactOnion,
                            callId,
                            "Failed to establish call"
                        )
                        handleCallEnded("Failed to answer call: ${result.exceptionOrNull()?.message}")
                        return@launch
                    }

                    android.util.Log.i(TAG, "Incoming call answered successfully")
                    showConnectedState()
                }

            } catch (e: Exception) {
                android.util.Log.e(TAG, "Error starting call", e)

                // Clean up any call state
                if (callManager.hasActiveCall()) {
                    callManager.endCall("Error during setup")
                }

                // Try to send rejection if this was an incoming call
                if (!isOutgoing) {
                    try {
                        val contactOnion = intent.getStringExtra(EXTRA_CONTACT_ONION) ?: ""
                        val contactX25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_X25519_PUBLIC_KEY) ?: ByteArray(0)
                        com.securelegion.voice.CallSignaling.sendCallReject(
                            contactX25519PublicKey,
                            contactOnion,
                            callId,
                            "Error: ${e.message}"
                        )
                    } catch (e2: Exception) {
                        android.util.Log.e(TAG, "Failed to send rejection", e2)
                    }
                }

                handleCallEnded("Error: ${e.message}")
            }
        }
    }

    override fun onBackPressed() {
        // Prevent accidental back button press
        confirmEndCall()
    }

    override fun onDestroy() {
        super.onDestroy()

        // Unregister as active instance
        if (activeInstance == this) {
            activeInstance = null
        }

        stopCallTimer()
        stopRingbackTone() // Stop ringback tone if still playing
        animatedRing.clearAnimation()
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        // Clean up active call if still exists
        if (callManager.hasActiveCall()) {
            callManager.endCall("Activity destroyed")
        }
    }
}
