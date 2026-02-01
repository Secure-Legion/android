package com.securelegion

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioDeviceInfo
import android.media.AudioManager
import android.media.ToneGenerator
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.view.animation.AnimationUtils
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.core.app.NotificationCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.securelegion.ui.WaveformView
import com.securelegion.utils.ThemedToast
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.VoiceCallSession
import com.securelegion.crypto.KeyManager
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
        private const val ONGOING_CALL_NOTIFICATION_ID = 1001

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

    // Signal quality bars
    private lateinit var signalBar1: View
    private lateinit var signalBar2: View
    private lateinit var signalBar3: View
    private lateinit var signalBar4: View
    private lateinit var signalBar5: View

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

    // Signal quality monitoring
    private val signalQualityHandler = Handler(Looper.getMainLooper())
    private var signalQualityRunnable: Runnable? = null

    // Ringback tone (plays while waiting for answer on outgoing calls)
    private var toneGenerator: ToneGenerator? = null
    private var isPlayingRingback = false

    // Proximity sensor wake lock (turns screen off when near ear)
    private var proximityWakeLock: PowerManager.WakeLock? = null

    // Audio manager for speaker/earpiece routing
    private var audioManager: AudioManager? = null
    private var previousAudioMode: Int = AudioManager.MODE_NORMAL

    // Notification manager for ongoing call notification
    private var notificationManager: NotificationManager? = null

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

        // Set up proximity sensor to turn off screen when phone is near ear
        setupProximitySensor()

        // Initialize AudioManager for proper speaker/earpiece routing
        audioManager = getSystemService(Context.AUDIO_SERVICE) as? AudioManager
        audioManager?.let { am ->
            previousAudioMode = am.mode
            am.mode = AudioManager.MODE_IN_COMMUNICATION
            Log.d(TAG, "AudioManager initialized: mode=MODE_IN_COMMUNICATION (prev: $previousAudioMode)")
        }
        // Start with earpiece (speaker OFF) by default using the correct API
        setSpeakerRoute(false)

        // Initialize NotificationManager for ongoing call notification
        notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager

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

        // Set up audio amplitude observer for waveform visualization
        callManager.onAudioAmplitude = { amplitude ->
            runOnUiThread {
                waveformView.updateAmplitude(amplitude)
            }
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

        // Signal quality bars
        signalBar1 = findViewById(R.id.signalBar1)
        signalBar2 = findViewById(R.id.signalBar2)
        signalBar3 = findViewById(R.id.signalBar3)
        signalBar4 = findViewById(R.id.signalBar4)
        signalBar5 = findViewById(R.id.signalBar5)

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

        // Route audio to speaker or earpiece
        setSpeakerRoute(isSpeakerOn)

        // Also notify call manager (for when AudioPlaybackManager is initialized)
        try {
            callManager.setSpeakerEnabled(isSpeakerOn)
        } catch (e: Exception) {
            Log.w(TAG, "Could not set speaker via callManager (call may not be active yet)", e)
        }

        // Update UI
        if (isSpeakerOn) {
            speakerButton.setImageResource(R.drawable.ic_speaker_on)
            speakerButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF4A9EFF.toInt())
        } else {
            speakerButton.setImageResource(R.drawable.ic_speaker)
            speakerButton.backgroundTintList = android.content.res.ColorStateList.valueOf(0xFF2C2C2C.toInt())
        }
    }

    /**
     * Route audio to speaker or earpiece using the correct API for the Android version.
     *
     * isSpeakerphoneOn is deprecated on API 31+ (Android 12) and silently ignored on many devices.
     * API 31+ requires setCommunicationDevice() to actually switch the audio route.
     */
    private fun setSpeakerRoute(speaker: Boolean) {
        audioManager?.let { am ->
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    // Android 12+ (API 31): Use setCommunicationDevice
                    if (speaker) {
                        val speakerDevice = am.availableCommunicationDevices.firstOrNull {
                            it.type == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER
                        }
                        if (speakerDevice != null) {
                            val success = am.setCommunicationDevice(speakerDevice)
                            Log.d(TAG, "Speaker ON via setCommunicationDevice: success=$success")
                        } else {
                            Log.e(TAG, "No built-in speaker device found")
                        }
                    } else {
                        am.clearCommunicationDevice()
                        Log.d(TAG, "Speaker OFF via clearCommunicationDevice (earpiece)")
                    }
                } else {
                    // Android 11 and below: Use legacy API
                    @Suppress("DEPRECATION")
                    am.isSpeakerphoneOn = speaker
                    Log.d(TAG, "Speaker ${if (speaker) "ON" else "OFF"} via isSpeakerphoneOn (mode=${am.mode})")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to set speaker route", e)
            }
        } ?: Log.e(TAG, "AudioManager is null, cannot toggle speaker")
    }


    private fun confirmEndCall() {
        // End call immediately without confirmation (like normal phones)
        updateCallStatus("Call ended")
        endCall()
    }

    private fun endCall() {
        // Stop waiting if we're in waiting state
        val wasWaitingForAnswer = waitingForAnswer
        waitingForAnswer = false

        // Stop ringback tone
        stopRingbackTone()

        // Stop monitoring
        stopSignalQualityMonitoring()

        // CRITICAL FIX: If this is an outgoing call that hasn't been answered yet,
        // send CALL_END to stop the recipient's phone from ringing
        if (isOutgoing && wasWaitingForAnswer && contactVoiceOnion != null && contactX25519PublicKey != null) {
            lifecycleScope.launch {
                try {
                    val keyManager = KeyManager.getInstance(this@VoiceCallActivity)
                    val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

                    Log.d(TAG, "Sending CALL_END to stop recipient's phone from ringing (callId=$callId)")
                    CallSignaling.sendCallEnd(
                        contactX25519PublicKey!!,
                        contactVoiceOnion!!,
                        callId,
                        "Caller ended before answer",
                        ourX25519PublicKey
                    )
                    Log.d(TAG, "CALL_END sent successfully")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to send CALL_END", e)
                }
            }
        }

        // Always try to end the call, even if it's not fully active
        try {
            if (callManager.hasActiveCall()) {
                callManager.endCall("User ended call")
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Error ending call", e)
        }
        stopCallTimer()

        // Save call to history
        saveCallToHistory()

        finish()
    }

    /**
     * Save call to call history database
     */
    private fun saveCallToHistory() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@VoiceCallActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = com.securelegion.database.SecureLegionDatabase.getInstance(this@VoiceCallActivity, dbPassphrase)

                // Calculate call duration in seconds
                val durationSeconds = if (callStartTime > 0) {
                    (System.currentTimeMillis() - callStartTime) / 1000
                } else {
                    0L
                }

                // Determine call type
                val callType = when {
                    isOutgoing -> com.securelegion.database.entities.CallType.OUTGOING
                    durationSeconds > 0 -> com.securelegion.database.entities.CallType.INCOMING
                    else -> com.securelegion.database.entities.CallType.MISSED
                }

                // Create call history entry
                val callHistory = com.securelegion.database.entities.CallHistory(
                    contactId = contactId,
                    contactName = contactName,
                    callId = java.util.UUID.randomUUID().toString(),
                    type = callType,
                    timestamp = System.currentTimeMillis(),
                    duration = durationSeconds
                )

                // Insert into database
                database.callHistoryDao().insert(callHistory)

                Log.i(TAG, "Call saved to history: type=$callType, duration=${durationSeconds}s, contact=$contactName")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to save call to history", e)
            }
        }
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
                    startSignalQualityMonitoring()
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
        // Don't show notification if activity is already finishing (user pressed End)
        if (isFinishing) {
            return
        }

        // Stop ringback tone if it's playing
        stopRingbackTone()

        runOnUiThread {
            updateCallStatus(reason)
            stopCallTimer()

            // Close activity after short delay to show the status message
            Handler(Looper.getMainLooper()).postDelayed({
                finish()
            }, 1500)
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

                val durationText = String.format(Locale.US, "%02d:%02d", minutes, secs)
                callTimerText.text = durationText

                // Update ongoing call notification with duration
                updateOngoingCallNotification(durationText)

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
     * Update signal quality bars based on telemetry
     * 0 bars = terrible, 5 bars = excellent
     */
    private fun updateSignalQualityBars(qualityScore: Int) {
        runOnUiThread {
            // Reset all bars to dim
            signalBar1.alpha = 0.3f
            signalBar2.alpha = 0.3f
            signalBar3.alpha = 0.3f
            signalBar4.alpha = 0.3f
            signalBar5.alpha = 0.3f

            // Light up bars based on quality score
            when (qualityScore) {
                5 -> {
                    signalBar1.alpha = 1.0f
                    signalBar2.alpha = 1.0f
                    signalBar3.alpha = 1.0f
                    signalBar4.alpha = 1.0f
                    signalBar5.alpha = 1.0f
                }
                4 -> {
                    signalBar1.alpha = 1.0f
                    signalBar2.alpha = 1.0f
                    signalBar3.alpha = 1.0f
                    signalBar4.alpha = 1.0f
                }
                3 -> {
                    signalBar1.alpha = 1.0f
                    signalBar2.alpha = 1.0f
                    signalBar3.alpha = 1.0f
                }
                2 -> {
                    signalBar1.alpha = 1.0f
                    signalBar2.alpha = 1.0f
                }
                1 -> {
                    signalBar1.alpha = 1.0f
                }
                // 0 = all bars dim (already set above)
            }
        }
    }

    /**
     * Start periodic signal quality monitoring
     * Updates signal bars every 2 seconds based on call telemetry
     */
    private fun startSignalQualityMonitoring() {
        signalQualityRunnable = object : Runnable {
            override fun run() {
                // Get quality score from active call
                val qualityScore = callManager.getActiveCall()?.getCallQualityScore() ?: 0
                updateSignalQualityBars(qualityScore)

                // Update every 2 seconds
                signalQualityHandler.postDelayed(this, 2000)
            }
        }
        signalQualityHandler.post(signalQualityRunnable!!)
        Log.d(TAG, "Started signal quality monitoring")
    }

    /**
     * Stop signal quality monitoring
     */
    private fun stopSignalQualityMonitoring() {
        signalQualityRunnable?.let {
            signalQualityHandler.removeCallbacks(it)
        }
        signalQualityRunnable = null
        Log.d(TAG, "Stopped signal quality monitoring")
    }

    /**
     * Start the actual voice call with VoiceCallManager
     * Called from onCreate() after UI is set up
     * Handles both outgoing and incoming calls
     */
    private fun startActualCall() {
        // Show ongoing call notification
        showOngoingCallNotification()

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
                        val contactVoiceOnionFromIntent = intent.getStringExtra(EXTRA_CONTACT_ONION) ?: "" // This is the voice onion from CALL_OFFER
                        val contactX25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_X25519_PUBLIC_KEY) ?: ByteArray(0)

                        // Get our X25519 public key for HTTP wire format
                        val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@VoiceCallActivity)
                        val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

                        com.securelegion.voice.CallSignaling.sendCallReject(
                            contactX25519PublicKey,
                            contactVoiceOnionFromIntent,
                            callId,
                            "Voice onion not available",
                            ourX25519PublicKey
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

                    val contactCallerVoiceOnion = intent.getStringExtra(EXTRA_CONTACT_ONION) ?: "" // This is the voice onion from CALL_OFFER
                    val contactX25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_X25519_PUBLIC_KEY) ?: ByteArray(0)

                    android.util.Log.i(TAG, "Sending CALL_ANSWER via HTTP POST immediately (before creating Tor circuits)...")
                    android.util.Log.d(TAG, "  contactCallerVoiceOnion: $contactCallerVoiceOnion")
                    android.util.Log.d(TAG, "  contactX25519PublicKey size: ${contactX25519PublicKey.size}")
                    android.util.Log.d(TAG, "  callId: $callId")
                    android.util.Log.d(TAG, "  myVoiceOnion: $myVoiceOnion")
                    android.util.Log.d(TAG, "  ourEphemeralKeypair.publicKey size: ${ourEphemeralKeypair.publicKey.asBytes.size}")

                    // Get our X25519 public key for HTTP wire format
                    val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@VoiceCallActivity)
                    val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

                    // Update UI to show we're sending the answer
                    updateCallStatus("Sending call response...")

                    // Send CALL_ANSWER on IO thread via HTTP POST to caller's voice .onion
                    // This will retry up to 5 times with 15-second timeout each
                    val success = withContext(kotlinx.coroutines.Dispatchers.IO) {
                        com.securelegion.voice.CallSignaling.sendCallAnswer(
                            contactX25519PublicKey,
                            contactCallerVoiceOnion,  // Caller's voice onion from CALL_OFFER
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
                        contactMessagingOnion = contact.messagingOnion!!,  // Use contact's messaging onion
                        ourEphemeralPublicKey = ourEphemeralKeypair.publicKey.asBytes,
                        myVoiceOnion = myVoiceOnion
                    )

                    if (result.isFailure) {
                        // Failed to create call session - send rejection to caller
                        android.util.Log.e(TAG, "Failed to answer call: ${result.exceptionOrNull()?.message}")

                        com.securelegion.voice.CallSignaling.sendCallReject(
                            contactX25519PublicKey,
                            contactCallerVoiceOnion,  // Caller's voice onion
                            callId,
                            "Failed to establish call",
                            ourX25519PublicKey
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
                        val contactVoiceOnionFromIntent = intent.getStringExtra(EXTRA_CONTACT_ONION) ?: "" // This is the voice onion from CALL_OFFER
                        val contactX25519PublicKey = intent.getByteArrayExtra(EXTRA_CONTACT_X25519_PUBLIC_KEY) ?: ByteArray(0)

                        // Get our X25519 public key for HTTP wire format
                        val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@VoiceCallActivity)
                        val ourX25519PublicKey = keyManager.getEncryptionPublicKey()

                        lifecycleScope.launch {
                            com.securelegion.voice.CallSignaling.sendCallReject(
                                contactX25519PublicKey,
                                contactVoiceOnionFromIntent,
                                callId,
                                "Error: ${e.message}",
                                ourX25519PublicKey
                            )
                        }
                    } catch (e2: Exception) {
                        android.util.Log.e(TAG, "Failed to send rejection", e2)
                    }
                }

                handleCallEnded("Error: ${e.message}")
            }
        }
    }

    @Suppress("GestureBackNavigation")  // Minimize call to background instead of ending
    override fun onBackPressed() {
        // Back button should minimize app, not end call (like real phone apps)
        // Call continues in background, user can return via ongoing notification
        moveTaskToBack(true)
        Log.d(TAG, "Back button pressed - minimizing to background (call continues)")
        super.onBackPressed()
    }

    override fun onDestroy() {
        super.onDestroy()

        // Unregister as active instance
        if (activeInstance == this) {
            activeInstance = null
        }

        // Clear callbacks to prevent memory leaks
        callManager.onCallStateChanged = null
        callManager.onCallEnded = null
        callManager.onAudioAmplitude = null

        stopCallTimer()
        stopRingbackTone() // Stop ringback tone if still playing
        animatedRing.clearAnimation()
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        // Release proximity sensor wake lock
        releaseProximitySensor()

        // Clear ongoing call notification
        clearOngoingCallNotification()

        // Restore previous audio mode and clear communication device
        audioManager?.let { am ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                am.clearCommunicationDevice()
            }
            am.mode = previousAudioMode
            Log.d(TAG, "Audio mode restored to $previousAudioMode")
        }

        // Clean up active call if still exists
        if (callManager.hasActiveCall()) {
            callManager.endCall("Activity destroyed")
        }
    }

    /**
     * Set up proximity sensor to automatically turn screen off when phone is near ear
     */
    private fun setupProximitySensor() {
        try {
            val powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager

            // PROXIMITY_SCREEN_OFF_WAKE_LOCK turns screen off when proximity sensor is triggered
            // This prevents accidental touches with your ear during calls
            @Suppress("DEPRECATION")
            proximityWakeLock = powerManager.newWakeLock(
                PowerManager.PROXIMITY_SCREEN_OFF_WAKE_LOCK,
                "SecureLegion:ProximityWakeLock"
            )

            proximityWakeLock?.acquire(10 * 60 * 1000L) // 10 minute timeout (max call duration)
            Log.i(TAG, "Proximity sensor wake lock acquired - screen will turn off when near ear")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to set up proximity sensor", e)
            // Not critical - call will still work, just won't turn off screen automatically
        }
    }

    /**
     * Release proximity sensor wake lock
     */
    private fun releaseProximitySensor() {
        try {
            proximityWakeLock?.let {
                if (it.isHeld) {
                    it.release()
                    Log.i(TAG, "Proximity sensor wake lock released")
                }
            }
            proximityWakeLock = null
        } catch (e: Exception) {
            Log.e(TAG, "Failed to release proximity sensor wake lock", e)
        }
    }

    /**
     * Show ongoing call notification
     * This appears in the notification bar while a call is active
     */
    private fun showOngoingCallNotification() {
        val intent = Intent(this, VoiceCallActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, SecureLegionApplication.CHANNEL_ID_CALLS)
            .setContentTitle("Call in progress")
            .setContentText(contactName)
            .setSmallIcon(R.drawable.ic_call)
            .setOngoing(true)  // Can't be swiped away
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)  // Low priority = silent, no heads-up
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setSound(null)  // No sound
            .setVibrate(longArrayOf(0))  // No vibration
            .setDefaults(0)  // Disable all defaults
            .setSilent(true)  // Explicitly mark as silent
            .build()

        notificationManager?.notify(ONGOING_CALL_NOTIFICATION_ID, notification)
        Log.d(TAG, "Ongoing call notification shown")
    }

    /**
     * Update ongoing call notification with current call duration
     */
    private fun updateOngoingCallNotification(durationText: String) {
        val intent = Intent(this, VoiceCallActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, SecureLegionApplication.CHANNEL_ID_CALLS)
            .setContentTitle("Call in progress")
            .setContentText("$contactName • $durationText")
            .setSmallIcon(R.drawable.ic_call)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)  // Low priority = silent, no heads-up
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setSound(null)  // No sound
            .setVibrate(longArrayOf(0))  // No vibration
            .setDefaults(0)  // Disable all defaults
            .setSilent(true)  // Explicitly mark as silent
            .build()

        notificationManager?.notify(ONGOING_CALL_NOTIFICATION_ID, notification)
    }

    /**
     * Clear ongoing call notification
     */
    private fun clearOngoingCallNotification() {
        notificationManager?.cancel(ONGOING_CALL_NOTIFICATION_ID)
        Log.d(TAG, "Ongoing call notification cleared")
    }
}
