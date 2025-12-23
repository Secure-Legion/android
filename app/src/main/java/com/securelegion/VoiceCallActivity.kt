package com.securelegion

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
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.VoiceCallSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.securelegion.database.entities.ed25519PublicKeyBytes
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

    // State
    private var isMuted = false
    private var isSpeakerOn = false
    private var callStartTime = 0L
    private val timerHandler = Handler(Looper.getMainLooper())
    private var timerRunnable: Runnable? = null

    // Call manager
    private lateinit var callManager: VoiceCallManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_voice_call)

        // Keep screen on during call
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        // Get data from intent
        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)
        contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: "@Contact"
        callId = intent.getStringExtra(EXTRA_CALL_ID) ?: ""
        isOutgoing = intent.getBooleanExtra(EXTRA_IS_OUTGOING, true)

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
        updateCallStatus("Encrypted voice call")

        // Actually start the call!
        startActualCall()
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
        callManager.endCall("User ended call")
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
        runOnUiThread {
            updateCallStatus(reason)
            stopCallTimer()

            // Show toast or dialog
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

    private fun updateCallStatus(status: String) {
        callStatusText.text = status
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

                // Get their ephemeral public key from intent
                val theirEphemeralKey = intent.getByteArrayExtra(EXTRA_THEIR_EPHEMERAL_KEY)
                if (theirEphemeralKey == null) {
                    android.util.Log.e(TAG, "No ephemeral key provided")
                    handleCallEnded("Missing encryption key")
                    return@launch
                }

                android.util.Log.i(TAG, "Starting voice call to ${contact.displayName}")
                updateCallStatus("Connecting...")

                // Start the actual call
                val result = callManager.startCall(
                    contactOnion = contact.messagingOnion!!,
                    contactEd25519PublicKey = contact.ed25519PublicKeyBytes,
                    contactName = contact.displayName,
                    theirEphemeralPublicKey = theirEphemeralKey
                )

                if (result.isFailure) {
                    android.util.Log.e(TAG, "Failed to start call", result.exceptionOrNull())
                    handleCallEnded("Failed to connect: ${result.exceptionOrNull()?.message}")
                } else {
                    android.util.Log.i(TAG, "Voice call started successfully")
                    showConnectedState()
                }

            } catch (e: Exception) {
                android.util.Log.e(TAG, "Error starting call", e)
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
        stopCallTimer()
        animatedRing.clearAnimation()
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        // Clean up active call if still exists
        if (callManager.hasActiveCall()) {
            callManager.endCall("Activity destroyed")
        }
    }
}
