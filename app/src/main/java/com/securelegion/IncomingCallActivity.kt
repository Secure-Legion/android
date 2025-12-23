package com.securelegion

import android.Manifest
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
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.crypto.VoiceCallCrypto
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.launch

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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

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

        // Get call manager
        callManager = VoiceCallManager.getInstance(this)

        // Update UI
        contactNameText.text = contactName
        callStatusText.text = "Incoming Call"

        // Start ring animation
        val pulseAnimation = AnimationUtils.loadAnimation(this, R.anim.pulse_ring)
        animatedRing.startAnimation(pulseAnimation)

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
    }

    private fun setupClickListeners() {
        // Decline button
        declineButton.setOnClickListener {
            declineCall()
        }

        // Answer button
        answerButton.setOnClickListener {
            answerCall()
        }
    }

    private fun declineCall() {
        // Stop ringtone
        stopRingtone()

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

        // Check microphone permission first
        if (ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.RECORD_AUDIO
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            // Request permission
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.RECORD_AUDIO),
                PERMISSION_REQUEST_CODE
            )
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

        lifecycleScope.launch {
            try {
                // First check if we can answer (no active call)
                if (callManager.hasActiveCall()) {
                    Log.e(TAG, "Cannot answer - call already in progress")
                    // Send rejection to caller
                    CallSignaling.sendCallReject(
                        contactX25519PublicKey,
                        contactOnion,
                        callId,
                        "Call already in progress"
                    )
                    ThemedToast.show(this@IncomingCallActivity, "Call already in progress")
                    finish()
                    return@launch
                }

                // Generate our ephemeral keypair
                val ourEphemeralKeypair = crypto.generateEphemeralKeypair()

                // Answer call in call manager FIRST (before sending CALL_ANSWER)
                val result = callManager.answerCall(callId)

                if (result.isFailure) {
                    // Failed to create call session - send rejection to caller
                    Log.e(TAG, "Failed to answer call: ${result.exceptionOrNull()?.message}")
                    CallSignaling.sendCallReject(
                        contactX25519PublicKey,
                        contactOnion,
                        callId,
                        "Failed to establish call"
                    )
                    ThemedToast.show(this@IncomingCallActivity, "Failed to answer call: ${result.exceptionOrNull()?.message}")
                    finish()
                    return@launch
                }

                // Now send CALL_ANSWER with our ephemeral public key
                val success = CallSignaling.sendCallAnswer(
                    contactX25519PublicKey,
                    contactOnion,
                    callId,
                    ourEphemeralKeypair.publicKey.asBytes
                )

                if (!success) {
                    // Failed to send answer - end the call we just created
                    callManager.endCall("Failed to send answer")
                    ThemedToast.show(this@IncomingCallActivity, "Failed to send call answer")
                    finish()
                    return@launch
                }

                // Success! Launch VoiceCallActivity
                val intent = Intent(this@IncomingCallActivity, VoiceCallActivity::class.java)
                intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_ID, contactId)
                intent.putExtra(VoiceCallActivity.EXTRA_CONTACT_NAME, contactName)
                intent.putExtra(VoiceCallActivity.EXTRA_CALL_ID, callId)
                intent.putExtra(VoiceCallActivity.EXTRA_IS_OUTGOING, false)
                intent.putExtra(VoiceCallActivity.EXTRA_THEIR_EPHEMERAL_KEY, theirEphemeralPublicKey)
                startActivity(intent)

                // Close this activity
                finish()

            } catch (e: Exception) {
                Log.e(TAG, "Error answering call", e)
                // Try to send rejection
                try {
                    CallSignaling.sendCallReject(
                        contactX25519PublicKey,
                        contactOnion,
                        callId,
                        "Error: ${e.message}"
                    )
                } catch (e2: Exception) {
                    Log.e(TAG, "Failed to send rejection", e2)
                }
                // Clean up any call state
                if (callManager.hasActiveCall()) {
                    callManager.endCall("Error answering")
                }
                ThemedToast.show(this@IncomingCallActivity, "Error answering call: ${e.message}")
                finish()
            }
        }
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

        // Clean up call state if activity destroyed without proper answer/decline
        // This handles cases like system killing the activity
        callManager.rejectCall(callId)
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
}
