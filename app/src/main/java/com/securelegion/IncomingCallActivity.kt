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
import com.securelegion.services.TorService
import com.securelegion.voice.CallSignaling
import com.securelegion.voice.VoiceCallManager
import com.securelegion.voice.crypto.VoiceCallCrypto
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers

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

    // Track if call was answered (to prevent rejecting in onDestroy)
    private var callWasAnswered = false

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

        // Start ring rotation animation
        val rotateAnimation = AnimationUtils.loadAnimation(this, R.anim.rotate_ring)
        animatedRing.startAnimation(rotateAnimation)

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

        // Apply 3D press effect to buttons
        val pressAnimator = android.animation.AnimatorInflater.loadStateListAnimator(
            this,
            R.animator.button_press_effect
        )
        declineButton.stateListAnimator = pressAnimator
        answerButton.stateListAnimator = pressAnimator
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
}
