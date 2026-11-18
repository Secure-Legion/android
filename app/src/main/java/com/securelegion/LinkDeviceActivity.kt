package com.securelegion

import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.services.DeviceEnrollmentCandidateRuntime
import com.securelegion.utils.BrandedQrGenerator
import kotlinx.coroutines.launch

/** Candidate enrollment requires matching codes and a signed roster grant. */
class LinkDeviceActivity : AppCompatActivity() {
    private lateinit var status: TextView
    private lateinit var qr: ImageView
    private lateinit var code: TextView
    private lateinit var approve: Button
    private lateinit var cancel: Button
    private var shownQr: String? = null
    private var openedLinkedProfile = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(32.dp, 48.dp, 32.dp, 32.dp)
            setBackgroundColor(Color.rgb(18, 20, 24))
        }
        root.addView(TextView(this).apply {
            text = "Link this device"
            textSize = 25f
            setTextColor(Color.WHITE)
        })
        status = TextView(this).apply {
            text = "Connecting Tor..."
            textSize = 16f
            setTextColor(Color.LTGRAY)
            gravity = Gravity.CENTER
        }
        root.addView(status, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 24.dp })
        qr = ImageView(this).apply { contentDescription = "Candidate device QR" }
        root.addView(qr, LinearLayout.LayoutParams(320.dp, 320.dp).apply { topMargin = 24.dp })
        code = TextView(this).apply {
            textSize = 28f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
        }
        root.addView(code, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 20.dp })
        approve = Button(this).apply {
            text = "Codes match — approve"
            isEnabled = false
            setOnClickListener {
                runCatching { DeviceEnrollmentCandidateRuntime.approve() }
                    .onFailure { status.text = it.message ?: "Could not approve" }
            }
        }
        root.addView(approve, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 20.dp })
        cancel = Button(this).apply {
            text = "Cancel linking"
            setOnClickListener {
                AlertDialog.Builder(this@LinkDeviceActivity)
                    .setTitle("Discard this link attempt?")
                    .setNegativeButton("Keep waiting", null)
                    .setPositiveButton("Discard") { _, _ ->
                        runCatching { DeviceEnrollmentCandidateRuntime.discard(this@LinkDeviceActivity) }
                            .onSuccess { finish() }
                            .onFailure { status.text = it.message ?: "Could not discard link" }
                    }.show()
            }
        }
        root.addView(cancel, LinearLayout.LayoutParams(-1, -2).apply { topMargin = 16.dp })
        setContentView(root)
        lifecycleScope.launch {
            DeviceEnrollmentCandidateRuntime.state.collect { render(it) }
        }
        runCatching { DeviceEnrollmentCandidateRuntime.start(this) }
            .onFailure { status.text = it.message ?: "Could not start linking" }
    }

    private fun render(state: DeviceEnrollmentCandidateRuntime.State) {
        status.text = when (state.phase) {
            DeviceEnrollmentCandidateRuntime.Phase.IDLE -> "Start device linking"
            DeviceEnrollmentCandidateRuntime.Phase.STARTING_TOR -> "Connecting Tor..."
            DeviceEnrollmentCandidateRuntime.Phase.SHOW_QR ->
                "Scan this QR with your primary device. Keep both devices online."
            DeviceEnrollmentCandidateRuntime.Phase.COMPARE ->
                "Compare this code on both devices, then approve here."
            DeviceEnrollmentCandidateRuntime.Phase.WAITING_FOR_GRANT ->
                "Waiting for the signed device grant..."
            DeviceEnrollmentCandidateRuntime.Phase.COMPLETE ->
                "Device authorized. Opening linked messages…"
            DeviceEnrollmentCandidateRuntime.Phase.FAILED -> state.detail
        }
        approve.isEnabled = state.phase == DeviceEnrollmentCandidateRuntime.Phase.COMPARE
        cancel.isEnabled = state.phase != DeviceEnrollmentCandidateRuntime.Phase.COMPLETE
        code.text = if (state.phase == DeviceEnrollmentCandidateRuntime.Phase.COMPARE ||
            state.phase == DeviceEnrollmentCandidateRuntime.Phase.WAITING_FOR_GRANT)
            state.code else ""
        if (state.qr.isNotEmpty() && shownQr != state.qr) {
            shownQr = state.qr
            qr.setImageBitmap(BrandedQrGenerator.generate(this,
                BrandedQrGenerator.QrOptions(state.qr, size = 640,
                    showLogo = false, showWebsite = false)))
        }
        if (state.phase == DeviceEnrollmentCandidateRuntime.Phase.COMPLETE &&
            !openedLinkedProfile) {
            openedLinkedProfile = true
            startActivity(Intent(this, LinkedMessengerActivity::class.java))
            finish()
        }
    }

    private val Int.dp: Int get() = (this * resources.displayMetrics.density).toInt()
}
