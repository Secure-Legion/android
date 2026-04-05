package com.securelegion

import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.TextView
import com.securelegion.utils.ThemedToast

/**
 * Devices screen - mirrors iOS Devices page.
 * Shows this device and allows linking a desktop/web session via QR code.
 * Multi-device linking is not yet implemented, so the QR flow shows a placeholder.
 */
class DevicesActivity : BaseActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_devices)

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }

        findViewById<TextView>(R.id.deviceName).text = Build.MODEL ?: "Android"
        findViewById<TextView>(R.id.deviceSubtitle).text =
            "Secure Android ${Build.VERSION.RELEASE}"

        findViewById<View>(R.id.linkDeviceButton).setOnClickListener {
            ThemedToast.show(this, "Desktop linking coming soon")
        }

        findViewById<View>(R.id.terminateSessionsRow).setOnClickListener {
            ThemedToast.show(this, "No other sessions to terminate")
        }
    }
}
