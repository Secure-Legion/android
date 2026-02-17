package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.RustBridge

/**
 * DeveloperActivity - Developer tools and debugging features
 *
 * Available tools:
 * - Call Log: View call quality telemetry from last voice call
 */
class DeveloperActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "DeveloperActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_developer)

        // Log Opus version for debugging
        try {
            val opusVersion = RustBridge.getOpusVersion()
            Log.i(TAG, "")
            Log.i(TAG, "Opus Library Version: $opusVersion")
            Log.i(TAG, "")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get Opus version: ${e.message}", e)
        }

        // Set up back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Set up Tor Health button
        findViewById<View>(R.id.torHealthItem).setOnClickListener {
            val intent = Intent(this, TorHealthActivity::class.java)
            startActivity(intent)
        }

        // Set up Call Log button
        findViewById<View>(R.id.callLogItem).setOnClickListener {
            val intent = Intent(this, CallLogActivity::class.java)
            startActivity(intent)
        }

        // Set up Stress Test button (master flavor only)
        val stressTestItem = findViewById<View>(R.id.stressTestItem)
        if (BuildConfig.ENABLE_STRESS_TESTING) {
            stressTestItem.setOnClickListener {
                val intent = Intent(this, com.securelegion.stresstest.StressTestActivity::class.java)
                startActivity(intent)
            }
        } else {
            stressTestItem.visibility = View.GONE
        }

        BottomNavigationHelper.setupBottomNavigation(this)
    }
}
