package com.securelegion

import android.app.Application
import android.util.Log
import com.securelegion.crypto.TorManager

/**
 * Application class for Secure Legion
 *
 * Handles:
 * - Tor network initialization on app startup
 * - Global app-level initialization
 */
class SecureLegionApplication : Application() {

    companion object {
        private const val TAG = "SecureLegionApp"
    }

    override fun onCreate() {
        super.onCreate()

        Log.d(TAG, "Application starting...")

        // Initialize Tor network
        try {
            Log.d(TAG, "About to initialize Tor...")
            initializeTor()
            Log.d(TAG, "Tor initialization started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize Tor", e)
        }
    }

    private fun initializeTor() {
        val torManager = TorManager.getInstance(this)

        // Initialize Tor asynchronously (this takes a few seconds)
        torManager.initializeAsync { success, onionAddress ->
            if (success && onionAddress != null) {
                Log.i(TAG, "Tor initialized successfully")
                Log.i(TAG, "Our .onion address: $onionAddress")
            } else {
                Log.e(TAG, "Tor initialization failed!")
            }
        }
    }
}
