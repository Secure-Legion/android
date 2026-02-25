package com.securelegion

import android.os.Bundle
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.securelegion.utils.DeviceProtectionGate

/**
 * Thin transparent Activity for Device Protection biometric prompt.
 * Launched from notification when app is in background.
 * Shows BiometricPrompt immediately, returns result to DeviceProtectionGate.
 */
class DeviceProtectionUnlockActivity : FragmentActivity() {

    companion object {
        private const val TAG = "DPUnlockActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No layout — transparent activity

        val gate = DeviceProtectionGate.getInstance(this)

        // Check if already in cooldown (another prompt may have succeeded)
        if (gate.isInCooldown()) {
            Log.d(TAG, "Already in cooldown — finishing")
            gate.onAuthSuccess()
            finish()
            return
        }

        showBiometricPrompt(gate)
    }

    private fun showBiometricPrompt(gate: DeviceProtectionGate) {
        val executor = ContextCompat.getMainExecutor(this)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.w(TAG, "Auth error: $errString (code $errorCode)")
                gate.onAuthDenied(errString.toString())
                finish()
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.i(TAG, "Auth succeeded — releasing pending pings")
                gate.onAuthSuccess()
                finish()
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.d(TAG, "Auth attempt failed (user can retry)")
                // Don't finish — user can retry
            }
        }

        val biometricPrompt = BiometricPrompt(this, executor, callback)

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock to receive messages")
            .setSubtitle("Verify your identity to download pending messages")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}
