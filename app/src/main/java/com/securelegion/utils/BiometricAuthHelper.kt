package com.securelegion.utils

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * BiometricAuthHelper - Hardware-backed biometric authentication
 *
 * Security Features:
 * - Uses Android Keystore (hardware-backed when available)
 * - Biometric key never leaves TEE/StrongBox
 * - Encrypts password hash with biometric-protected key
 * - Requires biometric authentication to decrypt
 */
class BiometricAuthHelper(private val context: Context) {

    companion object {
        private const val TAG = "BiometricAuthHelper"
        private const val KEY_NAME = "securelegion_biometric_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/" +
                KeyProperties.BLOCK_MODE_GCM + "/" +
                KeyProperties.ENCRYPTION_PADDING_NONE
        private const val PREFS_NAME = "biometric_auth"
        private const val PREF_ENCRYPTED_PASSWORD_HASH = "encrypted_password_hash"
        private const val PREF_IV = "iv"
    }

    /**
     * Check if biometric authentication is available on this device
     */
    fun isBiometricAvailable(): BiometricStatus {
        val biometricManager = BiometricManager.from(context)
        val result = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)

        android.util.Log.d(TAG, "BiometricManager.canAuthenticate(BIOMETRIC_STRONG) returned: $result")

        return when (result) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                android.util.Log.d(TAG, "Status: BIOMETRIC_SUCCESS")
                BiometricStatus.AVAILABLE
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                android.util.Log.w(TAG, "Status: BIOMETRIC_ERROR_NO_HARDWARE")
                BiometricStatus.NO_HARDWARE
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                android.util.Log.w(TAG, "Status: BIOMETRIC_ERROR_HW_UNAVAILABLE")
                BiometricStatus.HARDWARE_UNAVAILABLE
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                android.util.Log.w(TAG, "Status: BIOMETRIC_ERROR_NONE_ENROLLED")
                BiometricStatus.NONE_ENROLLED
            }
            else -> {
                android.util.Log.e(TAG, "Status: UNKNOWN_ERROR (code: $result)")
                BiometricStatus.UNKNOWN_ERROR
            }
        }
    }

    /**
     * Check if biometric authentication is enabled for this app
     */
    fun isBiometricEnabled(): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.contains(PREF_ENCRYPTED_PASSWORD_HASH)
    }

    /**
     * Enable biometric authentication by encrypting the password hash
     *
     * @param passwordHash The Argon2id hash of the user's password
     * @param activity The activity to show biometric prompt
     * @param onSuccess Callback when encryption succeeds
     * @param onError Callback when encryption fails
     */
    fun enableBiometric(
        passwordHash: ByteArray,
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        try {
            val cipher = getCipher()
            val secretKey = getOrCreateSecretKey()
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)

            val biometricPrompt = createBiometricPrompt(activity,
                onAuthSuccess = { cryptoObject ->
                    try {
                        val encryptedData = cryptoObject.cipher!!.doFinal(passwordHash)
                        val iv = cryptoObject.cipher!!.iv

                        // Store encrypted password hash and IV
                        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                        prefs.edit()
                            .putString(PREF_ENCRYPTED_PASSWORD_HASH, Base64.encodeToString(encryptedData, Base64.NO_WRAP))
                            .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                            .apply()

                        Log.i(TAG, "Biometric authentication enabled - password hash encrypted")
                        onSuccess()
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to encrypt password hash", e)
                        onError("Failed to encrypt password: ${e.message}")
                    }
                },
                onAuthError = { errorMsg ->
                    Log.w(TAG, "Biometric enrollment failed: $errorMsg")
                    onError(errorMsg)
                }
            )

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Enable Biometric Unlock")
                .setSubtitle("Authenticate to enable fingerprint/face unlock")
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()

            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to enable biometric", e)
            onError("Failed to enable biometric: ${e.message}")
        }
    }

    /**
     * Authenticate with biometric and decrypt the password hash
     *
     * @param activity The activity to show biometric prompt
     * @param onSuccess Callback with decrypted password hash
     * @param onError Callback when authentication fails
     */
    fun authenticateWithBiometric(
        activity: FragmentActivity,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit
    ) {
        if (!isBiometricEnabled()) {
            onError("Biometric authentication not enabled")
            return
        }

        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val encryptedDataB64 = prefs.getString(PREF_ENCRYPTED_PASSWORD_HASH, null)
            val ivB64 = prefs.getString(PREF_IV, null)

            if (encryptedDataB64 == null || ivB64 == null) {
                onError("Biometric data not found")
                return
            }

            val encryptedData = Base64.decode(encryptedDataB64, Base64.NO_WRAP)
            val iv = Base64.decode(ivB64, Base64.NO_WRAP)

            val cipher = getCipher()
            val secretKey = getSecretKey()
            if (secretKey == null) {
                onError("Biometric key not found")
                return
            }

            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

            val biometricPrompt = createBiometricPrompt(activity,
                onAuthSuccess = { cryptoObject ->
                    try {
                        val decryptedPasswordHash = cryptoObject.cipher!!.doFinal(encryptedData)
                        Log.i(TAG, "Biometric authentication successful - password hash decrypted")
                        onSuccess(decryptedPasswordHash)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to decrypt password hash", e)
                        onError("Failed to decrypt password: ${e.message}")
                    }
                },
                onAuthError = { errorMsg ->
                    Log.w(TAG, "Biometric authentication failed: $errorMsg")
                    onError(errorMsg)
                }
            )

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Secure Legion")
                .setSubtitle("Verify your identity to unlock")
                .setNegativeButtonText("Use Password")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()

            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to authenticate with biometric", e)
            onError("Failed to authenticate: ${e.message}")
        }
    }

    /**
     * Disable biometric authentication and delete encrypted data
     */
    fun disableBiometric() {
        try {
            // Delete stored encrypted data
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit()
                .remove(PREF_ENCRYPTED_PASSWORD_HASH)
                .remove(PREF_IV)
                .apply()

            // Delete biometric key from keystore
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.deleteEntry(KEY_NAME)

            Log.i(TAG, "Biometric authentication disabled")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to disable biometric", e)
        }
    }

    /**
     * Create or retrieve the biometric-protected secret key
     * Key is stored in Android Keystore (hardware-backed when available)
     */
    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        if (keyStore.containsAlias(KEY_NAME)) {
            return keyStore.getKey(KEY_NAME, null) as SecretKey
        }

        // Create new key - try with StrongBox first, fallback to regular TEE if unavailable
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        // Try with StrongBox first (highest security, but not all devices have it)
        var secretKey: SecretKey? = null
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            try {
                val keyGenParameterSpecStrongBox = KeyGenParameterSpec.Builder(
                    KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(true)
                    .setInvalidatedByBiometricEnrollment(true)
                    .setIsStrongBoxBacked(true)
                    .build()

                keyGenerator.init(keyGenParameterSpecStrongBox)
                secretKey = keyGenerator.generateKey()
                Log.i(TAG, "✓ Created biometric key in StrongBox (highest security)")
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox not available, falling back to TEE: ${e.message}")
                // Fall through to regular keystore
            }
        }

        // Fallback to regular hardware-backed Keystore (TEE) if StrongBox unavailable
        if (secretKey == null) {
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .build()

            keyGenerator.init(keyGenParameterSpec)
            secretKey = keyGenerator.generateKey()
            Log.i(TAG, "✓ Created biometric key in TEE (hardware-backed)")
        }

        return secretKey
    }

    /**
     * Get existing secret key (without creating new one)
     */
    private fun getSecretKey(): SecretKey? {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            if (keyStore.containsAlias(KEY_NAME)) {
                keyStore.getKey(KEY_NAME, null) as SecretKey
            } else {
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get secret key", e)
            null
        }
    }

    /**
     * Get AES/GCM cipher for encryption/decryption
     */
    private fun getCipher(): Cipher {
        return Cipher.getInstance(TRANSFORMATION)
    }

    /**
     * Create biometric prompt with callbacks
     */
    private fun createBiometricPrompt(
        activity: FragmentActivity,
        onAuthSuccess: (BiometricPrompt.CryptoObject) -> Unit,
        onAuthError: (String) -> Unit
    ): BiometricPrompt {
        val executor = ContextCompat.getMainExecutor(activity)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                onAuthError(errString.toString())
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                result.cryptoObject?.let { onAuthSuccess(it) }
                    ?: onAuthError("CryptoObject is null")
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                // Don't call onError here - user can retry
                Log.d(TAG, "Biometric authentication attempt failed (user can retry)")
            }
        }

        return BiometricPrompt(activity, executor, callback)
    }

    enum class BiometricStatus {
        AVAILABLE,
        NO_HARDWARE,
        HARDWARE_UNAVAILABLE,
        NONE_ENROLLED,
        UNKNOWN_ERROR
    }
}
