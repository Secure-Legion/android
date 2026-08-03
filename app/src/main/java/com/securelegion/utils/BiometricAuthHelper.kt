package com.securelegion.utils

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
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
 * - Biometric key is non-exportable from Android Keystore
 * - Encrypts the account password with a per-use authenticated Keystore key
 * - Binds each encrypt/decrypt operation to BiometricPrompt.CryptoObject
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
        private const val PREF_KEY_VERSION = "key_version"
        private const val KEY_VERSION = 2
    }

    /**
     * Check if biometric authentication is available on this device
     * Only Class 3 (BIOMETRIC_STRONG) authenticators can authorize the
     * per-operation cryptographic key used by this helper.
     */
    fun isBiometricAvailable(): BiometricStatus {
        val biometricManager = BiometricManager.from(context)
        val allowedAuthenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
        val result = biometricManager.canAuthenticate(allowedAuthenticators)

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
        val hasEncryptedData = prefs.contains(PREF_ENCRYPTED_PASSWORD_HASH)

        if (!hasEncryptedData) {
            return false
        }

        // Legacy keys relied on a UI-only prompt and were usable without a
        // cryptographic authentication token. Require secure re-enrollment.
        if (prefs.getInt(PREF_KEY_VERSION, 0) != KEY_VERSION) {
            Log.w(TAG, "Legacy biometric key found; forcing secure re-enrollment")
            disableBiometric()
            return false
        }

        // Also verify the key still exists (it can be invalidated by lockout or
        // biometric enrollment changes).
        val keyExists = try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
            keyStore.load(null)
            keyStore.containsAlias(KEY_NAME)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to check key existence", e)
            false
        }

        // If key is missing but data exists, clean up the orphaned data
        if (!keyExists && hasEncryptedData) {
            Log.w(TAG, "Biometric key invalidated - cleaning up orphaned encrypted data")
            prefs.edit()
                .remove(PREF_ENCRYPTED_PASSWORD_HASH)
                .remove(PREF_IV)
                .apply()
            return false
        }

        return keyExists
    }

    /**
     * Enable biometric authentication by encrypting the actual password.
     * The password is needed (not just the hash) because we derive the Argon2id
     * seed-wrapping key from it on unlock.
     *
     * @param password The user's plaintext password
     * @param activity The activity to show biometric prompt
     * @param onSuccess Callback when encryption succeeds
     * @param onError Callback when encryption fails
     */
    fun enableBiometric(
        password: String,
        activity: FragmentActivity,
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        try {
            // Enrollment always creates a fresh, authentication-bound key. This
            // also removes any legacy UI-gated key left by an older app version.
            disableBiometric()
            val secretKey = getOrCreateSecretKey()
            val cipher = getCipher().apply {
                init(Cipher.ENCRYPT_MODE, secretKey)
            }

            val biometricPrompt = createBiometricPrompt(activity,
                onAuthSuccess = { result ->
                    var passwordBytes: ByteArray? = null
                    try {
                        val authorizedCipher = result.cryptoObject?.cipher
                            ?: throw SecurityException("Authenticated cipher unavailable")
                        passwordBytes = password.toByteArray(Charsets.UTF_8)
                        val encryptedData = authorizedCipher.doFinal(passwordBytes)
                        val iv = authorizedCipher.iv

                        // Store encrypted password and IV
                        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                        val stored = prefs.edit()
                            .putString(PREF_ENCRYPTED_PASSWORD_HASH, Base64.encodeToString(encryptedData, Base64.NO_WRAP))
                            .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
                            .putInt(PREF_KEY_VERSION, KEY_VERSION)
                            .commit()
                        encryptedData.fill(0)
                        if (!stored) {
                            throw IllegalStateException("Failed to persist biometric enrollment")
                        }

                        Log.i(TAG, "Biometric authentication enabled - password encrypted")
                        onSuccess()
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to encrypt password", e)
                        disableBiometric()
                        onError("Failed to encrypt password: ${e.message}")
                    } finally {
                        passwordBytes?.fill(0)
                    }
                },
                onAuthError = { errorMsg ->
                    Log.w(TAG, "Biometric enrollment failed: $errorMsg")
                    onError(errorMsg)
                }
            )

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Enable Biometric Unlock")
                .setSubtitle("Authenticate to enable secure biometric unlock")
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
     * Authenticate with biometric and decrypt the stored password
     *
     * @param activity The activity to show biometric prompt
     * @param onSuccess Callback with decrypted password string
     * @param onError Callback when authentication fails
     */
    fun authenticateWithBiometric(
        activity: FragmentActivity,
        onSuccess: (String) -> Unit,
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
            val secretKey = getSecretKey()
            if (secretKey == null) {
                disableBiometric()
                onError("Biometric setup needs to be refreshed. Please use your password and re-enable biometrics in settings.")
                return
            }
            val cipher = getCipher().apply {
                init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            }

            val biometricPrompt = createBiometricPrompt(activity,
                onAuthSuccess = { result ->
                    try {
                        val authorizedCipher = result.cryptoObject?.cipher
                            ?: throw SecurityException("Authenticated cipher unavailable")
                        val decryptedBytes = authorizedCipher.doFinal(encryptedData)
                        val password = String(decryptedBytes, Charsets.UTF_8)
                        decryptedBytes.fill(0) // Zeroize plaintext bytes
                        Log.i(TAG, "Biometric authentication successful - password decrypted")
                        onSuccess(password)
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        Log.w(TAG, "Biometric key invalidated; re-enrollment required")
                        disableBiometric()
                        onError("Biometric setup needs to be refreshed. Please use your password and re-enable biometrics in settings.")
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to decrypt password", e)
                        onError("Failed to decrypt password: ${e.message}")
                    } finally {
                        encryptedData.fill(0)
                        iv.fill(0)
                    }
                },
                onAuthError = { errorMsg ->
                    encryptedData.fill(0)
                    iv.fill(0)
                    Log.w(TAG, "Biometric authentication failed: $errorMsg")
                    onError(errorMsg)
                }
            )

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock Secure Legion")
                .setSubtitle("Use a strong enrolled biometric to unlock")
                .setNegativeButtonText("Use Password")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()

            biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        } catch (e: KeyPermanentlyInvalidatedException) {
            Log.w(TAG, "Biometric key invalidated; re-enrollment required")
            disableBiometric()
            onError("Biometric setup needs to be refreshed. Please use your password and re-enable biometrics in settings.")
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
                .remove(PREF_KEY_VERSION)
                .commit()

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
     * Create or retrieve the secret key for biometric-gated encryption.
     * Key is stored in Android Keystore (hardware-backed when available).
     *
     * Every key operation requires a fresh Class 3 biometric authentication and is
     * bound to BiometricPrompt through a CryptoObject. UI success alone cannot use
     * this key.
     */
    private fun getOrCreateSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE)
        keyStore.load(null)

        if (keyStore.containsAlias(KEY_NAME)) {
            return keyStore.getKey(KEY_NAME, null) as SecretKey
        }

        // Create a new key, preferring StrongBox when the device supports it.
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        // Try StrongBox first; not all devices or AES modes support it.
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
                    .applyPerUseAuthentication()
                    .setIsStrongBoxBacked(true)
                    .build()

                keyGenerator.init(keyGenParameterSpecStrongBox)
                secretKey = keyGenerator.generateKey()
                Log.i(TAG, "Created biometric key in StrongBox (highest security)")
            } catch (e: Exception) {
                Log.w(TAG, "StrongBox not available, falling back to TEE: ${e.message}")
            }
        }

        // Fall back to the standard Android Keystore provider. Its security
        // level is device-specific and must not be described as guaranteed TEE.
        if (secretKey == null) {
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .applyPerUseAuthentication()
                .build()

            keyGenerator.init(keyGenParameterSpec)
            secretKey = keyGenerator.generateKey()
            Log.i(TAG, "Created biometric key in Android Keystore")
        }

        return secretKey
    }

    private fun KeyGenParameterSpec.Builder.applyPerUseAuthentication(): KeyGenParameterSpec.Builder {
        setUserAuthenticationRequired(true)
        setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            setUserAuthenticationValidityDurationSeconds(-1)
        }
        return this
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
        onAuthSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
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
                onAuthSuccess(result)
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
