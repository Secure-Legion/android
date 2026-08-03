package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.PasswordValidator
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DevicePasswordActivity : AppCompatActivity() {

    private lateinit var keyManager: KeyManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_device_password)

        keyManager = KeyManager.getInstance(this)

        setupBackButton()
        setupUI()
        setupChangePasswordButton()
        setupRemovePasswordButton()
    }

    private fun setupUI() {
        val hasUserPassword = keyManager.hasUserDefinedPassword()

        // Update header title and button label based on password state
        val headerTitle = findViewById<TextView>(R.id.headerTitle)
        val changeButtonLabel = findViewById<TextView>(R.id.changePasswordButtonLabel)
        val currentPasswordLabel = findViewById<View>(R.id.currentPasswordInput)

        if (hasUserPassword) {
            headerTitle.text = "Change Password"
            changeButtonLabel.text = "Change Password"
        } else {
            headerTitle.text = "Set Password"
            changeButtonLabel.text = "Set Password"
        }

        // Show/hide remove password button
        val removeButton = findViewById<View>(R.id.removePasswordButton)
        removeButton.visibility = if (hasUserPassword) View.VISIBLE else View.GONE
    }

    private fun setupChangePasswordButton() {
        findViewById<View>(R.id.changePasswordButton).setOnClickListener {
            val currentPassword = findViewById<EditText>(R.id.currentPasswordInput).text.toString()
            val newPassword = findViewById<EditText>(R.id.newPasswordInput).text.toString()
            val confirmPassword = findViewById<EditText>(R.id.confirmPasswordInput).text.toString()

            val hasUserPassword = keyManager.hasUserDefinedPassword()

            if (hasUserPassword && currentPassword.isEmpty()) {
                ThemedToast.show(this, "Please enter your current password")
                return@setOnClickListener
            }

            if (newPassword.isEmpty() || confirmPassword.isEmpty()) {
                ThemedToast.show(this, "Please fill in all fields")
                return@setOnClickListener
            }

            if (newPassword != confirmPassword) {
                ThemedToast.show(this, "New passwords do not match")
                return@setOnClickListener
            }

            // Validate password complexity
            val validation = PasswordValidator.validate(newPassword)
            if (!validation.isValid) {
                ThemedToast.showLong(this, validation.errorMessage ?: "Invalid password")
                return@setOnClickListener
            }

            if (
                DuressPinActivity.isDuressPinSet(this) &&
                DuressPinActivity.verifyDuressPin(this, newPassword)
            ) {
                ThemedToast.showLong(this, "Unlock password must be different from your duress PIN")
                return@setOnClickListener
            }

            // Disable button while changing password
            findViewById<View>(R.id.changePasswordButton).isEnabled = false

            lifecycleScope.launch {
                try {
                    Log.i("DevicePassword", "Attempting to change device password")

                    // Determine old password: if user has no user-defined password, get the system password
                    val oldPassword = if (hasUserPassword) {
                        // Verify current password is correct
                        val isCurrentPasswordValid = withContext(Dispatchers.IO) {
                            keyManager.verifyDevicePassword(currentPassword)
                        }
                        if (!isCurrentPasswordValid) {
                            withContext(Dispatchers.Main) {
                                ThemedToast.show(this@DevicePasswordActivity, "Current password is incorrect")
                                findViewById<View>(R.id.changePasswordButton).isEnabled = true
                            }
                            return@launch
                        }
                        currentPassword
                    } else {
                        // No user-defined password — use system password as old password
                        withContext(Dispatchers.IO) {
                            keyManager.getSystemPassword()
                        } ?: throw Exception("Cannot retrieve system password")
                    }

                    // Re-wrap seed with new password
                    withContext(Dispatchers.IO) {
                        if (!keyManager.rewrapSeed(oldPassword, newPassword, isNewUserDefined = true)) {
                            throw Exception("Failed to re-wrap seed with new password")
                        }
                    }

                    Log.i("DevicePassword", "Password changed successfully")

                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@DevicePasswordActivity, "Password changed successfully!")

                        // Clear input fields
                        findViewById<EditText>(R.id.currentPasswordInput).setText("")
                        findViewById<EditText>(R.id.newPasswordInput).setText("")
                        findViewById<EditText>(R.id.confirmPasswordInput).setText("")

                        findViewById<View>(R.id.changePasswordButton).isEnabled = true
                        finish()
                    }

                } catch (e: Exception) {
                    Log.e("DevicePassword", "Failed to change password", e)
                    withContext(Dispatchers.Main) {
                        ThemedToast.showLong(this@DevicePasswordActivity, "Failed to change password: ${e.message}")
                        findViewById<View>(R.id.changePasswordButton).isEnabled = true
                    }
                }
            }
        }
    }

    private fun setupRemovePasswordButton() {
        findViewById<View>(R.id.removePasswordButton).setOnClickListener {
            val currentPassword = findViewById<EditText>(R.id.currentPasswordInput).text.toString()
            if (currentPassword.isEmpty()) {
                ThemedToast.show(this, "Enter current password to confirm")
                return@setOnClickListener
            }
            if (!keyManager.verifyDevicePassword(currentPassword)) {
                ThemedToast.show(this, "Incorrect password")
                return@setOnClickListener
            }

            // Disable button while removing password
            findViewById<View>(R.id.removePasswordButton).isEnabled = false

            lifecycleScope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        val newSystemPassword = keyManager.generateSystemPasswordPublic()
                        if (!keyManager.rewrapSeed(currentPassword, newSystemPassword, isNewUserDefined = false)) {
                            throw Exception("Failed to remove password")
                        }
                    }
                    ThemedToast.show(this@DevicePasswordActivity, "Password removed")
                    finish()
                } catch (e: Exception) {
                    Log.e("DevicePassword", "Failed to remove password", e)
                    withContext(Dispatchers.Main) {
                        ThemedToast.show(this@DevicePasswordActivity, "Failed: ${e.message}")
                        findViewById<View>(R.id.removePasswordButton).isEnabled = true
                    }
                }
            }
        }
    }

    private fun setupBackButton() {
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }
}
