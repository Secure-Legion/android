package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.PasswordValidator
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DevicePasswordActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_device_password)

        setupBottomNavigation()
        setupBackButton()

        // Change Password button
        findViewById<View>(R.id.changePasswordButton).setOnClickListener {
            val currentPassword = findViewById<EditText>(R.id.currentPasswordInput).text.toString()
            val newPassword = findViewById<EditText>(R.id.newPasswordInput).text.toString()
            val confirmPassword = findViewById<EditText>(R.id.confirmPasswordInput).text.toString()

            if (currentPassword.isEmpty() || newPassword.isEmpty() || confirmPassword.isEmpty()) {
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

            // Disable button while changing password
            findViewById<View>(R.id.changePasswordButton).isEnabled = false

            lifecycleScope.launch {
                try {
                    Log.i("DevicePassword", "Attempting to change device password")

                    val keyManager = KeyManager.getInstance(this@DevicePasswordActivity)

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

                    // Change to new password
                    withContext(Dispatchers.IO) {
                        keyManager.setDevicePassword(newPassword)
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

    private fun setupBackButton() {
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
