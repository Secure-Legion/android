package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class LockActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_lock)

        findViewById<View>(R.id.unlockButton).setOnClickListener {
            val password = findViewById<EditText>(R.id.passwordInput).text.toString()

            if (password.isBlank()) {
                Toast.makeText(this, "Please enter password", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // TODO: Verify password with biometric/PIN
            // For development, accept "test" or any password
            Toast.makeText(this, "Unlocked!", Toast.LENGTH_SHORT).show()
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.newAccountLink).setOnClickListener {
            val intent = Intent(this, CreateAccountActivity::class.java)
            startActivity(intent)
        }

        findViewById<View>(R.id.restoreAccountLink).setOnClickListener {
            val intent = Intent(this, RestoreAccountActivity::class.java)
            startActivity(intent)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Prevent going back without unlocking
    }
}
