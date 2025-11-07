package com.example.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class DuressPinActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_duress_pin)

        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Save Duress PIN button
        findViewById<View>(R.id.saveDuressPinButton).setOnClickListener {
            val pin = findViewById<EditText>(R.id.duressPinInput).text.toString()
            val confirmPin = findViewById<EditText>(R.id.confirmDuressPinInput).text.toString()

            if (pin.isEmpty() || confirmPin.isEmpty()) {
                Toast.makeText(this, "Please enter and confirm your duress PIN", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (pin != confirmPin) {
                Toast.makeText(this, "PINs do not match", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            Toast.makeText(this, "Duress PIN saved successfully!", Toast.LENGTH_SHORT).show()
            // TODO: Save duress PIN securely
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
