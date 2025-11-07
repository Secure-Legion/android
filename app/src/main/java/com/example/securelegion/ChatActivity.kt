package com.example.securelegion

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class ChatActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_chat)

        val chatName = intent.getStringExtra("CHAT_NAME") ?: "@user"
        val isOnline = intent.getBooleanExtra("IS_ONLINE", false)

        findViewById<TextView>(R.id.chatName).text = chatName
        findViewById<TextView>(R.id.chatStatus).text = if (isOnline) "● Online • Active" else "● Offline"

        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Options button
        findViewById<View>(R.id.optionsButton).setOnClickListener {
            Toast.makeText(this, "Options menu", Toast.LENGTH_SHORT).show()
            // TODO: Show options menu
        }

        // Send button
        findViewById<View>(R.id.sendButton).setOnClickListener {
            val messageInput = findViewById<EditText>(R.id.messageInput)
            val message = messageInput.text.toString()

            if (message.isNotBlank()) {
                Toast.makeText(this, "Sending: $message", Toast.LENGTH_SHORT).show()
                messageInput.text.clear()
                // TODO: Send message via Rust core
            }
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
