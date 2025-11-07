package com.example.securelegion

import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class ComposeActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_compose)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Send button
        findViewById<View>(R.id.sendButton).setOnClickListener {
            val recipient = findViewById<EditText>(R.id.recipientInput).text.toString()
            val message = findViewById<EditText>(R.id.messageInput).text.toString()

            if (recipient.isBlank()) {
                Toast.makeText(this, "Please enter a recipient", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (message.isBlank()) {
                Toast.makeText(this, "Please enter a message", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            Toast.makeText(this, "Sending message to $recipient", Toast.LENGTH_SHORT).show()
            // TODO: Send message via Rust core
            finish()
        }
    }
}
