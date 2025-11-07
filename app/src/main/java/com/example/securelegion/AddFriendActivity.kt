package com.example.securelegion

import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class AddFriendActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_friend)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Search button
        findViewById<View>(R.id.searchButton).setOnClickListener {
            val handle = findViewById<EditText>(R.id.handleInput).text.toString()

            if (handle.isBlank()) {
                Toast.makeText(this, "Please enter a username or address", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            Toast.makeText(this, "Searching for $handle on blockchain...", Toast.LENGTH_SHORT).show()
            // TODO: Search Solana blockchain for contact card
        }
    }
}
