package com.example.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class ContactOptionsActivity : AppCompatActivity() {

    private lateinit var contactName: TextView
    private lateinit var contactAddress: TextView
    private lateinit var displayNameInput: EditText
    private lateinit var saveDisplayNameButton: TextView
    private lateinit var openMessagesButton: TextView
    private var fullAddress: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_contact_options)

        // Get contact info from intent
        val name = intent.getStringExtra("CONTACT_NAME") ?: "@unknown"
        val address = intent.getStringExtra("CONTACT_ADDRESS") ?: ""
        fullAddress = address

        initializeViews()
        setupContactInfo(name, address)
        setupClickListeners(name)
        setupBottomNav()
    }

    private fun initializeViews() {
        contactName = findViewById(R.id.contactName)
        contactAddress = findViewById(R.id.contactAddress)
        displayNameInput = findViewById(R.id.displayNameInput)
        saveDisplayNameButton = findViewById(R.id.saveDisplayNameButton)
        openMessagesButton = findViewById(R.id.openMessagesButton)
    }

    private fun setupContactInfo(name: String, address: String) {
        contactName.text = name
        contactAddress.text = address
        displayNameInput.hint = "Enter new display name for $name"
    }

    private fun setupClickListeners(name: String) {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Copy address on click
        findViewById<View>(R.id.copyAddressContainer).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", fullAddress)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Address copied to clipboard", Toast.LENGTH_SHORT).show()
        }

        // Save display name button
        saveDisplayNameButton.setOnClickListener {
            val newDisplayName = displayNameInput.text.toString().trim()

            if (newDisplayName.isEmpty()) {
                Toast.makeText(this, "Please enter a display name", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // TODO: Save display name to local storage/database
            Toast.makeText(
                this,
                "Display name updated!\n\n$name will now appear as \"$newDisplayName\" in your contacts and messages.",
                Toast.LENGTH_LONG
            ).show()

            // Clear the input
            displayNameInput.text.clear()
        }

        // Open messages button
        openMessagesButton.setOnClickListener {
            val intent = Intent(this, ChatActivity::class.java)
            intent.putExtra("CHAT_NAME", name)
            intent.putExtra("IS_ONLINE", false)
            startActivity(intent)
        }
    }

    private fun setupBottomNav() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
