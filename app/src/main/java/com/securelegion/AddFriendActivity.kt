package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.models.ContactCard
import com.securelegion.services.ContactCardManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AddFriendActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "AddFriend"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_friend)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Search button (for CID+PIN entry)
        findViewById<View>(R.id.searchButton).setOnClickListener {
            val input = findViewById<EditText>(R.id.handleInput).text.toString().trim()

            if (input.isBlank()) {
                Toast.makeText(this, "Please enter CID and PIN", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            // Parse input - expecting format: "CID PIN" or "CID:PIN" or just CID
            val parts = input.split(Regex("[\\s:]+"))

            when {
                parts.size == 2 -> {
                    // CID and PIN provided
                    val cid = parts[0]
                    val pin = parts[1]
                    downloadContactCard(cid, pin)
                }
                parts.size == 1 && (parts[0].startsWith("Qm") || parts[0].startsWith("baf")) -> {
                    // Only CID provided, prompt for PIN
                    Toast.makeText(
                        this,
                        "Please enter both CID and PIN separated by space",
                        Toast.LENGTH_LONG
                    ).show()
                }
                else -> {
                    // Treat as blockchain username search (future feature)
                    Toast.makeText(
                        this,
                        "To add via contact card, enter: CID PIN",
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun downloadContactCard(cid: String, pin: String) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Downloading contact card from IPFS...")
                Log.d(TAG, "CID: $cid")
                Log.d(TAG, "PIN: $pin")

                Toast.makeText(
                    this@AddFriendActivity,
                    "Downloading contact card...",
                    Toast.LENGTH_SHORT
                ).show()

                val cardManager = ContactCardManager(this@AddFriendActivity)
                val result = withContext(Dispatchers.IO) {
                    cardManager.downloadContactCard(cid, pin)
                }

                if (result.isSuccess) {
                    val contactCard = result.getOrThrow()
                    handleContactCardDownloaded(contactCard)
                } else {
                    throw result.exceptionOrNull()!!
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to download contact card", e)
                val errorMessage = when {
                    e.message?.contains("invalid PIN", ignoreCase = true) == true ||
                    e.message?.contains("decryption failed", ignoreCase = true) == true ->
                        "Invalid PIN. Please check and try again."
                    e.message?.contains("download failed", ignoreCase = true) == true ||
                    e.message?.contains("404", ignoreCase = true) == true ->
                        "Contact card not found. Check the CID."
                    else ->
                        "Failed to download contact: ${e.message}"
                }
                Toast.makeText(
                    this@AddFriendActivity,
                    errorMessage,
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun handleContactCardDownloaded(contactCard: ContactCard) {
        Log.i(TAG, "Successfully downloaded contact card:")
        Log.i(TAG, "  Name: ${contactCard.displayName}")
        Log.i(TAG, "  Solana: ${contactCard.solanaAddress}")
        Log.i(TAG, "  Onion: ${contactCard.torOnionAddress}")

        Toast.makeText(
            this,
            "Contact added: ${contactCard.displayName}\n${contactCard.solanaAddress}",
            Toast.LENGTH_LONG
        ).show()

        // TODO: Save contact to local database
        // TODO: Navigate back to contacts list

        finish()
    }
}
