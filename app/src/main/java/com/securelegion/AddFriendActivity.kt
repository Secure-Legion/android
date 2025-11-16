package com.securelegion

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
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

        // Add Friend button
        findViewById<View>(R.id.searchButton).setOnClickListener {
            val cid = findViewById<EditText>(R.id.cidInput).text.toString().trim()
            val pin = findViewById<EditText>(R.id.pinInput).text.toString().trim()

            if (cid.isEmpty()) {
                Toast.makeText(this, "Please enter CID", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (pin.isEmpty()) {
                Toast.makeText(this, "Please enter PIN", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (pin.length != 6 || !pin.all { it.isDigit() }) {
                Toast.makeText(this, "PIN must be 6 digits", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            downloadContactCard(cid, pin)
        }

        setupBottomNav()
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

        // Save contact to encrypted database
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Step 1: Getting KeyManager instance...")
                val keyManager = KeyManager.getInstance(this@AddFriendActivity)

                Log.d(TAG, "Step 2: Getting database passphrase...")
                val dbPassphrase = keyManager.getDatabasePassphrase()
                Log.d(TAG, "Database passphrase obtained (${dbPassphrase.size} bytes)")

                Log.d(TAG, "Step 3: Getting database instance...")
                val database = SecureLegionDatabase.getInstance(this@AddFriendActivity, dbPassphrase)
                Log.d(TAG, "Database instance obtained")

                Log.d(TAG, "Step 4: Checking if contact already exists...")
                val existingContact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactBySolanaAddress(contactCard.solanaAddress)
                }

                if (existingContact != null) {
                    Log.w(TAG, "Contact already exists in database")
                    Toast.makeText(
                        this@AddFriendActivity,
                        "Contact already exists: ${contactCard.displayName}",
                        Toast.LENGTH_SHORT
                    ).show()
                    finish()
                    return@launch
                }

                Log.d(TAG, "Step 5: Creating Contact entity...")
                val contact = Contact(
                    displayName = contactCard.displayName,
                    solanaAddress = contactCard.solanaAddress,
                    publicKeyBase64 = Base64.encodeToString(
                        contactCard.solanaPublicKey,
                        Base64.NO_WRAP
                    ),
                    x25519PublicKeyBase64 = Base64.encodeToString(
                        contactCard.x25519PublicKey,
                        Base64.NO_WRAP
                    ),
                    torOnionAddress = contactCard.torOnionAddress,
                    addedTimestamp = System.currentTimeMillis(),
                    lastContactTimestamp = System.currentTimeMillis(),
                    trustLevel = Contact.TRUST_UNTRUSTED
                )
                Log.d(TAG, "Contact entity created: ${contact.displayName}")

                Log.d(TAG, "Step 6: Inserting contact into database...")
                val contactId = withContext(Dispatchers.IO) {
                    database.contactDao().insertContact(contact)
                }

                Log.i(TAG, "SUCCESS! Contact saved to database with ID: $contactId")

                Toast.makeText(
                    this@AddFriendActivity,
                    "Contact added: ${contactCard.displayName}",
                    Toast.LENGTH_LONG
                ).show()

                // Navigate back to main screen
                finish()
            } catch (e: Exception) {
                Log.e(TAG, "DETAILED ERROR - Failed to save contact to database", e)
                Log.e(TAG, "Error type: ${e.javaClass.simpleName}")
                Log.e(TAG, "Error message: ${e.message}")
                Log.e(TAG, "Stack trace:", e)

                val errorMsg = when {
                    e.message?.contains("no such table") == true ->
                        "Database error: Table not created"
                    e.message?.contains("UNIQUE constraint") == true ->
                        "Contact already exists"
                    e.message != null ->
                        "Database error: ${e.message}"
                    else ->
                        "Database error: ${e.javaClass.simpleName}"
                }

                Toast.makeText(
                    this@AddFriendActivity,
                    errorMsg,
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private fun setupBottomNav() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            // Already on Add Friend screen, do nothing
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }
    }
}
