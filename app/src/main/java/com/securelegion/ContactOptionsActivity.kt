package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.ToastUtils
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ContactOptionsActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "ContactOptions"
    }

    private lateinit var contactName: TextView
    private lateinit var contactAddress: TextView
    private lateinit var displayNameInput: EditText
    private lateinit var saveDisplayNameButton: TextView
    private lateinit var deleteContactButton: TextView
    private lateinit var distressStarIcon: ImageView
    private var fullAddress: String = ""
    private var contactId: Long = -1
    private var isDistressContact: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_contact_options)

        // Get contact info from intent
        contactId = intent.getLongExtra("CONTACT_ID", -1L)
        val name = intent.getStringExtra("CONTACT_NAME") ?: "@unknown"
        val address = intent.getStringExtra("CONTACT_ADDRESS") ?: ""
        fullAddress = address

        initializeViews()
        setupContactInfo(name, address)
        loadDistressStatus()
        setupClickListeners(name)
        setupBottomNav()
    }

    private fun initializeViews() {
        contactName = findViewById(R.id.contactName)
        contactAddress = findViewById(R.id.contactAddress)
        displayNameInput = findViewById(R.id.displayNameInput)
        saveDisplayNameButton = findViewById(R.id.saveDisplayNameButton)
        deleteContactButton = findViewById(R.id.deleteContactButton)
        distressStarIcon = findViewById(R.id.distressStarIcon)
    }

    private fun setupContactInfo(name: String, address: String) {
        contactName.text = name
        contactAddress.text = address
        displayNameInput.hint = "Enter new display name for $name"
    }

    private fun loadDistressStatus() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) {
                    return@launch
                }

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                val contact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactById(contactId)
                }

                if (contact != null) {
                    isDistressContact = contact.isDistressContact
                    updateStarIcon()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load distress status", e)
            }
        }
    }

    private fun updateStarIcon() {
        if (isDistressContact) {
            distressStarIcon.setImageResource(R.drawable.ic_star_filled)
        } else {
            distressStarIcon.setImageResource(R.drawable.ic_star_outline)
        }
    }

    private fun toggleDistressStatus() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) {
                    ToastUtils.showCustomToast(this@ContactOptionsActivity, "Error: Invalid contact")
                    return@launch
                }

                // Toggle the status
                isDistressContact = !isDistressContact

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                // Update in database
                withContext(Dispatchers.IO) {
                    database.contactDao().updateDistressContactStatus(contactId, isDistressContact)
                }

                // Update UI
                updateStarIcon()

                val message = if (isDistressContact) {
                    "Distress signal enabled"
                } else {
                    "Distress signal disabled"
                }
                ToastUtils.showCustomToast(this@ContactOptionsActivity, message)

                Log.i(TAG, "Distress status updated: $isDistressContact")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to toggle distress status", e)
                ToastUtils.showCustomToast(this@ContactOptionsActivity, "Failed to update status")
            }
        }
    }

    private fun setupClickListeners(name: String) {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Distress star icon
        distressStarIcon.setOnClickListener {
            toggleDistressStatus()
        }

        // Copy address on click
        findViewById<View>(R.id.copyAddressContainer).setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", fullAddress)
            clipboard.setPrimaryClip(clip)
            ToastUtils.showCustomToast(this, "Address copied")
        }

        // Save display name button
        saveDisplayNameButton.setOnClickListener {
            val newDisplayName = displayNameInput.text.toString().trim()

            if (newDisplayName.isEmpty()) {
                ToastUtils.showCustomToast(this, "Enter a display name")
                return@setOnClickListener
            }

            saveDisplayName(newDisplayName, name)
        }

        // Delete contact button
        deleteContactButton.setOnClickListener {
            showDeleteConfirmationDialog(name)
        }
    }

    private fun saveDisplayName(newDisplayName: String, oldName: String) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Updating display name for contact ID: $contactId to: $newDisplayName")

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                // Update the contact display name in the database
                withContext(Dispatchers.IO) {
                    database.contactDao().updateContactDisplayName(contactId, newDisplayName)
                }

                Log.i(TAG, "Display name updated successfully")

                // Update the UI
                contactName.text = newDisplayName
                displayNameInput.text.clear()
                displayNameInput.hint = "Enter new display name for $newDisplayName"

                ToastUtils.showCustomToast(this@ContactOptionsActivity, "Name updated")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to update display name", e)
                ToastUtils.showCustomToast(this@ContactOptionsActivity, "Failed to update name")
            }
        }
    }

    private fun showDeleteConfirmationDialog(name: String) {
        AlertDialog.Builder(this, R.style.CustomAlertDialog)
            .setTitle("Delete Contact")
            .setMessage("Are you sure you want to delete $name from your contacts? This action cannot be undone.")
            .setPositiveButton("Delete") { _, _ ->
                deleteContact()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun deleteContact() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Deleting contact with address: $fullAddress")

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                // Find and delete the contact by Solana address
                val contact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactBySolanaAddress(fullAddress)
                }

                if (contact != null) {
                    withContext(Dispatchers.IO) {
                        // Delete all messages for this contact
                        database.messageDao().deleteMessagesForContact(contact.id)

                        // Delete the contact
                        database.contactDao().deleteContact(contact)

                        // Clear any pending Pings for this contact (breaks Ping-Pong as per user requirement)
                        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                        prefs.edit().apply {
                            remove("ping_${contact.id}_id")
                            remove("ping_${contact.id}_connection")
                            remove("ping_${contact.id}_name")
                            apply()
                        }

                        Log.i(TAG, "Contact deleted successfully: ${contact.displayName}")
                        Log.i(TAG, "Pending Ping cleared for contact ${contact.id} (if any)")
                    }

                    ToastUtils.showCustomToast(this@ContactOptionsActivity, "Contact deleted")

                    // Navigate back to MainActivity
                    val intent = Intent(this@ContactOptionsActivity, MainActivity::class.java)
                    startActivity(intent)
                    finish()
                } else {
                    Log.w(TAG, "Contact not found in database")
                    ToastUtils.showCustomToast(this@ContactOptionsActivity, "Contact not found")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete contact", e)
                ToastUtils.showCustomToast(this@ContactOptionsActivity, "Failed to delete contact")
            }
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
