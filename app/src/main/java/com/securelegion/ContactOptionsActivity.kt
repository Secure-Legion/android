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
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ContactOptionsActivity : BaseActivity() {

    companion object {
        private const val TAG = "ContactOptions"
    }

    private lateinit var contactName: TextView
    private lateinit var contactAddress: TextView
    private lateinit var displayNameInput: EditText
    private lateinit var saveDisplayNameButton: TextView
    private lateinit var blockContactButton: TextView
    private lateinit var deleteContactButton: TextView
    private lateinit var distressStarIcon: ImageView
    private var fullAddress: String = ""
    private var contactId: Long = -1
    private var isDistressContact: Boolean = false
    private var isBlocked: Boolean = false

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
        loadContactStatus()
        setupClickListeners(name)
        setupBottomNav()
    }

    private fun initializeViews() {
        contactName = findViewById(R.id.contactName)
        contactAddress = findViewById(R.id.contactAddress)
        displayNameInput = findViewById(R.id.displayNameInput)
        saveDisplayNameButton = findViewById(R.id.saveDisplayNameButton)
        blockContactButton = findViewById(R.id.blockContactButton)
        deleteContactButton = findViewById(R.id.deleteContactButton)
        distressStarIcon = findViewById(R.id.distressStarIcon)
    }

    private fun setupContactInfo(name: String, address: String) {
        contactName.text = name
        contactAddress.text = address
        displayNameInput.hint = "Enter new display name for $name"
    }

    private fun loadContactStatus() {
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
                    isBlocked = contact.isBlocked
                    updateStarIcon()
                    updateBlockButton()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contact status", e)
            }
        }
    }

    private fun updateBlockButton() {
        if (isBlocked) {
            blockContactButton.text = "Unblock Contact"
        } else {
            blockContactButton.text = "Block Contact"
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
                    ThemedToast.show(this@ContactOptionsActivity, "Error: Invalid contact")
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

                Log.i(TAG, "Distress status updated: $isDistressContact")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to toggle distress status", e)
                ThemedToast.show(this@ContactOptionsActivity, "Failed to update status")
            }
        }
    }

    private fun toggleBlockStatus() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) {
                    ThemedToast.show(this@ContactOptionsActivity, "Error: Invalid contact")
                    return@launch
                }

                // Toggle the status
                isBlocked = !isBlocked

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                // Update in database
                withContext(Dispatchers.IO) {
                    database.contactDao().updateBlockedStatus(contactId, isBlocked)
                }

                // Update UI
                updateBlockButton()

                val message = if (isBlocked) {
                    "Contact blocked"
                } else {
                    "Contact unblocked"
                }
                ThemedToast.show(this@ContactOptionsActivity, message)

                Log.i(TAG, "Blocked status updated: $isBlocked")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to toggle blocked status", e)
                ThemedToast.show(this@ContactOptionsActivity, "Failed to update status")
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
        contactAddress.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", fullAddress)
            clipboard.setPrimaryClip(clip)
            ThemedToast.show(this, "Address copied")
        }

        // Save display name button
        saveDisplayNameButton.setOnClickListener {
            val newDisplayName = displayNameInput.text.toString().trim()

            if (newDisplayName.isEmpty()) {
                ThemedToast.show(this, "Enter a display name")
                return@setOnClickListener
            }

            saveDisplayName(newDisplayName, name)
        }

        // Block contact button
        blockContactButton.setOnClickListener {
            toggleBlockStatus()
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

                ThemedToast.show(this@ContactOptionsActivity, "Name updated")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to update display name", e)
                ThemedToast.show(this@ContactOptionsActivity, "Failed to update name")
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
                Log.d(TAG, "Deleting contact ID: $contactId")

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                // Get contact by ID
                val contact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactById(contactId)
                }

                if (contact != null) {
                    withContext(Dispatchers.IO) {
                        // Get all messages for this contact to check for voice files
                        val messages = database.messageDao().getMessagesForContact(contact.id)

                        // Securely wipe any voice message audio files using DOD 3-pass
                        messages.forEach { message ->
                            if (message.messageType == com.securelegion.database.entities.Message.MESSAGE_TYPE_VOICE &&
                                message.voiceFilePath != null) {
                                try {
                                    val voiceFile = java.io.File(message.voiceFilePath)
                                    if (voiceFile.exists()) {
                                        com.securelegion.utils.SecureWipe.secureDeleteFile(voiceFile)
                                        Log.d(TAG, "✓ Securely wiped voice file: ${voiceFile.name}")
                                    }
                                } catch (e: Exception) {
                                    Log.e(TAG, "Failed to securely wipe voice file", e)
                                }
                            }
                        }

                        // Delete all messages for this contact
                        database.messageDao().deleteMessagesForContact(contact.id)

                        // Delete the contact
                        database.contactDao().deleteContact(contact)

                        // VACUUM database to compact and remove deleted records
                        try {
                            database.openHelper.writableDatabase.execSQL("VACUUM")
                            Log.d(TAG, "✓ Database vacuumed after contact deletion")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to vacuum database", e)
                        }

                        // Clear any pending Pings for this contact (breaks Ping-Pong as per user requirement)
                        val prefs = getSharedPreferences("pending_pings", MODE_PRIVATE)
                        prefs.edit().apply {
                            remove("ping_${contact.id}_id")
                            remove("ping_${contact.id}_connection")
                            remove("ping_${contact.id}_name")
                            apply()
                        }

                        Log.i(TAG, "Contact and all messages securely deleted (DOD 3-pass): ${contact.displayName}")
                        Log.i(TAG, "Pending Ping cleared for contact ${contact.id} (if any)")
                    }

                    ThemedToast.show(this@ContactOptionsActivity, "Contact deleted")

                    // Navigate back to MainActivity
                    val intent = Intent(this@ContactOptionsActivity, MainActivity::class.java)
                    startActivity(intent)
                    finish()
                } else {
                    Log.w(TAG, "Contact not found in database")
                    ThemedToast.show(this@ContactOptionsActivity, "Contact not found")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete contact", e)
                ThemedToast.show(this@ContactOptionsActivity, "Failed to delete contact")
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
