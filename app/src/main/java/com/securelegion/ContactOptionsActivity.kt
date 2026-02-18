package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.GlassBottomSheetDialog
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
    private lateinit var profilePicture: ImageView
    private lateinit var blockContactSwitch: androidx.appcompat.widget.SwitchCompat
    private lateinit var trustedContactSwitch: androidx.appcompat.widget.SwitchCompat
    private lateinit var trustedContactIcon: ImageView
    private var fullAddress: String = ""
    private var contactId: Long = -1
    private var isTrustedContact: Boolean = false
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
        setupContactInfo(name)
        loadContactStatus()
        setupClickListeners(name)
        setupBottomNav()
    }

    private fun initializeViews() {
        contactName = findViewById(R.id.contactName)
        profilePicture = findViewById(R.id.profilePicture)
        blockContactSwitch = findViewById(R.id.blockContactSwitch)
        trustedContactSwitch = findViewById(R.id.trustedContactSwitch)
        trustedContactIcon = findViewById(R.id.trustedContactIcon)
    }

    private fun setupContactInfo(name: String) {
        contactName.text = name
    }

    private fun loadContactStatus() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) return@launch

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                val contact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactById(contactId)
                }

                if (contact != null) {
                    isTrustedContact = contact.isDistressContact
                    isBlocked = contact.isBlocked
                    updateTrustedContactUI()
                    updateBlockUI()

                    // Load contact's profile photo
                    if (!contact.profilePictureBase64.isNullOrEmpty()) {
                        try {
                            val photoBytes = android.util.Base64.decode(contact.profilePictureBase64, android.util.Base64.NO_WRAP)
                            val bitmap = android.graphics.BitmapFactory.decodeByteArray(photoBytes, 0, photoBytes.size)
                            if (bitmap != null) {
                                profilePicture.setImageBitmap(bitmap)
                                Log.d(TAG, "Loaded contact profile photo (${photoBytes.size} bytes)")
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to decode contact profile photo", e)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contact status", e)
            }
        }
    }

    private fun updateBlockUI() {
        blockContactSwitch.isChecked = isBlocked
    }

    private fun updateTrustedContactUI() {
        trustedContactSwitch.isChecked = isTrustedContact
        if (isTrustedContact) {
            trustedContactIcon.setImageResource(R.drawable.ic_star_filled)
        } else {
            trustedContactIcon.setImageResource(R.drawable.ic_star_outline)
        }
    }

    private fun toggleTrustedContactStatus() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) {
                    ThemedToast.show(this@ContactOptionsActivity, "Error: Invalid contact")
                    return@launch
                }

                isTrustedContact = !isTrustedContact

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                withContext(Dispatchers.IO) {
                    database.contactDao().updateDistressContactStatus(contactId, isTrustedContact)
                }

                updateTrustedContactUI()

                val message = if (isTrustedContact) "Trusted contact enabled" else "Trusted contact disabled"
                ThemedToast.show(this@ContactOptionsActivity, message)
                Log.i(TAG, "Trusted contact status updated: $isTrustedContact")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to toggle trusted contact status", e)
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

                isBlocked = !isBlocked

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                withContext(Dispatchers.IO) {
                    database.contactDao().updateBlockedStatus(contactId, isBlocked)
                }

                updateBlockUI()

                val message = if (isBlocked) "Contact blocked" else "Contact unblocked"
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

        // Call action
        findViewById<View>(R.id.actionCall).setOnClickListener {
            val intent = Intent(this, VoiceCallActivity::class.java)
            intent.putExtra("CONTACT_ID", contactId)
            intent.putExtra("CONTACT_NAME", name)
            intent.putExtra("CONTACT_ADDRESS", fullAddress)
            intent.putExtra("IS_OUTGOING", true)
            startActivity(intent)
        }

        // Message action
        findViewById<View>(R.id.actionMessage).setOnClickListener {
            val intent = Intent(this, ChatActivity::class.java)
            intent.putExtra(ChatActivity.EXTRA_CONTACT_ID, contactId)
            intent.putExtra(ChatActivity.EXTRA_CONTACT_NAME, name)
            intent.putExtra(ChatActivity.EXTRA_CONTACT_ADDRESS, fullAddress)
            startActivity(intent)
        }

        // Delete action
        findViewById<View>(R.id.actionDelete).setOnClickListener {
            showDeleteConfirmationDialog(name)
        }

        // Block contact switch
        blockContactSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked != isBlocked) {
                toggleBlockStatus()
            }
        }

        // Trusted contact switch
        trustedContactSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked != isTrustedContact) {
                toggleTrustedContactStatus()
            }
        }
    }

    private fun showDeleteConfirmationDialog(name: String) {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_delete_contact, null)
        bottomSheet.setContentView(view)

        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.skipCollapsed = true

        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        view.findViewById<TextView>(R.id.deleteMessage).text =
            "Are you sure you want to delete $name from your contacts? This action cannot be undone."

        view.findViewById<View>(R.id.confirmDeleteButton).setOnClickListener {
            bottomSheet.dismiss()
            deleteContact()
        }

        view.findViewById<View>(R.id.cancelDeleteButton).setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun deleteContact() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Deleting contact ID: $contactId")

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

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
                                        Log.d(TAG, "Securely wiped voice file: ${voiceFile.name}")
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
                            Log.d(TAG, "Database vacuumed after contact deletion")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to vacuum database", e)
                        }

                        // Unpin friend's contact list from IPFS mesh
                        if (contact.ipfsCid != null) {
                            try {
                                val ipfsManager = com.securelegion.services.IPFSManager.getInstance(this@ContactOptionsActivity)
                                val unpinResult = ipfsManager.unpinFriendContactList(contact.ipfsCid)
                                if (unpinResult.isSuccess) {
                                    Log.i(TAG, "Unpinned friend's contact list from IPFS mesh: ${contact.ipfsCid}")
                                } else {
                                    Log.w(TAG, "Failed to unpin friend's contact list: ${unpinResult.exceptionOrNull()?.message}")
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Non-critical error during unpinning", e)
                            }
                        }

                        // Backup our own contact list (now excludes this deleted contact)
                        try {
                            val contactListManager = com.securelegion.services.ContactListManager.getInstance(this@ContactOptionsActivity)
                            val backupResult = contactListManager.backupToIPFS()
                            if (backupResult.isSuccess) {
                                val ourCID = backupResult.getOrThrow()
                                Log.i(TAG, "Contact list backed up after deletion: $ourCID")
                            } else {
                                Log.w(TAG, "Failed to backup contact list: ${backupResult.exceptionOrNull()?.message}")
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "Non-critical error during contact list backup", e)
                        }

                        // Delete all ping_inbox entries for this contact
                        database.pingInboxDao().deleteByContact(contact.id)

                        Log.i(TAG, "Contact and all messages securely deleted (DOD 3-pass): ${contact.displayName}")
                    }

                    ThemedToast.show(this@ContactOptionsActivity, "Contact deleted")

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
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val bottomNav = findViewById<View>(R.id.bottomNav)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { _, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            bottomNav.setPadding(bottomNav.paddingLeft, bottomNav.paddingTop, bottomNav.paddingRight, 0)
            windowInsets
        }

        BottomNavigationHelper.setupBottomNavigation(this)
    }
}
