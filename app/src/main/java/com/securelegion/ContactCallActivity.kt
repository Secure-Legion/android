package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.CallHistoryAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.CallHistory
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ContactCallActivity : BaseActivity() {

    companion object {
        private const val TAG = "ContactCallActivity"
        const val EXTRA_CONTACT_ID = "CONTACT_ID"
        const val EXTRA_CONTACT_NAME = "CONTACT_NAME"
        const val EXTRA_CONTACT_ADDRESS = "CONTACT_ADDRESS"
    }

    private var contactId: Long = -1
    private var contactName: String = ""
    private var contactAddress: String = ""
    private lateinit var historyAdapter: CallHistoryAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_contact_call)

        contactId = intent.getLongExtra(EXTRA_CONTACT_ID, -1)
        contactName = intent.getStringExtra(EXTRA_CONTACT_NAME) ?: ""
        contactAddress = intent.getStringExtra(EXTRA_CONTACT_ADDRESS) ?: ""

        // Set contact name
        findViewById<TextView>(R.id.contactName).text = contactName

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Call history button — opens full call history
        findViewById<View>(R.id.callHistoryButton).setOnClickListener {
            startActivity(Intent(this, CallHistoryActivity::class.java))
        }

        // Setup bottom nav
        setupBottomNav()

        // Call button — starts the actual call
        findViewById<View>(R.id.actionCall).setOnClickListener {
            startCall()
        }

        // Message button — opens chat
        findViewById<View>(R.id.actionMessage).setOnClickListener {
            val intent = Intent(this, ChatActivity::class.java).apply {
                putExtra(ChatActivity.EXTRA_CONTACT_ID, contactId)
                putExtra(ChatActivity.EXTRA_CONTACT_NAME, contactName)
                putExtra(ChatActivity.EXTRA_CONTACT_ADDRESS, contactAddress)
            }
            startActivity(intent)
        }

        // Setup call history list
        historyAdapter = CallHistoryAdapter(
            callHistory = emptyList(),
            onReCallClick = { startCall() },
            onItemClick = { /* no-op, already on this contact */ }
        )
        val recyclerView = findViewById<RecyclerView>(R.id.historyRecyclerView)
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = historyAdapter

        // Load contact info + call history
        loadContactData()
    }

    override fun onResume() {
        super.onResume()
        // Refresh call history when coming back from a call
        loadContactData()
    }

    private fun loadContactData() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val keyManager = KeyManager.getInstance(this@ContactCallActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactCallActivity, dbPassphrase)

                val contact = database.contactDao().getContactById(contactId)
                val history = database.callHistoryDao().getCallHistoryForContactList(contactId)

                withContext(Dispatchers.Main) {
                    // Load profile photo
                    if (contact != null && !contact.profilePictureBase64.isNullOrEmpty()) {
                        try {
                            val photoBytes = android.util.Base64.decode(contact.profilePictureBase64, android.util.Base64.NO_WRAP)
                            val bitmap = android.graphics.BitmapFactory.decodeByteArray(photoBytes, 0, photoBytes.size)
                            if (bitmap != null) {
                                findViewById<ImageView>(R.id.profilePicture).setImageBitmap(bitmap)
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to decode profile photo", e)
                        }
                    }

                    // Update call history
                    val emptyState = findViewById<TextView>(R.id.emptyStateText)
                    val recyclerView = findViewById<RecyclerView>(R.id.historyRecyclerView)

                    if (history.isEmpty()) {
                        emptyState.visibility = View.VISIBLE
                        recyclerView.visibility = View.GONE
                    } else {
                        emptyState.visibility = View.GONE
                        recyclerView.visibility = View.VISIBLE
                        historyAdapter.updateHistory(history)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contact data", e)
            }
        }
    }

    private fun setupBottomNav() {
        BottomNavigationHelper.setupBottomNavigation(this)
    }

    private fun startCall() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val keyManager = KeyManager.getInstance(this@ContactCallActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactCallActivity, dbPassphrase)
                val contact = database.contactDao().getContactById(contactId)

                withContext(Dispatchers.Main) {
                    if (contact == null) {
                        ThemedToast.show(this@ContactCallActivity, "Contact not found")
                        return@withContext
                    }

                    if (contact.voiceOnion.isNullOrEmpty()) {
                        ThemedToast.show(this@ContactCallActivity, "${contact.displayName} doesn't have a voice address")
                        return@withContext
                    }

                    val intent = Intent(this@ContactCallActivity, VoiceCallActivity::class.java).apply {
                        putExtra("CONTACT_ID", contact.id)
                        putExtra("CONTACT_NAME", contact.displayName)
                        putExtra("VOICE_ONION", contact.voiceOnion)
                        putExtra("IS_OUTGOING", true)
                    }
                    startActivity(intent)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start call", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@ContactCallActivity, "Failed to start call")
                }
            }
        }
    }
}
