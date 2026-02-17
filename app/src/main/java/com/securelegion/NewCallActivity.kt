package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.CallableContact
import com.securelegion.adapters.NewCallContactsAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class NewCallActivity : BaseActivity() {

    companion object {
        private const val TAG = "NewCallActivity"
    }

    private lateinit var contactsRecyclerView: RecyclerView
    private lateinit var searchInput: EditText
    private lateinit var emptyStateText: TextView
    private lateinit var contactsAdapter: NewCallContactsAdapter

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_new_call)

        // Initialize views
        contactsRecyclerView = findViewById(R.id.contactsRecyclerView)
        searchInput = findViewById(R.id.searchInput)
        emptyStateText = findViewById(R.id.emptyStateText)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // History button
        findViewById<View>(R.id.historyButton).setOnClickListener {
            val intent = Intent(this, CallHistoryActivity::class.java)
            startActivity(intent)
        }

        // Setup RecyclerView
        contactsAdapter = NewCallContactsAdapter(
            contacts = emptyList(),
            onCallClick = { contact ->
                initiateCall(contact)
            }
        )
        contactsRecyclerView.layoutManager = LinearLayoutManager(this)
        contactsRecyclerView.adapter = contactsAdapter

        // Setup search
        searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                contactsAdapter.filter(s?.toString() ?: "")
            }
        })

        // Load contacts
        loadContacts()

        // Setup bottom navigation
        setupBottomNavigation()
    }

    private fun setupBottomNavigation() {
        BottomNavigationHelper.setupBottomNavigation(this)
    }

    private fun loadContacts() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val keyManager = KeyManager.getInstance(this@NewCallActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@NewCallActivity, dbPassphrase)

                // Get all contacts
                val contacts = database.contactDao().getAllContacts()

                // For each contact, get their last call
                val callableContacts = contacts.map { contact ->
                    val lastCall = database.callHistoryDao().getLastCallForContact(contact.id)
                    CallableContact(
                        contactId = contact.id,
                        contactName = contact.displayName,
                        voiceOnion = contact.voiceOnion ?: "",
                        lastCall = lastCall
                    )
                }

                // Sort: Missed calls first, then recent calls, then alphabetical
                val sortedContacts = callableContacts.sortedWith(
                    compareByDescending<CallableContact> { it.lastCall?.type == com.securelegion.database.entities.CallType.MISSED }
                        .thenByDescending { it.lastCall?.timestamp ?: 0 }
                        .thenBy { it.contactName }
                )

                withContext(Dispatchers.Main) {
                    if (sortedContacts.isEmpty()) {
                        emptyStateText.visibility = View.VISIBLE
                        contactsRecyclerView.visibility = View.GONE
                    } else {
                        emptyStateText.visibility = View.GONE
                        contactsRecyclerView.visibility = View.VISIBLE
                        contactsAdapter.updateContacts(sortedContacts)
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error loading contacts", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@NewCallActivity, "Error loading contacts")
                }
            }
        }
    }

    private fun initiateCall(contact: CallableContact) {
        if (contact.voiceOnion.isEmpty()) {
            ThemedToast.show(this, "${contact.contactName} doesn't have a voice .onion address")
            return
        }

        // Launch VoiceCallActivity
        val intent = Intent(this, VoiceCallActivity::class.java).apply {
            putExtra("CONTACT_ID", contact.contactId)
            putExtra("CONTACT_NAME", contact.contactName)
            putExtra("VOICE_ONION", contact.voiceOnion)
            putExtra("IS_OUTGOING", true)
        }
        startActivity(intent)
    }
}
