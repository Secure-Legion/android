package com.securelegion

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact as DbContact
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ComposeActivity : BaseActivity() {

    companion object {
        private const val TAG = "ComposeActivity"
    }

    private lateinit var searchInput: EditText
    private lateinit var contactsList: RecyclerView
    private lateinit var emptyState: View
    private lateinit var contactsAdapter: ComposeContactsAdapter

    private var allContacts: List<DbContact> = emptyList()
    private var filteredContacts: List<DbContact> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_compose)

        searchInput = findViewById(R.id.searchInput)
        contactsList = findViewById(R.id.contactsList)
        emptyState = findViewById(R.id.emptyState)

        setupContactsList()
        setupClickListeners()
        loadContacts()
    }

    private fun setupContactsList() {
        contactsAdapter = ComposeContactsAdapter { contact ->
            // Contact clicked - open chat
            openChat(contact)
        }
        contactsList.layoutManager = LinearLayoutManager(this)
        contactsList.adapter = contactsAdapter

        // Setup search
        searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}

            override fun afterTextChanged(s: Editable?) {
                val query = s?.toString() ?: ""
                filterContacts(query)
            }
        })
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(android.app.Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        // Settings button
        findViewById<View>(R.id.settingsButton).setOnClickListener {
            val intent = Intent(this, SettingsActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(android.app.Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        // Handle system bar insets for bottom nav
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val bottomNav = findViewById<View>(R.id.bottomNav)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { _, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            bottomNav.setPadding(bottomNav.paddingLeft, bottomNav.paddingTop, bottomNav.paddingRight, insets.bottom)
            windowInsets
        }

        // Bottom navigation
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
        }

        findViewById<View>(R.id.navPhone).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_PHONE", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }
    }

    private fun loadContacts() {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@ComposeActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ComposeActivity, dbPassphrase)

                allContacts = withContext(Dispatchers.IO) {
                    // Only load CONFIRMED friends (not PENDING)
                    database.contactDao().getAllContacts()
                        .filter { it.friendshipStatus == DbContact.FRIENDSHIP_CONFIRMED }
                        .sortedBy { it.displayName.lowercase() }
                }

                filteredContacts = allContacts
                updateUI()

                Log.d(TAG, "Loaded ${allContacts.size} contacts")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contacts", e)
            }
        }
    }

    private fun filterContacts(query: String) {
        filteredContacts = if (query.isBlank()) {
            allContacts
        } else {
            allContacts.filter {
                it.displayName.contains(query, ignoreCase = true)
            }
        }
        updateUI()
    }

    private fun updateUI() {
        if (filteredContacts.isEmpty()) {
            contactsList.visibility = View.GONE
            emptyState.visibility = View.VISIBLE
        } else {
            contactsList.visibility = View.VISIBLE
            emptyState.visibility = View.GONE
            contactsAdapter.submitList(filteredContacts)
        }
    }

    private fun openChat(contact: DbContact) {
        val intent = Intent(this, ChatActivity::class.java)
        intent.putExtra(ChatActivity.EXTRA_CONTACT_ID, contact.id)
        intent.putExtra(ChatActivity.EXTRA_CONTACT_NAME, contact.displayName)
        intent.putExtra(ChatActivity.EXTRA_CONTACT_ADDRESS, contact.solanaAddress)
        startActivity(intent)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            overrideActivityTransition(android.app.Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
        } else {
            @Suppress("DEPRECATION")
            overridePendingTransition(0, 0)
        }
    }

    // RecyclerView Adapter
    private class ComposeContactsAdapter(
        private val onContactClick: (DbContact) -> Unit
    ) : RecyclerView.Adapter<ComposeContactsAdapter.ContactViewHolder>() {

        private var contacts = listOf<DbContact>()

        fun submitList(newContacts: List<DbContact>) {
            contacts = newContacts
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ContactViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_compose_contact, parent, false)
            return ContactViewHolder(view, onContactClick)
        }

        override fun onBindViewHolder(holder: ContactViewHolder, position: Int) {
            holder.bind(contacts[position])
        }

        override fun getItemCount() = contacts.size

        class ContactViewHolder(
            itemView: View,
            private val onContactClick: (DbContact) -> Unit
        ) : RecyclerView.ViewHolder(itemView) {

            private val contactName: TextView = itemView.findViewById(R.id.contactName)
            private val onlineIndicator: View = itemView.findViewById(R.id.onlineIndicator)

            fun bind(contact: DbContact) {
                contactName.text = contact.displayName

                // Show online indicator (placeholder - can be implemented later)
                onlineIndicator.visibility = View.GONE

                itemView.setOnClickListener {
                    onContactClick(contact)
                }
            }
        }
    }
}
