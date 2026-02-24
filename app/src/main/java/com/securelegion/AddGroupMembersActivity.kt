package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.services.CrdtGroupManager
import com.securelegion.ui.adapters.AddToGroupAdapter
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Full-screen activity for selecting contacts to add to a group.
 * Looks like the contacts page with an add-to-group icon per row.
 */
class AddGroupMembersActivity : BaseActivity() {

    companion object {
        private const val TAG = "AddGroupMembers"

        /** Pass a group ID to exclude contacts already in that group */
        const val EXTRA_GROUP_ID = "group_id"

        /** Pass a comma-separated list of contact IDs to pre-select */
        const val EXTRA_PRESELECTED_IDS = "preselected_ids"

        /** Result: comma-separated selected contact IDs */
        const val RESULT_SELECTED_IDS = "selected_ids"
    }

    private lateinit var contactsList: RecyclerView
    private lateinit var searchBar: EditText
    private lateinit var emptyState: LinearLayout
    private lateinit var adapter: AddToGroupAdapter

    private var allContacts = listOf<Contact>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_group_members)

        setupWindowInsets()
        initializeViews()
        setupSearch()
        loadContacts()
    }

    private fun setupWindowInsets() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val topBar = findViewById<View>(R.id.topBar)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { _, windowInsets ->
            val insets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            topBar.setPadding(topBar.paddingLeft, insets.top, topBar.paddingRight, topBar.paddingBottom)
            windowInsets
        }
    }

    private fun initializeViews() {
        contactsList = findViewById(R.id.contactsList)
        searchBar = findViewById(R.id.searchBar)
        emptyState = findViewById(R.id.emptyState)

        // Pre-selected IDs from intent
        val preselectedStr = intent.getStringExtra(EXTRA_PRESELECTED_IDS) ?: ""
        val preselectedIds = preselectedStr.split(",")
            .filter { it.isNotBlank() }
            .mapNotNull { it.trim().toLongOrNull() }
            .toMutableSet()

        adapter = AddToGroupAdapter(preselectedIds)
        contactsList.layoutManager = LinearLayoutManager(this)
        contactsList.adapter = adapter

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finishWithSelection()
        }

        // Done button
        findViewById<TextView>(R.id.doneButton).setOnClickListener {
            finishWithSelection()
        }
    }

    private fun finishWithSelection() {
        val selectedContacts = adapter.getSelectedContacts()
        val resultIds = selectedContacts.joinToString(",") { it.id.toString() }
        val resultIntent = Intent().apply {
            putExtra(RESULT_SELECTED_IDS, resultIds)
        }
        setResult(RESULT_OK, resultIntent)
        finish()
    }

    @Deprecated("Use onBackPressedDispatcher")
    override fun onBackPressed() {
        finishWithSelection()
    }

    private fun setupSearch() {
        searchBar.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                filterContacts(s.toString())
            }
        })
    }

    private fun filterContacts(query: String) {
        val filtered = if (query.isEmpty()) {
            allContacts
        } else {
            allContacts.filter {
                it.displayName.contains(query, ignoreCase = true)
            }
        }
        adapter.submitList(filtered)
        emptyState.visibility = if (filtered.isEmpty()) View.VISIBLE else View.GONE
        contactsList.visibility = if (filtered.isEmpty()) View.GONE else View.VISIBLE
    }

    private fun loadContacts() {
        val groupId = intent.getStringExtra(EXTRA_GROUP_ID)

        lifecycleScope.launch {
            try {
                val contacts = withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@AddGroupMembersActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@AddGroupMembersActivity, dbPassphrase)
                    val allDbContacts = database.contactDao().getAllContacts()

                    // If a group ID was provided, filter out contacts already in the group
                    if (!groupId.isNullOrEmpty()) {
                        val mgr = CrdtGroupManager.getInstance(this@AddGroupMembersActivity)
                        val memberPubkeys = mgr.queryMembers(groupId)
                            .filter { !it.removed }
                            .map { it.pubkeyHex }
                            .toSet()

                        allDbContacts.filter { contact ->
                            val pubkeyHex = contact.ed25519PublicKeyBytes
                                .joinToString("") { "%02x".format(it) }
                            pubkeyHex !in memberPubkeys
                        }
                    } else {
                        allDbContacts
                    }
                }

                withContext(Dispatchers.Main) {
                    allContacts = contacts.sortedBy { it.displayName.uppercase() }
                    adapter.submitList(allContacts)

                    if (allContacts.isEmpty()) {
                        emptyState.visibility = View.VISIBLE
                        contactsList.visibility = View.GONE
                        val msg = if (!groupId.isNullOrEmpty()) {
                            "All contacts are already members"
                        } else {
                            "No contacts available"
                        }
                        findViewById<TextView>(R.id.emptyMessage).text = msg
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contacts", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@AddGroupMembersActivity, "Failed to load contacts")
                }
            }
        }
    }
}
