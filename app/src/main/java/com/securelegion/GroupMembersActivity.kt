package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.ContactAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.models.Contact
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class GroupMembersActivity : BaseActivity() {

    companion object {
        private const val TAG = "GroupMembers"
        const val EXTRA_GROUP_ID = "group_id"
        const val EXTRA_GROUP_NAME = "group_name"
    }

    // Views
    private lateinit var backButton: View
    private lateinit var settingsIcon: FrameLayout
    private lateinit var searchBar: EditText
    private lateinit var addMemberBtn: View
    private lateinit var membersList: RecyclerView
    private lateinit var alphabetIndex: View

    // Data
    private var groupId: String? = null
    private var groupName: String = "Group"
    private lateinit var contactAdapter: ContactAdapter
    private var allMembers = listOf<Contact>()
    private var filteredMembers = listOf<Contact>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_group_members)

        // Get group data from intent
        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        groupName = intent.getStringExtra(EXTRA_GROUP_NAME) ?: "Group"

        initializeViews()
        setupClickListeners()
        setupRecyclerView()
        setupAlphabetIndex()
        loadGroupMembers()
        setupBottomNav()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        settingsIcon = findViewById(R.id.settingsIcon)
        searchBar = findViewById(R.id.searchBar)
        addMemberBtn = findViewById(R.id.addMemberBtn)
        membersList = findViewById(R.id.membersList)
        alphabetIndex = findViewById(R.id.alphabetIndex)
    }

    private fun setupClickListeners() {
        // Back button
        backButton.setOnClickListener {
            finish()
        }

        // Settings icon
        settingsIcon.setOnClickListener {
            ThemedToast.show(this, "Group settings - Coming soon")
        }

        // Add member button
        addMemberBtn.setOnClickListener {
            showAddMemberDialog()
        }

        // Search functionality
        searchBar.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                filterMembers(s.toString())
            }
        })
    }

    private fun setupRecyclerView() {
        contactAdapter = ContactAdapter(
            contacts = mutableListOf(),
            onContactClick = { contact ->
                // Open member profile or options
                ThemedToast.show(this, "Member: ${contact.name}")
                Log.i(TAG, "Clicked member: ${contact.name}")
            }
        )

        membersList.apply {
            layoutManager = LinearLayoutManager(this@GroupMembersActivity)
            adapter = contactAdapter
        }
    }

    private fun setupAlphabetIndex() {
        val letters = listOf(
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
            "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"
        )

        letters.forEach { letter ->
            val letterId = resources.getIdentifier("index$letter", "id", packageName)
            if (letterId != 0) {
                findViewById<TextView>(letterId)?.setOnClickListener {
                    scrollToLetter(letter)
                }
            }
        }
    }

    private fun scrollToLetter(letter: String) {
        val position = filteredMembers.indexOfFirst {
            it.name.uppercase().startsWith(letter)
        }

        if (position != -1) {
            membersList.smoothScrollToPosition(position)
            Log.i(TAG, "Scrolling to letter $letter at position $position")
        } else {
            Log.i(TAG, "No members found starting with letter $letter")
        }
    }

    private fun loadGroupMembers() {
        val currentGroupId = groupId
        if (currentGroupId == null) {
            Log.e(TAG, "Group ID is null, cannot load members")
            return
        }

        lifecycleScope.launch {
            try {
                val members = withContext(Dispatchers.IO) {
                    // Load actual group members from database
                    val keyManager = KeyManager.getInstance(this@GroupMembersActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupMembersActivity, dbPassphrase)

                    // Get contacts who are members of this group
                    val dbContacts = database.groupMemberDao().getContactsForGroup(currentGroupId)

                    // Convert database entities to models
                    dbContacts.map { dbContact ->
                        Contact(
                            id = dbContact.id.toString(),
                            name = dbContact.displayName,
                            address = dbContact.solanaAddress,
                            friendshipStatus = dbContact.friendshipStatus
                        )
                    }
                }

                allMembers = members.sortedBy { it.name.uppercase() }
                filteredMembers = allMembers
                contactAdapter.updateContacts(filteredMembers)

                Log.i(TAG, "Loaded ${allMembers.size} members for group: $groupName")

                if (allMembers.isEmpty()) {
                    ThemedToast.show(this@GroupMembersActivity, "No members yet")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to load group members", e)
                ThemedToast.show(this@GroupMembersActivity, "Failed to load members")
            }
        }
    }

    private fun filterMembers(query: String) {
        filteredMembers = if (query.isEmpty()) {
            allMembers
        } else {
            allMembers.filter {
                it.name.contains(query, ignoreCase = true)
            }
        }

        contactAdapter.updateContacts(filteredMembers)
        Log.d(TAG, "Filtered to ${filteredMembers.size} members")
    }

    private fun showAddMemberDialog() {
        val currentGroupId = groupId
        if (currentGroupId == null) {
            ThemedToast.show(this, "Invalid group")
            return
        }

        lifecycleScope.launch {
            try {
                // Get all contacts who are NOT in this group
                val availableContacts = withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@GroupMembersActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupMembersActivity, dbPassphrase)

                    // Get all contacts
                    val allContacts = database.contactDao().getAllContacts()

                    // Get current group members
                    val currentMemberIds = database.groupMemberDao().getMembersForGroup(currentGroupId)
                        .map { it.contactId }

                    // Filter out contacts already in the group
                    allContacts.filter { it.id !in currentMemberIds }
                }

                withContext(Dispatchers.Main) {
                    if (availableContacts.isEmpty()) {
                        ThemedToast.show(this@GroupMembersActivity, "All contacts are already members")
                        return@withContext
                    }

                    // Show contact selection dialog
                    val contactNames = availableContacts.map { it.displayName }.toTypedArray()
                    val selectedContacts = mutableListOf<com.securelegion.database.entities.Contact>()

                    AlertDialog.Builder(this@GroupMembersActivity)
                        .setTitle("Add Members to Group")
                        .setMultiChoiceItems(contactNames, null) { _, which, isChecked ->
                            if (isChecked) {
                                selectedContacts.add(availableContacts[which])
                            } else {
                                selectedContacts.remove(availableContacts[which])
                            }
                        }
                        .setPositiveButton("Add") { dialog, _ ->
                            if (selectedContacts.isEmpty()) {
                                ThemedToast.show(this@GroupMembersActivity, "No contacts selected")
                            } else {
                                addMembersToGroup(currentGroupId, selectedContacts)
                            }
                            dialog.dismiss()
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to load available contacts", e)
                ThemedToast.show(this@GroupMembersActivity, "Failed to load contacts")
            }
        }
    }

    private fun addMembersToGroup(
        groupId: String,
        contacts: List<com.securelegion.database.entities.Contact>
    ) {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@GroupMembersActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupMembersActivity, dbPassphrase)

                    // Add members to group
                    val timestamp = System.currentTimeMillis()
                    val groupMembers = contacts.map { contact ->
                        com.securelegion.database.entities.GroupMember(
                            groupId = groupId,
                            contactId = contact.id,
                            isAdmin = false,
                            addedAt = timestamp
                        )
                    }

                    database.groupMemberDao().insertGroupMembers(groupMembers)

                    // TODO: Send encrypted group key to new members via Tor
                    // For now, just log
                    Log.i(TAG, "Added ${contacts.size} members to group")
                }

                withContext(Dispatchers.Main) {
                    val memberNames = contacts.joinToString(", ") { it.displayName }
                    ThemedToast.show(this@GroupMembersActivity, "Added: $memberNames")

                    // Reload member list
                    loadGroupMembers()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to add members", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupMembersActivity, "Failed to add members: ${e.message}")
                }
            }
        }
    }


    private fun setupBottomNav() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val bottomNav = findViewById<View>(R.id.bottomNav)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { _, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            bottomNav?.setPadding(bottomNav.paddingLeft, bottomNav.paddingTop, bottomNav.paddingRight, 0)
            windowInsets
        }

        BottomNavigationHelper.setupBottomNavigation(this)
    }

    private fun startActivityWithSlideAnimation(intent: Intent) {
        startActivity(intent)
        overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left)
    }

    private fun lockApp() {
        val intent = Intent(this, LockActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
}
