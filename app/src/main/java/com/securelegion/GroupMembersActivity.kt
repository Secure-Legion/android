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
import com.securelegion.adapters.GroupMemberAdapter
import com.securelegion.adapters.GroupMemberItem
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.services.CrdtGroupManager
import com.securelegion.ui.adapters.ContactSelectionAdapter
import com.securelegion.utils.GlassBottomSheetDialog
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
    private lateinit var memberAdapter: GroupMemberAdapter
    private var allMembers = listOf<GroupMemberItem>()
    private var filteredMembers = listOf<GroupMemberItem>()

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
        memberAdapter = GroupMemberAdapter(
            members = emptyList(),
            onMemberClick = { member ->
                ThemedToast.show(this, "${member.displayName} — ${member.role}")
            },
            onMuteClick = { member ->
                ThemedToast.show(this, "Muted ${member.displayName}")
                Log.i(TAG, "Mute: ${member.displayName}")
            },
            onRemoveClick = { member ->
                confirmRemoveMember(member)
            },
            onPromoteClick = { member ->
                confirmPromoteMember(member)
            }
        )

        membersList.apply {
            layoutManager = LinearLayoutManager(this@GroupMembersActivity)
            adapter = memberAdapter
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
            it.displayName.uppercase().startsWith(letter)
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
                    val mgr = CrdtGroupManager.getInstance(this@GroupMembersActivity)
                    val keyManager = KeyManager.getInstance(this@GroupMembersActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupMembersActivity, dbPassphrase)

                    val crdtMembers = mgr.queryMembers(currentGroupId)
                        .filter { !it.removed }

                    val localPubkeyHex = keyManager.getSigningPublicKey()
                        .joinToString("") { "%02x".format(it) }

                    crdtMembers.mapNotNull { member ->
                        val isMe = member.pubkeyHex == localPubkeyHex
                        val role = if (!member.accepted) "Pending" else member.role

                        if (isMe) {
                            return@mapNotNull GroupMemberItem(
                                pubkeyHex = member.pubkeyHex,
                                displayName = "You",
                                role = role,
                                isMe = true
                            )
                        }

                        val pubkeyBytes = member.pubkeyHex.chunked(2)
                            .map { it.toInt(16).toByte() }.toByteArray()
                        val pubkeyB64 = android.util.Base64.encodeToString(
                            pubkeyBytes, android.util.Base64.NO_WRAP
                        )
                        val dbContact = database.contactDao().getContactByPublicKey(pubkeyB64)
                        val displayName = dbContact?.displayName
                            ?: (member.deviceIdHex.take(16) + "...")
                        val photo = dbContact?.profilePictureBase64

                        GroupMemberItem(
                            pubkeyHex = member.pubkeyHex,
                            displayName = displayName,
                            role = role,
                            isMe = false,
                            profilePhotoBase64 = photo
                        )
                    }
                }

                allMembers = members.sortedWith(compareBy({ !it.isMe }, { it.displayName.uppercase() }))
                filteredMembers = allMembers
                memberAdapter.updateMembers(filteredMembers)

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
                it.displayName.contains(query, ignoreCase = true)
            }
        }

        memberAdapter.updateMembers(filteredMembers)
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
                val availableContacts = withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@GroupMembersActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupMembersActivity, dbPassphrase)
                    val mgr = CrdtGroupManager.getInstance(this@GroupMembersActivity)

                    // Get all contacts
                    val allContacts = database.contactDao().getAllContacts()

                    // Get current CRDT member pubkeys (hex)
                    val memberPubkeys = mgr.queryMembers(currentGroupId)
                        .filter { !it.removed }
                        .map { it.pubkeyHex }
                        .toSet()

                    // Filter out contacts already in the group
                    allContacts.filter { contact ->
                        val pubkeyHex = contact.ed25519PublicKeyBytes
                            .joinToString("") { "%02x".format(it) }
                        pubkeyHex !in memberPubkeys
                    }
                }

                withContext(Dispatchers.Main) {
                    if (availableContacts.isEmpty()) {
                        ThemedToast.show(this@GroupMembersActivity, "All contacts are already members")
                        return@withContext
                    }

                    val bottomSheetDialog = GlassBottomSheetDialog(this@GroupMembersActivity)
                    val view = layoutInflater.inflate(R.layout.bottom_sheet_select_contacts, null)
                    bottomSheetDialog.setContentView(view)

                    bottomSheetDialog.behavior.isDraggable = true
                    bottomSheetDialog.behavior.skipCollapsed = true

                    bottomSheetDialog.setOnShowListener {
                        (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
                    }

                    val contactsRecyclerView = view.findViewById<RecyclerView>(R.id.contactsRecyclerView)
                    val doneButton = view.findViewById<TextView>(R.id.doneButton)

                    val adapter = ContactSelectionAdapter(mutableSetOf())
                    contactsRecyclerView.layoutManager = LinearLayoutManager(this@GroupMembersActivity)
                    contactsRecyclerView.adapter = adapter
                    adapter.submitList(availableContacts)

                    doneButton.setOnClickListener {
                        val selected = adapter.getSelectedContacts()
                        if (selected.isEmpty()) {
                            ThemedToast.show(this@GroupMembersActivity, "No contacts selected")
                        } else {
                            addMembersToGroup(currentGroupId, selected)
                        }
                        bottomSheetDialog.dismiss()
                    }

                    bottomSheetDialog.show()
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
                    val mgr = CrdtGroupManager.getInstance(this@GroupMembersActivity)
                    for (contact in contacts) {
                        val pubkeyHex = contact.ed25519PublicKeyBytes
                            .joinToString("") { "%02x".format(it) }
                        mgr.inviteMember(groupId, pubkeyHex)
                        Log.i(TAG, "Invited ${contact.displayName}")
                    }
                }

                withContext(Dispatchers.Main) {
                    val memberNames = contacts.joinToString(", ") { it.displayName }
                    ThemedToast.show(this@GroupMembersActivity, "Invited: $memberNames")
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


    private fun confirmRemoveMember(member: GroupMemberItem) {
        val currentGroupId = groupId ?: return

        AlertDialog.Builder(this)
            .setTitle("Remove Member")
            .setMessage("Remove ${member.displayName} from this group?")
            .setPositiveButton("Remove") { dialog, _ ->
                dialog.dismiss()
                lifecycleScope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            val mgr = CrdtGroupManager.getInstance(this@GroupMembersActivity)
                            val opBytes = mgr.removeMember(currentGroupId, member.pubkeyHex)
                            mgr.broadcastOpToGroup(currentGroupId, opBytes)
                        }
                        ThemedToast.show(this@GroupMembersActivity, "${member.displayName} removed")
                        loadGroupMembers()
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to remove member", e)
                        ThemedToast.show(this@GroupMembersActivity, "Failed to remove: ${e.message}")
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun confirmPromoteMember(member: GroupMemberItem) {
        AlertDialog.Builder(this)
            .setTitle("Promote Member")
            .setMessage("Promote ${member.displayName} to Admin?")
            .setPositiveButton("Promote") { dialog, _ ->
                dialog.dismiss()
                // TODO: CRDT MetadataSet for role change when role ops are implemented
                ThemedToast.show(this, "Promote — Coming soon")
                Log.i(TAG, "Promote: ${member.displayName}")
            }
            .setNegativeButton("Cancel", null)
            .show()
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
