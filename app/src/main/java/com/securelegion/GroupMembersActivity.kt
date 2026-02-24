package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.TextView
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
import androidx.activity.result.contract.ActivityResultContracts
import com.securelegion.utils.GlassDialog
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
    private var currentUserRole: String = "Member"

    // Member selection launcher
    private val addMembersLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val idsStr = result.data?.getStringExtra(AddGroupMembersActivity.RESULT_SELECTED_IDS) ?: ""
            val selectedIds = idsStr.split(",")
                .filter { it.isNotBlank() }
                .mapNotNull { it.trim().toLongOrNull() }
                .toSet()

            if (selectedIds.isNotEmpty()) {
                val currentGroupId = groupId ?: return@registerForActivityResult
                lifecycleScope.launch {
                    try {
                        val contacts = withContext(Dispatchers.IO) {
                            val keyManager = KeyManager.getInstance(this@GroupMembersActivity)
                            val dbPassphrase = keyManager.getDatabasePassphrase()
                            val database = SecureLegionDatabase.getInstance(this@GroupMembersActivity, dbPassphrase)
                            database.contactDao().getAllContacts().filter { it.id in selectedIds }
                        }
                        if (contacts.isNotEmpty()) {
                            addMembersToGroup(currentGroupId, contacts)
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to resolve selected contacts", e)
                    }
                }
            }
        }
    }

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
                val (members, myRole) = withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupMembersActivity)
                    val keyManager = KeyManager.getInstance(this@GroupMembersActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupMembersActivity, dbPassphrase)

                    val crdtMembers = mgr.queryMembers(currentGroupId)
                        .filter { !it.removed }

                    val localPubkeyHex = keyManager.getSigningPublicKey()
                        .joinToString("") { "%02x".format(it) }

                    // Determine current user's role for permission checks
                    val myEntry = crdtMembers.find { it.pubkeyHex == localPubkeyHex }
                    val role = if (myEntry != null && myEntry.accepted) myEntry.role else "Member"

                    val memberList = crdtMembers.mapNotNull { member ->
                        val isMe = member.pubkeyHex == localPubkeyHex
                        val memberRole = if (!member.accepted) "Pending" else member.role

                        if (isMe) {
                            return@mapNotNull GroupMemberItem(
                                pubkeyHex = member.pubkeyHex,
                                displayName = "You",
                                role = memberRole,
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
                            ?: database.groupPeerDao().getByGroupAndPubkey(currentGroupId, member.pubkeyHex)?.displayName
                            ?: (member.deviceIdHex.take(16) + "...")
                        val photo = dbContact?.profilePictureBase64

                        GroupMemberItem(
                            pubkeyHex = member.pubkeyHex,
                            displayName = displayName,
                            role = memberRole,
                            isMe = false,
                            profilePhotoBase64 = photo
                        )
                    }

                    Pair(memberList, role)
                }

                currentUserRole = myRole
                allMembers = members.sortedWith(compareBy({ !it.isMe }, { it.displayName.uppercase() }))
                filteredMembers = allMembers
                memberAdapter.updateMembers(filteredMembers, currentUserRole)

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

        val intent = Intent(this, AddGroupMembersActivity::class.java).apply {
            putExtra(AddGroupMembersActivity.EXTRA_GROUP_ID, currentGroupId)
        }
        addMembersLauncher.launch(intent)
    }

    private fun addMembersToGroup(
        groupId: String,
        contacts: List<com.securelegion.database.entities.Contact>
    ) {
        val mgr = CrdtGroupManager.getInstance(this@GroupMembersActivity)
        val contactPairs = contacts.map { contact ->
            val pubkeyHex = contact.ed25519PublicKeyBytes
                .joinToString("") { "%02x".format(it) }
            Pair(pubkeyHex, contact.displayName)
        }
        val batchId = mgr.inviteDispatcher.enqueue(groupId, contactPairs)

        val memberNames = contacts.joinToString(", ") { it.displayName }
        ThemedToast.show(this, "Inviting: $memberNames")

        // Observe progress — refresh list on completion
        lifecycleScope.launch {
            mgr.inviteDispatcher.observeBatch(batchId).collect { state ->
                if (state.isComplete) {
                    ThemedToast.show(this@GroupMembersActivity, state.summaryText)
                    loadGroupMembers()
                    mgr.inviteDispatcher.clearBatch(batchId)
                    return@collect
                }
            }
        }
    }


    private fun confirmRemoveMember(member: GroupMemberItem) {
        val currentGroupId = groupId ?: return

        if (currentUserRole !in listOf("Owner", "Admin")) {
            ThemedToast.show(this, "Only owners and admins can remove members")
            return
        }

        val dialog = GlassDialog.builder(this)
            .setTitle("Remove Member")
            .setMessage("Remove ${member.displayName} from this group?")
            .setPositiveButton("Remove") { d, _ ->
                d.dismiss()
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
            .create()
        GlassDialog.show(dialog)
    }

    private fun confirmPromoteMember(member: GroupMemberItem) {
        val dialog = GlassDialog.builder(this)
            .setTitle("Promote Member")
            .setMessage("Promote ${member.displayName} to Admin?")
            .setPositiveButton("Promote") { d, _ ->
                d.dismiss()
                // TODO: CRDT MetadataSet for role change when role ops are implemented
                ThemedToast.show(this, "Promote — Coming soon")
                Log.i(TAG, "Promote: ${member.displayName}")
            }
            .setNegativeButton("Cancel", null)
            .create()
        GlassDialog.show(dialog)
    }

    private fun setupBottomNav() {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        val bottomNav = findViewById<View>(R.id.bottomNav)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(android.R.id.content)) { _, windowInsets ->
            val insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            bottomNav?.setPadding(bottomNav.paddingLeft, bottomNav.paddingTop, bottomNav.paddingRight, insets.bottom)
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
