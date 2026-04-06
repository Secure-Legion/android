package com.securelegion

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.services.CrdtGroupManager
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.applySlideInTransition
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ImagePicker
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class GroupProfileActivity : BaseActivity() {

    companion object {
        private const val TAG = "GroupProfile"
        const val EXTRA_GROUP_ID = "group_id"
        const val EXTRA_GROUP_NAME = "group_name"
    }

    // Views
    private lateinit var backButton: View
    private lateinit var groupNameTitle: android.widget.EditText
    private lateinit var memberCountText: TextView
    private lateinit var groupIconContainer: FrameLayout
    private lateinit var groupIconImage: ImageView
    private lateinit var inviteMemberButton: View
    private lateinit var leaveGroupButton: View
    private lateinit var changePinButton: View
    private lateinit var membersButton: View
    private lateinit var advanceButton: View
    private lateinit var permissionsButton: View
    private lateinit var administratorsButton: View
    private lateinit var bannedUsersButton: View
    private lateinit var recentActionsButton: View
    private lateinit var deleteGroupButton: View
    private lateinit var syncPhotoButton: View
    private lateinit var permissionsCount: TextView
    private lateinit var administratorsCount: TextView
    private lateinit var recentActionsCount: TextView
    private lateinit var bannedUsersCount: TextView
    private lateinit var seeAllMembersCount: TextView
    private var canEditName: Boolean = false

    // Group data
    private var groupId: String? = null
    private var groupName: String = "Group"

    // Image picker launchers
    private val galleryLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val uri = result.data?.data
            val base64 = ImagePicker.processImageUri(this, uri)
            if (base64 != null) {
                updateGroupIconPreview(base64)
                saveGroupIcon(base64)
                ThemedToast.show(this, "Group icon updated")
            } else {
                ThemedToast.show(this, "Failed to process image")
            }
        }
    }

    private val cameraLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val bitmap = result.data?.extras?.let { androidx.core.os.BundleCompat.getParcelable(it, "data", Bitmap::class.java) }
            val base64 = ImagePicker.processImageBitmap(bitmap)
            if (base64 != null) {
                updateGroupIconPreview(base64)
                saveGroupIcon(base64)
                ThemedToast.show(this, "Group icon updated")
            } else {
                ThemedToast.show(this, "Failed to process image")
            }
        }
    }

    // Member selection launcher — receives selected contact IDs from AddGroupMembersActivity
    private val addMembersLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val idsStr = result.data?.getStringExtra(AddGroupMembersActivity.RESULT_SELECTED_IDS) ?: ""
            val selectedIds = idsStr.split(",")
                .filter { it.isNotBlank() }
                .mapNotNull { it.trim().toLongOrNull() }
                .toSet()

            if (selectedIds.isNotEmpty()) {
                val currentGroupId = groupId ?: return@registerForActivityResult
                lifecycleScope.launch {
                    try {
                        val (contacts, myRole) = withContext(Dispatchers.IO) {
                            val keyManager = KeyManager.getInstance(this@GroupProfileActivity)
                            val dbPassphrase = keyManager.getDatabasePassphrase()
                            val database = SecureLegionDatabase.getInstance(this@GroupProfileActivity, dbPassphrase)
                            val resolved = database.contactDao().getAllContacts().filter { it.id in selectedIds }

                            // Role check — only Owner/Admin can invite (matches Rust can_author_op)
                            val mgr = CrdtGroupManager.getInstance(this@GroupProfileActivity)
                            val myPubkeyHex = keyManager.getSigningPublicKey()
                                .joinToString("") { "%02x".format(it) }
                            val role = mgr.queryMembers(currentGroupId)
                                .firstOrNull { it.pubkeyHex == myPubkeyHex && it.accepted && !it.removed }
                                ?.role ?: "Member"
                            Pair(resolved, role)
                        }
                        if (myRole !in listOf("Owner", "Admin")) {
                            ThemedToast.show(this@GroupProfileActivity, "Only admins can add friends")
                            return@launch
                        }
                        if (contacts.isNotEmpty()) {
                            inviteContactsToGroup(currentGroupId, contacts)
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
        setContentView(R.layout.activity_group_profile)

        // Get group data from intent
        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        groupName = intent.getStringExtra(EXTRA_GROUP_NAME) ?: "Group"

        initializeViews()
        setupClickListeners()
        loadGroupData()
        setupBottomNav()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        groupNameTitle = findViewById(R.id.groupNameTitle)
        memberCountText = findViewById(R.id.memberCountText)
        groupIconContainer = findViewById(R.id.groupIconContainer)
        groupIconImage = findViewById(R.id.groupIconImage)
        inviteMemberButton = findViewById(R.id.inviteMemberButton)
        leaveGroupButton = findViewById(R.id.leaveGroupButton)
        changePinButton = findViewById(R.id.changePinButton)
        changePinButton.visibility = View.GONE // CRDT groups use cryptographic membership, not PINs
        membersButton = findViewById(R.id.membersButton)
        advanceButton = findViewById(R.id.advanceButton)
        permissionsButton = findViewById(R.id.permissionsButton)
        administratorsButton = findViewById(R.id.administratorsButton)
        bannedUsersButton = findViewById(R.id.bannedUsersButton)
        recentActionsButton = findViewById(R.id.recentActionsButton)
        deleteGroupButton = findViewById(R.id.deleteGroupButton)
        syncPhotoButton = findViewById(R.id.syncPhotoButton)
        permissionsCount = findViewById(R.id.permissionsCount)
        administratorsCount = findViewById(R.id.administratorsCount)
        recentActionsCount = findViewById(R.id.recentActionsCount)
        bannedUsersCount = findViewById(R.id.bannedUsersCount)
        seeAllMembersCount = findViewById(R.id.seeAllMembersCount)
    }

    private fun setupClickListeners() {
        // Back button
        backButton.setOnClickListener {
            finish()
        }

        // Group icon - photo picker
        groupIconContainer.setOnClickListener {
            showGroupIconPickerDialog()
        }

        // Change PIN — hidden for CRDT groups
        changePinButton.setOnClickListener { }

        // Members
        membersButton.setOnClickListener {
            showMembersScreen()
        }

        // Invite Member — opens AddGroupMembersActivity
        inviteMemberButton.setOnClickListener {
            val currentGroupId = groupId
            if (currentGroupId == null) {
                ThemedToast.show(this, "Invalid group")
                return@setOnClickListener
            }
            val intent = Intent(this, AddGroupMembersActivity::class.java).apply {
                putExtra(AddGroupMembersActivity.EXTRA_GROUP_ID, currentGroupId)
            }
            addMembersLauncher.launch(intent)
        }

        // Leave Group button removed — users swipe-to-leave on the thread list.
        // Hidden View kept in layout for Kotlin field compatibility.

        // Group name inline edit — save on IME "Done" or focus loss
        groupNameTitle.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == android.view.inputmethod.EditorInfo.IME_ACTION_DONE) {
                saveGroupNameInline()
                groupNameTitle.clearFocus()
                val imm = getSystemService(android.content.Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
                imm.hideSoftInputFromWindow(groupNameTitle.windowToken, 0)
                true
            } else false
        }
        groupNameTitle.setOnFocusChangeListener { _, hasFocus ->
            if (!hasFocus) saveGroupNameInline()
        }

        // Advance
        advanceButton.setOnClickListener {
            showAdvancedSettings()
        }

        // Permissions
        permissionsButton.setOnClickListener {
            showPermissionsSettings()
        }

        administratorsButton.setOnClickListener {
            val gid = groupId ?: return@setOnClickListener
            val intent = Intent(this, GroupAdminsActivity::class.java).apply {
                putExtra(GroupAdminsActivity.EXTRA_GROUP_ID, gid)
            }
            startActivity(intent)
        }

        bannedUsersButton.setOnClickListener {
            val gid = groupId ?: return@setOnClickListener
            val intent = Intent(this, BannedUsersActivity::class.java).apply {
                putExtra(BannedUsersActivity.EXTRA_GROUP_ID, gid)
            }
            startActivity(intent)
        }

        recentActionsButton.setOnClickListener {
            val gid = groupId ?: return@setOnClickListener
            val intent = Intent(this, RecentActionsActivity::class.java).apply {
                putExtra(RecentActionsActivity.EXTRA_GROUP_ID, gid)
            }
            startActivity(intent)
        }

        deleteGroupButton.setOnClickListener {
            showDeleteGroupConfirmation()
        }

        // Sync profile photo to group
        syncPhotoButton.setOnClickListener {
            syncProfilePhoto()
        }

    }

    private fun loadGroupData() {
        groupNameTitle.setText(groupName)
        findViewById<com.securelegion.views.AvatarView>(R.id.groupAvatarView)?.setName(groupName)

        val currentGroupId = groupId ?: return

        lifecycleScope.launch {
            try {
                val (groupIcon, crdtName) = withContext(Dispatchers.IO) {
                    // Load group photo from Room entity
                    val keyManager = KeyManager.getInstance(this@GroupProfileActivity)
                    val db = SecureLegionDatabase.getInstance(this@GroupProfileActivity, keyManager.getDatabasePassphrase())
                    val group = db.groupDao().getGroupById(currentGroupId)
                    val icon = group?.groupIcon

                    // Also check CRDT metadata for name
                    var name: String? = null
                    try {
                        val mgr = CrdtGroupManager.getInstance(this@GroupProfileActivity)
                        val metadata = mgr.queryMetadata(currentGroupId)
                        name = metadata.name
                    } catch (_: Exception) { }

                    Pair(icon, name)
                }

                withContext(Dispatchers.Main) {
                    // Display group photo if available
                    if (!groupIcon.isNullOrEmpty()) {
                        val bitmap = ImagePicker.decodeBase64ToBitmap(groupIcon)
                        if (bitmap != null) {
                            findViewById<com.securelegion.views.AvatarView>(R.id.groupAvatarView)?.visibility = View.GONE
                            groupIconImage.visibility = View.VISIBLE
                            groupIconImage.imageTintList = null
                            groupIconImage.setImageBitmap(bitmap)
                            groupIconImage.scaleType = ImageView.ScaleType.CENTER_CROP
                        }
                    }

                    // Update name from CRDT state if available
                    if (!crdtName.isNullOrEmpty()) {
                        groupNameTitle.setText(crdtName)
                    }
                }

                Log.d(TAG, "Group profile loaded: $groupName (ID: $groupId)")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to load group data", e)
            }
        }
        refreshMemberCount()
    }

    override fun onResume() {
        super.onResume()
        refreshMemberCount()
        refreshOwnerControls()
    }

    /** Role-gated row visibility: Delete Group (Owner only); Banned + Recent Actions (Owner/Admin). */
    private fun refreshOwnerControls() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            val role = withContext(Dispatchers.IO) {
                try {
                    val mgr = CrdtGroupManager.getInstance(this@GroupProfileActivity)
                    val myPubkeyHex = KeyManager.getInstance(this@GroupProfileActivity)
                        .getSigningPublicKey().joinToString("") { "%02x".format(it) }
                    mgr.queryMembers(gid)
                        .firstOrNull { it.pubkeyHex == myPubkeyHex && it.accepted && !it.removed }
                        ?.role
                } catch (_: Exception) { null }
            }
            if (isFinishing || isDestroyed) return@launch
            val isOwner = role == "Owner"
            val isOwnerOrAdmin = isOwner || role == "Admin"
            canEditName = isOwnerOrAdmin
            groupNameTitle.isEnabled = isOwnerOrAdmin
            groupNameTitle.isFocusable = isOwnerOrAdmin
            groupNameTitle.isFocusableInTouchMode = isOwnerOrAdmin
            deleteGroupButton.visibility = if (isOwner) View.VISIBLE else View.GONE
            bannedUsersButton.visibility = if (isOwnerOrAdmin) View.VISIBLE else View.GONE
            recentActionsButton.visibility = if (isOwnerOrAdmin) View.VISIBLE else View.GONE
        }
        refreshCounts()
    }

    /** Populate the count badges on each info box. */
    private fun refreshCounts() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            val counts = withContext(Dispatchers.IO) {
                try {
                    val mgr = CrdtGroupManager.getInstance(this@GroupProfileActivity)
                    val members = mgr.queryMembers(gid)
                    val metadata = try { mgr.queryMetadata(gid) } catch (_: Exception) { null }

                    val activeMembers = members.count { it.accepted && !it.removed }
                    val admins = members.count { (it.role == "Admin" || it.role == "Owner") && it.accepted && !it.removed }
                    val banned = members.count { it.removed }

                    val permsEnabled = if (metadata != null) {
                        var n = 0
                        if (metadata.effectiveAllowSend()) n++
                        if (metadata.effectiveAllowInvites()) n++
                        if (metadata.effectiveAllowPin()) n++
                        if (metadata.effectiveAllowChangeInfo()) n++
                        n
                    } else 0

                    // Recent actions = number of membership-related ops in the log
                    val recent = try {
                        val db = com.securelegion.database.SecureLegionDatabase.getInstance(
                            this@GroupProfileActivity,
                            KeyManager.getInstance(this@GroupProfileActivity).getDatabasePassphrase()
                        )
                        db.crdtOpLogDao().getMembershipOps(gid).size
                    } catch (_: Exception) { 0 }

                    intArrayOf(permsEnabled, admins, banned, recent, activeMembers)
                } catch (_: Exception) { intArrayOf(0, 0, 0, 0, 0) }
            }
            if (isFinishing || isDestroyed) return@launch
            permissionsCount.text = "${counts[0]}/4"
            administratorsCount.text = counts[1].toString()
            bannedUsersCount.text = counts[2].toString()
            recentActionsCount.text = counts[3].toString()
            seeAllMembersCount.text = counts[4].toString()
        }
    }

    /** Save group name from inline EditText (called on IME Done or focus loss). */
    private fun saveGroupNameInline() {
        val currentGroupId = groupId ?: return
        val newName = groupNameTitle.text.toString().trim()
        if (newName.isEmpty() || newName == groupName) return
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupProfileActivity)
                    val valueB64 = android.util.Base64.encodeToString(
                        newName.toByteArray(Charsets.UTF_8),
                        android.util.Base64.NO_WRAP
                    )
                    val opBytes = mgr.setMetadata(currentGroupId, "Name", valueB64)
                    mgr.broadcastOpToGroup(currentGroupId, opBytes)
                }
                groupName = newName
                ThemedToast.show(this@GroupProfileActivity, "Group name updated")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to update group name", e)
                groupNameTitle.setText(groupName) // revert on failure
                ThemedToast.show(this@GroupProfileActivity, "Failed to update name")
            }
        }
    }

    private fun refreshMemberCount() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            try {
                val count = withContext(Dispatchers.IO) {
                    CrdtGroupManager.getInstance(this@GroupProfileActivity)
                        .queryMembers(gid)
                        .count { it.accepted && !it.removed }
                }
                if (!isFinishing && !isDestroyed) {
                    val max = AddGroupMembersActivity.MAX_GROUP_MEMBERS
                    memberCountText.text = "$count/$max members"
                }
            } catch (_: Exception) { }
        }
    }

    private fun inviteContactsToGroup(
        groupId: String,
        contacts: List<com.securelegion.database.entities.Contact>
    ) {
        val mgr = CrdtGroupManager.getInstance(this@GroupProfileActivity)
        val contactPairs = contacts.map { contact ->
            val pubkeyHex = contact.ed25519PublicKeyBytes
                .joinToString("") { "%02x".format(it) }
            Pair(pubkeyHex, contact.displayName)
        }
        val batchId = mgr.inviteDispatcher.enqueue(groupId, contactPairs)

        val memberNames = contacts.joinToString(", ") { it.displayName }
        ThemedToast.show(this, "Inviting: $memberNames")

        lifecycleScope.launch {
            mgr.inviteDispatcher.observeBatch(batchId).collect { state ->
                if (state.isComplete) {
                    ThemedToast.show(this@GroupProfileActivity, state.summaryText)
                    refreshMemberCount()
                    mgr.inviteDispatcher.clearBatch(batchId)
                    return@collect
                }
            }
        }
    }

    private fun showDeleteGroupConfirmation() {
        val currentGroupId = groupId ?: return
        val dialog = GlassDialog.builder(this)
            .setTitle("Delete Group")
            .setMessage("Delete this group for everyone? This cannot be undone.")
            .setPositiveButton("Delete") { d, _ ->
                d.dismiss()
                lifecycleScope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            CrdtGroupManager.getInstance(this@GroupProfileActivity)
                                .deleteGroup(currentGroupId)
                        }
                        ThemedToast.show(this@GroupProfileActivity, "Group deleted")
                        finish()
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to delete group", e)
                        ThemedToast.show(this@GroupProfileActivity, "Failed to delete: ${e.message}")
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .create()
        GlassDialog.show(dialog)
    }

    private fun showLeaveGroupConfirmation() {
        val currentGroupId = groupId ?: return
        val dialog = GlassDialog.builder(this)
            .setTitle("Leave Group")
            .setMessage("Are you sure you want to leave this group?")
            .setPositiveButton("Leave") { d, _ ->
                d.dismiss()
                leaveGroup(currentGroupId)
            }
            .setNegativeButton("Cancel", null)
            .create()
        GlassDialog.show(dialog)
    }

    private fun leaveGroup(currentGroupId: String) {
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupProfileActivity)
                    val km = KeyManager.getInstance(this@GroupProfileActivity)
                    val myPubkeyHex = km.getSigningPublicKey()
                        .joinToString("") { "%02x".format(it) }
                    val opBytes = mgr.removeMember(currentGroupId, myPubkeyHex)
                    mgr.broadcastOpToGroup(currentGroupId, opBytes)
                    val authorName = km.getUsername() ?: "Someone"
                    mgr.sendSystemMessage(currentGroupId, "$authorName left the group")
                }
                ThemedToast.show(this@GroupProfileActivity, "You left the group")
                finish()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to leave group", e)
                ThemedToast.show(this@GroupProfileActivity, "Failed to leave: ${e.message}")
            }
        }
    }

    private fun syncProfilePhoto() {
        val currentGroupId = groupId ?: return

        ThemedToast.show(this, "Syncing profile photo...")

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupProfileActivity)
                    mgr.sendGroupProfilePhoto(currentGroupId)
                }
                ThemedToast.show(this@GroupProfileActivity, "Profile photo synced")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to sync profile photo", e)
                ThemedToast.show(this@GroupProfileActivity, "Failed to sync photo")
            }
        }
    }

    private fun showChangePinDialog() {
        // CRDT groups use cryptographic membership — no PIN needed
    }

    private fun showMembersScreen() {
        // Open members list screen
        val intent = Intent(this, GroupMembersActivity::class.java)
        intent.putExtra(GroupMembersActivity.EXTRA_GROUP_ID, groupId)
        intent.putExtra(GroupMembersActivity.EXTRA_GROUP_NAME, groupName)
        startActivityWithSlideAnimation(intent)
        Log.i(TAG, "Opening members screen for group: $groupName")
    }

    private fun showAdvancedSettings() {
        // TODO: Implement advanced settings when group messaging is implemented
        // This could include:
        // - Group description
        // - Auto-delete messages timer
        // - Disappearing messages
        // - Export chat history
        // - Leave group option
        // - Delete group (if admin)

        ThemedToast.show(this, "Advanced settings - Coming soon")
        Log.i(TAG, "Advance clicked for group: $groupName")
    }

    private fun showPermissionsSettings() {
        val gid = groupId ?: return
        val intent = Intent(this, GroupPermissionsActivity::class.java).apply {
            putExtra(GroupPermissionsActivity.EXTRA_GROUP_ID, gid)
        }
        startActivity(intent)
    }

    // ==================== GROUP ICON PICKER ====================

    private fun showGroupIconPickerDialog() {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_photo_picker, null)
        bottomSheet.setContentView(view)

        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.skipCollapsed = true

        bottomSheet.setOnShowListener {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        view.findViewById<View>(R.id.optionTakePhoto).setOnClickListener {
            bottomSheet.dismiss()
            ImagePicker.pickFromCamera(cameraLauncher)
        }

        view.findViewById<View>(R.id.optionGallery).setOnClickListener {
            bottomSheet.dismiss()
            ImagePicker.pickFromGallery(galleryLauncher)
        }

        view.findViewById<View>(R.id.optionRemovePhoto).setOnClickListener {
            bottomSheet.dismiss()
            removeGroupIcon()
        }

        bottomSheet.show()
    }

    private fun updateGroupIconPreview(base64: String) {
        val bitmap = ImagePicker.decodeBase64ToBitmap(base64)
        if (bitmap != null) {
            groupIconImage.imageTintList = null
            groupIconImage.setImageBitmap(bitmap)
            groupIconImage.scaleType = ImageView.ScaleType.CENTER_CROP
        }
    }

    private fun removeGroupIcon() {
        groupIconImage.setImageResource(R.drawable.ic_contacts)
        groupIconImage.scaleType = ImageView.ScaleType.CENTER_INSIDE
        groupIconImage.imageTintList = android.content.res.ColorStateList.valueOf(
            ContextCompat.getColor(this, R.color.lock_title_gray)
        )
        saveGroupIcon(null)
        ThemedToast.show(this, "Group icon removed")
    }

    private fun saveGroupIcon(base64: String?) {
        val currentGroupId = groupId ?: return
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@GroupProfileActivity)
                    val db = SecureLegionDatabase.getInstance(this@GroupProfileActivity, keyManager.getDatabasePassphrase())
                    db.groupDao().updateGroupIcon(currentGroupId, base64 ?: "")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to save group icon", e)
            }
        }
    }

    private fun setupBottomNav() {
        // Bottom nav removed from this screen — keep window-insets handling
        // so content respects gesture-nav bar.
        WindowCompat.setDecorFitsSystemWindows(window, false)
    }

    private fun startActivityWithSlideAnimation(intent: Intent) {
        startActivity(intent)
        applySlideInTransition(R.anim.slide_in_right, R.anim.slide_out_left)
    }

    private fun lockApp() {
        val intent = Intent(this, LockActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
}
