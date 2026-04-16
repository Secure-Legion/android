package com.securelegion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.services.CrdtGroupManager
import com.securelegion.services.TorService
import com.securelegion.network.TransportGate
import com.securelegion.ui.adapters.GroupMessageAdapter
import com.securelegion.ui.adapters.GroupChatMessage
import com.securelegion.views.MediaKeyboardView
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.applySlideInTransition
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class GroupChatActivity : BaseActivity() {

    companion object {
        private const val TAG = "GroupChat"
        const val EXTRA_GROUP_ID = "group_id"
        const val EXTRA_GROUP_NAME = "group_name"
        private const val STICKER_PREFIX = "[STICKER]"
    }

    // Views
    private lateinit var backButton: View
    private lateinit var groupAvatar: com.securelegion.views.AvatarView
    private lateinit var groupNameTitle: TextView
    private lateinit var memberCountText: TextView
    private lateinit var syncIcon: FrameLayout
    private lateinit var settingsIcon: FrameLayout
    private lateinit var messagesRecyclerView: RecyclerView
    private lateinit var messageInput: EditText
    private lateinit var plusButton: FrameLayout
    private lateinit var sendButton: FrameLayout
    private lateinit var sendButtonIcon: ImageView
    private lateinit var inviteBanner: LinearLayout
    private lateinit var inviteBannerText: TextView
    private lateinit var acceptInviteButton: TextView
    private lateinit var bottomSheetOverlay: View
    private lateinit var bottomSheetContainer: LinearLayout
    private lateinit var sendImageOption: View
    private lateinit var addFriendOption: View
    private lateinit var cancelButton: TextView

    // Data
    private var groupId: String? = null
    private var groupName: String = "Group"
    private var isBottomSheetVisible = false
    private var isPendingInvite = false
    private lateinit var messageAdapter: GroupMessageAdapter

    // Local device ID hex (computed once on load)
    private var myDeviceIdHex: String? = null
    private var myPubkeyHex: String? = null

    // Broadcast receiver for new group messages
    private val groupMessageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (isFinishing || isDestroyed) return
            if (intent?.action == "com.securelegion.NEW_GROUP_MESSAGE") {
                val receivedGroupId = intent.getStringExtra("GROUP_ID")
                if (receivedGroupId == groupId) {
                    Log.d(TAG, "Received NEW_GROUP_MESSAGE broadcast - reloading messages")
                    runOnUiThread {
                        if (!isFinishing && !isDestroyed) loadMessages()
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_group_chat)

        // Enable edge-to-edge display (matches ChatActivity)
        WindowCompat.setDecorFitsSystemWindows(window, false)

        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        groupName = intent.getStringExtra(EXTRA_GROUP_NAME) ?: "Group"

        initializeViews()
        setupClickListeners()
        setupRecyclerView()
        setupWindowInsets()
        loadMessages()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        groupAvatar = findViewById(R.id.groupAvatar)
        groupNameTitle = findViewById(R.id.groupNameTitle)
        memberCountText = findViewById(R.id.memberCountText)
        syncIcon = findViewById(R.id.syncIcon)
        settingsIcon = findViewById(R.id.settingsIcon)
        messagesRecyclerView = findViewById(R.id.messagesRecyclerView)
        messageInput = findViewById(R.id.messageInput)
        plusButton = findViewById(R.id.plusButton)
        sendButton = findViewById(R.id.sendButton)
        sendButtonIcon = findViewById(R.id.sendButtonIcon)
        inviteBanner = findViewById(R.id.inviteBanner)
        inviteBannerText = findViewById(R.id.inviteBannerText)
        acceptInviteButton = findViewById(R.id.acceptInviteButton)
        bottomSheetOverlay = findViewById(R.id.bottomSheetOverlay)
        bottomSheetContainer = findViewById(R.id.bottomSheetContainer)
        sendImageOption = findViewById(R.id.sendImageOption)
        addFriendOption = findViewById(R.id.addFriendOption)
        cancelButton = findViewById(R.id.cancelButton)

        groupNameTitle.text = groupName
        memberCountText.text = "0 members"

        // Load group avatar + member count
        groupAvatar.setName(groupName)
        val gid = groupId
        if (gid != null) {
            lifecycleScope.launch {
                try {
                    val icon = withContext(Dispatchers.IO) {
                        val km = KeyManager.getInstance(this@GroupChatActivity)
                        val db = SecureLegionDatabase.getInstance(this@GroupChatActivity, km.getDatabasePassphrase())
                        db.groupDao().getGroupById(gid)?.groupIcon
                    }
                    if (!icon.isNullOrEmpty()) {
                        groupAvatar.setPhotoBase64(icon)
                    }
                } catch (_: Exception) { }
            }
            refreshMemberCount()
        }
    }

    private fun refreshMemberCount() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            try {
                val count = withContext(Dispatchers.IO) {
                    CrdtGroupManager.getInstance(this@GroupChatActivity)
                        .queryMembers(gid)
                        .count { it.accepted && !it.removed }
                }
                if (!isFinishing && !isDestroyed) {
                    memberCountText.text = "$count/${AddGroupMembersActivity.MAX_GROUP_MEMBERS} members"
                }
            } catch (_: Exception) { }
        }
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener { finish() }

        settingsIcon.setOnClickListener {
            val intent = Intent(this, GroupProfileActivity::class.java)
            intent.putExtra(GroupProfileActivity.EXTRA_GROUP_ID, groupId)
            intent.putExtra(GroupProfileActivity.EXTRA_GROUP_NAME, groupName)
            startActivity(intent)
            applySlideInTransition(R.anim.slide_in_right, R.anim.slide_out_left)
        }

        syncIcon.setOnClickListener {
            val currentGroupId = groupId
            if (currentGroupId == null) return@setOnClickListener
            ThemedToast.show(this, "Syncing...")
            lifecycleScope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        CrdtGroupManager.getInstance(this@GroupChatActivity)
                            .fullSync(currentGroupId)
                    }
                    loadMessages()
                    refreshMemberCount()
                } catch (e: Exception) {
                    Log.w(TAG, "Sync failed", e)
                }
            }
        }

        // Plus button is hidden for groups for now — no click listener needed.
        // Send button — voice for groups is disabled for now, always sends text.
        sendButton.setOnClickListener { sendMessage() }

        bottomSheetOverlay.setOnClickListener { hideBottomSheet() }

        sendImageOption.setOnClickListener {
            hideBottomSheet()
            showStickerGifPicker()
        }

        addFriendOption.setOnClickListener {
            hideBottomSheet()
            showAddMemberDialog()
        }

        cancelButton.setOnClickListener { hideBottomSheet() }

        acceptInviteButton.setOnClickListener { acceptInvite() }

        messageInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == android.view.inputmethod.EditorInfo.IME_ACTION_SEND) {
                sendMessage()
                true
            } else {
                false
            }
        }
    }

    private fun setupRecyclerView() {
        messageAdapter = GroupMessageAdapter(
            onMessageClick = { message ->
                Log.d(TAG, "Message clicked: ${message.messageId}")
            },
            onMessageLongClick = { message ->
                Log.d(TAG, "Message long-clicked: ${message.messageId}")
            }
        )

        messagesRecyclerView.layoutManager = LinearLayoutManager(this).apply {
            stackFromEnd = true
        }
        messagesRecyclerView.adapter = messageAdapter

        // Show/hide scroll-to-bottom button based on scroll position
        val scrollToBottomBtn = findViewById<View>(R.id.scrollToBottomBtn)
        messagesRecyclerView.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                val lm = recyclerView.layoutManager as? LinearLayoutManager ?: return
                val lastVisible = lm.findLastVisibleItemPosition()
                val totalItems = lm.itemCount
                val farFromBottom = totalItems - lastVisible > 5
                if (farFromBottom && scrollToBottomBtn.visibility != View.VISIBLE) {
                    scrollToBottomBtn.visibility = View.VISIBLE
                    scrollToBottomBtn.alpha = 0f
                    scrollToBottomBtn.animate().alpha(1f).setDuration(150).start()
                } else if (!farFromBottom && scrollToBottomBtn.visibility == View.VISIBLE) {
                    scrollToBottomBtn.animate().alpha(0f).setDuration(150).withEndAction {
                        scrollToBottomBtn.visibility = View.GONE
                    }.start()
                }
            }
        })
        scrollToBottomBtn.setOnClickListener {
            val count = messageAdapter.itemCount
            if (count > 0) messagesRecyclerView.smoothScrollToPosition(count - 1)
        }
    }

    private fun setupWindowInsets() {
        val rootView = findViewById<View>(android.R.id.content)
        val topBar = findViewById<View>(R.id.topBar)
        val messageInputContainer = findViewById<View>(R.id.messageInputContainer)
        var wasImeVisible = false
        val topBarBasePaddingLeft = topBar.paddingLeft
        val topBarBasePaddingTop = topBar.paddingTop
        val topBarBasePaddingRight = topBar.paddingRight
        val topBarBasePaddingBottom = topBar.paddingBottom

        var currentBottomInset = 0

        fun updateRecyclerPadding() {
            val inputContentHeight = messageInputContainer.height - messageInputContainer.paddingBottom
            val bottomMargin = (28 * resources.displayMetrics.density).toInt()
            messagesRecyclerView.setPadding(
                messagesRecyclerView.paddingLeft,
                messagesRecyclerView.paddingTop,
                messagesRecyclerView.paddingRight,
                currentBottomInset + inputContentHeight + bottomMargin
            )
        }

        messageInputContainer.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ ->
            updateRecyclerPadding()
        }

        ViewCompat.setOnApplyWindowInsetsListener(rootView) { _, windowInsets ->
            val systemInsets = windowInsets.getInsets(
                WindowInsetsCompat.Type.systemBars() or
                WindowInsetsCompat.Type.displayCutout()
            )

            val imeInsets = windowInsets.getInsets(WindowInsetsCompat.Type.ime())
            val imeVisible = windowInsets.isVisible(WindowInsetsCompat.Type.ime())

            // Apply top inset to header
            topBar.setPadding(
                topBarBasePaddingLeft + systemInsets.left,
                topBarBasePaddingTop + systemInsets.top,
                topBarBasePaddingRight + systemInsets.right,
                topBarBasePaddingBottom
            )

            // Apply bottom inset to message input container
            // Use IME inset when keyboard is visible, system nav bar inset otherwise
            currentBottomInset = if (imeVisible) {
                imeInsets.bottom
            } else {
                systemInsets.bottom
            }

            messageInputContainer.setPadding(
                messageInputContainer.paddingLeft,
                messageInputContainer.paddingTop,
                messageInputContainer.paddingRight,
                currentBottomInset
            )

            updateRecyclerPadding()

            // Scroll to bottom when keyboard appears
            if (imeVisible && !wasImeVisible) {
                messagesRecyclerView.post {
                    val count = messageAdapter.itemCount
                    if (count > 0) {
                        messagesRecyclerView.smoothScrollToPosition(count - 1)
                    }
                }
            }
            wasImeVisible = imeVisible

            windowInsets
        }
    }

    private fun loadMessages() {
        val currentGroupId = groupId ?: return

        lifecycleScope.launch {
            try {
                data class LoadResult(
                    val messages: List<GroupChatMessage>,
                    val pendingInvite: Boolean,
                    val canSend: Boolean
                )

                val result = withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupChatActivity)
                    val keyManager = KeyManager.getInstance(this@GroupChatActivity)
                    val db = SecureLegionDatabase.getInstance(this@GroupChatActivity, keyManager.getDatabasePassphrase())

                    // Determine local pubkey + device ID
                    if (myPubkeyHex == null) {
                        myPubkeyHex = keyManager.getSigningPublicKey()
                            .joinToString("") { "%02x".format(it) }
                    }

                    val members = mgr.queryMembers(currentGroupId)
                    val myEntry = members.find { it.pubkeyHex == myPubkeyHex }
                    myDeviceIdHex = myEntry?.deviceIdHex

                    // Build deviceIdHex → displayName and deviceIdHex → profilePhoto maps
                    val nameMap = mutableMapOf<String, String>()
                    val photoMap = mutableMapOf<String, String?>()
                    for (member in members) {
                        if (member.pubkeyHex == myPubkeyHex) continue
                        try {
                            val pubkeyBytes = member.pubkeyHex.chunked(2)
                                .map { it.toInt(16).toByte() }.toByteArray()
                            val pubkeyB64 = android.util.Base64.encodeToString(
                                pubkeyBytes, android.util.Base64.NO_WRAP
                            )
                            val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
                            val groupPeer = db.groupPeerDao().getByGroupAndPubkey(currentGroupId, member.pubkeyHex)
                            val displayName = contact?.displayName
                                ?: groupPeer?.displayName
                                ?: member.deviceIdHex.take(8)
                            nameMap[member.deviceIdHex] = displayName
                            // Photo priority: group peer photo > contact photo > null
                            photoMap[member.deviceIdHex] = groupPeer?.profilePictureBase64
                                ?: contact?.profilePictureBase64
                        } catch (_: Exception) {
                            nameMap[member.deviceIdHex] = member.deviceIdHex.take(8)
                        }
                    }

                    // Load Room Group entity for UI state checks
                    val group = db.groupDao().getGroupById(currentGroupId)

                    // Safety guard: verify group secret exists before attempting decrypt
                    if (group == null || group.groupSecretB64.isNullOrEmpty()) {
                        Log.w(TAG, "loadMessages: no group secret yet for $currentGroupId — showing empty")
                        return@withContext LoadResult(emptyList(), pendingInvite = true, canSend = false)
                    }

                    // Auto-accept invite when user opens the group chat
                    var pending = group.isPendingInvite == true
                    if (pending) {
                        try {
                            val myEntryForAccept = members.find { it.pubkeyHex == myPubkeyHex }
                            if (myEntryForAccept != null && !myEntryForAccept.accepted && myEntryForAccept.invitedByOpId.isNotEmpty()) {
                                Log.i(TAG, "Auto-accepting invite on open: opId=${myEntryForAccept.invitedByOpId}")
                                mgr.acceptInvite(currentGroupId, myEntryForAccept.invitedByOpId)
                            } else {
                                // Protocol already accepted — just clear the UI flag
                                db.groupDao().updatePendingInvite(currentGroupId, false)
                            }
                            pending = false
                            Log.i(TAG, "Auto-accepted invite for group $currentGroupId")
                        } catch (e: Exception) {
                            Log.w(TAG, "Auto-accept failed, user can re-open chat to retry", e)
                        }
                    }

                    // Query and decrypt messages
                    val messages = try {
                        mgr.queryAndDecryptMessages(currentGroupId)
                    } catch (e: Exception) {
                        Log.e(TAG, "loadMessages: decrypt failed — showing empty", e)
                        emptyList()
                    }

                    // Map to UI model
                    val mapped = messages.map { msg ->
                        val isMe = msg.authorDeviceHex == myDeviceIdHex
                        val decrypted = msg.decryptedText ?: "[Encrypted]"
                        // System messages: new format uses an invisible U+0002 sentinel;
                        // legacy "[SYSTEM] " prefix kept for backward compat with older ops.
                        val isSystem = decrypted.startsWith("\u0002") || decrypted.startsWith("[SYSTEM] ")
                        val isSticker = !isSystem && decrypted.startsWith(STICKER_PREFIX)
                        val text = when {
                            isSystem -> decrypted.removePrefix("\u0002").removePrefix("[SYSTEM] ")
                            isSticker -> decrypted.removePrefix(STICKER_PREFIX).trimStart()
                            else -> decrypted
                        }

                        GroupChatMessage(
                            messageId = msg.msgIdHex,
                            text = text,
                            timestamp = msg.timestampMs,
                            isSentByMe = isMe,
                            senderName = if (isMe) ""
                                else nameMap[msg.authorDeviceHex] ?: msg.authorDeviceHex.take(8),
                            senderProfilePhotoBase64 = if (isMe) null
                                else photoMap[msg.authorDeviceHex],
                            messageType = when {
                                isSystem -> "SYSTEM"
                                isSticker -> "STICKER"
                                else -> "TEXT"
                            }
                        )
                    }

                    // Query membership ops for system messages
                    val membershipOps = db.crdtOpLogDao().getMembershipOps(currentGroupId)
                    val systemMessages = membershipOps.mapNotNull { op ->
                        // Extract author device ID from opId format: "authorHex:lamportHex:nonceHex"
                        val authorDeviceHex = op.opId.substringBefore(":")
                        val authorName = if (authorDeviceHex == myDeviceIdHex) "You"
                            else nameMap[authorDeviceHex] ?: authorDeviceHex.take(8)

                        val text = when (op.opType) {
                            "GroupCreate" -> "$authorName created the group"
                            "MemberInvite" -> "$authorName added a new member"
                            "MemberAccept" -> "$authorName joined the group"
                            "MemberRemove" -> "$authorName removed a member"
                            "RoleSet" -> "$authorName changed a member's role"
                            "MemberMute" -> "$authorName muted a member"
                            "MemberReport" -> "$authorName reported a member"
                            else -> null
                        } ?: return@mapNotNull null

                        GroupChatMessage(
                            messageId = "sys_${op.opId}",
                            text = text,
                            timestamp = op.createdAt,
                            isSentByMe = false,
                            messageType = "SYSTEM"
                        )
                    }

                    // Merge and sort by timestamp
                    val allMessages = (mapped + systemMessages).sortedBy { it.timestamp }

                    // Check send permission: Owner/Admin always can; Members check metadata toggle
                    val myRole = myEntry?.role ?: "Member"
                    val canSend = if (myRole in listOf("Owner", "Admin")) {
                        true
                    } else {
                        val metadata = mgr.queryMetadata(currentGroupId)
                        metadata.effectiveAllowSend()
                    }

                    LoadResult(allMessages, pending, canSend)
                }

                withContext(Dispatchers.Main) {
                    isPendingInvite = result.pendingInvite
                    inviteBanner.visibility = View.GONE

                    // Determine input bar state: pending invite or send-restricted
                    val inputEnabled = !result.pendingInvite && result.canSend
                    messageInput.isEnabled = inputEnabled
                    sendButton.isEnabled = inputEnabled
                    sendButton.alpha = if (inputEnabled) 1.0f else 0.4f
                    plusButton.isEnabled = inputEnabled
                    plusButton.alpha = if (inputEnabled) 1.0f else 0.4f
                    messageInput.hint = when {
                        result.pendingInvite -> "Accept invite to send messages"
                        !result.canSend -> "Message sending not allowed"
                        else -> "Message"
                    }

                    messageAdapter.submitList(result.messages)
                    Log.i(TAG, "Loaded ${result.messages.size} messages for group: $groupName (pending=${result.pendingInvite}, canSend=${result.canSend})")

                    if (result.messages.isNotEmpty()) {
                        messagesRecyclerView.post {
                            messagesRecyclerView.smoothScrollToPosition(result.messages.size - 1)
                        }
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to load messages", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupChatActivity, "Failed to load messages")
                }
            }
        }
    }

    private fun acceptInvite() {
        val currentGroupId = groupId ?: return

        acceptInviteButton.isEnabled = false
        acceptInviteButton.text = "Accepting..."

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupChatActivity)
                    val keyManager = KeyManager.getInstance(this@GroupChatActivity)
                    val db = SecureLegionDatabase.getInstance(this@GroupChatActivity, keyManager.getDatabasePassphrase())

                    // Check if protocol already auto-accepted
                    if (myPubkeyHex == null) {
                        myPubkeyHex = keyManager.getSigningPublicKey()
                            .joinToString("") { "%02x".format(it) }
                    }

                    val members = mgr.queryMembers(currentGroupId)
                    val myEntry = members.find { it.pubkeyHex == myPubkeyHex }

                    if (myEntry != null && !myEntry.accepted && myEntry.invitedByOpId.isNotEmpty()) {
                        // Protocol hasn't auto-accepted yet — do it now
                        Log.i(TAG, "Accepting invite (protocol): opId=${myEntry.invitedByOpId}")
                        mgr.acceptInvite(currentGroupId, myEntry.invitedByOpId)
                    } else {
                        Log.i(TAG, "Protocol already accepted — just clearing UI pending state")
                    }

                    // Clear the UI-level pending flag
                    db.groupDao().updatePendingInvite(currentGroupId, false)
                }

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupChatActivity, "Invite accepted!")
                    loadMessages()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to accept invite", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupChatActivity, "Failed to accept invite: ${e.message}")
                    acceptInviteButton.isEnabled = true
                    acceptInviteButton.text = "Accept"
                }
            }
        }
    }

    private fun sendMessage() {
        val messageText = messageInput.text.toString().trim()
        if (messageText.isEmpty()) return
        sendMessageText(messageText, restoreTextOnFailure = true)
        messageInput.setText("")
    }

    private fun sendStickerMessage(assetPath: String) {
        if (assetPath.isBlank()) return
        sendMessageText("$STICKER_PREFIX $assetPath", restoreTextOnFailure = false)
    }

    private fun sendMessageText(messageText: String, restoreTextOnFailure: Boolean) {
        val currentGroupId = groupId

        if (isPendingInvite || !messageInput.isEnabled) {
            return
        }

        if (currentGroupId == null) {
            ThemedToast.show(this, "Invalid group")
            return
        }

        lifecycleScope.launch {
            try {
                // Step 1: Persist locally (synchronous Room write)
                val (opBytes, mgr) = withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupChatActivity)
                    val (opBytes, msgIdHex) = mgr.sendMessage(currentGroupId, messageText)
                    Log.i(TAG, "Message persisted: $msgIdHex (${opBytes.size} bytes)")
                    Pair(opBytes, mgr)
                }

                // Step 2: Refresh UI immediately — message is in DB, show it now
                loadMessages()

                // Ensure scroll to bottom so sender sees their message
                messagesRecyclerView.post {
                    val count = messageAdapter.itemCount
                    if (count > 0) messagesRecyclerView.smoothScrollToPosition(count - 1)
                }

                // Step 3: Broadcast to peers (fire-and-forget — network failure is non-fatal)
                withContext(Dispatchers.IO) {
                    try {
                        mgr.broadcastOpToGroup(currentGroupId, opBytes)
                    } catch (e: Exception) {
                        Log.w(TAG, "Broadcast failed (message saved locally, sync will retry): ${e.message}")
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send message", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupChatActivity, "Failed to send message: ${e.message}")
                    if (restoreTextOnFailure) {
                        messageInput.setText(messageText)
                    }
                }
            }
        }
    }

    private fun showStickerGifPicker() {
        val bottomSheet = GlassBottomSheetDialog(this)
        val mediaKeyboard = layoutInflater.inflate(R.layout.view_media_keyboard, null) as MediaKeyboardView

        mediaKeyboard.selectTab(1)
        mediaKeyboard.setOnStickerSelectedListener { assetPath ->
            bottomSheet.dismiss()
            sendStickerMessage(assetPath)
        }
        mediaKeyboard.setOnGifSelectedListener { _ ->
            bottomSheet.dismiss()
            // TODO: Group image/GIF send not yet implemented
            com.securelegion.utils.ThemedToast.show(this, "GIFs in groups coming soon")
        }
        mediaKeyboard.setOnEmojiSelectedListener { emoji ->
            val start = messageInput.selectionStart.coerceAtLeast(0)
            val end = messageInput.selectionEnd.coerceAtLeast(0)
            messageInput.text.replace(start.coerceAtMost(end), start.coerceAtLeast(end), emoji)
        }

        bottomSheet.setContentView(mediaKeyboard)
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        bottomSheet.show()
    }

    private fun showBottomSheet() {
        if (isBottomSheetVisible) return
        isBottomSheetVisible = true

        bottomSheetOverlay.visibility = View.VISIBLE
        bottomSheetOverlay.alpha = 0f
        bottomSheetOverlay.animate().alpha(1f).setDuration(200).start()

        bottomSheetContainer.visibility = View.VISIBLE
        bottomSheetContainer.translationY = bottomSheetContainer.height.toFloat()
        bottomSheetContainer.animate().translationY(0f).setDuration(300).start()
    }

    private fun hideBottomSheet() {
        if (!isBottomSheetVisible) return
        isBottomSheetVisible = false

        bottomSheetOverlay.animate().alpha(0f).setDuration(200)
            .withEndAction { bottomSheetOverlay.visibility = View.GONE }.start()

        bottomSheetContainer.animate()
            .translationY(bottomSheetContainer.height.toFloat()).setDuration(300)
            .withEndAction { bottomSheetContainer.visibility = View.GONE }.start()
    }

    private fun showAddMemberDialog() {
        lifecycleScope.launch {
            try {
                val contacts = withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@GroupChatActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupChatActivity, dbPassphrase)
                    database.contactDao().getAllContacts()
                }

                withContext(Dispatchers.Main) {
                    if (contacts.isEmpty()) {
                        ThemedToast.show(this@GroupChatActivity, "No contacts available. Add friends first!")
                        return@withContext
                    }

                    val contactNames = contacts.map { it.displayName }.toTypedArray()
                    val selectedContacts = mutableListOf<Contact>()

                    val addMembersDialog = GlassDialog.builder(this@GroupChatActivity)
                        .setTitle("Add Members to Group")
                        .setMultiChoiceItems(contactNames, null) { _, which, isChecked ->
                            if (isChecked) {
                                selectedContacts.add(contacts[which])
                            } else {
                                selectedContacts.remove(contacts[which])
                            }
                        }
                        .setPositiveButton("Add") { dialog, _ ->
                            if (selectedContacts.isEmpty()) {
                                ThemedToast.show(this@GroupChatActivity, "No contacts selected")
                            } else {
                                addMembersToGroup(selectedContacts)
                            }
                            dialog.dismiss()
                        }
                        .setNegativeButton("Cancel", null)
                        .create()
                    GlassDialog.show(addMembersDialog)
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contacts", e)
                ThemedToast.show(this@GroupChatActivity, "Failed to load contacts")
            }
        }
    }

    private fun addMembersToGroup(contacts: List<Contact>) {
        val currentGroupId = groupId
        if (currentGroupId == null) {
            ThemedToast.show(this, "Invalid group")
            return
        }

        // Enforce 20-member group limit
        lifecycleScope.launch {
            val existing = withContext(Dispatchers.IO) {
                CrdtGroupManager.getInstance(this@GroupChatActivity)
                    .queryMembers(currentGroupId)
                    .count { !it.removed }
            }
            if (existing + contacts.size > AddGroupMembersActivity.MAX_GROUP_MEMBERS) {
                ThemedToast.show(this@GroupChatActivity, "Groups are limited to ${AddGroupMembersActivity.MAX_GROUP_MEMBERS} members")
                return@launch
            }
            addMembersToGroupInternal(currentGroupId, contacts)
        }
    }

    private fun addMembersToGroupInternal(currentGroupId: String, contacts: List<Contact>) {

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupChatActivity)
                    for ((index, contact) in contacts.withIndex()) {
                        val pubkeyHex = contact.ed25519PublicKeyBytes
                            .joinToString("") { "%02x".format(it) }
                        mgr.inviteMember(currentGroupId, pubkeyHex)
                        Log.i(TAG, "Invited ${contact.displayName}")
                        // Backpressure: give Tor circuits time to settle between invites
                        if (index < contacts.size - 1) {
                            kotlinx.coroutines.delay(800)
                        }
                    }
                }

                withContext(Dispatchers.Main) {
                    val memberNames = contacts.joinToString(", ") { it.displayName }
                    ThemedToast.show(this@GroupChatActivity, "Invited: $memberNames")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to add members", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupChatActivity, "Failed to add members: ${e.message}")
                }
            }
        }
    }

    @Deprecated("Use OnBackPressedDispatcher")
    @Suppress("GestureBackNavigation", "DEPRECATION")
    override fun onBackPressed() {
        if (isBottomSheetVisible) {
            hideBottomSheet()
        } else {
            super.onBackPressed()
        }
    }

    override fun onResume() {
        super.onResume()
        val filter = IntentFilter("com.securelegion.NEW_GROUP_MESSAGE")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(groupMessageReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(groupMessageReceiver, filter)
        }

        // Tell TorService this group is on-screen so new-message notifications
        // for it are suppressed while the user is here.
        com.securelegion.services.TorService.activeGroupId = groupId

        // Dismiss any lingering notifications for this group (e.g. queued while
        // the user was elsewhere but tapped into the group list).
        groupId?.let { gid ->
            try {
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as android.app.NotificationManager
                // Group-message notifications use a group key of "GROUP_MESSAGES_${groupId}"
                for (notif in nm.activeNotifications) {
                    if (notif.notification.group == "GROUP_MESSAGES_$gid") {
                        nm.cancel(notif.id)
                    }
                }
            } catch (_: Exception) { }
        }

        refreshMemberCount()

        // Clear unread badge when user opens this group chat
        val currentGroupId = groupId ?: return
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                CrdtGroupManager.getInstance(this@GroupChatActivity).clearUnreadCount(currentGroupId)
            } catch (_: Exception) { }
        }

        // Full sync on resume: flush pending + routing + pull ops + profile photo
        lifecycleScope.launch {
            try {
                kotlinx.coroutines.withContext(Dispatchers.IO) {
                    CrdtGroupManager.getInstance(this@GroupChatActivity)
                        .fullSync(currentGroupId)
                }
                loadMessages()
                refreshMemberCount()
            } catch (e: Exception) {
                Log.w(TAG, "Full sync failed (non-fatal)", e)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        // Clear active-group marker only if it still points at us — avoids
        // clobbering if another GroupChatActivity already took over (e.g. deep
        // linking from one group notification while another is on-screen).
        if (com.securelegion.services.TorService.activeGroupId == groupId) {
            com.securelegion.services.TorService.activeGroupId = null
        }
        try {
            unregisterReceiver(groupMessageReceiver)
        } catch (e: Exception) {
            // Receiver wasn't registered
        }
    }
}
