package com.securelegion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
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
    }

    // Views
    private lateinit var backButton: View
    private lateinit var groupAvatar: com.securelegion.views.AvatarView
    private lateinit var groupNameTitle: TextView
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
    private var isShowingSendButton = false
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

        // Load group avatar
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
        }
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener { finish() }

        settingsIcon.setOnClickListener {
            val intent = Intent(this, GroupProfileActivity::class.java)
            intent.putExtra(GroupProfileActivity.EXTRA_GROUP_ID, groupId)
            intent.putExtra(GroupProfileActivity.EXTRA_GROUP_NAME, groupName)
            startActivity(intent)
            overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left)
        }

        plusButton.setOnClickListener { showBottomSheet() }

        // Send/Mic button — sends text when text present, voice coming soon
        sendButton.setOnClickListener {
            if (isShowingSendButton) {
                sendMessage()
            } else {
                ThemedToast.show(this, "Voice messages - Coming soon")
            }
        }

        // Monitor text input to switch between mic and send icon
        messageInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                val hasText = !s.isNullOrBlank()
                if (hasText && !isShowingSendButton) {
                    sendButtonIcon.setImageResource(R.drawable.ic_send)
                    isShowingSendButton = true
                } else if (!hasText && isShowingSendButton) {
                    sendButtonIcon.setImageResource(R.drawable.ic_mic)
                    isShowingSendButton = false
                }
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        bottomSheetOverlay.setOnClickListener { hideBottomSheet() }

        sendImageOption.setOnClickListener {
            hideBottomSheet()
            ThemedToast.show(this, "Send image - Coming soon")
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
    }

    private fun setupWindowInsets() {
        val rootView = findViewById<View>(android.R.id.content)
        val topBar = findViewById<View>(R.id.topBar)
        val messageInputContainer = findViewById<View>(R.id.messageInputContainer)
        var wasImeVisible = false

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
                topBar.paddingLeft,
                systemInsets.top,
                topBar.paddingRight,
                topBar.paddingBottom
            )

            // Apply bottom inset to message input container
            currentBottomInset = if (imeVisible) {
                imeInsets.bottom
            } else {
                0
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
                val (chatMessages, pendingInvite) = withContext(Dispatchers.IO) {
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

                    // Build deviceIdHex → displayName map
                    val nameMap = mutableMapOf<String, String>()
                    for (member in members) {
                        if (member.pubkeyHex == myPubkeyHex) continue
                        try {
                            val pubkeyBytes = member.pubkeyHex.chunked(2)
                                .map { it.toInt(16).toByte() }.toByteArray()
                            val pubkeyB64 = android.util.Base64.encodeToString(
                                pubkeyBytes, android.util.Base64.NO_WRAP
                            )
                            val contact = db.contactDao().getContactByPublicKey(pubkeyB64)
                            nameMap[member.deviceIdHex] = contact?.displayName
                                ?: member.deviceIdHex.take(8)
                        } catch (_: Exception) {
                            nameMap[member.deviceIdHex] = member.deviceIdHex.take(8)
                        }
                    }

                    // Load Room Group entity for UI state checks
                    val group = db.groupDao().getGroupById(currentGroupId)

                    // Safety guard: verify group secret exists before attempting decrypt
                    if (group == null || group.groupSecretB64.isNullOrEmpty()) {
                        Log.w(TAG, "loadMessages: no group secret yet for $currentGroupId — showing empty")
                        return@withContext Pair(emptyList<GroupChatMessage>(), true)
                    }

                    // UI-level pending: protocol auto-accepts immediately so we can decrypt,
                    // but UI stays pending until user explicitly taps Accept.
                    val pending = group.isPendingInvite == true

                    // Query and decrypt messages
                    val messages = try {
                        mgr.queryAndDecryptMessages(currentGroupId)
                    } catch (e: Exception) {
                        Log.e(TAG, "loadMessages: decrypt failed — showing empty", e)
                        emptyList()
                    }

                    // Map to UI model
                    val mapped = messages.map { msg ->
                        GroupChatMessage(
                            messageId = msg.msgIdHex,
                            text = msg.decryptedText ?: "[Encrypted]",
                            timestamp = msg.timestampMs,
                            isSentByMe = msg.authorDeviceHex == myDeviceIdHex,
                            senderName = if (msg.authorDeviceHex == myDeviceIdHex) ""
                                else nameMap[msg.authorDeviceHex] ?: msg.authorDeviceHex.take(8)
                        )
                    }

                    Pair(mapped, pending)
                }

                withContext(Dispatchers.Main) {
                    // Update invite banner visibility
                    isPendingInvite = pendingInvite
                    if (pendingInvite) {
                        inviteBanner.visibility = View.VISIBLE
                        messageInput.isEnabled = false
                        messageInput.hint = "Accept invite to send messages"
                    } else {
                        inviteBanner.visibility = View.GONE
                        messageInput.isEnabled = true
                        messageInput.hint = "Message"
                    }

                    messageAdapter.submitList(chatMessages)
                    Log.i(TAG, "Loaded ${chatMessages.size} messages for group: $groupName (pending=$pendingInvite)")

                    if (chatMessages.isNotEmpty()) {
                        messagesRecyclerView.post {
                            messagesRecyclerView.smoothScrollToPosition(chatMessages.size - 1)
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
        val currentGroupId = groupId

        if (messageText.isEmpty()) return

        if (isPendingInvite) {
            ThemedToast.show(this, "Accept the invite first")
            return
        }

        if (currentGroupId == null) {
            ThemedToast.show(this, "Invalid group")
            return
        }

        messageInput.text.clear()

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupChatActivity)
                    val (opBytes, msgIdHex) = mgr.sendMessage(currentGroupId, messageText)
                    Log.i(TAG, "Message sent: $msgIdHex (${opBytes.size} bytes)")
                    mgr.broadcastOpToGroup(currentGroupId, opBytes)
                }

                loadMessages()

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send message", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupChatActivity, "Failed to send message: ${e.message}")
                    messageInput.setText(messageText)
                }
            }
        }
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

                    AlertDialog.Builder(this@GroupChatActivity)
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
                        .show()
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

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@GroupChatActivity)
                    for (contact in contacts) {
                        val pubkeyHex = contact.ed25519PublicKeyBytes
                            .joinToString("") { "%02x".format(it) }
                        mgr.inviteMember(currentGroupId, pubkeyHex)
                        Log.i(TAG, "Invited ${contact.displayName}")
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

    @Suppress("GestureBackNavigation")
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

        // Pull-based sync: request missing ops from peers on every resume
        val currentGroupId = groupId ?: return
        lifecycleScope.launch {
            try {
                kotlinx.coroutines.withContext(Dispatchers.IO) {
                    CrdtGroupManager.getInstance(this@GroupChatActivity)
                        .requestSyncToAllPeers(currentGroupId)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Sync request failed (non-fatal)", e)
            }
        }
    }

    override fun onPause() {
        super.onPause()
        try {
            unregisterReceiver(groupMessageReceiver)
        } catch (e: Exception) {
            // Receiver wasn't registered
        }
    }
}
