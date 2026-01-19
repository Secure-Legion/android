package com.securelegion

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.view.animation.AnimationUtils
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.GroupMessage
import com.securelegion.services.GroupManager
import com.securelegion.ui.adapters.GroupMessageAdapter
import com.securelegion.utils.ThemedToast
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
    private lateinit var groupNameTitle: TextView
    private lateinit var settingsIcon: FrameLayout
    private lateinit var messagesRecyclerView: RecyclerView
    private lateinit var messageInput: EditText
    private lateinit var plusButton: FrameLayout
    private lateinit var micButton: FrameLayout
    private lateinit var bottomSheetOverlay: View
    private lateinit var bottomSheetContainer: LinearLayout
    private lateinit var sendImageOption: View
    private lateinit var addFriendOption: View
    private lateinit var cancelButton: TextView

    // Data
    private var groupId: String? = null
    private var groupName: String = "Group"
    private var isBottomSheetVisible = false
    private lateinit var messageAdapter: GroupMessageAdapter

    // Broadcast receiver for new group messages
    private val groupMessageReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == "com.securelegion.NEW_GROUP_MESSAGE") {
                val receivedGroupId = intent.getStringExtra("GROUP_ID")
                if (receivedGroupId == groupId) {
                    Log.d(TAG, "Received NEW_GROUP_MESSAGE broadcast - reloading messages")
                    runOnUiThread {
                        loadMessages()
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_group_chat)

        // Get group data from intent
        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        groupName = intent.getStringExtra(EXTRA_GROUP_NAME) ?: "Group"

        initializeViews()
        setupClickListeners()
        setupRecyclerView()
        loadMessages()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        groupNameTitle = findViewById(R.id.groupNameTitle)
        settingsIcon = findViewById(R.id.settingsIcon)
        messagesRecyclerView = findViewById(R.id.messagesRecyclerView)
        messageInput = findViewById(R.id.messageInput)
        plusButton = findViewById(R.id.plusButton)
        micButton = findViewById(R.id.micButton)
        bottomSheetOverlay = findViewById(R.id.bottomSheetOverlay)
        bottomSheetContainer = findViewById(R.id.bottomSheetContainer)
        sendImageOption = findViewById(R.id.sendImageOption)
        addFriendOption = findViewById(R.id.addFriendOption)
        cancelButton = findViewById(R.id.cancelButton)

        // Set group name
        groupNameTitle.text = groupName
    }

    private fun setupClickListeners() {
        // Back button
        backButton.setOnClickListener {
            finish()
        }

        // Settings icon - opens group profile
        settingsIcon.setOnClickListener {
            val intent = Intent(this, GroupProfileActivity::class.java)
            intent.putExtra(GroupProfileActivity.EXTRA_GROUP_ID, groupId)
            intent.putExtra(GroupProfileActivity.EXTRA_GROUP_NAME, groupName)
            startActivity(intent)
            overridePendingTransition(R.anim.slide_in_right, R.anim.slide_out_left)
        }

        // Plus button - show bottom sheet
        plusButton.setOnClickListener {
            showBottomSheet()
        }

        // Mic button
        micButton.setOnClickListener {
            // TODO: Implement voice message recording when voice messaging is complete
            ThemedToast.show(this, "Voice messages - Coming soon")
        }

        // Bottom sheet overlay - close bottom sheet when tapped
        bottomSheetOverlay.setOnClickListener {
            hideBottomSheet()
        }

        // Send Image option
        sendImageOption.setOnClickListener {
            hideBottomSheet()
            // TODO: Implement image sending when implemented
            ThemedToast.show(this, "Send image - Coming soon")
            Log.i(TAG, "Send image clicked")
        }

        // Add Friend option - show contact selection
        addFriendOption.setOnClickListener {
            hideBottomSheet()
            showAddMemberDialog()
        }

        // Cancel button
        cancelButton.setOnClickListener {
            hideBottomSheet()
        }

        // Send message when user types (demo)
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
        // Initialize message adapter
        messageAdapter = GroupMessageAdapter(
            onMessageClick = { message ->
                // Handle message click (e.g., show message details)
                Log.d(TAG, "Message clicked: ${message.messageId}")
            },
            onMessageLongClick = { message ->
                // Handle long click (e.g., show delete/copy options)
                Log.d(TAG, "Message long-clicked: ${message.messageId}")
            }
        )

        messagesRecyclerView.layoutManager = LinearLayoutManager(this).apply {
            stackFromEnd = true
        }
        messagesRecyclerView.adapter = messageAdapter

        Log.d(TAG, "RecyclerView setup complete")
    }

    private fun loadMessages() {
        val currentGroupId = groupId ?: return

        lifecycleScope.launch {
            try {
                val messages = withContext(Dispatchers.IO) {
                    val keyManager = KeyManager.getInstance(this@GroupChatActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupChatActivity, dbPassphrase)

                    // Get group to decrypt group key
                    val group = database.groupDao().getGroupById(currentGroupId)
                        ?: return@withContext emptyList<GroupMessage>()

                    // Decrypt group key
                    val groupManager = GroupManager.getInstance(this@GroupChatActivity)
                    val groupKey = groupManager.decryptGroupKeyFromStorage(group.encryptedGroupKeyBase64)

                    // Load messages
                    val encryptedMessages = database.groupMessageDao().getMessagesForGroup(currentGroupId)

                    // Decrypt message content
                    encryptedMessages.forEach { message ->
                        try {
                            // Skip system messages (they're not encrypted with group key)
                            if (message.messageType == GroupMessage.MESSAGE_TYPE_SYSTEM) {
                                message.decryptedContent = String(
                                    Base64.decode(message.encryptedContent, Base64.NO_WRAP),
                                    Charsets.UTF_8
                                )
                            } else {
                                // Decrypt with AES-256-GCM using group key
                                val decrypted = groupManager.decryptGroupMessage(
                                    message.encryptedContent,
                                    message.nonceBase64,
                                    groupKey
                                )
                                message.decryptedContent = decrypted
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to decrypt message ${message.messageId}", e)
                            message.decryptedContent = "[Decryption failed]"
                        }
                    }

                    encryptedMessages
                }

                withContext(Dispatchers.Main) {
                    messageAdapter.submitList(messages)
                    Log.i(TAG, "Loaded ${messages.size} messages for group: $groupName")

                    // Scroll to bottom if there are messages
                    if (messages.isNotEmpty()) {
                        messagesRecyclerView.scrollToPosition(messages.size - 1)
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

    private fun sendMessage() {
        val messageText = messageInput.text.toString().trim()
        val currentGroupId = groupId

        if (messageText.isEmpty()) {
            return
        }

        if (currentGroupId == null) {
            ThemedToast.show(this, "Invalid group")
            return
        }

        // Clear input immediately
        messageInput.text.clear()

        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val groupManager = GroupManager.getInstance(this@GroupChatActivity)

                    // Send message using GroupManager
                    val result = groupManager.sendGroupMessage(currentGroupId, messageText)

                    if (result.isFailure) {
                        throw result.exceptionOrNull() ?: Exception("Failed to send message")
                    }

                    Log.i(TAG, "Message sent successfully: ${result.getOrNull()}")
                }

                // Reload messages to show the new message
                loadMessages()

                withContext(Dispatchers.Main) {
                    Log.d(TAG, "Message sent: $messageText")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to send message", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupChatActivity, "Failed to send message: ${e.message}")
                    // Restore message text so user can try again
                    messageInput.setText(messageText)
                }
            }
        }
    }

    private fun showBottomSheet() {
        if (isBottomSheetVisible) return

        isBottomSheetVisible = true

        // Show overlay
        bottomSheetOverlay.visibility = View.VISIBLE
        bottomSheetOverlay.alpha = 0f
        bottomSheetOverlay.animate()
            .alpha(1f)
            .setDuration(200)
            .start()

        // Show bottom sheet with slide up animation
        bottomSheetContainer.visibility = View.VISIBLE
        bottomSheetContainer.translationY = bottomSheetContainer.height.toFloat()
        bottomSheetContainer.animate()
            .translationY(0f)
            .setDuration(300)
            .start()

        Log.d(TAG, "Bottom sheet shown")
    }

    private fun hideBottomSheet() {
        if (!isBottomSheetVisible) return

        isBottomSheetVisible = false

        // Hide overlay
        bottomSheetOverlay.animate()
            .alpha(0f)
            .setDuration(200)
            .withEndAction {
                bottomSheetOverlay.visibility = View.GONE
            }
            .start()

        // Hide bottom sheet with slide down animation
        bottomSheetContainer.animate()
            .translationY(bottomSheetContainer.height.toFloat())
            .setDuration(300)
            .withEndAction {
                bottomSheetContainer.visibility = View.GONE
            }
            .start()

        Log.d(TAG, "Bottom sheet hidden")
    }

    private fun showAddMemberDialog() {
        lifecycleScope.launch {
            try {
                val contacts = withContext(Dispatchers.IO) {
                    // Get all contacts
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

                    // Show contact selection dialog
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
                    val keyManager = KeyManager.getInstance(this@GroupChatActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@GroupChatActivity, dbPassphrase)

                    // Add members to group
                    val timestamp = System.currentTimeMillis()
                    val groupMembers = contacts.map { contact ->
                        com.securelegion.database.entities.GroupMember(
                            groupId = currentGroupId,
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
                    ThemedToast.show(this@GroupChatActivity, "Added: $memberNames")
                    Log.i(TAG, "Members added successfully")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to add members", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@GroupChatActivity, "Failed to add members: ${e.message}")
                }
            }
        }
    }

    @Suppress("GestureBackNavigation")  // Bottom sheet handling handled via hideBottomSheet()
    override fun onBackPressed() {
        if (isBottomSheetVisible) {
            hideBottomSheet()
        } else {
            super.onBackPressed()
        }
    }

    override fun onResume() {
        super.onResume()
        // Register broadcast receiver for new group messages
        val filter = IntentFilter("com.securelegion.NEW_GROUP_MESSAGE")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(groupMessageReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")  // RECEIVER_NOT_EXPORTED not available in API < 31
            registerReceiver(groupMessageReceiver, filter)
        }
        Log.d(TAG, "Registered NEW_GROUP_MESSAGE receiver")
    }

    override fun onPause() {
        super.onPause()
        // Unregister broadcast receiver
        try {
            unregisterReceiver(groupMessageReceiver)
            Log.d(TAG, "Unregistered NEW_GROUP_MESSAGE receiver")
        } catch (e: Exception) {
            // Receiver wasn't registered
        }
    }
}
