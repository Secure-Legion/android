package com.securelegion

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.util.Patterns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.MediaGridAdapter
import com.securelegion.adapters.VoiceClipAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Message
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class ContactOptionsActivity : BaseActivity() {

    companion object {
        private const val TAG = "ContactOptions"
    }

    private lateinit var contactName: TextView
    private lateinit var contactNickname: TextView
    private lateinit var editNicknameButton: TextView
    private lateinit var profilePicture: ImageView
    private lateinit var blockContactSwitch: androidx.appcompat.widget.SwitchCompat
    private lateinit var trustedContactSwitch: androidx.appcompat.widget.SwitchCompat
    private lateinit var trustedStarIcon: ImageView
    private var fullAddress: String = ""
    private var contactId: Long = -1
    private var isTrustedContact: Boolean = false
    private var isBlocked: Boolean = false
    private var isMuted: Boolean = false
    private var currentNickname: String? = null

    // Tab views
    private lateinit var tabMedia: TextView
    private lateinit var tabVoice: TextView
    private lateinit var tabFiles: TextView
    private lateinit var tabLinks: TextView
    private lateinit var tabGroups: TextView
    private lateinit var mediaTabContent: View
    private lateinit var voiceTabContent: View
    private lateinit var filesTabContent: View
    private lateinit var linksTabContent: View
    private lateinit var groupsTabContent: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_contact_options)

        // Get contact info from intent
        contactId = intent.getLongExtra("CONTACT_ID", -1L)
        val name = intent.getStringExtra("CONTACT_NAME") ?: "@unknown"
        val address = intent.getStringExtra("CONTACT_ADDRESS") ?: ""
        fullAddress = address

        initializeViews()
        setupContactInfo(name)
        loadContactStatus()
        setupClickListeners(name)
        setupTabs()
        loadMediaContent()
        loadVoiceContent()
        loadLinksContent()
        loadGroupsContent()
    }

    private fun initializeViews() {
        contactName = findViewById(R.id.contactName)
        contactNickname = findViewById(R.id.contactNickname)
        editNicknameButton = findViewById(R.id.editNicknameButton)
        profilePicture = findViewById(R.id.profilePicture)
        blockContactSwitch = findViewById(R.id.blockContactSwitch)
        trustedContactSwitch = findViewById(R.id.trustedContactSwitch)
        trustedStarIcon = findViewById(R.id.trustedStarIcon)

        // Tab views
        tabMedia = findViewById(R.id.tabMedia)
        tabVoice = findViewById(R.id.tabVoice)
        tabFiles = findViewById(R.id.tabFiles)
        tabLinks = findViewById(R.id.tabLinks)
        tabGroups = findViewById(R.id.tabGroups)
        mediaTabContent = findViewById(R.id.mediaTabContent)
        voiceTabContent = findViewById(R.id.voiceTabContent)
        filesTabContent = findViewById(R.id.filesTabContent)
        linksTabContent = findViewById(R.id.linksTabContent)
        groupsTabContent = findViewById(R.id.groupsTabContent)
    }

    private fun setupContactInfo(name: String) {
        contactName.text = name
        com.securelegion.utils.TextGradient.apply(contactName)
    }

    private fun loadContactStatus() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) return@launch

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                val contact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactById(contactId)
                }

                if (contact != null) {
                    isTrustedContact = contact.isDistressContact
                    isBlocked = contact.isBlocked
                    currentNickname = contact.nickname
                    updateNicknameUI(contact.displayName)
                    updateTrustedContactUI()
                    updateBlockUI()
                    loadMuteStatus()

                    // Load contact's profile photo
                    if (!contact.profilePictureBase64.isNullOrEmpty()) {
                        try {
                            val photoBytes = android.util.Base64.decode(contact.profilePictureBase64, android.util.Base64.NO_WRAP)
                            val bitmap = android.graphics.BitmapFactory.decodeByteArray(photoBytes, 0, photoBytes.size)
                            if (bitmap != null) {
                                profilePicture.setImageBitmap(bitmap)
                                Log.d(TAG, "Loaded contact profile photo (${photoBytes.size} bytes)")
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to decode contact profile photo", e)
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load contact status", e)
            }
        }
    }

    private fun updateBlockUI() {
        blockContactSwitch.isChecked = isBlocked
        val blockLabel = findViewById<TextView>(R.id.blockLabel)
        val blockIcon = findViewById<ImageView>(R.id.blockIcon)
        if (isBlocked) {
            blockLabel?.text = "unblock"
            blockIcon?.setColorFilter(android.graphics.Color.parseColor("#FF4444"))
        } else {
            blockLabel?.text = "block"
            blockIcon?.clearColorFilter()
        }
    }

    private fun updateTrustedContactUI() {
        trustedContactSwitch.isChecked = isTrustedContact
        val favLabel = findViewById<TextView>(R.id.favLabel)
        if (isTrustedContact) {
            trustedStarIcon.setImageResource(R.drawable.ic_star_filled)
            trustedStarIcon.setColorFilter(android.graphics.Color.WHITE)
            favLabel?.text = "uncircle"
        } else {
            trustedStarIcon.setImageResource(R.drawable.ic_star_outline)
            trustedStarIcon.clearColorFilter()
            favLabel?.text = "circle"
        }
    }

    private fun loadMuteStatus() {
        val prefs = getSharedPreferences("muted_contacts", MODE_PRIVATE)
        isMuted = prefs.getBoolean("muted_$contactId", false)
        updateMuteUI()
    }

    private fun updateMuteUI() {
        val muteIcon = findViewById<ImageView>(R.id.muteIcon)
        val muteLabel = findViewById<TextView>(R.id.muteLabel)
        if (isMuted) {
            muteIcon?.setImageResource(R.drawable.ic_bell_muted)
            muteLabel?.text = "unmute"
        } else {
            muteIcon?.setImageResource(R.drawable.ic_bell)
            muteLabel?.text = "mute"
        }
    }

    private fun toggleMuteStatus() {
        isMuted = !isMuted
        val prefs = getSharedPreferences("muted_contacts", MODE_PRIVATE)
        prefs.edit().putBoolean("muted_$contactId", isMuted).apply()
        updateMuteUI()

        val message = if (isMuted) "Contact muted" else "Contact unmuted"
        ThemedToast.show(this, message)
        Log.i(TAG, "Mute status updated: $isMuted")
    }

    private fun toggleTrustedContactStatus() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) {
                    ThemedToast.show(this@ContactOptionsActivity, "Error: Invalid contact")
                    return@launch
                }

                isTrustedContact = !isTrustedContact

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                withContext(Dispatchers.IO) {
                    database.contactDao().updateDistressContactStatus(contactId, isTrustedContact)
                }

                updateTrustedContactUI()

                val message = if (isTrustedContact) "Trusted contact enabled" else "Trusted contact disabled"
                ThemedToast.show(this@ContactOptionsActivity, message)
                Log.i(TAG, "Trusted contact status updated: $isTrustedContact")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to toggle trusted contact status", e)
                ThemedToast.show(this@ContactOptionsActivity, "Failed to update status")
            }
        }
    }

    private fun toggleBlockStatus() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) {
                    ThemedToast.show(this@ContactOptionsActivity, "Error: Invalid contact")
                    return@launch
                }

                isBlocked = !isBlocked

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                withContext(Dispatchers.IO) {
                    database.contactDao().updateBlockedStatus(contactId, isBlocked)
                }

                updateBlockUI()

                val message = if (isBlocked) "Contact blocked" else "Contact unblocked"
                ThemedToast.show(this@ContactOptionsActivity, message)
                Log.i(TAG, "Blocked status updated: $isBlocked")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to toggle blocked status", e)
                ThemedToast.show(this@ContactOptionsActivity, "Failed to update status")
            }
        }
    }

    private fun updateNicknameUI(username: String) {
        if (!currentNickname.isNullOrBlank()) {
            // Nickname is set — show nickname large, username smaller below
            contactNickname.text = currentNickname
            contactNickname.visibility = View.VISIBLE
            com.securelegion.utils.TextGradient.apply(contactNickname)

            contactName.textSize = 14f
            contactName.text = username
            contactName.setTextColor(android.graphics.Color.parseColor("#6C6C6C"))

            editNicknameButton.text = "Edit Nickname"
        } else {
            // No nickname — show username large
            contactNickname.visibility = View.GONE
            contactName.textSize = 26f
            contactName.text = username
            contactName.setTextColor(resources.getColor(R.color.lock_title_gray, theme))
            com.securelegion.utils.TextGradient.apply(contactName)

            editNicknameButton.text = "Set Nickname"
        }
    }

    private fun showNicknameDialog(username: String) {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_edit_nickname, null)
        bottomSheet.setContentView(view)

        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.skipCollapsed = true

        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        val nicknameInput = view.findViewById<android.widget.EditText>(R.id.nicknameInput)
        nicknameInput.setText(currentNickname ?: "")
        nicknameInput.setSelection(nicknameInput.text.length)

        view.findViewById<View>(R.id.saveNicknameButton).setOnClickListener {
            val newNickname = nicknameInput.text.toString().trim()
            saveNickname(if (newNickname.isEmpty()) null else newNickname, username)
            bottomSheet.dismiss()
        }

        view.findViewById<View>(R.id.clearNicknameButton).setOnClickListener {
            saveNickname(null, username)
            bottomSheet.dismiss()
        }

        bottomSheet.show()

        // Auto-show keyboard
        nicknameInput.requestFocus()
        nicknameInput.postDelayed({
            val imm = getSystemService(android.content.Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
            imm.showSoftInput(nicknameInput, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)
        }, 200)
    }

    private fun saveNickname(nickname: String?, username: String) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                if (contactId == -1L) return@launch

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                withContext(Dispatchers.IO) {
                    database.contactDao().updateContactNickname(contactId, nickname)
                }

                currentNickname = nickname
                updateNicknameUI(username)

                val message = if (nickname != null) "Nickname set" else "Nickname cleared"
                ThemedToast.show(this@ContactOptionsActivity, message)
                Log.i(TAG, "Nickname updated: $nickname")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to save nickname", e)
                ThemedToast.show(this@ContactOptionsActivity, "Failed to save nickname")
            }
        }
    }

    private fun setupClickListeners(name: String) {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Nickname edit button
        editNicknameButton.setOnClickListener {
            showNicknameDialog(name)
        }

        // Message action
        findViewById<View>(R.id.actionMessage).setOnClickListener {
            val intent = Intent(this, ChatActivity::class.java)
            intent.putExtra(ChatActivity.EXTRA_CONTACT_ID, contactId)
            intent.putExtra(ChatActivity.EXTRA_CONTACT_NAME, currentNickname ?: name)
            intent.putExtra(ChatActivity.EXTRA_CONTACT_ADDRESS, fullAddress)
            startActivity(intent)
        }

        // Mute action
        findViewById<View>(R.id.actionMute).setOnClickListener {
            toggleMuteStatus()
        }

        // Fav action (trusted contact toggle)
        findViewById<View>(R.id.actionFav).setOnClickListener {
            toggleTrustedContactStatus()
        }

        // Delete action
        findViewById<View>(R.id.actionDelete).setOnClickListener {
            showDeleteConfirmationDialog(name)
        }

        // Block action button
        findViewById<View>(R.id.actionBlock).setOnClickListener {
            toggleBlockStatus()
        }
    }

    private fun setupTabs() {
        val tabs = listOf(tabMedia, tabVoice, tabFiles, tabLinks, tabGroups)
        val contents = listOf(mediaTabContent, voiceTabContent, filesTabContent, linksTabContent, groupsTabContent)

        fun selectTab(index: Int) {
            tabs.forEachIndexed { i, tab ->
                if (i == index) {
                    tab.setBackgroundResource(R.drawable.contact_tab_active)
                    tab.setTextColor(0xFFFFFFFF.toInt())
                } else {
                    tab.setBackgroundResource(R.drawable.contact_tab_inactive)
                    tab.setTextColor(0xFF666666.toInt())
                }
            }
            contents.forEachIndexed { i, content ->
                content.visibility = if (i == index) View.VISIBLE else View.GONE
            }
        }

        tabMedia.setOnClickListener { selectTab(0) }
        tabVoice.setOnClickListener { selectTab(1) }
        tabFiles.setOnClickListener { selectTab(2) }
        tabLinks.setOnClickListener { selectTab(3) }
        tabGroups.setOnClickListener { selectTab(4) }

        // Default to Media tab
        selectTab(0)
    }

    private fun loadMediaContent() {
        if (contactId == -1L) return

        CoroutineScope(Dispatchers.Main).launch {
            try {
                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                val imageMessages = withContext(Dispatchers.IO) {
                    database.messageDao().getImageMessagesForContact(contactId)
                }

                val mediaRecyclerView = findViewById<RecyclerView>(R.id.mediaRecyclerView)
                val mediaEmptyState = findViewById<TextView>(R.id.mediaEmptyState)

                if (imageMessages.isEmpty()) {
                    mediaRecyclerView.visibility = View.GONE
                    mediaEmptyState.visibility = View.VISIBLE
                    return@launch
                }

                // Convert to MediaItem list, filtering out entries without attachment data
                val mediaItems = imageMessages.mapNotNull { msg ->
                    val data = msg.attachmentData
                    if (!data.isNullOrEmpty()) {
                        MediaGridAdapter.MediaItem(
                            attachmentData = data,
                            messageId = msg.messageId,
                            timestamp = msg.timestamp
                        )
                    } else null
                }

                if (mediaItems.isEmpty()) {
                    mediaRecyclerView.visibility = View.GONE
                    mediaEmptyState.visibility = View.VISIBLE
                    return@launch
                }

                mediaEmptyState.visibility = View.GONE
                mediaRecyclerView.visibility = View.VISIBLE
                mediaRecyclerView.layoutManager = GridLayoutManager(this@ContactOptionsActivity, 3)
                mediaRecyclerView.adapter = MediaGridAdapter(
                    mediaItems = mediaItems,
                    decryptImage = { encryptedBytes ->
                        keyManager.decryptImageFile(encryptedBytes)
                    }
                )

                Log.d(TAG, "Loaded ${mediaItems.size} media items for contact")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load media content", e)
            }
        }
    }

    private fun loadVoiceContent() {
        if (contactId == -1L) return

        CoroutineScope(Dispatchers.Main).launch {
            try {
                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                val voiceMessages = withContext(Dispatchers.IO) {
                    database.messageDao().getVoiceMessagesForContact(contactId)
                }

                val voiceRecyclerView = findViewById<RecyclerView>(R.id.voiceRecyclerView)
                val voiceEmptyState = findViewById<TextView>(R.id.voiceEmptyState)

                if (voiceMessages.isEmpty()) {
                    voiceRecyclerView.visibility = View.GONE
                    voiceEmptyState.visibility = View.VISIBLE
                    return@launch
                }

                val voiceItems = voiceMessages.map { msg ->
                    VoiceClipAdapter.VoiceItem(
                        voiceFilePath = msg.voiceFilePath,
                        durationSeconds = msg.voiceDuration ?: 0,
                        timestamp = msg.timestamp,
                        isSentByMe = msg.isSentByMe
                    )
                }

                voiceEmptyState.visibility = View.GONE
                voiceRecyclerView.visibility = View.VISIBLE
                voiceRecyclerView.layoutManager = androidx.recyclerview.widget.LinearLayoutManager(this@ContactOptionsActivity)
                voiceRecyclerView.adapter = VoiceClipAdapter(voiceItems)

                Log.d(TAG, "Loaded ${voiceItems.size} voice clips for contact")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load voice content", e)
            }
        }
    }

    private fun loadLinksContent() {
        if (contactId == -1L) return

        CoroutineScope(Dispatchers.Main).launch {
            try {
                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                val textMessages = withContext(Dispatchers.IO) {
                    database.messageDao().getMessagesForContact(contactId)
                }

                // Extract URLs from message content
                data class SharedLink(val url: String, val timestamp: Long)

                val links = mutableListOf<SharedLink>()
                val seenUrls = mutableSetOf<String>()

                for (msg in textMessages) {
                    val content = msg.encryptedContent ?: continue
                    // encryptedContent is decrypted at display time in chat,
                    // but for TEXT messages the content is stored as plaintext in local DB
                    if (msg.messageType != "TEXT") continue

                    val matcher = Patterns.WEB_URL.matcher(content)
                    while (matcher.find()) {
                        val url = matcher.group()
                        if (url != null && seenUrls.add(url.lowercase())) {
                            links.add(SharedLink(url, msg.timestamp))
                        }
                    }
                }

                // Sort newest first
                links.sortByDescending { it.timestamp }

                val linksRecyclerView = findViewById<RecyclerView>(R.id.linksRecyclerView)
                val linksEmptyState = findViewById<TextView>(R.id.linksEmptyState)

                if (links.isEmpty()) {
                    linksRecyclerView.visibility = View.GONE
                    linksEmptyState.visibility = View.VISIBLE
                    return@launch
                }

                linksEmptyState.visibility = View.GONE
                linksRecyclerView.visibility = View.VISIBLE
                linksRecyclerView.layoutManager = LinearLayoutManager(this@ContactOptionsActivity)
                linksRecyclerView.adapter = object : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
                    inner class LinkViewHolder(view: View) : RecyclerView.ViewHolder(view) {
                        val urlText: TextView = view.findViewById(R.id.linkUrl)
                        val timestampText: TextView = view.findViewById(R.id.linkTimestamp)
                    }

                    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
                        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_shared_link, parent, false)
                        return LinkViewHolder(view)
                    }

                    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
                        val link = links[position]
                        val h = holder as LinkViewHolder
                        h.urlText.text = link.url
                        val dateFormat = java.text.SimpleDateFormat("MMM d, yyyy", java.util.Locale.getDefault())
                        h.timestampText.text = dateFormat.format(java.util.Date(link.timestamp))

                        holder.itemView.setOnClickListener {
                            showLinkWarning(link.url)
                        }
                    }

                    override fun getItemCount(): Int = links.size
                }

                Log.d(TAG, "Loaded ${links.size} shared links for contact")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load links content", e)
            }
        }
    }

    private fun loadGroupsContent() {
        if (contactId == -1L) return

        CoroutineScope(Dispatchers.Main).launch {
            try {
                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                val contact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactById(contactId)
                }

                val onionAddress = contact?.messagingOnion
                if (onionAddress.isNullOrEmpty()) {
                    Log.d(TAG, "No onion address for contact, skipping groups load")
                    return@launch
                }

                val sharedGroups = withContext(Dispatchers.IO) {
                    val groupIds = database.groupPeerDao().getGroupIdsForPeer(onionAddress)
                    groupIds.mapNotNull { gid -> database.groupDao().getGroupById(gid) }
                }

                val groupsRecyclerView = findViewById<RecyclerView>(R.id.groupsRecyclerView) ?: return@launch
                val groupsEmptyState = findViewById<TextView>(R.id.groupsEmptyState) ?: return@launch

                if (sharedGroups.isEmpty()) {
                    groupsRecyclerView.visibility = View.GONE
                    groupsEmptyState.visibility = View.VISIBLE
                    return@launch
                }

                groupsEmptyState.visibility = View.GONE
                groupsRecyclerView.visibility = View.VISIBLE
                groupsRecyclerView.layoutManager = LinearLayoutManager(this@ContactOptionsActivity)
                groupsRecyclerView.adapter = object : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
                    inner class GroupViewHolder(view: View) : RecyclerView.ViewHolder(view) {
                        val icon: TextView = view.findViewById(R.id.groupIcon)
                        val name: TextView = view.findViewById(R.id.groupName)
                        val members: TextView = view.findViewById(R.id.groupMembers)
                    }

                    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): RecyclerView.ViewHolder {
                        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_shared_group, parent, false)
                        return GroupViewHolder(view)
                    }

                    override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
                        val group = sharedGroups[position]
                        val h = holder as GroupViewHolder
                        h.icon.text = group.groupIcon ?: "\uD83D\uDC65"
                        h.name.text = group.name
                        h.members.text = "${group.memberCount} members"
                    }

                    override fun getItemCount(): Int = sharedGroups.size
                }

                Log.d(TAG, "Loaded ${sharedGroups.size} shared groups for contact")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load groups content", e)
            }
        }
    }

    private fun showLinkWarning(url: String) {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_link_warning, null)
        bottomSheet.setContentView(view)

        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.skipCollapsed = true

        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        view.findViewById<TextView>(R.id.linkPreview).text = url

        view.findViewById<View>(R.id.openLinkButton).setOnClickListener {
            bottomSheet.dismiss()
            try {
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(
                    if (url.startsWith("http://") || url.startsWith("https://")) url
                    else "https://$url"
                ))
                startActivity(intent)
            } catch (e: Exception) {
                ThemedToast.show(this, "Failed to open link")
            }
        }

        view.findViewById<View>(R.id.cancelLinkButton).setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun showDeleteConfirmationDialog(name: String) {
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_delete_contact, null)
        bottomSheet.setContentView(view)

        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.skipCollapsed = true

        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        view.findViewById<TextView>(R.id.deleteMessage).text =
            "Are you sure you want to delete $name from your contacts? This action cannot be undone."

        view.findViewById<View>(R.id.confirmDeleteButton).setOnClickListener {
            bottomSheet.dismiss()
            deleteContact()
        }

        view.findViewById<View>(R.id.cancelDeleteButton).setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun deleteContact() {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Deleting contact ID: $contactId")

                val keyManager = KeyManager.getInstance(this@ContactOptionsActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ContactOptionsActivity, dbPassphrase)

                val contact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactById(contactId)
                }

                if (contact != null) {
                    withContext(Dispatchers.IO) {
                        val deleteInfos = database.messageDao().getDeleteInfoForContact(contact.id)

                        deleteInfos.forEach { info ->
                            if (info.messageType == Message.MESSAGE_TYPE_VOICE &&
                                info.voiceFilePath != null) {
                                try {
                                    val voiceFile = java.io.File(info.voiceFilePath)
                                    if (voiceFile.exists()) {
                                        com.securelegion.utils.SecureWipe.secureDeleteFile(voiceFile)
                                        Log.d(TAG, "Securely wiped voice file: ${voiceFile.name}")
                                    }
                                } catch (e: Exception) {
                                    Log.e(TAG, "Failed to securely wipe voice file", e)
                                }
                            }
                            if (info.messageType == Message.MESSAGE_TYPE_IMAGE) {
                                try {
                                    val encFile = java.io.File(filesDir, "image_messages/${info.messageId}.enc")
                                    val imgFile = java.io.File(filesDir, "image_messages/${info.messageId}.img")
                                    val imageFile = if (encFile.exists()) encFile else imgFile
                                    if (imageFile.exists()) {
                                        com.securelegion.utils.SecureWipe.secureDeleteFile(imageFile)
                                        Log.d(TAG, "Securely wiped image file: ${imageFile.name}")
                                    }
                                } catch (e: Exception) {
                                    Log.e(TAG, "Failed to securely wipe image file", e)
                                }
                            }
                        }

                        database.messageDao().deleteMessagesForContact(contact.id)
                        database.contactDao().deleteContact(contact)

                        if (contact.ipfsCid != null) {
                            try {
                                val ipfsManager = com.securelegion.services.IPFSManager.getInstance(this@ContactOptionsActivity)
                                val unpinResult = ipfsManager.unpinFriendContactList(contact.ipfsCid)
                                if (unpinResult.isSuccess) {
                                    Log.i(TAG, "Unpinned friend's contact list from IPFS mesh: ${contact.ipfsCid}")
                                } else {
                                    Log.w(TAG, "Failed to unpin friend's contact list: ${unpinResult.exceptionOrNull()?.message}")
                                }
                            } catch (e: Exception) {
                                Log.w(TAG, "Non-critical error during unpinning", e)
                            }
                        }

                        try {
                            val contactListManager = com.securelegion.services.ContactListManager.getInstance(this@ContactOptionsActivity)
                            val backupResult = contactListManager.backupToIPFS()
                            if (backupResult.isSuccess) {
                                val ourCID = backupResult.getOrThrow()
                                Log.i(TAG, "Contact list backed up after deletion: $ourCID")
                            } else {
                                Log.w(TAG, "Failed to backup contact list: ${backupResult.exceptionOrNull()?.message}")
                            }
                        } catch (e: Exception) {
                            Log.w(TAG, "Non-critical error during contact list backup", e)
                        }

                        database.pingInboxDao().deleteByContact(contact.id)

                        getSharedPreferences("muted_contacts", MODE_PRIVATE)
                            .edit().remove("muted_$contactId").apply()

                        Log.i(TAG, "Contact and all messages securely deleted (DOD 3-pass): ${contact.displayName}")
                    }

                    ThemedToast.show(this@ContactOptionsActivity, "Contact deleted")

                    val intent = Intent(this@ContactOptionsActivity, MainActivity::class.java)
                    startActivity(intent)
                    finish()
                } else {
                    Log.w(TAG, "Contact not found in database")
                    ThemedToast.show(this@ContactOptionsActivity, "Contact not found")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to delete contact", e)
                ThemedToast.show(this@ContactOptionsActivity, "Failed to delete contact")
            }
        }
    }
}
