package com.securelegion

import android.app.Activity
import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.utils.GlassBottomSheetDialog
import android.content.Intent
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.ed25519PublicKeyBytes
import com.securelegion.services.CrdtGroupManager
import com.securelegion.ui.adapters.ContactSelectionAdapter
import com.securelegion.ui.adapters.SelectedMembersAdapter
import com.securelegion.utils.ImagePicker
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class CreateGroupActivity : BaseActivity() {

    companion object {
        private const val TAG = "CreateGroup"
    }

    // Views
    private lateinit var backButton: View
    private lateinit var settingsIcon: FrameLayout
    private lateinit var groupIconContainer: FrameLayout
    private lateinit var groupIconImage: ImageView
    private lateinit var groupNameInput: EditText
    private lateinit var addMemberButton: LinearLayout
    private lateinit var selectedMembersList: RecyclerView
    private lateinit var createGroupButton: TextView

    // Selected members
    private val selectedMembers = mutableListOf<Contact>()
    private var selectedGroupIcon: String? = null // Stores Base64-encoded image
    private lateinit var selectedMembersAdapter: SelectedMembersAdapter

    // Image picker launchers
    private val galleryLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val uri = result.data?.data
            val base64 = ImagePicker.processImageUri(this, uri)
            if (base64 != null) {
                selectedGroupIcon = base64
                updateGroupIconPreview(base64)
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
            val bitmap = result.data?.extras?.get("data") as? Bitmap
            val base64 = ImagePicker.processImageBitmap(bitmap)
            if (base64 != null) {
                selectedGroupIcon = base64
                updateGroupIconPreview(base64)
                ThemedToast.show(this, "Group icon updated")
            } else {
                ThemedToast.show(this, "Failed to process image")
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_group)

        initializeViews()
        setupClickListeners()
        setupSelectedMembersRecyclerView()
    }

    private fun setupSelectedMembersRecyclerView() {
        selectedMembersAdapter = SelectedMembersAdapter { contact ->
            // Remove member when X is clicked
            selectedMembers.remove(contact)
            updateSelectedMembersUI()
        }

        selectedMembersList.apply {
            layoutManager = LinearLayoutManager(this@CreateGroupActivity, LinearLayoutManager.HORIZONTAL, false)
            adapter = selectedMembersAdapter
        }
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        settingsIcon = findViewById(R.id.settingsIcon)
        groupIconContainer = findViewById(R.id.groupIconContainer)
        groupIconImage = findViewById(R.id.groupIconImage)
        groupNameInput = findViewById(R.id.groupNameInput)
        addMemberButton = findViewById(R.id.addMemberButton)
        selectedMembersList = findViewById(R.id.selectedMembersList)
        createGroupButton = findViewById(R.id.createGroupButton)

    }

    private fun setupClickListeners() {
        // Back button
        backButton.setOnClickListener {
            finish()
        }

        // Settings icon (future: group settings/options)
        settingsIcon.setOnClickListener {
            ThemedToast.show(this, "Group settings - Coming soon")
        }

        // Group icon container - image picker
        groupIconContainer.setOnClickListener {
            showGroupIconPickerDialog()
        }

        // Add member button
        addMemberButton.setOnClickListener {
            showContactSelectionDialog()
        }

        // Create group button
        createGroupButton.setOnClickListener {
            validateAndCreateGroup()
        }
    }

    private fun showContactSelectionDialog() {
        lifecycleScope.launch {
            val contacts = withContext(Dispatchers.IO) {
                try {
                    val keyManager = KeyManager.getInstance(this@CreateGroupActivity)
                    val dbPassphrase = keyManager.getDatabasePassphrase()
                    val database = SecureLegionDatabase.getInstance(this@CreateGroupActivity, dbPassphrase)
                    database.contactDao().getAllContacts()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to load contacts", e)
                    emptyList()
                }
            }

            withContext(Dispatchers.Main) {
                if (contacts.isEmpty()) {
                    ThemedToast.show(this@CreateGroupActivity, "No contacts available. Add friends first!")
                    return@withContext
                }

                // Create bottom sheet
                val bottomSheetDialog = GlassBottomSheetDialog(this@CreateGroupActivity)
                val view = layoutInflater.inflate(R.layout.bottom_sheet_select_contacts, null)
                bottomSheetDialog.setContentView(view)

                bottomSheetDialog.behavior.isDraggable = true
                bottomSheetDialog.behavior.skipCollapsed = true

                bottomSheetDialog.setOnShowListener {
                    (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
                }

                // Setup RecyclerView in bottom sheet
                val contactsRecyclerView = view.findViewById<RecyclerView>(R.id.contactsRecyclerView)
                val doneButton = view.findViewById<TextView>(R.id.doneButton)

                // Pre-select existing members
                val selectedIds = selectedMembers.map { it.id }.toMutableSet()
                val adapter = ContactSelectionAdapter(selectedIds)

                contactsRecyclerView.layoutManager = LinearLayoutManager(this@CreateGroupActivity)
                contactsRecyclerView.adapter = adapter
                adapter.submitList(contacts)

                // Done button
                doneButton.setOnClickListener {
                    // Update selected members list
                    selectedMembers.clear()
                    selectedMembers.addAll(adapter.getSelectedContacts())
                    updateSelectedMembersUI()
                    bottomSheetDialog.dismiss()
                }

                bottomSheetDialog.show()
            }
        }
    }

    private fun updateSelectedMembersUI() {
        if (selectedMembers.isEmpty()) {
            selectedMembersList.visibility = View.GONE
        } else {
            selectedMembersList.visibility = View.VISIBLE
            selectedMembersAdapter.submitList(selectedMembers.toList())
        }
    }

    private fun validateAndCreateGroup() {
        val groupName = groupNameInput.text.toString().trim()

        if (groupName.isEmpty()) {
            ThemedToast.show(this, "Please enter a group name")
            groupNameInput.requestFocus()
            return
        }

        if (groupName.length < 3) {
            ThemedToast.show(this, "Group name must be at least 3 characters")
            groupNameInput.requestFocus()
            return
        }

        createGroup(groupName)
    }

    private fun createGroup(groupName: String) {
        createGroupButton.isEnabled = false
        createGroupButton.alpha = 0.5f
        createGroupButton.text = "Creating..."

        lifecycleScope.launch {
            try {
                val groupId = withContext(Dispatchers.IO) {
                    Log.d(TAG, "Creating CRDT group: $groupName with ${selectedMembers.size} members")

                    val mgr = CrdtGroupManager.getInstance(this@CreateGroupActivity)
                    val gid = mgr.createGroup(groupName, selectedGroupIcon)

                    // Invite selected members (inviteMember handles broadcast + bundle internally)
                    for (member in selectedMembers) {
                        val pubkeyHex = member.ed25519PublicKeyBytes
                            .joinToString("") { "%02x".format(it) }
                        mgr.inviteMember(gid, pubkeyHex)
                        Log.i(TAG, "Invited ${member.displayName}")
                    }

                    gid
                }

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@CreateGroupActivity, "Group '$groupName' created!")

                    val intent = Intent(this@CreateGroupActivity, GroupChatActivity::class.java).apply {
                        putExtra(GroupChatActivity.EXTRA_GROUP_ID, groupId)
                        putExtra(GroupChatActivity.EXTRA_GROUP_NAME, groupName)
                    }
                    startActivity(intent)
                    finish()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to create group", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@CreateGroupActivity, "Failed to create group: ${e.message}")
                }
            } finally {
                withContext(Dispatchers.Main) {
                    createGroupButton.isEnabled = true
                    createGroupButton.alpha = 1.0f
                    createGroupButton.text = "Create Group"
                }
            }
        }
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
        selectedGroupIcon = null
        groupIconImage.setImageResource(R.drawable.ic_contacts)
        groupIconImage.scaleType = ImageView.ScaleType.CENTER_INSIDE
        groupIconImage.imageTintList = android.content.res.ColorStateList.valueOf(
            android.graphics.Color.parseColor("#999999")
        )
        ThemedToast.show(this, "Group icon removed")
    }
}
