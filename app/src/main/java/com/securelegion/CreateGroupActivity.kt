package com.securelegion

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Bitmap
import android.os.Bundle
import android.text.InputFilter
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
import com.securelegion.services.GroupManager
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
    private lateinit var pinBoxesContainer: LinearLayout
    private lateinit var addMemberButton: LinearLayout
    private lateinit var selectedMembersList: RecyclerView
    private lateinit var createGroupButton: TextView

    // PIN boxes
    private val pinBoxes = mutableListOf<EditText>()

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
        setupPinBoxes()
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
        pinBoxesContainer = findViewById(R.id.pinBoxesContainer)
        addMemberButton = findViewById(R.id.addMemberButton)
        selectedMembersList = findViewById(R.id.selectedMembersList)
        createGroupButton = findViewById(R.id.createGroupButton)

        // Initialize PIN boxes
        pinBoxes.add(findViewById(R.id.pinBox1))
        pinBoxes.add(findViewById(R.id.pinBox2))
        pinBoxes.add(findViewById(R.id.pinBox3))
        pinBoxes.add(findViewById(R.id.pinBox4))
        pinBoxes.add(findViewById(R.id.pinBox5))
        pinBoxes.add(findViewById(R.id.pinBox6))
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

    private fun setupPinBoxes() {
        // Set input filters to allow only digits and limit to 1 character
        pinBoxes.forEach { box ->
            box.filters = arrayOf(
                InputFilter.LengthFilter(1),
                InputFilter { source, start, end, dest, dstart, dend ->
                    // Only allow digits
                    if (source.toString().matches(Regex("[0-9]*"))) {
                        null // Accept the input
                    } else {
                        "" // Reject the input
                    }
                }
            )
        }

        // Add key listener to handle backspace (moves to previous box and deletes)
        pinBoxes.forEachIndexed { index, box ->
            box.setOnKeyListener { _, keyCode, event ->
                if (keyCode == android.view.KeyEvent.KEYCODE_DEL && event.action == android.view.KeyEvent.ACTION_DOWN) {
                    if (box.text.isEmpty() && index > 0) {
                        // If current box is empty and backspace pressed, move to previous box and clear it
                        pinBoxes[index - 1].text.clear()
                        pinBoxes[index - 1].requestFocus()
                        return@setOnKeyListener true
                    }
                }
                false
            }
        }

        // Auto-advance to next box when digit is entered
        pinBoxes.forEachIndexed { index, box ->
            box.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    if (s?.length == 1 && index < pinBoxes.size - 1) {
                        // Auto-advance to next box
                        pinBoxes[index + 1].requestFocus()
                    }
                }
            })
        }
    }

    private fun getPinFromBoxes(): String {
        return pinBoxes.joinToString("") { it.text.toString() }
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
        val groupPin = getPinFromBoxes()

        // Validation
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

        if (groupPin.length != 6) {
            ThemedToast.show(this, "Please enter a 6-digit PIN")
            pinBoxes[0].requestFocus()
            return
        }

        if (!groupPin.all { it.isDigit() }) {
            ThemedToast.show(this, "PIN must be 6 digits")
            pinBoxes[0].requestFocus()
            return
        }

        if (selectedMembers.isEmpty()) {
            ThemedToast.show(this, "Please select at least one member")
            return
        }

        // Create the group
        createGroup(groupName, groupPin)
    }

    private fun createGroup(groupName: String, groupPin: String) {
        // Disable button to prevent double-tap
        createGroupButton.isEnabled = false
        createGroupButton.alpha = 0.5f

        lifecycleScope.launch {
            try {
                val groupId = withContext(Dispatchers.IO) {
                    Log.d(TAG, "Creating group: $groupName")
                    Log.i(TAG, "Members: ${selectedMembers.size}")
                    selectedMembers.forEach { contact ->
                        Log.i(TAG, "- ${contact.displayName}")
                    }

                    // Create group using GroupManager
                    val groupManager = GroupManager.getInstance(this@CreateGroupActivity)
                    val result = groupManager.createGroup(
                        groupName = groupName,
                        groupPin = groupPin,
                        members = selectedMembers,
                        groupIcon = selectedGroupIcon
                    )

                    if (result.isSuccess) {
                        Log.i(TAG, "Group created successfully: ${result.getOrNull()}")
                        result.getOrNull() // Return group ID
                    } else {
                        Log.e(TAG, "Failed to create group", result.exceptionOrNull())
                        throw result.exceptionOrNull() ?: Exception("Unknown error")
                    }
                }

                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@CreateGroupActivity, "Group '$groupName' created!")

                    // Navigate to the group chat
                    if (groupId != null) {
                        val intent = Intent(this@CreateGroupActivity, GroupChatActivity::class.java).apply {
                            putExtra("GROUP_ID", groupId)
                            putExtra("GROUP_NAME", groupName)
                        }
                        startActivity(intent)
                    }

                    // Finish this activity
                    finish()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Failed to create group", e)
                withContext(Dispatchers.Main) {
                    createGroupButton.isEnabled = true
                    createGroupButton.alpha = 1.0f
                    ThemedToast.show(this@CreateGroupActivity, "Failed to create group: ${e.message}")
                }
            }
        }
    }

    // ==================== GROUP ICON PICKER ====================

    private fun showGroupIconPickerDialog() {
        AlertDialog.Builder(this)
            .setTitle("Change Group Icon")
            .setItems(arrayOf("Take Photo", "Choose from Gallery", "Remove Icon")) { _, which ->
                when (which) {
                    0 -> ImagePicker.pickFromCamera(cameraLauncher)
                    1 -> ImagePicker.pickFromGallery(galleryLauncher)
                    2 -> removeGroupIcon()
                }
            }
            .show()
    }

    private fun updateGroupIconPreview(base64: String) {
        val bitmap = ImagePicker.decodeBase64ToBitmap(base64)
        if (bitmap != null) {
            groupIconImage.setImageBitmap(bitmap)
            groupIconImage.scaleType = ImageView.ScaleType.CENTER_CROP
        }
    }

    private fun removeGroupIcon() {
        selectedGroupIcon = null
        groupIconImage.setImageResource(R.drawable.ic_contacts)
        groupIconImage.scaleType = ImageView.ScaleType.CENTER_INSIDE
        ThemedToast.show(this, "Group icon removed")
    }
}
