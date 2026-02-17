package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.text.InputFilter
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.constraintlayout.widget.ConstraintLayout
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
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
    private lateinit var groupNameTitle: TextView
    private lateinit var groupIconContainer: FrameLayout
    private lateinit var groupIconImage: ImageView
    private lateinit var changePinButton: ConstraintLayout
    private lateinit var membersButton: ConstraintLayout
    private lateinit var advanceButton: ConstraintLayout
    private lateinit var permissionsButton: ConstraintLayout
    private lateinit var renameGroupButton: ConstraintLayout

    // Group data
    private var groupId: String? = null
    private var groupName: String = "Group"

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
        groupIconContainer = findViewById(R.id.groupIconContainer)
        groupIconImage = findViewById(R.id.groupIconImage)
        changePinButton = findViewById(R.id.changePinButton)
        membersButton = findViewById(R.id.membersButton)
        advanceButton = findViewById(R.id.advanceButton)
        permissionsButton = findViewById(R.id.permissionsButton)
        renameGroupButton = findViewById(R.id.renameGroupButton)
    }

    private fun setupClickListeners() {
        // Back button
        backButton.setOnClickListener {
            finish()
        }

        // Group icon - future: open icon/emoji picker
        groupIconContainer.setOnClickListener {
            ThemedToast.show(this, "Icon picker - Coming soon")
        }

        // Change PIN
        changePinButton.setOnClickListener {
            showChangePinDialog()
        }

        // Members
        membersButton.setOnClickListener {
            showMembersScreen()
        }

        // Advance
        advanceButton.setOnClickListener {
            showAdvancedSettings()
        }

        // Permissions
        permissionsButton.setOnClickListener {
            showPermissionsSettings()
        }

        // Rename Group
        renameGroupButton.setOnClickListener {
            showRenameDialog()
        }
    }

    private fun loadGroupData() {
        // Set group name in title
        groupNameTitle.text = groupName

        // TODO: Load group data from database when group messaging is implemented
        // This would include:
        // - Group icon/emoji
        // - Member count
        // - Group creation date
        // - Current permissions
        // - etc.

        Log.d(TAG, "Group profile loaded: $groupName (ID: $groupId)")
    }

    private fun showChangePinDialog() {
        val currentGroupId = groupId
        if (currentGroupId == null) {
            ThemedToast.show(this, "Invalid group")
            return
        }

        // Create dialog with PIN input boxes
        val dialogView = layoutInflater.inflate(R.layout.activity_create_group, null)
        val pinBoxesContainer = dialogView.findViewById<LinearLayout>(R.id.pinBoxesContainer)

        // Get the 6 PIN input boxes
        val pinBoxes = listOf(
            dialogView.findViewById<EditText>(R.id.pinBox1),
            dialogView.findViewById<EditText>(R.id.pinBox2),
            dialogView.findViewById<EditText>(R.id.pinBox3),
            dialogView.findViewById<EditText>(R.id.pinBox4),
            dialogView.findViewById<EditText>(R.id.pinBox5),
            dialogView.findViewById<EditText>(R.id.pinBox6)
        )

        // Set up PIN box behavior
        pinBoxes.forEach { box ->
            box.filters = arrayOf(
                InputFilter.LengthFilter(1),
                InputFilter { source, start, end, dest, dstart, dend ->
                    if (source.toString().matches(Regex("[0-9]*"))) null else ""
                }
            )
        }

        // Auto-advance to next box
        pinBoxes.forEachIndexed { index, box ->
            box.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    if (s?.length == 1 && index < pinBoxes.size - 1) {
                        pinBoxes[index + 1].requestFocus()
                    }
                }
            })
        }

        AlertDialog.Builder(this)
            .setTitle("Change Group PIN")
            .setMessage("Enter new 6-digit PIN")
            .setView(dialogView)
            .setPositiveButton("Save") { dialog, _ ->
                val newPin = pinBoxes.joinToString("") { it.text.toString() }

                if (newPin.length != 6) {
                    ThemedToast.show(this, "Please enter a 6-digit PIN")
                    return@setPositiveButton
                }

                if (!newPin.all { it.isDigit() }) {
                    ThemedToast.show(this, "PIN must be 6 digits")
                    return@setPositiveButton
                }

                // Update PIN in database
                lifecycleScope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            val keyManager = KeyManager.getInstance(this@GroupProfileActivity)
                            val dbPassphrase = keyManager.getDatabasePassphrase()
                            val database = SecureLegionDatabase.getInstance(this@GroupProfileActivity, dbPassphrase)
                            database.groupDao().updateGroupPin(currentGroupId, newPin)
                            Log.i(TAG, "Group PIN changed")
                        }

                        withContext(Dispatchers.Main) {
                            ThemedToast.show(this@GroupProfileActivity, "PIN changed successfully")
                        }

                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to change PIN", e)
                        withContext(Dispatchers.Main) {
                            ThemedToast.show(this@GroupProfileActivity, "Failed to change PIN: ${e.message}")
                        }
                    }
                }

                dialog.dismiss()
            }
            .setNegativeButton("Cancel", null)
            .show()
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
        // TODO: Implement permissions settings when group messaging is implemented
        // This would control:
        // - Who can send messages (all members vs admins only)
        // - Who can add members
        // - Who can remove members
        // - Who can change group name/icon
        // - Who can change group settings

        ThemedToast.show(this, "Permissions - Coming soon")
        Log.i(TAG, "Permissions clicked for group: $groupName")
    }

    private fun showRenameDialog() {
        val currentGroupId = groupId
        if (currentGroupId == null) {
            ThemedToast.show(this, "Invalid group")
            return
        }

        // Create rename dialog
        val input = EditText(this).apply {
            setText(groupName)
            hint = "Enter new group name"
            setTextColor(resources.getColor(R.color.text_white, null))
            setHintTextColor(resources.getColor(R.color.text_gray, null))
            setBackgroundColor(resources.getColor(android.R.color.transparent, null))
            setPadding(32, 32, 32, 32)
        }

        AlertDialog.Builder(this)
            .setTitle("Rename Group")
            .setView(input)
            .setPositiveButton("Save") { dialog, _ ->
                val newName = input.text.toString().trim()
                if (newName.isEmpty()) {
                    ThemedToast.show(this, "Group name cannot be empty")
                    return@setPositiveButton
                }

                if (newName.length < 3) {
                    ThemedToast.show(this, "Group name must be at least 3 characters")
                    return@setPositiveButton
                }

                // Update group name in database
                lifecycleScope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            val keyManager = KeyManager.getInstance(this@GroupProfileActivity)
                            val dbPassphrase = keyManager.getDatabasePassphrase()
                            val database = SecureLegionDatabase.getInstance(this@GroupProfileActivity, dbPassphrase)
                            database.groupDao().updateGroupName(currentGroupId, newName)
                            Log.i(TAG, "Group renamed to: $newName")
                        }

                        withContext(Dispatchers.Main) {
                            groupName = newName
                            groupNameTitle.text = newName
                            ThemedToast.show(this@GroupProfileActivity, "Group renamed successfully")
                        }

                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to rename group", e)
                        withContext(Dispatchers.Main) {
                            ThemedToast.show(this@GroupProfileActivity, "Failed to rename group: ${e.message}")
                        }
                    }
                }

                dialog.dismiss()
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
