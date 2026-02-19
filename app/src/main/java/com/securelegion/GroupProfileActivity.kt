package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.TextView
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.CrdtGroupManager
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
    private lateinit var groupNameTitle: TextView
    private lateinit var groupIconContainer: FrameLayout
    private lateinit var groupIconImage: ImageView
    private lateinit var changePinButton: View
    private lateinit var membersButton: View
    private lateinit var advanceButton: View
    private lateinit var permissionsButton: View

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
        changePinButton.visibility = View.GONE // CRDT groups use cryptographic membership, not PINs
        membersButton = findViewById(R.id.membersButton)
        advanceButton = findViewById(R.id.advanceButton)
        permissionsButton = findViewById(R.id.permissionsButton)
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

        // Change PIN — hidden for CRDT groups
        changePinButton.setOnClickListener { }

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

    }

    private fun loadGroupData() {
        groupNameTitle.text = groupName

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
                            groupIconImage.imageTintList = null
                            groupIconImage.setImageBitmap(bitmap)
                            groupIconImage.scaleType = ImageView.ScaleType.CENTER_CROP
                        }
                    }

                    // Update name from CRDT state if available
                    if (!crdtName.isNullOrEmpty()) {
                        groupNameTitle.text = crdtName
                    }
                }

                Log.d(TAG, "Group profile loaded: $groupName (ID: $groupId)")

            } catch (e: Exception) {
                Log.e(TAG, "Failed to load group data", e)
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
