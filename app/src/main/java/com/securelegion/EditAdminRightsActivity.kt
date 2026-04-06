package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.services.CrdtGroupManager
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Edit per-admin rights bitfield + custom title, or promote a Member to Admin.
 *
 * Intent EXTRAs:
 *  - EXTRA_GROUP_ID        — group hex
 *  - EXTRA_MEMBER_PUBKEY   — target member's Ed25519 pubkey hex
 *  - EXTRA_MEMBER_NAME     — display name (for the title row)
 *
 * Behavior:
 *  - If target is currently a Member → this screen promotes them to Admin on Save
 *  - If target is currently Admin   → this screen edits their rights/title; also shows Demote
 *  - Owner target is rejected (Owner is immutable)
 */
class EditAdminRightsActivity : BaseActivity() {

    companion object {
        private const val TAG = "EditAdminRights"
        const val EXTRA_GROUP_ID = "group_id"
        const val EXTRA_MEMBER_PUBKEY = "member_pubkey_hex"
        const val EXTRA_MEMBER_NAME = "member_display_name"
    }

    private lateinit var backButton: View
    private lateinit var saveButton: TextView
    private lateinit var targetNameText: TextView
    private lateinit var targetSubtitleText: TextView
    private lateinit var customTitleInput: EditText
    private lateinit var toggleInvite: SwitchCompat
    private lateinit var toggleRemove: SwitchCompat
    private lateinit var toggleChangeInfo: SwitchCompat
    private lateinit var toggleDeleteMessages: SwitchCompat
    private lateinit var togglePinMessages: SwitchCompat
    private lateinit var toggleAddAdmins: SwitchCompat
    private lateinit var demoteButton: TextView

    private var groupId: String? = null
    private var targetPubkeyHex: String? = null
    private var targetDisplayName: String = "Member"
    private var isCurrentlyAdmin: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_edit_admin_rights)

        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        targetPubkeyHex = intent.getStringExtra(EXTRA_MEMBER_PUBKEY)
        targetDisplayName = intent.getStringExtra(EXTRA_MEMBER_NAME) ?: "Member"

        if (groupId.isNullOrEmpty() || targetPubkeyHex.isNullOrEmpty()) {
            ThemedToast.show(this, "Invalid member")
            finish()
            return
        }

        initializeViews()
        setupClickListeners()
        loadCurrentRights()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        saveButton = findViewById(R.id.saveButton)
        targetNameText = findViewById(R.id.targetNameText)
        targetSubtitleText = findViewById(R.id.targetSubtitleText)
        customTitleInput = findViewById(R.id.customTitleInput)
        toggleInvite = findViewById(R.id.toggleInvite)
        toggleRemove = findViewById(R.id.toggleRemove)
        toggleChangeInfo = findViewById(R.id.toggleChangeInfo)
        toggleDeleteMessages = findViewById(R.id.toggleDeleteMessages)
        togglePinMessages = findViewById(R.id.togglePinMessages)
        toggleAddAdmins = findViewById(R.id.toggleAddAdmins)
        demoteButton = findViewById(R.id.demoteButton)

        targetNameText.text = targetDisplayName
    }

    private fun setupClickListeners() {
        backButton.setOnClickListener { finish() }
        saveButton.setOnClickListener { onSave() }
        demoteButton.setOnClickListener { onDemote() }
    }

    private fun loadCurrentRights() {
        val gid = groupId ?: return
        val pk = targetPubkeyHex ?: return
        lifecycleScope.launch {
            try {
                val (role, rights, title) = withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@EditAdminRightsActivity)
                    val member = mgr.queryMembers(gid).firstOrNull { it.pubkeyHex == pk }
                    Triple(member?.role ?: "Member", member?.adminRights, member?.customTitle)
                }

                if (role == "Owner") {
                    ThemedToast.show(this@EditAdminRightsActivity, "Owner role cannot be changed")
                    finish()
                    return@launch
                }

                isCurrentlyAdmin = (role == "Admin")
                targetSubtitleText.text = if (isCurrentlyAdmin) "Edit Admin Rights" else "Promote to Admin"
                demoteButton.visibility = if (isCurrentlyAdmin) View.VISIBLE else View.GONE

                val r = rights ?: CrdtGroupManager.AdminRights.allFalse()
                toggleInvite.isChecked = r.canInvite
                toggleRemove.isChecked = r.canRemove
                toggleChangeInfo.isChecked = r.canChangeInfo
                toggleDeleteMessages.isChecked = r.canDeleteMessages
                togglePinMessages.isChecked = r.canPinMessages
                toggleAddAdmins.isChecked = r.canAddAdmins
                customTitleInput.setText(title ?: "")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load member rights", e)
                ThemedToast.show(this@EditAdminRightsActivity, "Failed to load member data")
                finish()
            }
        }
    }

    private fun onSave() {
        val gid = groupId ?: return
        val pk = targetPubkeyHex ?: return

        val rights = CrdtGroupManager.AdminRights(
            canInvite = toggleInvite.isChecked,
            canRemove = toggleRemove.isChecked,
            canChangeInfo = toggleChangeInfo.isChecked,
            canDeleteMessages = toggleDeleteMessages.isChecked,
            canPinMessages = togglePinMessages.isChecked,
            canAddAdmins = toggleAddAdmins.isChecked
        )
        val title = customTitleInput.text?.toString()?.trim()?.takeIf { it.isNotEmpty() }

        saveButton.isEnabled = false
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val mgr = CrdtGroupManager.getInstance(this@EditAdminRightsActivity)
                    mgr.setAdminRole(gid, pk, rights, title)
                    val authorName = KeyManager.getInstance(this@EditAdminRightsActivity).getUsername() ?: "Someone"
                    val verb = if (isCurrentlyAdmin) "updated admin rights for" else "promoted"
                    mgr.sendSystemMessage(gid, "$authorName $verb $targetDisplayName")
                }
                val msg = if (isCurrentlyAdmin) "Rights updated" else "$targetDisplayName promoted to Admin"
                ThemedToast.show(this@EditAdminRightsActivity, msg)
                finish()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to set admin role", e)
                ThemedToast.show(this@EditAdminRightsActivity, "Failed: ${e.message}")
                saveButton.isEnabled = true
            }
        }
    }

    private fun onDemote() {
        val gid = groupId ?: return
        val pk = targetPubkeyHex ?: return

        val dialog = GlassDialog.builder(this)
            .setTitle("Demote Admin")
            .setMessage("Remove admin rights from $targetDisplayName? They'll become a regular Member.")
            .setPositiveButton("Demote") { d, _ ->
                d.dismiss()
                lifecycleScope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            val mgr = CrdtGroupManager.getInstance(this@EditAdminRightsActivity)
                            mgr.demoteAdmin(gid, pk)
                            val authorName = KeyManager.getInstance(this@EditAdminRightsActivity).getUsername() ?: "Someone"
                            mgr.sendSystemMessage(gid, "$authorName demoted $targetDisplayName")
                        }
                        ThemedToast.show(this@EditAdminRightsActivity, "$targetDisplayName demoted")
                        finish()
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to demote admin", e)
                        ThemedToast.show(this@EditAdminRightsActivity, "Failed: ${e.message}")
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .create()
        GlassDialog.show(dialog)
    }
}
