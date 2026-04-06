package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.TextView
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.services.CrdtGroupManager
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Group-wide member-tier permission toggles (Owner-only).
 *
 * Four toggles, each backed by a MetadataSet CRDT op:
 *  - Send Messages (default ON; OFF = admins-only broadcast mode)
 *  - Invite Members (default OFF)
 *  - Pin Messages (default OFF)
 *  - Change Group Info (default OFF)
 *
 * Non-Owner viewers see read-only state + notice.
 */
class GroupPermissionsActivity : BaseActivity() {

    companion object {
        private const val TAG = "GroupPermissions"
        const val EXTRA_GROUP_ID = "group_id"
    }

    private lateinit var backButton: View
    private lateinit var toggleSendMessages: SwitchCompat
    private lateinit var toggleInvites: SwitchCompat
    private lateinit var togglePin: SwitchCompat
    private lateinit var toggleChangeInfo: SwitchCompat
    private lateinit var readOnlyNotice: TextView

    private var groupId: String? = null
    private var isOwner: Boolean = false
    // Suppress writing while we load current state into the switches
    private var loading: Boolean = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_group_permissions)

        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        if (groupId.isNullOrEmpty()) {
            ThemedToast.show(this, "Invalid group")
            finish()
            return
        }

        initializeViews()
        backButton.setOnClickListener { finish() }
        loadCurrentPermissions()
    }

    private fun initializeViews() {
        backButton = findViewById(R.id.backButton)
        toggleSendMessages = findViewById(R.id.toggleSendMessages)
        toggleInvites = findViewById(R.id.toggleInvites)
        togglePin = findViewById(R.id.togglePin)
        toggleChangeInfo = findViewById(R.id.toggleChangeInfo)
        readOnlyNotice = findViewById(R.id.readOnlyNotice)
    }

    private fun loadCurrentPermissions() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            val (metadata, myRole) = withContext(Dispatchers.IO) {
                val mgr = CrdtGroupManager.getInstance(this@GroupPermissionsActivity)
                val md = mgr.queryMetadata(gid)
                val myPubkeyHex = KeyManager.getInstance(this@GroupPermissionsActivity)
                    .getSigningPublicKey().joinToString("") { "%02x".format(it) }
                val role = mgr.queryMembers(gid)
                    .firstOrNull { it.pubkeyHex == myPubkeyHex && it.accepted && !it.removed }
                    ?.role ?: "Member"
                Pair(md, role)
            }

            isOwner = (myRole == "Owner")
            if (!isOwner) {
                readOnlyNotice.visibility = View.VISIBLE
                toggleSendMessages.isEnabled = false
                toggleInvites.isEnabled = false
                togglePin.isEnabled = false
                toggleChangeInfo.isEnabled = false
            }

            toggleSendMessages.isChecked = metadata.effectiveAllowSend()
            toggleInvites.isChecked = metadata.effectiveAllowInvites()
            togglePin.isChecked = metadata.effectiveAllowPin()
            toggleChangeInfo.isChecked = metadata.effectiveAllowChangeInfo()

            loading = false
            wireToggles()
        }
    }

    private fun wireToggles() {
        toggleSendMessages.setOnCheckedChangeListener { _, checked ->
            onToggleChanged(allowSendMessages = checked)
        }
        toggleInvites.setOnCheckedChangeListener { _, checked ->
            onToggleChanged(allowInvites = checked)
        }
        togglePin.setOnCheckedChangeListener { _, checked ->
            onToggleChanged(allowPin = checked)
        }
        toggleChangeInfo.setOnCheckedChangeListener { _, checked ->
            onToggleChanged(allowChangeInfo = checked)
        }
    }

    private fun onToggleChanged(
        allowSendMessages: Boolean? = null,
        allowInvites: Boolean? = null,
        allowPin: Boolean? = null,
        allowChangeInfo: Boolean? = null
    ) {
        if (loading || !isOwner) return
        val gid = groupId ?: return
        lifecycleScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    CrdtGroupManager.getInstance(this@GroupPermissionsActivity)
                        .updateMemberPermissions(
                            gid, allowSendMessages, allowInvites, allowPin, allowChangeInfo
                        )
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to update permissions", e)
                ThemedToast.show(this@GroupPermissionsActivity, "Failed to save: ${e.message}")
            }
        }
    }
}
