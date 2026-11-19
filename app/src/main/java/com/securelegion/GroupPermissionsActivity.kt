package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.TextView
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LocalDeviceIdentity
import com.securelegion.database.DelegatedGroupStateStore
import com.securelegion.database.SecureLegionDatabase
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
    private var delegatedGroup: Boolean = false
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
        loading = true
        lifecycleScope.launch {
            val delegatedState = withContext(Dispatchers.IO) {
                val km = KeyManager.getInstance(this@GroupPermissionsActivity)
                val db = SecureLegionDatabase.getInstance(this@GroupPermissionsActivity,
                    km.getDatabasePassphrase())
                val delegated = DelegatedGroupStateStore(db)
                if (!delegated.isAdopted(gid)) null else {
                    val summary = delegated.read(gid, km.getSigningPublicKey())
                    val metadata = summary.getJSONArray("metadata")
                    val values = hashMapOf<String, Boolean>()
                    for (index in 0 until metadata.length()) {
                        val row = metadata.getJSONObject(index)
                        val bytes = android.util.Base64.decode(row.getString("value"),
                            android.util.Base64.DEFAULT)
                        values[row.getString("key")] = bytes.size == 1 && bytes[0] == 1.toByte()
                    }
                    Pair(summary.getString("our_role"), listOf(
                        values["AllowMemberSendMessages"] ?: true,
                        values["AllowMemberInvites"] ?: false,
                        values["AllowMemberPin"] ?: false,
                        values["AllowMemberChangeInfo"] ?: false))
                }
            }
            if (delegatedState != null) {
                delegatedGroup = true
                isOwner = delegatedState.first == "Owner"
                val delegatedValues = delegatedState.second
                readOnlyNotice.visibility = if (isOwner) View.GONE else View.VISIBLE
                toggleSendMessages.isChecked = delegatedValues[0]
                toggleInvites.isChecked = delegatedValues[1]
                togglePin.isChecked = delegatedValues[2]
                toggleChangeInfo.isChecked = delegatedValues[3]
                toggleSendMessages.isEnabled = isOwner
                toggleInvites.isEnabled = isOwner
                togglePin.isEnabled = isOwner
                toggleChangeInfo.isEnabled = isOwner
                loading = false
                wireToggles()
                return@launch
            }
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
                    if (delegatedGroup) {
                        val entry = when {
                            allowSendMessages != null -> "AllowMemberSendMessages" to allowSendMessages
                            allowInvites != null -> "AllowMemberInvites" to allowInvites
                            allowPin != null -> "AllowMemberPin" to allowPin
                            allowChangeInfo != null -> "AllowMemberChangeInfo" to allowChangeInfo
                            else -> throw IllegalArgumentException("Missing permission change")
                        }
                        val km = KeyManager.getInstance(this@GroupPermissionsActivity)
                        val db = SecureLegionDatabase.getInstance(this@GroupPermissionsActivity,
                            km.getDatabasePassphrase())
                        val identity = LocalDeviceIdentity.loadExisting(this@GroupPermissionsActivity)
                        try {
                            DelegatedGroupStateStore(db).setMetadata(gid,
                                km.getSigningPublicKey(), entry.first,
                                byteArrayOf(if (entry.second) 1 else 0), identity)
                        } finally { identity.close() }
                    } else CrdtGroupManager.getInstance(this@GroupPermissionsActivity)
                        .updateMemberPermissions(gid, allowSendMessages,
                            allowInvites, allowPin, allowChangeInfo)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to update permissions", e)
                ThemedToast.show(this@GroupPermissionsActivity, "Failed to save: ${e.message}")
                loadCurrentPermissions()
            }
        }
    }
}
