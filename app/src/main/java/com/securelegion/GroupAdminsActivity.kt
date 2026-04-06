package com.securelegion

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.CrdtGroupManager
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Lists the group's Owner + Admins, with "promoted by X" attribution and
 * custom titles. Owner/Admins-with-can_add_admins can tap rows to edit
 * rights, or the "Add Admin" entry to promote a Member.
 */
class GroupAdminsActivity : BaseActivity() {

    companion object {
        private const val TAG = "GroupAdmins"
        const val EXTRA_GROUP_ID = "group_id"
    }

    private lateinit var backButton: View
    private lateinit var addAdminButton: View
    private lateinit var adminList: RecyclerView
    private lateinit var adapter: AdminAdapter

    private var groupId: String? = null
    private var canEdit: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_group_admins)

        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        if (groupId.isNullOrEmpty()) {
            ThemedToast.show(this, "Invalid group")
            finish()
            return
        }

        backButton = findViewById(R.id.backButton)
        addAdminButton = findViewById(R.id.addAdminButton)
        adminList = findViewById(R.id.adminList)

        backButton.setOnClickListener { finish() }
        addAdminButton.setOnClickListener { showAddAdminPicker() }

        adapter = AdminAdapter(emptyList()) { entry -> onAdminTap(entry) }
        adminList.layoutManager = LinearLayoutManager(this)
        adminList.adapter = adapter
    }

    override fun onResume() {
        super.onResume()
        loadAdmins()
    }

    private fun loadAdmins() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            val (entries, canUserEdit) = withContext(Dispatchers.IO) {
                val mgr = CrdtGroupManager.getInstance(this@GroupAdminsActivity)
                val members = mgr.queryMembers(gid).filter { it.accepted && !it.removed }

                val myPubkeyHex = KeyManager.getInstance(this@GroupAdminsActivity)
                    .getSigningPublicKey().joinToString("") { "%02x".format(it) }
                val me = members.firstOrNull { it.pubkeyHex == myPubkeyHex }
                val myCanEdit = me?.role == "Owner"
                    || (me?.role == "Admin" && me.adminRights?.canAddAdmins == true)

                // Resolve names + promoted_by
                val keyManager = KeyManager.getInstance(this@GroupAdminsActivity)
                val db = SecureLegionDatabase.getInstance(
                    this@GroupAdminsActivity, keyManager.getDatabasePassphrase()
                )
                val myUsername = keyManager.getUsername() ?: "You"

                fun resolveName(pubkeyHex: String): String {
                    if (pubkeyHex.equals(myPubkeyHex, ignoreCase = true)) return myUsername
                    return try {
                        val pubkeyBytes = pubkeyHex.chunked(2)
                            .map { it.toInt(16).toByte() }.toByteArray()
                        val pubkeyB64 = android.util.Base64.encodeToString(
                            pubkeyBytes, android.util.Base64.NO_WRAP
                        )
                        db.contactDao().getContactByPublicKey(pubkeyB64)?.displayName
                    } catch (_: Exception) { null } ?: "Unknown (${pubkeyHex.take(8)})"
                }

                // device_id → pubkey_hex map for promoted_by resolution
                val deviceToPubkey = members.associate { it.deviceIdHex to it.pubkeyHex }

                val items = members
                    .filter { it.role == "Owner" || it.role == "Admin" }
                    .sortedBy { if (it.role == "Owner") 0 else 1 }
                    .map { m ->
                        val promoterName = m.promotedByDeviceHex?.let { devHex ->
                            deviceToPubkey[devHex]?.let { resolveName(it) }
                        }
                        AdminEntry(
                            pubkeyHex = m.pubkeyHex,
                            displayName = resolveName(m.pubkeyHex),
                            role = m.role,
                            customTitle = m.customTitle,
                            promotedByName = promoterName
                        )
                    }
                Pair(items, myCanEdit)
            }
            canEdit = canUserEdit
            adapter.submit(entries)
            addAdminButton.visibility = if (canEdit) View.VISIBLE else View.GONE
        }
    }

    private fun onAdminTap(entry: AdminEntry) {
        if (!canEdit) {
            ThemedToast.show(this, "You don't have permission to edit admins")
            return
        }
        if (entry.role == "Owner") {
            ThemedToast.show(this, "Owner role cannot be changed")
            return
        }
        val gid = groupId ?: return
        val intent = Intent(this, EditAdminRightsActivity::class.java).apply {
            putExtra(EditAdminRightsActivity.EXTRA_GROUP_ID, gid)
            putExtra(EditAdminRightsActivity.EXTRA_MEMBER_PUBKEY, entry.pubkeyHex)
            putExtra(EditAdminRightsActivity.EXTRA_MEMBER_NAME, entry.displayName)
        }
        startActivity(intent)
    }

    private fun showAddAdminPicker() {
        val gid = groupId ?: return
        val intent = Intent(this, AddAdminPickerActivity::class.java).apply {
            putExtra(AddAdminPickerActivity.EXTRA_GROUP_ID, gid)
        }
        startActivity(intent)
    }

    data class AdminEntry(
        val pubkeyHex: String,
        val displayName: String,
        val role: String,
        val customTitle: String?,
        val promotedByName: String?
    )

    private class AdminAdapter(
        private var items: List<AdminEntry>,
        private val onClick: (AdminEntry) -> Unit
    ) : RecyclerView.Adapter<AdminAdapter.VH>() {

        fun submit(list: List<AdminEntry>) { items = list; notifyDataSetChanged() }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_admin, parent, false)
            return VH(v)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            holder.name.text = item.displayName
            holder.subtitle.text = when {
                item.promotedByName != null -> "promoted by ${item.promotedByName}"
                item.role == "Owner" -> "group creator"
                else -> ""
            }
            holder.subtitle.visibility =
                if (holder.subtitle.text.isNullOrEmpty()) View.GONE else View.VISIBLE
            // Badge shows customTitle if set, else role lowercased
            holder.badge.text = item.customTitle?.takeIf { it.isNotEmpty() }
                ?: item.role.lowercase()
            holder.itemView.setOnClickListener { onClick(item) }
        }

        override fun getItemCount(): Int = items.size

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val name: TextView = view.findViewById(R.id.nameText)
            val subtitle: TextView = view.findViewById(R.id.subtitleText)
            val badge: TextView = view.findViewById(R.id.roleBadge)
        }
    }
}
