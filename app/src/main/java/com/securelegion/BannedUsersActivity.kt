package com.securelegion

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
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * List of members banned from this group. Admins with can_remove (or Owner)
 * can unban entries, making the user eligible for re-invite.
 */
class BannedUsersActivity : BaseActivity() {

    companion object {
        private const val TAG = "BannedUsers"
        const val EXTRA_GROUP_ID = "group_id"
    }

    private lateinit var backButton: View
    private lateinit var bannedList: RecyclerView
    private lateinit var emptyState: TextView
    private lateinit var adapter: BannedAdapter

    private var groupId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_banned_users)

        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        if (groupId.isNullOrEmpty()) {
            ThemedToast.show(this, "Invalid group")
            finish()
            return
        }

        backButton = findViewById(R.id.backButton)
        bannedList = findViewById(R.id.bannedList)
        emptyState = findViewById(R.id.emptyState)

        backButton.setOnClickListener { finish() }

        adapter = BannedAdapter(emptyList()) { entry -> onUnban(entry) }
        bannedList.layoutManager = LinearLayoutManager(this)
        bannedList.adapter = adapter

        loadBanned()
    }

    private fun loadBanned() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            val entries = withContext(Dispatchers.IO) {
                val mgr = CrdtGroupManager.getInstance(this@BannedUsersActivity)
                val banned = mgr.queryBannedMembers(gid)
                // Join with Contact table for display names where possible
                val keyManager = KeyManager.getInstance(this@BannedUsersActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val db = SecureLegionDatabase.getInstance(this@BannedUsersActivity, dbPassphrase)
                banned.map { m ->
                    val name = try {
                        val pubkeyB64 = android.util.Base64.encodeToString(
                            m.pubkeyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
                            android.util.Base64.NO_WRAP
                        )
                        db.contactDao().getContactByPublicKey(pubkeyB64)?.displayName
                    } catch (_: Exception) { null }
                    BannedEntry(
                        pubkeyHex = m.pubkeyHex,
                        displayName = name ?: "Unknown (${m.pubkeyHex.take(8)})"
                    )
                }
            }
            adapter.submit(entries)
            emptyState.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
            bannedList.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE
        }
    }

    private fun onUnban(entry: BannedEntry) {
        val gid = groupId ?: return
        val dialog = GlassDialog.builder(this)
            .setTitle("Unban ${entry.displayName}?")
            .setMessage("They'll be eligible for re-invite. This doesn't automatically re-add them.")
            .setPositiveButton("Unban") { d, _ ->
                d.dismiss()
                lifecycleScope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            val mgr = CrdtGroupManager.getInstance(this@BannedUsersActivity)
                            mgr.unbanMember(gid, entry.pubkeyHex)
                            val authorName = KeyManager.getInstance(this@BannedUsersActivity).getUsername() ?: "Someone"
                            mgr.sendSystemMessage(gid, "$authorName unbanned ${entry.displayName}")
                        }
                        ThemedToast.show(this@BannedUsersActivity, "${entry.displayName} unbanned")
                        loadBanned()
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to unban", e)
                        ThemedToast.show(this@BannedUsersActivity, "Failed: ${e.message}")
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .create()
        GlassDialog.show(dialog)
    }

    data class BannedEntry(val pubkeyHex: String, val displayName: String)

    private class BannedAdapter(
        private var items: List<BannedEntry>,
        private val onUnbanClick: (BannedEntry) -> Unit
    ) : RecyclerView.Adapter<BannedAdapter.VH>() {

        fun submit(list: List<BannedEntry>) { items = list; notifyDataSetChanged() }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_banned_user, parent, false)
            return VH(v)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            holder.nameText.text = item.displayName
            holder.pubkeyText.text = item.pubkeyHex.take(16) + "…"
            holder.unbanButton.setOnClickListener { onUnbanClick(item) }
        }

        override fun getItemCount(): Int = items.size

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val nameText: TextView = view.findViewById(R.id.nameText)
            val pubkeyText: TextView = view.findViewById(R.id.pubkeyText)
            val unbanButton: TextView = view.findViewById(R.id.unbanButton)
        }
    }
}
