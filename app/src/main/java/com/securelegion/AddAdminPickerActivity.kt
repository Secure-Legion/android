package com.securelegion

import android.content.Intent
import android.os.Bundle
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
 * Dedicated picker that lists non-admin group members eligible for promotion.
 * Tapping a row launches EditAdminRightsActivity for that member.
 */
class AddAdminPickerActivity : BaseActivity() {

    companion object {
        const val EXTRA_GROUP_ID = "group_id"
    }

    private lateinit var backButton: View
    private lateinit var candidatesList: RecyclerView
    private lateinit var emptyState: TextView
    private lateinit var adapter: CandidateAdapter

    private var groupId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_admin_picker)

        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        if (groupId.isNullOrEmpty()) {
            ThemedToast.show(this, "Invalid group")
            finish()
            return
        }

        backButton = findViewById(R.id.backButton)
        candidatesList = findViewById(R.id.candidatesList)
        emptyState = findViewById(R.id.emptyState)

        backButton.setOnClickListener { finish() }

        adapter = CandidateAdapter(emptyList()) { c -> onCandidateTap(c) }
        candidatesList.layoutManager = LinearLayoutManager(this)
        candidatesList.adapter = adapter
    }

    override fun onResume() {
        super.onResume()
        loadCandidates()
    }

    private fun loadCandidates() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            val items = withContext(Dispatchers.IO) {
                val mgr = CrdtGroupManager.getInstance(this@AddAdminPickerActivity)
                val keyManager = KeyManager.getInstance(this@AddAdminPickerActivity)
                val db = SecureLegionDatabase.getInstance(
                    this@AddAdminPickerActivity, keyManager.getDatabasePassphrase()
                )
                val myPubkeyHex = keyManager.getSigningPublicKey()
                    .joinToString("") { "%02x".format(it) }
                val myUsername = keyManager.getUsername() ?: "You"

                mgr.queryMembers(gid)
                    .filter { it.accepted && !it.removed && it.role == "Member" }
                    .map { m ->
                        val name = if (m.pubkeyHex.equals(myPubkeyHex, ignoreCase = true)) {
                            myUsername
                        } else {
                            try {
                                val pubkeyBytes = m.pubkeyHex.chunked(2)
                                    .map { it.toInt(16).toByte() }.toByteArray()
                                val pubkeyB64 = android.util.Base64.encodeToString(
                                    pubkeyBytes, android.util.Base64.NO_WRAP
                                )
                                db.contactDao().getContactByPublicKey(pubkeyB64)?.displayName
                            } catch (_: Exception) { null }
                                ?: "Unknown (${m.pubkeyHex.take(8)})"
                        }
                        Candidate(m.pubkeyHex, name)
                    }
                    .sortedBy { it.displayName.lowercase() }
            }
            adapter.submit(items)
            emptyState.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
            candidatesList.visibility = if (items.isEmpty()) View.GONE else View.VISIBLE
        }
    }

    private fun onCandidateTap(c: Candidate) {
        val gid = groupId ?: return
        val intent = Intent(this, EditAdminRightsActivity::class.java).apply {
            putExtra(EditAdminRightsActivity.EXTRA_GROUP_ID, gid)
            putExtra(EditAdminRightsActivity.EXTRA_MEMBER_PUBKEY, c.pubkeyHex)
            putExtra(EditAdminRightsActivity.EXTRA_MEMBER_NAME, c.displayName)
        }
        startActivity(intent)
        // Close this picker so the user returns to the admins list, not the picker
        finish()
    }

    data class Candidate(val pubkeyHex: String, val displayName: String)

    private class CandidateAdapter(
        private var items: List<Candidate>,
        private val onClick: (Candidate) -> Unit
    ) : RecyclerView.Adapter<CandidateAdapter.VH>() {

        fun submit(list: List<Candidate>) { items = list; notifyDataSetChanged() }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_admin_candidate, parent, false)
            return VH(v)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            holder.name.text = item.displayName
            holder.avatar.setName(item.displayName)
            holder.itemView.setOnClickListener { onClick(item) }
            holder.selectButton.setOnClickListener { onClick(item) }
        }

        override fun getItemCount(): Int = items.size

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val name: TextView = view.findViewById(R.id.nameText)
            val avatar: com.securelegion.views.AvatarView = view.findViewById(R.id.candidateAvatar)
            val selectButton: TextView = view.findViewById(R.id.selectButton)
        }
    }
}
