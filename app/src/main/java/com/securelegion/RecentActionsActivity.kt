package com.securelegion

import android.os.Bundle
import android.text.format.DateUtils
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.services.AuditLogFormatter
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Read-only viewer for the CRDT op log, filtered to audit-worthy actions
 * (membership, roles, metadata, group lifecycle). Newest-first.
 */
class RecentActionsActivity : BaseActivity() {

    companion object {
        const val EXTRA_GROUP_ID = "group_id"
    }

    private lateinit var backButton: View
    private lateinit var actionsList: RecyclerView
    private lateinit var emptyState: TextView
    private lateinit var adapter: AuditAdapter

    private var groupId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_recent_actions)

        groupId = intent.getStringExtra(EXTRA_GROUP_ID)
        if (groupId.isNullOrEmpty()) {
            ThemedToast.show(this, "Invalid group")
            finish()
            return
        }

        backButton = findViewById(R.id.backButton)
        actionsList = findViewById(R.id.actionsList)
        emptyState = findViewById(R.id.emptyState)

        backButton.setOnClickListener { finish() }

        adapter = AuditAdapter(emptyList())
        actionsList.layoutManager = LinearLayoutManager(this)
        actionsList.adapter = adapter

        loadEntries()
    }

    private fun loadEntries() {
        val gid = groupId ?: return
        lifecycleScope.launch {
            val entries = withContext(Dispatchers.IO) {
                AuditLogFormatter.buildEntries(this@RecentActionsActivity, gid)
            }
            adapter.submit(entries)
            emptyState.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
            actionsList.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE
        }
    }

    private class AuditAdapter(
        private var items: List<AuditLogFormatter.AuditEntry>
    ) : RecyclerView.Adapter<AuditAdapter.VH>() {

        fun submit(list: List<AuditLogFormatter.AuditEntry>) {
            items = list
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val v = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_audit_entry, parent, false)
            return VH(v)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            holder.description.text = item.description
            holder.timestamp.text = DateUtils.getRelativeTimeSpanString(
                item.timestampMs,
                System.currentTimeMillis(),
                DateUtils.MINUTE_IN_MILLIS
            ).toString()
        }

        override fun getItemCount(): Int = items.size

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val description: TextView = view.findViewById(R.id.descriptionText)
            val timestamp: TextView = view.findViewById(R.id.timestampText)
        }
    }
}
