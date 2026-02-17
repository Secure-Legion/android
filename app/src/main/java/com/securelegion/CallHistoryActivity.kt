package com.securelegion

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.TextView
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.adapters.CallHistoryAdapter
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.CallHistory
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class CallHistoryActivity : BaseActivity() {

    companion object {
        private const val TAG = "CallHistoryActivity"
    }

    private lateinit var historyRecyclerView: RecyclerView
    private lateinit var emptyStateText: TextView
    private lateinit var historyAdapter: CallHistoryAdapter
    private lateinit var database: SecureLegionDatabase

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_call_history)

        // Initialize views
        historyRecyclerView = findViewById(R.id.historyRecyclerView)
        emptyStateText = findViewById(R.id.emptyStateText)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Clear All button
        findViewById<View>(R.id.clearAllButton).setOnClickListener {
            showClearAllConfirmation()
        }

        // Setup RecyclerView
        historyAdapter = CallHistoryAdapter(
            callHistory = emptyList(),
            onReCallClick = { call ->
                reCall(call)
            },
            onItemClick = { call ->
                openContactChat(call)
            }
        )
        historyRecyclerView.layoutManager = LinearLayoutManager(this)
        historyRecyclerView.adapter = historyAdapter

        // Load call history
        loadCallHistory()

        // Setup bottom navigation
        setupBottomNavigation()
    }

    private fun setupBottomNavigation() {
        BottomNavigationHelper.setupBottomNavigation(this)
    }

    private fun loadCallHistory() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val keyManager = KeyManager.getInstance(this@CallHistoryActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                database = SecureLegionDatabase.getInstance(this@CallHistoryActivity, dbPassphrase)

                // Get all call history (already sorted by timestamp DESC in DAO)
                val history = database.callHistoryDao().getAllCallHistoryList()

                withContext(Dispatchers.Main) {
                    if (history.isEmpty()) {
                        emptyStateText.visibility = View.VISIBLE
                        historyRecyclerView.visibility = View.GONE
                    } else {
                        emptyStateText.visibility = View.GONE
                        historyRecyclerView.visibility = View.VISIBLE
                        historyAdapter.updateHistory(history)
                    }
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error loading call history", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@CallHistoryActivity, "Error loading call history")
                }
            }
        }
    }

    private fun showClearAllConfirmation() {
        AlertDialog.Builder(this)
            .setTitle("Clear Call History")
            .setMessage("Clear all call history? This cannot be undone.")
            .setPositiveButton("Clear All") { _, _ ->
                clearAllHistory()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun clearAllHistory() {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                database.callHistoryDao().deleteAll()

                withContext(Dispatchers.Main) {
                    emptyStateText.visibility = View.VISIBLE
                    historyRecyclerView.visibility = View.GONE
                    historyAdapter.updateHistory(emptyList())
                    ThemedToast.show(this@CallHistoryActivity, "Call history cleared")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error clearing call history", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@CallHistoryActivity, "Error clearing history")
                }
            }
        }
    }

    private fun reCall(call: CallHistory) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Get contact from database
                val contact = database.contactDao().getContactById(call.contactId)

                withContext(Dispatchers.Main) {
                    if (contact == null) {
                        ThemedToast.show(this@CallHistoryActivity, "Contact not found")
                        return@withContext
                    }

                    if (contact.voiceOnion.isNullOrEmpty()) {
                        ThemedToast.show(this@CallHistoryActivity, "${contact.displayName} doesn't have a voice .onion address")
                        return@withContext
                    }

                    // Launch VoiceCallActivity
                    val intent = Intent(this@CallHistoryActivity, VoiceCallActivity::class.java).apply {
                        putExtra("CONTACT_ID", contact.id)
                        putExtra("CONTACT_NAME", contact.displayName)
                        putExtra("VOICE_ONION", contact.voiceOnion)
                        putExtra("IS_OUTGOING", true)
                    }
                    startActivity(intent)
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error initiating re-call", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@CallHistoryActivity, "Error initiating call")
                }
            }
        }
    }

    private fun openContactChat(call: CallHistory) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Get contact from database
                val contact = database.contactDao().getContactById(call.contactId)

                withContext(Dispatchers.Main) {
                    if (contact == null) {
                        ThemedToast.show(this@CallHistoryActivity, "Contact not found")
                        return@withContext
                    }

                    // Launch ChatActivity
                    val intent = Intent(this@CallHistoryActivity, ChatActivity::class.java).apply {
                        putExtra("CONTACT_ID", contact.id)
                        putExtra("CONTACT_NAME", contact.displayName)
                    }
                    startActivity(intent)
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error opening chat", e)
            }
        }
    }
}
