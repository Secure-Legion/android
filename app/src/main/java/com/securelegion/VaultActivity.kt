package com.securelegion

import android.os.Bundle
import android.text.InputType
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.database.entities.VaultItem
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast
import com.securelegion.vault.VaultManager
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Secure Vault browser — 3 tabs (Media, Voice, Files), optional PIN gate.
 *
 * Items are inserted into the vault from chat long-press "Save to Vault" (premium,
 * coming soon). This activity is currently read/delete only.
 */
class VaultActivity : AppCompatActivity() {

    private lateinit var vaultList: RecyclerView
    private lateinit var emptyState: View
    private lateinit var tabMedia: TextView
    private lateinit var tabVoice: TextView
    private lateinit var tabFiles: TextView

    private var currentTab: String = "image"
    private val adapter = VaultAdapter(
        onClick = { item -> onItemClicked(item) },
        onLongPress = { item -> confirmDelete(item) }
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_vault)

        // PIN gate: if a PIN is set, prompt before showing content
        if (VaultManager.isPinSet(this)) {
            promptPin(onSuccess = { setup() }, onCancel = { finish() })
        } else {
            setup()
        }
    }

    private fun setup() {
        vaultList = findViewById(R.id.vaultList)
        emptyState = findViewById(R.id.emptyState)
        tabMedia = findViewById(R.id.tabMedia)
        tabVoice = findViewById(R.id.tabVoice)
        tabFiles = findViewById(R.id.tabFiles)

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }
        findViewById<View>(R.id.settingsButton).setOnClickListener { showSettingsDialog() }

        tabMedia.setOnClickListener { switchTab("image") }
        tabVoice.setOnClickListener { switchTab("voice") }
        tabFiles.setOnClickListener { switchTab("file") }

        vaultList.adapter = adapter
        switchTab("image")
    }

    private fun switchTab(type: String) {
        currentTab = type
        // Active pill styling
        fun setActive(tv: TextView, active: Boolean) {
            tv.setTextColor(ContextCompat.getColor(this,
                if (active) R.color.tab_pill_active_text else R.color.text_gray))
            tv.setBackgroundResource(
                if (active) R.drawable.tab_pill_active_bg else R.drawable.tab_pill_bg)
        }
        setActive(tabMedia, type == "image")
        setActive(tabVoice, type == "voice")
        setActive(tabFiles, type == "file")

        // Media tab uses grid, others use list
        vaultList.layoutManager = if (type == "image") {
            GridLayoutManager(this, 3)
        } else {
            LinearLayoutManager(this)
        }
        adapter.isGrid = (type == "image")

        loadItems()
    }

    private fun loadItems() {
        lifecycleScope.launch {
            val items = VaultManager.fetchAll(this@VaultActivity, currentTab)
            adapter.submit(items)
            if (items.isEmpty()) {
                emptyState.visibility = View.VISIBLE
                vaultList.visibility = View.GONE
            } else {
                emptyState.visibility = View.GONE
                vaultList.visibility = View.VISIBLE
            }
        }
    }

    private fun onItemClicked(item: VaultItem) {
        // Placeholder for full-screen preview / playback — Kotlin-only scope for now
        ThemedToast.show(this, "${item.type}: ${item.fileName ?: item.id.take(8)}")
    }

    private fun confirmDelete(item: VaultItem) {
        GlassDialog.builder(this)
            .setTitle("Delete from vault?")
            .setMessage("This cannot be undone.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Delete") { _, _ ->
                lifecycleScope.launch {
                    if (VaultManager.delete(this@VaultActivity, item.id)) {
                        loadItems()
                    }
                }
            }
            .show()
    }

    // ─── PIN gate ───────────────────────────────────────────────────

    private fun promptPin(onSuccess: () -> Unit, onCancel: () -> Unit) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = "Enter vault PIN"
            setTextColor(ContextCompat.getColor(this@VaultActivity, R.color.text_primary))
            setHintTextColor(ContextCompat.getColor(this@VaultActivity, R.color.text_gray))
        }
        GlassDialog.builder(this)
            .setTitle("Secure Vault")
            .setView(input)
            .setCancelable(false)
            .setNegativeButton("Cancel") { _, _ -> onCancel() }
            .setPositiveButton("Unlock") { _, _ ->
                val pin = input.text.toString()
                if (VaultManager.verifyPin(this, pin)) {
                    onSuccess()
                } else {
                    ThemedToast.show(this, "Incorrect PIN")
                    finish()
                }
            }
            .show()
    }

    private fun showSettingsDialog() {
        val hasPin = VaultManager.isPinSet(this)
        val options = if (hasPin) arrayOf("Change PIN", "Remove PIN") else arrayOf("Set PIN")
        GlassDialog.builder(this)
            .setTitle("Vault Settings")
            .setItems(options) { _, which ->
                when (options[which]) {
                    "Set PIN", "Change PIN" -> promptNewPin()
                    "Remove PIN" -> {
                        VaultManager.clearPin(this)
                        ThemedToast.show(this, "PIN removed")
                    }
                }
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun promptNewPin() {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = "Enter new PIN (4+ digits)"
            setTextColor(ContextCompat.getColor(this@VaultActivity, R.color.text_primary))
            setHintTextColor(ContextCompat.getColor(this@VaultActivity, R.color.text_gray))
        }
        GlassDialog.builder(this)
            .setTitle("Set Vault PIN")
            .setView(input)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save") { _, _ ->
                val pin = input.text.toString()
                if (VaultManager.setPin(this, pin)) {
                    ThemedToast.show(this, "PIN saved")
                } else {
                    ThemedToast.show(this, "PIN must be 4+ digits")
                }
            }
            .show()
    }

    // ─── Adapter ────────────────────────────────────────────────────

    private class VaultAdapter(
        private val onClick: (VaultItem) -> Unit,
        private val onLongPress: (VaultItem) -> Unit
    ) : RecyclerView.Adapter<VaultAdapter.VH>() {

        private val items = mutableListOf<VaultItem>()
        var isGrid: Boolean = false

        fun submit(newItems: List<VaultItem>) {
            items.clear()
            items.addAll(newItems)
            notifyDataSetChanged()
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_vault_entry, parent, false)
            return VH(view)
        }

        override fun onBindViewHolder(holder: VH, position: Int) {
            val item = items[position]
            val dateStr = item.sourceTimestamp?.let {
                SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(it))
            } ?: SimpleDateFormat("MMM d, yyyy", Locale.getDefault()).format(Date(item.createdAtMs))

            when (item.type) {
                "image" -> {
                    holder.title.text = item.fileName ?: "Photo"
                    holder.subtitle.text = dateStr
                    holder.icon.setImageResource(R.drawable.ic_image_placeholder)
                    // Try to decode base64 thumb
                    val data = item.data
                    if (!data.isNullOrBlank()) {
                        try {
                            val bytes = Base64.decode(data, Base64.NO_WRAP)
                            val bitmap = android.graphics.BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
                            if (bitmap != null) {
                                holder.thumb.setImageBitmap(bitmap)
                                holder.thumb.visibility = View.VISIBLE
                                holder.icon.visibility = View.GONE
                            }
                        } catch (e: Exception) {
                            Log.w("VaultAdapter", "Failed to decode thumb", e)
                        }
                    }
                }
                "voice" -> {
                    holder.title.text = item.fileName ?: "Voice clip"
                    val dur = item.duration?.toInt() ?: 0
                    holder.subtitle.text = "${dur}s  ·  $dateStr"
                    holder.icon.setImageResource(R.drawable.ic_mic)
                    holder.thumb.visibility = View.GONE
                    holder.icon.visibility = View.VISIBLE
                }
                "file" -> {
                    holder.title.text = item.fileName ?: "File"
                    holder.subtitle.text = dateStr
                    holder.icon.setImageResource(R.drawable.ic_image_placeholder)
                    holder.thumb.visibility = View.GONE
                    holder.icon.visibility = View.VISIBLE
                }
            }
            holder.itemView.setOnClickListener { onClick(item) }
            holder.itemView.setOnLongClickListener { onLongPress(item); true }
        }

        override fun getItemCount() = items.size

        class VH(view: View) : RecyclerView.ViewHolder(view) {
            val icon: ImageView = view.findViewById(R.id.vaultItemIcon)
            val thumb: ImageView = view.findViewById(R.id.vaultItemThumb)
            val title: TextView = view.findViewById(R.id.vaultItemTitle)
            val subtitle: TextView = view.findViewById(R.id.vaultItemSubtitle)
        }
    }
}
