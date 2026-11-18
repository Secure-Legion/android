package com.securelegion

import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LinkedProfileContentCrypto
import com.securelegion.crypto.LinkedProfileCredentialStore
import com.securelegion.database.DeviceChatOutboundStore
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.LinkedDeviceService
import com.securelegion.utils.SessionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Seedless linked-device chat entry point. All sends use recipient device sessions. */
class LinkedMessengerActivity : AppCompatActivity() {
    private lateinit var heading: TextView
    private lateinit var status: TextView
    private lateinit var list: LinearLayout
    private lateinit var input: EditText
    private lateinit var send: Button
    private var selectedId: Long? = null
    private var lastRender = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (KeyManager.getInstance(this).isInitialized() ||
            LinkedProfileCredentialStore(this).activeProfile() == null) {
            startActivity(Intent(this, SplashActivity::class.java))
            finish()
            return
        }
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE)
        SessionManager.setUnlocked(this)
        val service = Intent(this, LinkedDeviceService::class.java)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(service)
        else startService(service)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(20, 30, 20, 20)
            setBackgroundColor(Color.rgb(18, 20, 24))
        }
        heading = TextView(this).apply {
            text = "Linked messages"
            textSize = 23f
            setTextColor(Color.WHITE)
        }
        root.addView(heading)
        status = TextView(this).apply {
            text = "Connecting device sync…"
            textSize = 14f
            setTextColor(Color.LTGRAY)
        }
        root.addView(status)
        val scroll = ScrollView(this)
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(list)
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        val compose = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        input = EditText(this).apply {
            hint = "Message"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            maxLines = 4
        }
        compose.addView(input, LinearLayout.LayoutParams(0, -2, 1f))
        send = Button(this).apply {
            text = "Send"
            isEnabled = false
            setOnClickListener { sendText() }
        }
        compose.addView(send)
        root.addView(compose)
        setContentView(root)
        lifecycleScope.launch {
            while (isActive) {
                val snapshot = withContext(Dispatchers.IO) {
                    runCatching { loadSnapshot() }.getOrElse {
                        Snapshot(emptyList(), emptyList(), it.message ?: "Sync unavailable")
                    }
                }
                render(snapshot)
                delay(1_500)
            }
        }
    }

    private data class ContactRow(val id: Long, val name: String)
    private data class MessageRow(val mine: Boolean, val text: String, val time: Long)
    private data class Snapshot(val contacts: List<ContactRow>,
                                val messages: List<MessageRow>, val issue: String? = null)

    private fun loadSnapshot(): Snapshot {
        val credentials = LinkedProfileCredentialStore(this)
        val key = credentials.activeDatabaseKey() ?: error("Linked profile is locked")
        val database = try { SecureLegionDatabase.getInstance(this, key) }
            finally { key.fill(0) }
        val db = database.openHelper.readableDatabase
        val contacts = db.query(SimpleSQLiteQuery("SELECT id,displayName FROM contacts " +
            "WHERE friendshipStatus='CONFIRMED' AND isBlocked=0 " +
            "ORDER BY lastContactTimestamp DESC LIMIT 100")).use { cursor ->
            buildList {
                while (cursor.moveToNext()) add(ContactRow(cursor.getLong(0),
                    cursor.getString(1)))
            }
        }
        val selected = selectedId
        val messages = if (selected == null) emptyList() else
            LinkedProfileContentCrypto(this).use { crypto ->
                db.query(SimpleSQLiteQuery("SELECT isSentByMe,encryptedContent," +
                    "messageType,timestamp FROM messages WHERE contactId=? " +
                    "ORDER BY timestamp DESC LIMIT 100", arrayOf(selected))).use { cursor ->
                    buildList {
                        while (cursor.moveToNext()) {
                            val type = cursor.getString(2)
                            val text = when (type) {
                                "IMAGE" -> "[Image]"
                                "VOICE" -> "[Voice message]"
                                else -> runCatching { crypto.decryptText(cursor.getString(1)) }
                                    .getOrDefault("[Unable to decrypt]")
                            }
                            add(MessageRow(cursor.getInt(0) == 1, text,
                                cursor.getLong(3)))
                        }
                    }.asReversed()
                }
            }
        return Snapshot(contacts, messages)
    }

    private fun render(snapshot: Snapshot) {
        val selected = selectedId
        val title = snapshot.contacts.firstOrNull { it.id == selected }?.name
        heading.text = title ?: "Linked messages"
        status.text = snapshot.issue ?: if (snapshot.contacts.isEmpty())
            "Waiting for synced contacts" else "${snapshot.contacts.size} contacts"
        send.isEnabled = selected != null && snapshot.issue == null
        val renderKey = snapshot.toString() + selected
        if (renderKey == lastRender) return
        lastRender = renderKey
        list.removeAllViews()
        if (selected == null) {
            for (contact in snapshot.contacts) list.addView(Button(this).apply {
                text = contact.name
                setOnClickListener { selectedId = contact.id; lastRender = "" }
            })
        } else {
            list.addView(Button(this).apply {
                text = "‹ All contacts"
                setOnClickListener { selectedId = null; lastRender = "" }
            })
            for (message in snapshot.messages) list.addView(TextView(this).apply {
                text = message.text
                textSize = 16f
                setTextColor(Color.WHITE)
                gravity = if (message.mine) Gravity.END else Gravity.START
                setPadding(12, 10, 12, 10)
            })
        }
    }

    private fun sendText() {
        val contactId = selectedId ?: return
        val text = input.text.toString().trim()
        if (text.isEmpty()) return
        send.isEnabled = false
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { runCatching {
                val credentials = LinkedProfileCredentialStore(this@LinkedMessengerActivity)
                val profile = credentials.activeProfile() ?: error("Linked profile unavailable")
                val key = credentials.activeDatabaseKey() ?: error("Linked database unavailable")
                val database = try { SecureLegionDatabase.getInstance(
                    this@LinkedMessengerActivity, key) } finally { key.fill(0) }
                val contact = database.contactDao().getContactById(contactId)
                    ?: error("Contact unavailable")
                LinkedProfileContentCrypto(this@LinkedMessengerActivity).use { crypto ->
                    DeviceChatOutboundStore(this@LinkedMessengerActivity, database,
                        DeviceRosterStore(database), profile.accountEd, crypto::encryptText)
                        .queueApplication(contact, text, text.toByteArray(Charsets.UTF_8),
                            0x00, null, false)
                }
            } }
            result.onSuccess { input.text.clear(); lastRender = "" }
                .onFailure { status.text = it.message ?: "Could not send" }
            send.isEnabled = selectedId != null
        }
    }
}
