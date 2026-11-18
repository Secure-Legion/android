package com.securelegion

import android.content.Intent
import android.app.AlertDialog
import android.graphics.BitmapFactory
import android.media.MediaMetadataRetriever
import android.media.MediaDataSource
import android.media.MediaPlayer
import android.net.Uri
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import androidx.sqlite.db.SimpleSQLiteQuery
import com.securelegion.crypto.KeyManager
import com.securelegion.crypto.LinkedProfileContentCrypto
import com.securelegion.crypto.LinkedProfileCredentialStore
import com.securelegion.database.DeviceChatOutboundStore
import com.securelegion.database.DeviceRosterStore
import com.securelegion.database.LinkedChatStore
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.services.LinkedDeviceService
import com.securelegion.sync.DeviceSyncMediaFiles
import com.securelegion.sync.NearbyHistoryServer
import com.securelegion.utils.BrandedQrGenerator
import com.securelegion.utils.SessionManager
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.util.UUID
import java.io.File

/** Seedless linked-device chat entry point. All sends use recipient device sessions. */
class LinkedMessengerActivity : AppCompatActivity() {
    @Volatile private var historyServer: NearbyHistoryServer? = null
    private var historyDialog: AlertDialog? = null
    private lateinit var heading: TextView
    private lateinit var status: TextView
    private lateinit var list: LinearLayout
    private lateinit var input: EditText
    private lateinit var send: Button
    private lateinit var image: Button
    private lateinit var voice: Button
    private var selectedId: String? = null
    private var lastRender = ""
    private val imagePicker = registerForActivityResult(ActivityResultContracts.GetContent()) {
        uri -> if (uri != null) sendMedia(uri, "IMAGE")
    }
    private val voicePicker = registerForActivityResult(ActivityResultContracts.GetContent()) {
        uri -> if (uri != null) sendMedia(uri, "VOICE")
    }

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
        root.addView(Button(this).apply {
            text = "Receive history over Wi-Fi"
            setOnClickListener { chooseHistorySource() }
        })
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
        val attachments = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        image = Button(this).apply {
            text = "Image"
            isEnabled = false
            setOnClickListener { imagePicker.launch("image/*") }
        }
        voice = Button(this).apply {
            text = "Voice file"
            isEnabled = false
            setOnClickListener { voicePicker.launch("audio/*") }
        }
        attachments.addView(image, LinearLayout.LayoutParams(0, -2, 1f))
        attachments.addView(voice, LinearLayout.LayoutParams(0, -2, 1f))
        root.addView(attachments)
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

    private data class ContactRow(val id: String, val name: String)
    private data class MessageRow(val mine: Boolean, val text: String, val time: Long,
                                  val type: String, val mediaPath: String?)
    private data class Snapshot(val contacts: List<ContactRow>,
                                val messages: List<MessageRow>, val issue: String? = null)

    private fun loadSnapshot(): Snapshot {
        val credentials = LinkedProfileCredentialStore(this)
        val key = credentials.activeDatabaseKey() ?: error("Linked profile is locked")
        val database = try { SecureLegionDatabase.getInstance(this, key) }
            finally { key.fill(0) }
        return LinkedProfileContentCrypto(this).use { crypto ->
            LinkedChatStore(database, DeviceRosterStore(database),
                crypto::encryptText, DeviceSyncMediaFiles(this,
                    crypto::encryptImage, crypto::encryptVoice)).ensureSchema()
            val db = database.openHelper.readableDatabase
            val contacts = db.query(SimpleSQLiteQuery(
                "SELECT account_ed,display_name FROM linked_chat_contacts " +
                    "WHERE blocked=0 ORDER BY updated_at_ms DESC LIMIT 100"
            )).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(ContactRow(cursor.getString(0),
                        cursor.getString(1)))
                }
            }
            val selected = selectedId
            val messages = if (selected == null) emptyList() else
                db.query(SimpleSQLiteQuery("SELECT sent_by_me,encrypted_content," +
                    "type,timestamp_ms,media_path FROM linked_chat_messages WHERE account_ed=? " +
                    "ORDER BY timestamp_ms DESC LIMIT 100", arrayOf(selected))).use { cursor ->
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
                                cursor.getLong(3), type,
                                if (cursor.isNull(4)) null else cursor.getString(4)))
                        }
                    }.asReversed()
                }
            Snapshot(contacts, messages)
        }
    }

    private fun render(snapshot: Snapshot) {
        val selected = selectedId
        val title = snapshot.contacts.firstOrNull { it.id == selected }?.name
        heading.text = title ?: "Linked messages"
        status.text = snapshot.issue ?: if (snapshot.contacts.isEmpty())
            "Waiting for synced contacts" else "${snapshot.contacts.size} contacts"
        send.isEnabled = selected != null && snapshot.issue == null
        image.isEnabled = send.isEnabled
        voice.isEnabled = send.isEnabled
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
            for (message in snapshot.messages) {
                val view = if (message.mediaPath == null) TextView(this) else Button(this)
                view.text = message.text
                view.textSize = 16f
                view.setTextColor(Color.WHITE)
                view.gravity = if (message.mine) Gravity.END else Gravity.START
                view.setPadding(12, 10, 12, 10)
                if (message.mediaPath != null) view.setOnClickListener {
                    openMedia(message)
                }
                list.addView(view)
            }
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
                LinkedProfileContentCrypto(this@LinkedMessengerActivity).use { crypto ->
                    LinkedChatStore(database, DeviceRosterStore(database),
                        crypto::encryptText, DeviceSyncMediaFiles(
                            this@LinkedMessengerActivity, crypto::encryptImage,
                            crypto::encryptVoice)).ensureSchema()
                    DeviceChatOutboundStore(this@LinkedMessengerActivity, database,
                        DeviceRosterStore(database), profile.accountEd, crypto::encryptText)
                        .queueLinkedText(Base64.decode(contactId, Base64.NO_WRAP), text)
                }
            } }
            if (result.isSuccess) {
                input.text.clear()
                lastRender = ""
                withContext(Dispatchers.IO) { runCatching { loadSnapshot() }.getOrNull() }
                    ?.let(::render)
            } else status.text = result.exceptionOrNull()?.message ?: "Could not send"
            send.isEnabled = selectedId != null
        }
    }

    private fun sendMedia(uri: Uri, type: String) {
        val contactId = selectedId ?: return
        send.isEnabled = false
        image.isEnabled = false
        voice.isEnabled = false
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { runCatching {
                val maximum = if (type == "IMAGE") 4 * 1024 * 1024 else 5 * 1024 * 1024
                val raw = readBounded(uri, maximum)
                try {
                    val duration = if (type == "VOICE") {
                        MediaMetadataRetriever().use { retriever ->
                            retriever.setDataSource(this@LinkedMessengerActivity, uri)
                            val millis = retriever.extractMetadata(
                                MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull()
                                ?: error("Audio duration unavailable")
                            ((millis + 999) / 1000).toInt().also {
                                require(it in 1..600)
                            }
                        }
                    } else null
                    val credentials = LinkedProfileCredentialStore(
                        this@LinkedMessengerActivity)
                    val profile = credentials.activeProfile()
                        ?: error("Linked profile unavailable")
                    val key = credentials.activeDatabaseKey()
                        ?: error("Linked database unavailable")
                    val database = try { SecureLegionDatabase.getInstance(
                        this@LinkedMessengerActivity, key) } finally { key.fill(0) }
                    LinkedProfileContentCrypto(this@LinkedMessengerActivity).use { crypto ->
                        val roster = DeviceRosterStore(database)
                        val files = DeviceSyncMediaFiles(this@LinkedMessengerActivity,
                            crypto::encryptImage, crypto::encryptVoice)
                        LinkedChatStore(database, roster, crypto::encryptText,
                            files).ensureSchema()
                        val body = if (type == "VOICE") ByteArray(4 + raw.size).also {
                            val seconds = requireNotNull(duration)
                            for (i in 0..3) it[i] =
                                (seconds ushr ((3 - i) * 8)).toByte()
                            raw.copyInto(it, 4)
                        } else raw.copyOf()
                        try {
                            val path = files.storeRaw(type, UUID.randomUUID().toString(),
                                raw.copyOf())
                            DeviceChatOutboundStore(this@LinkedMessengerActivity,
                                database, roster, profile.accountEd, crypto::encryptText)
                                .queueLinkedApplication(Base64.decode(contactId,
                                    Base64.NO_WRAP), "", body,
                                    if (type == "IMAGE") 0x02 else 0x01,
                                    mediaPath = path, voiceDuration = duration)
                        } finally { body.fill(0) }
                    }
                } finally { raw.fill(0) }
            } }
            if (result.isSuccess) {
                lastRender = ""
                withContext(Dispatchers.IO) { runCatching { loadSnapshot() }.getOrNull() }
                    ?.let(::render)
            } else status.text = result.exceptionOrNull()?.message ?: "Could not attach media"
            send.isEnabled = selectedId != null
            image.isEnabled = send.isEnabled
            voice.isEnabled = send.isEnabled
        }
    }

    private fun readBounded(uri: Uri, maximum: Int): ByteArray {
        val input = contentResolver.openInputStream(uri) ?: error("Attachment unavailable")
        return input.use { stream ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(32 * 1024)
            while (true) {
                val count = stream.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) { "Attachment too large" }
                output.write(buffer, 0, count)
            }
            output.toByteArray().also { require(it.isNotEmpty()) }
        }
    }

    private fun openMedia(message: MessageRow) {
        val path = message.mediaPath ?: return
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { runCatching {
                val folder = if (message.type == "IMAGE") "image_messages"
                    else "voice_messages"
                require(message.type == "IMAGE" || message.type == "VOICE")
                val root = File(filesDir, folder).canonicalFile
                val file = File(path).canonicalFile
                require(file.parentFile == root && file.isFile &&
                    file.length() in 29L..5_242_944L)
                val encrypted = file.readBytes()
                try {
                    LinkedProfileContentCrypto(this@LinkedMessengerActivity).use { crypto ->
                        if (message.type == "IMAGE") crypto.decryptImage(encrypted)
                        else crypto.decryptVoice(encrypted)
                    }
                } finally { encrypted.fill(0) }
            } }
            result.onFailure { status.text = "Could not open attachment" }
            result.onSuccess { bytes ->
                if (message.type == "IMAGE") {
                    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                    var sample = 1
                    while (bounds.outWidth / sample > 2048 ||
                        bounds.outHeight / sample > 2048) sample *= 2
                    val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size,
                        BitmapFactory.Options().apply { inSampleSize = sample })
                    bytes.fill(0)
                    if (bitmap == null) { status.text = "Could not open image"; return@onSuccess }
                    val view = ImageView(this@LinkedMessengerActivity).apply {
                        setImageBitmap(bitmap)
                        adjustViewBounds = true
                    }
                    AlertDialog.Builder(this@LinkedMessengerActivity)
                        .setView(view).setPositiveButton("Close", null)
                        .setOnDismissListener { bitmap.recycle() }.show()
                } else {
                    val source = MemoryAudioSource(bytes)
                    val player = MediaPlayer()
                    runCatching {
                        player.setDataSource(source)
                        player.prepare()
                        player.start()
                        AlertDialog.Builder(this@LinkedMessengerActivity)
                            .setMessage("Playing voice message")
                            .setPositiveButton("Stop", null)
                            .setOnDismissListener { player.release(); source.close() }
                            .show()
                    }.onFailure {
                        player.release(); source.close()
                        status.text = "Could not play voice message"
                    }
                }
            }
        }
    }

    private class MemoryAudioSource(private val bytes: ByteArray) : MediaDataSource() {
        override fun getSize(): Long = bytes.size.toLong()
        override fun readAt(position: Long, buffer: ByteArray, offset: Int,
                            size: Int): Int {
            if (position >= bytes.size) return -1
            val count = minOf(size, bytes.size - position.toInt())
            bytes.copyInto(buffer, offset, position.toInt(), position.toInt() + count)
            return count
        }
        override fun close() { bytes.fill(0) }
    }

    private fun chooseHistorySource() {
        lifecycleScope.launch {
            val devices = withContext(Dispatchers.IO) { runCatching {
                val credentials = LinkedProfileCredentialStore(this@LinkedMessengerActivity)
                val account = credentials.activeProfile()?.accountEd
                    ?: error("Linked profile unavailable")
                val key = credentials.activeDatabaseKey() ?: error("Linked database unavailable")
                val db = try { SecureLegionDatabase.getInstance(this@LinkedMessengerActivity, key) }
                    finally { key.fill(0) }
                DeviceRosterStore(db).listAuthorizedDevices(account).filter { !it.isSelf }
            } }
            val choices = devices.getOrElse {
                status.text = it.message ?: "Device list unavailable"
                return@launch
            }
            if (choices.isEmpty()) {
                status.text = "Link another device first"
                return@launch
            }
            AlertDialog.Builder(this@LinkedMessengerActivity)
                .setTitle("Receive history from")
                .setItems(choices.map { it.displayName }.toTypedArray()) { _, which ->
                    receiveHistory(choices[which].deviceId)
                }.show()
        }
    }

    private fun receiveHistory(peerId: String) {
        if (historyServer != null) return
        lifecycleScope.launch {
            val opened = withContext(Dispatchers.IO) {
                runCatching { NearbyHistoryServer.open(this@LinkedMessengerActivity, peerId) }
            }
            val server = opened.getOrElse {
                status.text = it.message ?: "Could not start Nearby history"
                return@launch
            }
            historyServer = server
            val bitmap = BrandedQrGenerator.generate(this@LinkedMessengerActivity,
                BrandedQrGenerator.QrOptions(server.offer, size = 640,
                    showLogo = false, showWebsite = false))
            if (bitmap == null) {
                server.close()
                historyServer = null
                status.text = "Could not show transfer code"
                return@launch
            }
            val qr = ImageView(this@LinkedMessengerActivity).apply {
                setPadding(24, 24, 24, 24)
                setImageBitmap(bitmap)
                contentDescription = "Secure Nearby history QR"
            }
            historyDialog = AlertDialog.Builder(this@LinkedMessengerActivity)
                .setTitle("Scan on your other device")
                .setView(qr)
                .setMessage("Keep both devices on the same Wi-Fi network.")
                .setNegativeButton("Stop") { _, _ -> server.close() }
                .create().also { it.show() }
            val result = withContext(Dispatchers.IO) {
                runCatching { server.run { message ->
                    runOnUiThread { status.text = message }
                } }
            }
            historyServer = null
            server.close()
            historyDialog?.dismiss()
            historyDialog = null
            status.text = result.fold(
                onSuccess = { "Imported ${it.imported} updates; ${it.deferred} deferred" },
                onFailure = { it.message ?: "History transfer stopped" })
        }
    }

    override fun onStop() {
        historyServer?.close()
        historyDialog?.dismiss()
        historyDialog = null
        super.onStop()
    }
}
