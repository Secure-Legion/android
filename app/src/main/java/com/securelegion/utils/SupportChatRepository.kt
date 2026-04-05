package com.securelegion.utils

import android.content.Context
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.Message
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Local-only "support chat" thread that matches the iOS behavior.
 *
 * Creates a pseudo-contact (`support_company_thread`) and inserts messages directly
 * into the encrypted database. No network activity — the thread lives purely on
 * device and is rendered like any other contact thread.
 */
object SupportChatRepository {
    const val SUPPORT_CONTACT_ID = "support_company_thread"
    const val SUPPORT_CONTACT_NAME = "Secure Legion Support"

    private const val SUPPORT_PREFS = "support"
    private const val KEY_TICKET_OPEN = "ticket_open"
    private const val KEY_TICKET_ID = "ticket_id"
    private const val KEY_TICKET_OPENED_AT = "ticket_opened_at"

    private const val AUTO_REPLY_BODY =
        "Thanks for reaching out! A Secure Legion team member will be with you shortly. " +
        "We usually reply within 24 hours."

    private val secureRandom = SecureRandom()

    /**
     * Ensure the fake support contact exists. Idempotent.
     */
    suspend fun ensureSupportContact(context: Context): Contact = withContext(Dispatchers.IO) {
        val db = database(context)
        val existing = db.contactDao().getContactByOnionAddress(SUPPORT_CONTACT_ID)
        if (existing != null) return@withContext existing

        val now = System.currentTimeMillis()
        val contact = Contact(
            id = 0,
            displayName = SUPPORT_CONTACT_NAME,
            solanaAddress = SUPPORT_CONTACT_ID, // unique key — must be non-empty, unique
            publicKeyBase64 = "",
            x25519PublicKeyBase64 = "",
            kyberPublicKeyBase64 = null,
            torOnionAddress = SUPPORT_CONTACT_ID,
            friendRequestOnion = "",
            messagingOnion = SUPPORT_CONTACT_ID,
            voiceOnion = null,
            ipfsCid = null,
            contactPin = null,
            profilePictureBase64 = null,
            addedTimestamp = now,
            lastContactTimestamp = now,
            trustLevel = Contact.TRUST_TRUSTED,
            isDistressContact = false,
            notes = null,
            isBlocked = false,
            friendshipStatus = Contact.FRIENDSHIP_CONFIRMED,
            needsTapSync = false,
            isPinned = false,
            nickname = null
        )
        val rowId = db.contactDao().insertContact(contact)
        contact.copy(id = rowId)
    }

    /**
     * Submit a support ticket. Inserts the user's ticket message plus an auto-reply
     * into the support thread and persists open-ticket state in SharedPreferences.
     *
     * @return The 8-character ticket ID.
     */
    suspend fun submitTicket(
        context: Context,
        reason: String,
        details: String,
        includeDebugLog: Boolean
    ): String = withContext(Dispatchers.IO) {
        val contact = ensureSupportContact(context)
        val keyManager = KeyManager.getInstance(context)
        val db = database(context)

        val ticketId = UUID.randomUUID().toString().replace("-", "").take(8).uppercase(Locale.US)
        val dateStr = SimpleDateFormat("MMM d, yyyy 'at' h:mm a", Locale.US).format(Date())

        val ticketBody = buildString {
            appendLine("[Support Ticket]")
            appendLine("Ticket ID: $ticketId")
            appendLine("Date: $dateStr")
            appendLine("Reason: $reason")
            appendLine("Client Response: $details")
            if (includeDebugLog) {
                appendLine()
                appendLine("[Debug Info]")
                appendLine("Device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
                appendLine("Android: ${android.os.Build.VERSION.RELEASE} (SDK ${android.os.Build.VERSION.SDK_INT})")
            }
        }.trimEnd()

        val now = System.currentTimeMillis()

        // Outgoing ticket message
        val userMessageId = "support_ticket_${UUID.randomUUID()}"
        val userMsg = Message(
            contactId = contact.id,
            messageId = userMessageId,
            encryptedContent = keyManager.encryptMessageContent(ticketBody),
            isSentByMe = true,
            timestamp = now,
            status = Message.STATUS_SENT,
            signatureBase64 = "",
            nonceBase64 = "",
            messageNonce = secureRandom.nextLong(),
            messageType = Message.MESSAGE_TYPE_TEXT,
            pingDelivered = true,
            messageDelivered = true,
            isRead = true,
            requiresReadReceipt = false
        )
        db.messageDao().insertMessage(userMsg)

        // Incoming auto-reply
        val replyMessageId = "support_auto_${UUID.randomUUID()}"
        val autoReply = Message(
            contactId = contact.id,
            messageId = replyMessageId,
            encryptedContent = keyManager.encryptMessageContent(AUTO_REPLY_BODY),
            isSentByMe = false,
            timestamp = now + 100,
            status = Message.STATUS_DELIVERED,
            signatureBase64 = "",
            nonceBase64 = "",
            messageNonce = secureRandom.nextLong(),
            messageType = Message.MESSAGE_TYPE_TEXT,
            pingDelivered = true,
            messageDelivered = true,
            isRead = false,
            requiresReadReceipt = false
        )
        db.messageDao().insertMessage(autoReply)

        // Bump last-contact so the thread surfaces at the top of the chats list
        db.contactDao().updateLastContactTime(contact.id, now + 100)

        val prefs = context.getSharedPreferences(SUPPORT_PREFS, Context.MODE_PRIVATE)
        prefs.edit()
            .putBoolean(KEY_TICKET_OPEN, true)
            .putString(KEY_TICKET_ID, ticketId)
            .putLong(KEY_TICKET_OPENED_AT, now)
            .apply()

        ticketId
    }

    /** @return true if there is an outstanding ticket waiting for a reply. */
    fun isTicketOpen(context: Context): Boolean {
        return context.getSharedPreferences(SUPPORT_PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_TICKET_OPEN, false)
    }

    /** @return The current open ticket ID, or null if no ticket is open. */
    fun currentTicketId(context: Context): String? {
        val prefs = context.getSharedPreferences(SUPPORT_PREFS, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(KEY_TICKET_OPEN, false)) return null
        return prefs.getString(KEY_TICKET_ID, null)
    }

    private fun database(context: Context): SecureLegionDatabase {
        val keyManager = KeyManager.getInstance(context)
        return SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())
    }
}
