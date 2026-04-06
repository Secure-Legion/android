package com.securelegion.services

import android.content.Context
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.CrdtOpLog

/**
 * Stateless helper that turns a [CrdtOpLog] row into a human-readable
 * audit entry for the Recent Actions viewer.
 *
 * Author resolution goes through Contact table → group members → raw pubkey hex.
 * Payload-level details (target, flags) aren't decoded here — the Rust op bytes
 * would need FFI parsing. For v1 we display op-type-level labels which is
 * enough to answer "what did Alice do?" at a glance.
 */
object AuditLogFormatter {

    /** Ops worth surfacing in the audit log. Skips message traffic (too spammy). */
    private val AUDIT_OP_TYPES = setOf(
        "GroupCreate", "MemberInvite", "MemberAccept", "MemberRemove",
        "MemberUnban", "RoleSet", "MetadataSet", "GroupDelete",
    )

    data class AuditEntry(
        val opId: String,
        val lamport: Long,
        val timestampMs: Long,
        val authorDeviceIdHex: String,
        val authorDisplayName: String,
        val opType: String,
        val description: String,
    )

    /**
     * Filter + format all audit-worthy ops for a group, newest-first.
     *
     * Author resolution chain:
     *   opId prefix = DeviceID (16 bytes, 32 hex chars)
     *   → group member.pubkeyHex (via queryMembers device_id lookup)
     *   → Contact.displayName (via contactDao) or local username if it's us.
     */
    suspend fun buildEntries(context: Context, groupId: String): List<AuditEntry> {
        val keyManager = KeyManager.getInstance(context)
        val db = SecureLegionDatabase.getInstance(context, keyManager.getDatabasePassphrase())

        val rawOps = db.crdtOpLogDao().getOpsForGroup(groupId)
        val localPubkeyHex = keyManager.getSigningPublicKey()
            .joinToString("") { "%02x".format(it) }
        val localUsername = keyManager.getUsername() ?: "You"

        // Build deviceIdHex → pubkeyHex map from the group's members
        val mgr = com.securelegion.services.CrdtGroupManager.getInstance(context)
        val members = try { mgr.queryMembers(groupId) } catch (_: Exception) { emptyList() }
        val deviceToPubkey = members.associate { it.deviceIdHex.lowercase() to it.pubkeyHex.lowercase() }

        // Resolve device_id → display name once per author
        val nameCache = HashMap<String, String>()
        fun resolveName(authorDeviceHex: String): String {
            nameCache[authorDeviceHex]?.let { return it }
            val pubkeyHex = deviceToPubkey[authorDeviceHex.lowercase()]
            val resolved = when {
                pubkeyHex == null -> "Unknown (${authorDeviceHex.take(8)})"
                pubkeyHex.equals(localPubkeyHex, ignoreCase = true) -> localUsername
                else -> try {
                    val pubkeyBytes = pubkeyHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                    val pubkeyB64 = android.util.Base64.encodeToString(pubkeyBytes, android.util.Base64.NO_WRAP)
                    db.contactDao().getContactByPublicKey(pubkeyB64)?.displayName
                } catch (_: Exception) { null } ?: "Unknown (${pubkeyHex.take(8)})"
            }
            nameCache[authorDeviceHex] = resolved
            return resolved
        }

        return rawOps
            .filter { it.opType in AUDIT_OP_TYPES }
            .map { op ->
                val authorDeviceHex = parseAuthorFromOpId(op.opId)
                val authorName = resolveName(authorDeviceHex)
                AuditEntry(
                    opId = op.opId,
                    lamport = op.lamport,
                    timestampMs = op.createdAt,
                    authorDeviceIdHex = authorDeviceHex,
                    authorDisplayName = authorName,
                    opType = op.opType,
                    description = describe(op.opType, authorName),
                )
            }
            .sortedByDescending { it.lamport }
    }

    /** Extract the 32-char device-id hex prefix from an "deviceHex:lamportHex:nonceHex" opId. */
    private fun parseAuthorFromOpId(opId: String): String =
        opId.substringBefore(':').lowercase()

    /**
     * Human-readable verb phrase for a given op type. Keeps v1 audit log
     * useful without payload parsing — answers "who did what category".
     */
    fun describe(opType: String, authorName: String): String = when (opType) {
        "GroupCreate" -> "$authorName created the group"
        "MemberInvite" -> "$authorName invited a member"
        "MemberAccept" -> "$authorName joined the group"
        "MemberRemove" -> "$authorName removed a member"
        "MemberUnban" -> "$authorName unbanned a member"
        "RoleSet" -> "$authorName updated admin rights"
        "MetadataSet" -> "$authorName updated group settings"
        "GroupDelete" -> "$authorName deleted the group"
        else -> "$authorName • $opType"
    }
}
