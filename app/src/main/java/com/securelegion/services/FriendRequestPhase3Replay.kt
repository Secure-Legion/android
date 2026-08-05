package com.securelegion.services

import com.securelegion.models.ContactCard
import com.securelegion.database.entities.PendingFriendRequest
import java.util.Base64
import java.util.Locale
import java.security.MessageDigest

internal const val FRIEND_REQUEST_LEASE_DURATION_MS = 90_000L
internal const val PHASE3_REPLAY_TTL_MS = 7L * 24 * 60 * 60 * 1000
internal const val PHASE3_REPLAY_MAX_ROWS = 256

internal fun decodeStoredFriendRequestCiphertext(encoded: String?): ByteArray? {
    if (encoded.isNullOrBlank()) return null
    return try {
        Base64.getDecoder().decode(encoded)
    } catch (_: IllegalArgumentException) {
        null
    }
}

internal fun friendRequestPayloadFingerprint(payload: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(payload)
    return "phase2-sha256:" + Base64.getEncoder().withoutPadding().encodeToString(digest)
}

internal fun shouldShortCircuitFriendRequestSend(phase: Int, alreadyFriend: Boolean): Boolean {
    return alreadyFriend && phase != PendingFriendRequest.PHASE_3_SENT
}

internal fun normalizeFriendRequestOnion(value: String): String? {
    val normalized = value.trim()
        .lowercase(Locale.ROOT)
        .removeSuffix(".onion")
    return normalized.takeIf { it.isNotBlank() }
}

/**
 * Match only authenticated, transaction-stable peer identity. Profile fields and timestamps may
 * legitimately change between an original Phase 2 and a retry.
 */
internal fun phase3ReplayIdentityMatches(
    storedPeerCard: ContactCard,
    authenticatedPeerCard: ContactCard,
    tombstoneRecipientOnion: String
): Boolean {
    if (storedPeerCard.solanaPublicKey.size != 32 ||
        authenticatedPeerCard.solanaPublicKey.size != 32 ||
        storedPeerCard.x25519PublicKey.size != 32 ||
        authenticatedPeerCard.x25519PublicKey.size != 32
    ) return false

    val storedFriendOnion = normalizeFriendRequestOnion(storedPeerCard.friendRequestOnion)
        ?: return false
    val authenticatedFriendOnion =
        normalizeFriendRequestOnion(authenticatedPeerCard.friendRequestOnion) ?: return false
    val recipientOnion = normalizeFriendRequestOnion(tombstoneRecipientOnion) ?: return false
    val storedMessagingOnion = normalizeFriendRequestOnion(storedPeerCard.messagingOnion)
        ?: return false
    val authenticatedMessagingOnion =
        normalizeFriendRequestOnion(authenticatedPeerCard.messagingOnion) ?: return false

    return storedPeerCard.solanaPublicKey.contentEquals(authenticatedPeerCard.solanaPublicKey) &&
        storedPeerCard.x25519PublicKey.contentEquals(authenticatedPeerCard.x25519PublicKey) &&
        storedPeerCard.solanaAddress == authenticatedPeerCard.solanaAddress &&
        storedFriendOnion == authenticatedFriendOnion &&
        storedFriendOnion == recipientOnion &&
        storedMessagingOnion == authenticatedMessagingOnion
}
