package com.securelegion.services

import java.security.MessageDigest

/**
 * A legacy friend-request encrypted payload is framed as:
 * [sender X25519 public key: 32][XChaCha20 nonce: 24][ciphertext + tag: >= 16].
 */
internal const val PHASE2_MIN_ENCRYPTED_PAYLOAD_BYTES = 32 + 24 + 16

internal fun phase2EmbeddedSenderKey(encryptedPayload: ByteArray): ByteArray? {
    if (encryptedPayload.size < PHASE2_MIN_ENCRYPTED_PAYLOAD_BYTES) return null
    return encryptedPayload.copyOfRange(0, 32)
}

internal data class Phase2PendingCandidate<T>(
    val value: T,
    val recipientOnion: String,
    val recipientInviteToken: String?
)

internal sealed class Phase2CandidateSelection<out T> {
    data class Matched<T>(
        val value: T
    ) : Phase2CandidateSelection<T>()

    object MalformedPayload : Phase2CandidateSelection<Nothing>()
    object NoMatch : Phase2CandidateSelection<Nothing>()
    object AmbiguousMatch : Phase2CandidateSelection<Nothing>()
}

/**
 * Correlate an authenticated Phase 2 card to the Phase 1 request that targeted that peer.
 *
 * The Phase 2 wire prefix is the responder's X25519 key, while an outgoing Phase 1 snapshot
 * contains the initiator's key. Those keys must never be compared. The caller first decrypts with
 * the embedded responder key and authenticates that key against the signed ContactCard, then this
 * function binds the card to the QR destination stored in Room.
 *
 * Current Android and iOS ContactCards both return the recipient's friend-request onion and invite
 * token, so this requires no wire-format change. Legacy/manual Phase 1 rows used a zero invite
 * token; they may fall back to a unique onion match, but a real token can never be downgraded to
 * that fallback.
 */
internal fun <T> selectExactPhase2Candidate(
    authenticatedFriendRequestOnion: String,
    authenticatedInviteToken: String,
    eligibleCandidates: List<Phase2PendingCandidate<T>>
): Phase2CandidateSelection<T> {
    val authenticatedOnion = normalizeFriendRequestOnion(authenticatedFriendRequestOnion)
        ?: return Phase2CandidateSelection.MalformedPayload

    val onionMatches = eligibleCandidates.filter {
        normalizeFriendRequestOnion(it.recipientOnion) == authenticatedOnion
    }
    if (onionMatches.isEmpty()) return Phase2CandidateSelection.NoMatch

    val strongCandidates = onionMatches.filter {
        isUsableInviteToken(it.recipientInviteToken)
    }
    val strongMatches = strongCandidates.filter {
        constantTimeEquals(it.recipientInviteToken.orEmpty(), authenticatedInviteToken)
    }

    if (strongMatches.size > 1) return Phase2CandidateSelection.AmbiguousMatch
    if (strongMatches.size == 1) {
        return Phase2CandidateSelection.Matched(strongMatches.single().value)
    }

    // Never fall back to an onion-only match when a modern row expected a different token.
    if (strongCandidates.isNotEmpty()) return Phase2CandidateSelection.NoMatch

    val legacyMatches = onionMatches.filter {
        !isUsableInviteToken(it.recipientInviteToken)
    }

    return when (legacyMatches.size) {
        0 -> Phase2CandidateSelection.NoMatch
        1 -> Phase2CandidateSelection.Matched(legacyMatches.single().value)
        else -> Phase2CandidateSelection.AmbiguousMatch
    }
}

private fun isUsableInviteToken(value: String?): Boolean {
    return value != null && value.length == FriendRequestValidator.EXPECTED_TOKEN_LEN &&
        value.any { it != '0' }
}

private fun constantTimeEquals(left: String, right: String): Boolean {
    return MessageDigest.isEqual(
        left.toByteArray(Charsets.UTF_8),
        right.toByteArray(Charsets.UTF_8)
    )
}
