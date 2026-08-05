package com.securelegion.services

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
    val senderX25519PublicKey: ByteArray
)

internal sealed class Phase2CandidateSelection<out T> {
    data class Matched<T>(
        val value: T,
        val senderX25519PublicKey: ByteArray
    ) : Phase2CandidateSelection<T>()

    object MalformedPayload : Phase2CandidateSelection<Nothing>()
    object MalformedCandidate : Phase2CandidateSelection<Nothing>()
    object NoMatch : Phase2CandidateSelection<Nothing>()
    object AmbiguousMatch : Phase2CandidateSelection<Nothing>()
}

/**
 * Correlate Phase 2 using the sender identity that native decryption actually uses.
 *
 * Native decryptMessage derives its ECDH peer from the first 32 payload bytes; its historical
 * senderPublicKey argument is ignored. Selecting a request by trial decryption therefore makes
 * candidate order authoritative. Match the embedded key first and allow exactly one candidate.
 */
internal fun <T> selectExactPhase2Candidate(
    encryptedPayload: ByteArray,
    eligibleCandidates: List<Phase2PendingCandidate<T>>
): Phase2CandidateSelection<T> {
    val embeddedSenderKey = phase2EmbeddedSenderKey(encryptedPayload)
        ?: return Phase2CandidateSelection.MalformedPayload
    if (eligibleCandidates.any { it.senderX25519PublicKey.size != 32 }) {
        return Phase2CandidateSelection.MalformedCandidate
    }

    val matches = eligibleCandidates.filter {
        it.senderX25519PublicKey.contentEquals(embeddedSenderKey)
    }

    return when (matches.size) {
        0 -> Phase2CandidateSelection.NoMatch
        1 -> Phase2CandidateSelection.Matched(
            value = matches.single().value,
            senderX25519PublicKey = embeddedSenderKey
        )
        else -> Phase2CandidateSelection.AmbiguousMatch
    }
}
