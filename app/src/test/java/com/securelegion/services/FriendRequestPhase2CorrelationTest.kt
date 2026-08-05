package com.securelegion.services

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class FriendRequestPhase2CorrelationTest {
    @Test
    fun twoPendingKeys_matchingSecondCandidate_isSelectedInsteadOfListOrder() {
        val wrongKey = key(0x11)
        val senderKey = key(0x22)
        val result = selectExactPhase2Candidate(
            encryptedPayload = wirePayload(senderKey),
            eligibleCandidates = listOf(
                Phase2PendingCandidate("wrong-first", wrongKey),
                Phase2PendingCandidate("correct-second", senderKey)
            )
        )

        val match = result as Phase2CandidateSelection.Matched
        assertEquals("correct-second", match.value)
        assertArrayEquals(senderKey, match.senderX25519PublicKey)
    }

    @Test
    fun candidateOrder_doesNotChangeExactSelection() {
        val senderKey = key(0x33)
        val otherKey = key(0x44)
        val payload = wirePayload(senderKey)

        listOf(
            listOf(
                Phase2PendingCandidate("sender", senderKey),
                Phase2PendingCandidate("other", otherKey)
            ),
            listOf(
                Phase2PendingCandidate("other", otherKey),
                Phase2PendingCandidate("sender", senderKey)
            )
        ).forEach { candidates ->
            val match = selectExactPhase2Candidate(payload, candidates)
                as Phase2CandidateSelection.Matched
            assertEquals("sender", match.value)
        }
    }

    @Test
    fun payloadShorterThanNativeWireMinimum_isRejectedAsMalformed() {
        val payload = ByteArray(PHASE2_MIN_ENCRYPTED_PAYLOAD_BYTES - 1)

        val result = selectExactPhase2Candidate(
            payload,
            listOf(Phase2PendingCandidate("sender", key(0x55)))
        )

        assertSame(Phase2CandidateSelection.MalformedPayload, result)
    }

    @Test
    fun malformedPendingKey_isRejectedBeforeMatching() {
        val result = selectExactPhase2Candidate(
            wirePayload(key(0x66)),
            listOf(Phase2PendingCandidate("sender", ByteArray(31)))
        )

        assertSame(Phase2CandidateSelection.MalformedCandidate, result)
    }

    @Test
    fun embeddedKeyWithNoEligibleCandidate_failsClosed() {
        val result = selectExactPhase2Candidate(
            wirePayload(key(0x77)),
            listOf(Phase2PendingCandidate("other", key(0x78)))
        )

        assertSame(Phase2CandidateSelection.NoMatch, result)
    }

    @Test
    fun duplicateEligibleCandidatesForEmbeddedKey_failClosedAsAmbiguous() {
        val senderKey = key(0x7f)
        val result = selectExactPhase2Candidate(
            wirePayload(senderKey),
            listOf(
                Phase2PendingCandidate("first", senderKey),
                Phase2PendingCandidate("second", senderKey.copyOf())
            )
        )

        assertSame(Phase2CandidateSelection.AmbiguousMatch, result)
    }

    private fun wirePayload(senderKey: ByteArray): ByteArray =
        senderKey + ByteArray(PHASE2_MIN_ENCRYPTED_PAYLOAD_BYTES - senderKey.size) { 0x5a }

    private fun key(value: Int): ByteArray = ByteArray(32) { value.toByte() }
}
