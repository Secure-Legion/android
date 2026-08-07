package com.securelegion.services

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class FriendRequestPhase2CorrelationTest {
    @Test
    fun androidPhase2_responderKeyDiffersFromInitiator_matchesQrDestination() {
        val result = selectExactPhase2Candidate(
            authenticatedFriendRequestOnion = PEER_ONION,
            authenticatedInviteToken = PEER_TOKEN,
            eligibleCandidates = listOf(
                candidate("other", OTHER_ONION, OTHER_TOKEN),
                candidate("peer", PEER_ONION, PEER_TOKEN)
            )
        )

        val match = result as Phase2CandidateSelection.Matched
        assertEquals("peer", match.value)
    }

    @Test
    fun iosCompatibleCard_sameExistingOnionAndTokenFormat_matches() {
        val result = selectExactPhase2Candidate(
            authenticatedFriendRequestOnion = PEER_ONION.removeSuffix(".onion").uppercase(),
            authenticatedInviteToken = PEER_TOKEN,
            eligibleCandidates = listOf(candidate("ios-peer", PEER_ONION, PEER_TOKEN))
        )

        val match = result as Phase2CandidateSelection.Matched
        assertEquals("ios-peer", match.value)
    }

    @Test
    fun authenticatedCardWithWrongInviteToken_isRejected() {
        val result = selectExactPhase2Candidate(
            authenticatedFriendRequestOnion = PEER_ONION,
            authenticatedInviteToken = OTHER_TOKEN,
            eligibleCandidates = listOf(candidate("peer", PEER_ONION, PEER_TOKEN))
        )

        assertSame(Phase2CandidateSelection.NoMatch, result)
    }

    @Test
    fun legacyZeroToken_uniqueOnionMatch_isAcceptedWithoutDowngradingModernRows() {
        val result = selectExactPhase2Candidate(
            authenticatedFriendRequestOnion = PEER_ONION,
            authenticatedInviteToken = PEER_TOKEN,
            eligibleCandidates = listOf(candidate("legacy", PEER_ONION, "0".repeat(32)))
        )

        val match = result as Phase2CandidateSelection.Matched
        assertEquals("legacy", match.value)
    }

    @Test
    fun modernTokenMismatch_doesNotDowngradeToLegacyCandidate() {
        val result = selectExactPhase2Candidate(
            authenticatedFriendRequestOnion = PEER_ONION,
            authenticatedInviteToken = OTHER_TOKEN,
            eligibleCandidates = listOf(
                candidate("modern", PEER_ONION, PEER_TOKEN),
                candidate("legacy", PEER_ONION, "0".repeat(32))
            )
        )

        assertSame(Phase2CandidateSelection.NoMatch, result)
    }

    @Test
    fun duplicateEligibleCandidatesForIdentity_failClosedAsAmbiguous() {
        val result = selectExactPhase2Candidate(
            authenticatedFriendRequestOnion = PEER_ONION,
            authenticatedInviteToken = PEER_TOKEN,
            eligibleCandidates = listOf(
                candidate("first", PEER_ONION, PEER_TOKEN),
                candidate("second", PEER_ONION, PEER_TOKEN)
            )
        )

        assertSame(Phase2CandidateSelection.AmbiguousMatch, result)
    }

    @Test
    fun malformedAuthenticatedOnion_isRejected() {
        val result = selectExactPhase2Candidate(
            authenticatedFriendRequestOnion = "   ",
            authenticatedInviteToken = PEER_TOKEN,
            eligibleCandidates = listOf(candidate("peer", PEER_ONION, PEER_TOKEN))
        )

        assertSame(Phase2CandidateSelection.MalformedPayload, result)
    }

    private fun candidate(value: String, onion: String, token: String?) =
        Phase2PendingCandidate(value, onion, token)

    private companion object {
        const val PEER_ONION = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
        const val OTHER_ONION = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"
        const val PEER_TOKEN = "0123456789abcdef0123456789abcdef"
        const val OTHER_TOKEN = "fedcba9876543210fedcba9876543210"
    }
}
