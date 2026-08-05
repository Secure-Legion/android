package com.securelegion.services

import com.securelegion.models.PendingFriendRequest
import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression coverage for matching a received 0x08 frame to its local friend-request state.
 *
 * These tests intentionally invoke the production predicates rather than duplicating their
 * implementation in test code. TorService is allocated without running Android's Service
 * constructor because the predicates are pure and JVM unit tests do not provide an Android
 * application context.
 */
class FriendRequestCandidateEligibilityTest {
    private val service: TorService by lazy { allocateWithoutConstructor(TorService::class.java) }

    @Test
    fun phase1Response_pendingAndSendingOutgoingRequests_areEligible() {
        listOf(
            PendingFriendRequest.STATUS_PENDING,
            PendingFriendRequest.STATUS_SENDING
        ).forEach { status ->
            assertTrue(
                "Expected outgoing Phase 1 request in $status to accept a Phase 2 response",
                isPhase1AwaitingResponse(request(status), phase1Json())
            )
        }
    }

    @Test
    fun phase3Ack_pendingAndSendingOutgoingPhase2Requests_areEligible() {
        listOf(
            PendingFriendRequest.STATUS_PENDING,
            PendingFriendRequest.STATUS_SENDING
        ).forEach { status ->
            assertTrue(
                "Expected outgoing Phase 2 request in $status to accept a Phase 3 ACK",
                isPhase2AwaitingAck(request(status), phase2Json())
            )
        }
    }

    @Test
    fun transientRetry_projectedBackToPending_remainsEligibleForEitherResponse() {
        // FriendRequestWorker uses Room for retry metadata. The UI snapshot must be projected
        // back to PENDING before retrying so a delayed Phase 2 or Phase 3 response can match it.
        val retryingRequest = request(PendingFriendRequest.STATUS_PENDING)

        assertTrue(isPhase1AwaitingResponse(retryingRequest, phase1Json()))
        assertTrue(isPhase2AwaitingAck(retryingRequest, phase2Json()))
    }

    @Test
    fun terminalStatuses_areIneligibleForPhase2AndPhase3Responses() {
        listOf(
            PendingFriendRequest.STATUS_FAILED,
            PendingFriendRequest.STATUS_ACCEPTED,
            PendingFriendRequest.STATUS_INVALID_PIN
        ).forEach { status ->
            val terminalRequest = request(status)
            assertFalse(
                "Terminal state $status must not match a Phase 2 response",
                isPhase1AwaitingResponse(terminalRequest, phase1Json())
            )
            assertFalse(
                "Terminal state $status must not match a Phase 3 ACK",
                isPhase2AwaitingAck(terminalRequest, phase2Json())
            )
        }
    }

    @Test
    fun incomingRequests_neverMatchOutgoingPhaseResponses() {
        val incoming = request(
            status = PendingFriendRequest.STATUS_PENDING,
            direction = PendingFriendRequest.DIRECTION_INCOMING
        )

        assertFalse(isPhase1AwaitingResponse(incoming, phase1Json()))
        assertFalse(isPhase2AwaitingAck(incoming, phase2Json()))
    }

    @Test
    fun phase1Candidate_requiresPhaseOneMarkerAndX25519Key() {
        val pending = request(PendingFriendRequest.STATUS_PENDING)

        assertFalse(isPhase1AwaitingResponse(pending, null))
        assertFalse(isPhase1AwaitingResponse(pending, JSONObject().put("phase", 1)))
        assertFalse(isPhase1AwaitingResponse(pending, phase2Json()))
    }

    @Test
    fun phase2Candidate_requiresContactIdentityAndIsNotPhaseOne() {
        val pending = request(PendingFriendRequest.STATUS_PENDING)

        assertFalse(isPhase2AwaitingAck(pending, null))
        assertFalse(isPhase2AwaitingAck(pending, phase1Json()))
        assertFalse(
            isPhase2AwaitingAck(
                pending,
                phase2Json().apply { remove("friend_request_onion") }
            )
        )
        assertFalse(
            isPhase2AwaitingAck(
                pending,
                phase2Json().apply { remove("x25519_public_key") }
            )
        )
    }

    private fun request(
        status: String,
        direction: String = PendingFriendRequest.DIRECTION_OUTGOING
    ) = PendingFriendRequest(
        displayName = "Friend",
        ipfsCid = "friend-request-address.onion",
        direction = direction,
        status = status,
        timestamp = 1L,
        contactCardJson = null,
        id = "request-id"
    )

    private fun phase1Json() = JSONObject()
        .put("phase", 1)
        .put("x25519_public_key", "sender-x25519")

    private fun phase2Json() = JSONObject()
        .put("phase", 2)
        .put("username", "Friend")
        .put("friend_request_onion", "friend-request-address.onion")
        .put("x25519_public_key", "sender-x25519")

    private fun isPhase1AwaitingResponse(
        request: PendingFriendRequest,
        json: JSONObject?
    ): Boolean = invokePredicate("isOutgoingPhase1AwaitingResponse", request, json)

    private fun isPhase2AwaitingAck(
        request: PendingFriendRequest,
        json: JSONObject?
    ): Boolean = invokePredicate("isOutgoingPhase2AwaitingAck", request, json)

    private fun invokePredicate(
        name: String,
        request: PendingFriendRequest,
        json: JSONObject?
    ): Boolean {
        val method = TorService::class.java.getDeclaredMethod(
            name,
            PendingFriendRequest::class.java,
            JSONObject::class.java
        )
        method.isAccessible = true
        return method.invoke(service, request, json) as Boolean
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T> allocateWithoutConstructor(type: Class<T>): T {
        val unsafeClass = Class.forName("sun.misc.Unsafe")
        val unsafeField = unsafeClass.getDeclaredField("theUnsafe").apply { isAccessible = true }
        val unsafe = unsafeField.get(null)
        return unsafeClass
            .getMethod("allocateInstance", Class::class.java)
            .invoke(unsafe, type) as T
    }
}
