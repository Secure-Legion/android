package com.securelegion.services

import com.securelegion.database.entities.PendingFriendRequest
import com.securelegion.models.ContactCard
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FriendRequestPhase3ReplayTest {
    @Test
    fun storedCiphertext_decodesByteForByte() {
        val original = ByteArray(96) { index -> (index * 17).toByte() }
        val encoded = Base64.getEncoder().encodeToString(original)

        assertArrayEquals(original, decodeStoredFriendRequestCiphertext(encoded))
        assertTrue(decodeStoredFriendRequestCiphertext("not-base64!") == null)
    }

    @Test
    fun payloadFingerprint_isStableAndRequestSpecific() {
        val payload = ByteArray(80) { 0x41 }

        assertTrue(
            friendRequestPayloadFingerprint(payload) ==
                friendRequestPayloadFingerprint(payload.copyOf())
        )
        assertNotEquals(
            friendRequestPayloadFingerprint(payload),
            friendRequestPayloadFingerprint(payload.copyOf().also { it[79] = 0x42 })
        )
    }

    @Test
    fun existingContact_neverSuppressesPhase3Delivery() {
        assertFalse(
            shouldShortCircuitFriendRequestSend(
                PendingFriendRequest.PHASE_3_SENT,
                alreadyFriend = true
            )
        )
        assertTrue(
            shouldShortCircuitFriendRequestSend(
                PendingFriendRequest.PHASE_2_SENT,
                alreadyFriend = true
            )
        )
    }

    @Test
    fun replayIdentity_ignoresMutableProfileFields() {
        val stored = card(displayName = "Before", timestamp = 10, profile = "old-photo")
        val updated = card(displayName = "After", timestamp = 99, profile = "new-photo")

        assertTrue(
            phase3ReplayIdentityMatches(
                stored,
                updated,
                "PEER-FRIEND-ADDRESS.ONION"
            )
        )
    }

    @Test
    fun replayIdentity_rejectsKeyAndOnionChanges() {
        val stored = card()

        assertFalse(
            phase3ReplayIdentityMatches(
                stored,
                card(x25519 = ByteArray(32) { 0x33 }),
                stored.friendRequestOnion
            )
        )
        assertFalse(
            phase3ReplayIdentityMatches(
                stored,
                card(friendOnion = "different-peer.onion"),
                stored.friendRequestOnion
            )
        )
    }

    private fun card(
        displayName: String = "Peer",
        timestamp: Long = 1,
        profile: String? = null,
        x25519: ByteArray = ByteArray(32) { 0x22 },
        friendOnion: String = "peer-friend-address.onion"
    ) = ContactCard(
        displayName = displayName,
        solanaPublicKey = ByteArray(32) { 0x11 },
        x25519PublicKey = x25519,
        kyberPublicKey = ByteArray(1568),
        solanaAddress = "stable-solana-address",
        friendRequestOnion = friendOnion,
        messagingOnion = "peer-messaging-address.onion",
        voiceOnion = "peer-voice-address.onion",
        contactPin = "123-456-7890",
        inviteToken = "0123456789abcdef0123456789abcdef",
        profilePictureBase64 = profile,
        timestamp = timestamp
    )
}
