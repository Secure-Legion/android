package com.securelegion.services

import java.security.MessageDigest

/**
 * Bounded-size, TTL-based replay cache for friend-request nonces.
 * Thread-safe via synchronized access. Used to prevent replayed Phase 1 FR envelopes
 * within the (TIMESTAMP_WINDOW_SEC) validity window.
 */
class NonceReplayCache(
    private val ttlMs: Long,
    private val maxEntries: Int
) {
    private data class Entry(val expiresAt: Long)

    // Insertion-order LinkedHashMap so iter.next() gives the oldest entry first.
    private val entries = java.util.LinkedHashMap<String, Entry>(
        /*initialCapacity=*/ 64,
        /*loadFactor=*/ 0.75f,
        /*accessOrder=*/ false
    )

    /**
     * Records the nonce if absent. Returns true if this nonce was already recorded
     * (i.e. it's a replay). Lazily sweeps expired entries on each call.
     */
    @Synchronized
    fun isReplayAndMark(nonce: String): Boolean {
        val now = System.currentTimeMillis()

        // Lazy sweep: drop expired entries from the head of insertion order.
        val iter = entries.entries.iterator()
        while (iter.hasNext()) {
            if (iter.next().value.expiresAt <= now) iter.remove() else break
        }

        if (entries.containsKey(nonce)) return true

        while (entries.size >= maxEntries) {
            val oldest = entries.entries.iterator().next()
            entries.remove(oldest.key)
        }

        entries[nonce] = Entry(expiresAt = now + ttlMs)
        return false
    }
}

/**
 * Validates incoming friend-request Phase 1 envelopes against the user's current and previous
 * PIN+token pairs. Uses constant-time SHA-256 digest comparison, timestamp window enforcement,
 * and nonce-based replay protection.
 *
 * All failure modes return a single uniform Result.INVALID — do NOT leak which field failed.
 */
class FriendRequestValidator(private val replayCache: NonceReplayCache) {

    enum class Result { OK, INVALID }

    companion object {
        const val TIMESTAMP_WINDOW_SEC = 120L
        const val EXPECTED_TOKEN_LEN = 32
    }

    fun validate(
        incomingPin: String,
        incomingToken: String,
        nonce: String,
        timestampSec: Long,
        currentPin: String,
        currentToken: String,
        previousPin: String?,
        previousToken: String?
    ): Result {
        val nowSec = System.currentTimeMillis() / 1000
        if (kotlin.math.abs(nowSec - timestampSec) > TIMESTAMP_WINDOW_SEC) return Result.INVALID
        if (nonce.isBlank()) return Result.INVALID
        if (incomingToken.length != EXPECTED_TOKEN_LEN) return Result.INVALID
        if (replayCache.isReplayAndMark(nonce)) return Result.INVALID

        val incomingPinHash = sha256(incomingPin)
        val incomingTokenHash = sha256(incomingToken)

        val currentMatch =
            MessageDigest.isEqual(incomingPinHash, sha256(currentPin)) &&
            MessageDigest.isEqual(incomingTokenHash, sha256(currentToken))

        val prevMatch = previousPin != null && previousToken != null &&
            MessageDigest.isEqual(incomingPinHash, sha256(previousPin)) &&
            MessageDigest.isEqual(incomingTokenHash, sha256(previousToken))

        return if (currentMatch || prevMatch) Result.OK else Result.INVALID
    }

    private fun sha256(input: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
}
