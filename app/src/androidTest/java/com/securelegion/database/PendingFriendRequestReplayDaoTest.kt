package com.securelegion.database

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.database.entities.PendingFriendRequest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PendingFriendRequestReplayDaoTest {
    private lateinit var database: SecureLegionDatabase

    @Before
    fun setUp() {
        database = Room.inMemoryDatabaseBuilder(
            InstrumentationRegistry.getInstrumentation().targetContext,
            SecureLegionDatabase::class.java
        ).build()
    }

    @After
    fun tearDown() = database.close()

    @Test
    fun tombstoneLookupAndCleanup_preserveBoundaryAndActiveRows() = runBlocking {
        val dao = database.pendingFriendRequestDao()
        val cutoff = 10_000L
        val boundaryId = dao.insertRequest(tombstone(completedAt = cutoff))
        val recentId = dao.insertRequest(tombstone(completedAt = cutoff + 1))
        val expiredId = dao.insertRequest(tombstone(completedAt = cutoff - 1))
        val activeId = dao.insertRequest(
            tombstone(completedAt = null).copy(isCompleted = false, needsRetry = true)
        )
        dao.insertRequest(
            tombstone(completedAt = cutoff + 2).copy(
                phase = PendingFriendRequest.PHASE_2_SENT
            )
        )

        assertEquals(
            2,
            dao.getPhase3ByRequestFingerprint("phase2-sha256:test").size
        )
        val recent = dao.getRecentCompletedPhase3(cutoff).map { it.id }
        assertEquals(listOf(recentId, boundaryId), recent)
        assertEquals(1, dao.deleteExpiredCompletedPhase3(cutoff))
        assertNull(dao.getById(expiredId))
        assertNotNull(dao.getById(boundaryId))
        assertNotNull(dao.getById(activeId))

        assertEquals(1, dao.deleteCompletedPhase3BeyondLimit(1))
        assertNotNull(dao.getById(recentId))
        assertNull(dao.getById(boundaryId))
        assertNotNull(dao.getById(activeId))
    }

    @Test
    fun confirmedPeerCleanup_preservesActiveAndCompletedPhase3() = runBlocking {
        val dao = database.pendingFriendRequestDao()
        val completedId = dao.insertRequest(tombstone(completedAt = 20_000L))
        val activePhase3Id = dao.insertRequest(
            tombstone(completedAt = null).copy(isCompleted = false, needsRetry = true)
        )
        val obsoletePhase2Id = dao.insertRequest(
            tombstone(completedAt = null).copy(
                phase = PendingFriendRequest.PHASE_2_SENT,
                isCompleted = false,
                needsRetry = true
            )
        )

        assertEquals(1, dao.deleteUnfinishedByRecipientOnion(PEER_ONION))
        assertNotNull(dao.getById(completedId))
        assertNotNull(dao.getById(activePhase3Id))
        assertNull(dao.getById(obsoletePhase2Id))
    }

    @Test
    fun targetedClaim_hasOneWinnerAndEarliestDueRespectsLease() = runBlocking {
        val dao = database.pendingFriendRequestDao()
        val now = 50_000L
        val requestId = dao.insertRequest(
            tombstone(completedAt = null).copy(
                isCompleted = false,
                needsRetry = true,
                nextRetryAt = now
            )
        )
        val start = CompletableDeferred<Unit>()
        val claims = (1..8).map { index ->
            async(Dispatchers.IO) {
                start.await()
                dao.claimById(requestId, now, "lease-$index", now + 5_000L)
            }
        }
        start.complete(Unit)
        assertEquals(1, claims.awaitAll().count { it != null })
        assertEquals(now + 5_000L, dao.getEarliestRetryAt(now))
    }

    private fun tombstone(completedAt: Long?) = PendingFriendRequest(
        recipientOnion = PEER_ONION,
        phase = PendingFriendRequest.PHASE_3_SENT,
        direction = PendingFriendRequest.DIRECTION_OUTGOING,
        needsRetry = false,
        isCompleted = completedAt != null,
        nextRetryAt = 0,
        phase1PayloadJson = "phase2-sha256:test",
        phase2PayloadBase64 = "AQID",
        contactCardJson = "{}",
        completedAt = completedAt
    )

    private companion object {
        const val PEER_ONION = "peer-friend-address.onion"
    }
}
