package com.securelegion.database

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.securelegion.database.entities.Contact
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Persistence regression tests for duplicate Phase 3 delivery.
 *
 * Phase 3 finalization may race with an identical frame. The conflict-safe insert must never
 * replace the first contact row because its stable ID owns the contact's key-chain state.
 */
@RunWith(AndroidJUnit4::class)
class Phase3ContactIdempotencyTest {
    private lateinit var database: SecureLegionDatabase

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        database = Room.inMemoryDatabaseBuilder(
            context,
            SecureLegionDatabase::class.java
        ).build()
    }

    @After
    fun tearDown() {
        database.close()
    }

    @Test
    fun duplicateIdentityInsert_doesNotReplaceStableContactIdOrLocalState() = runBlocking {
        val dao = database.contactDao()
        val original = contact(
            displayName = "Original name",
            nickname = "Local nickname",
            trustLevel = Contact.TRUST_TRUSTED
        )

        val originalId = withContext(Dispatchers.IO) {
            dao.insertContactIfAbsent(original)
        }
        assertTrue(originalId > 0L)

        val duplicateResult = withContext(Dispatchers.IO) {
            dao.insertContactIfAbsent(
                contact(
                    displayName = "Duplicate frame name",
                    nickname = null,
                    trustLevel = Contact.TRUST_UNTRUSTED
                )
            )
        }

        assertEquals("Room IGNORE must report a conflict", -1L, duplicateResult)

        val stored = withContext(Dispatchers.IO) {
            dao.getContactByX25519PublicKey(X25519_KEY)
        }
        assertNotNull(stored)
        assertEquals(originalId, stored!!.id)
        assertEquals("Original name", stored.displayName)
        assertEquals("Local nickname", stored.nickname)
        assertEquals(Contact.TRUST_TRUSTED, stored.trustLevel)
        assertEquals(1, withContext(Dispatchers.IO) { dao.getContactCount() })
    }

    @Test
    fun concurrentDuplicateIdentityInsert_createsOneStableRow() = runBlocking {
        val dao = database.contactDao()
        val start = CompletableDeferred<Unit>()

        val results = (1..8).map {
            async(Dispatchers.IO) {
                start.await()
                dao.insertContactIfAbsent(contact())
            }
        }
        start.complete(Unit)
        val ids = results.awaitAll()

        val insertedIds = ids.filter { it > 0L }
        assertEquals("Exactly one duplicate Phase 3 finalizer may create the contact", 1, insertedIds.size)
        assertEquals(7, ids.count { it == -1L })

        val stored = withContext(Dispatchers.IO) {
            dao.getContactByX25519PublicKey(X25519_KEY)
        }
        assertNotNull(stored)
        assertEquals(insertedIds.single(), stored!!.id)
        assertEquals(1, withContext(Dispatchers.IO) { dao.getContactCount() })
    }

    private fun contact(
        displayName: String = "Friend",
        nickname: String? = null,
        trustLevel: Int = Contact.TRUST_UNTRUSTED
    ) = Contact(
        displayName = displayName,
        solanaAddress = SOLANA_ADDRESS,
        publicKeyBase64 = ED25519_KEY,
        x25519PublicKeyBase64 = X25519_KEY,
        friendRequestOnion = "friend-request-address.onion",
        messagingOnion = "messaging-address.onion",
        addedTimestamp = 1L,
        trustLevel = trustLevel,
        friendshipStatus = Contact.FRIENDSHIP_CONFIRMED,
        nickname = nickname
    )

    private companion object {
        const val SOLANA_ADDRESS = "stable-solana-identity"
        const val ED25519_KEY = "stable-ed25519-key"
        const val X25519_KEY = "stable-x25519-key"
    }
}
