package com.securelegion.database

import android.content.Context
import android.util.Log
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.database.dao.CallHistoryDao
import com.securelegion.database.dao.CallQualityLogDao
import com.securelegion.database.dao.ContactDao
import com.securelegion.database.dao.ContactKeyChainDao
import com.securelegion.database.dao.GroupDao
import com.securelegion.database.dao.GroupMemberDao
import com.securelegion.database.dao.GroupMessageDao
import com.securelegion.database.dao.MessageDao
import com.securelegion.database.dao.PendingFriendRequestDao
import com.securelegion.database.dao.PingInboxDao
import com.securelegion.database.dao.ReceivedIdDao
import com.securelegion.database.dao.SkippedMessageKeyDao
import com.securelegion.database.dao.UsedSignatureDao
import com.securelegion.database.dao.WalletDao
import com.securelegion.database.entities.CallHistory
import com.securelegion.database.entities.CallQualityLog
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.ContactKeyChain
import com.securelegion.database.entities.Group
import com.securelegion.database.entities.GroupMember
import com.securelegion.database.entities.GroupMessage
import com.securelegion.database.entities.Message
import com.securelegion.database.entities.PendingFriendRequest
import com.securelegion.database.entities.PingInbox
import com.securelegion.database.entities.ReceivedId
import com.securelegion.database.entities.SkippedMessageKey
import com.securelegion.database.entities.UsedSignature
import com.securelegion.database.entities.Wallet
import net.zetetic.database.sqlcipher.SQLiteDatabase
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

/**
 * Encrypted SQLite database using SQLCipher + Room
 *
 * Security features:
 * - AES-256 full database encryption
 * - Encryption key derived from BIP39 seed via KeyManager
 * - No plaintext data ever touches disk
 * - Secure deletion enabled
 * - WAL mode disabled for maximum security
 *
 * Database file location: /data/data/com.securelegion/databases/secure_legion.db
 */
@Database(
    entities = [Contact::class, Message::class, Wallet::class, ReceivedId::class, UsedSignature::class, Group::class, GroupMember::class, GroupMessage::class, CallHistory::class, CallQualityLog::class, PingInbox::class, ContactKeyChain::class, SkippedMessageKey::class, PendingFriendRequest::class],
    version = 36,
    exportSchema = false
)
abstract class SecureLegionDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun messageDao(): MessageDao
    abstract fun walletDao(): WalletDao
    abstract fun receivedIdDao(): ReceivedIdDao
    abstract fun usedSignatureDao(): UsedSignatureDao
    abstract fun groupDao(): GroupDao
    abstract fun groupMemberDao(): GroupMemberDao
    abstract fun groupMessageDao(): GroupMessageDao
    abstract fun callHistoryDao(): CallHistoryDao
    abstract fun callQualityLogDao(): CallQualityLogDao
    abstract fun pingInboxDao(): PingInboxDao
    abstract fun contactKeyChainDao(): ContactKeyChainDao
    abstract fun skippedMessageKeyDao(): SkippedMessageKeyDao
    abstract fun pendingFriendRequestDao(): PendingFriendRequestDao

    companion object {
        private const val TAG = "SecureLegionDatabase"
        private const val DATABASE_NAME = "secure_legion.db"

        @Volatile
        private var INSTANCE: SecureLegionDatabase? = null

        /**
         * Migration from version 1 to 2: Add isDistressContact field
         */
        private val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 1 to 2")
                // Add isDistressContact column with default value false
                database.execSQL("ALTER TABLE contacts ADD COLUMN isDistressContact INTEGER NOT NULL DEFAULT 0")
                Log.i(TAG, "Migration completed: Added isDistressContact column")
            }
        }

        /**
         * Migration from version 2 to 3: Add self-destruct and read receipt fields
         */
        private val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 2 to 3")
                // Add selfDestructAt column (nullable)
                database.execSQL("ALTER TABLE messages ADD COLUMN selfDestructAt INTEGER")
                // Add requiresReadReceipt column with default value true
                database.execSQL("ALTER TABLE messages ADD COLUMN requiresReadReceipt INTEGER NOT NULL DEFAULT 1")
                Log.i(TAG, "Migration completed: Added selfDestructAt and requiresReadReceipt columns")
            }
        }

        /**
         * Migration from version 3 to 4: Add X25519 public key for ECDH encryption
         */
        private val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 3 to 4")
                // Add x25519PublicKeyBase64 column with empty default
                // Note: Existing contacts will need to be updated with their X25519 keys
                database.execSQL("ALTER TABLE contacts ADD COLUMN x25519PublicKeyBase64 TEXT NOT NULL DEFAULT ''")
                Log.i(TAG, "Migration completed: Added x25519PublicKeyBase64 column")
            }
        }

        /**
         * Migration from version 4 to 5: Add wallets table for multi-wallet support
         */
        private val MIGRATION_4_5 = object : Migration(4, 5) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 4 to 5")
                // Create wallets table
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS wallets (
                        walletId TEXT PRIMARY KEY NOT NULL,
                        name TEXT NOT NULL,
                        solanaAddress TEXT NOT NULL,
                        isMainWallet INTEGER NOT NULL,
                        createdAt INTEGER NOT NULL,
                        lastUsedAt INTEGER NOT NULL
                    )
                """.trimIndent())
                Log.i(TAG, "Migration completed: Added wallets table")
            }
        }

        /**
         * Migration from version 5 to 6: Add persistent messaging fields for Ping-Pong protocol
         */
        private val MIGRATION_5_6 = object : Migration(5, 6) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 5 to 6")
                // Add pingId column (nullable)
                database.execSQL("ALTER TABLE messages ADD COLUMN pingId TEXT")
                // Add encryptedPayload column (nullable)
                database.execSQL("ALTER TABLE messages ADD COLUMN encryptedPayload TEXT")
                // Add retryCount column with default value 0
                database.execSQL("ALTER TABLE messages ADD COLUMN retryCount INTEGER NOT NULL DEFAULT 0")
                // Add lastRetryTimestamp column (nullable)
                database.execSQL("ALTER TABLE messages ADD COLUMN lastRetryTimestamp INTEGER")
                Log.i(TAG, "Migration completed: Added pingId, encryptedPayload, retryCount, lastRetryTimestamp columns")
            }
        }

        /**
         * Migration from version 6 to 7: Add voice message support
         */
        private val MIGRATION_6_7 = object : Migration(6, 7) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 6 to 7")
                // Add messageType column with default value 'TEXT'
                database.execSQL("ALTER TABLE messages ADD COLUMN messageType TEXT NOT NULL DEFAULT 'TEXT'")
                // Add voiceDuration column (nullable)
                database.execSQL("ALTER TABLE messages ADD COLUMN voiceDuration INTEGER")
                // Add voiceFilePath column (nullable)
                database.execSQL("ALTER TABLE messages ADD COLUMN voiceFilePath TEXT")
                Log.i(TAG, "Migration completed: Added messageType, voiceDuration, voiceFilePath columns for voice messages")
            }
        }

        /**
         * Migration from version 7 to 8: Add isBlocked field to contacts
         */
        private val MIGRATION_7_8 = object : Migration(7, 8) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 7 to 8")
                // Add isBlocked column with default value false
                database.execSQL("ALTER TABLE contacts ADD COLUMN isBlocked INTEGER NOT NULL DEFAULT 0")
                Log.i(TAG, "Migration completed: Added isBlocked column")
            }
        }

        /**
         * Migration from version 8 to 9: Add pingDelivered field for ACK tracking
         */
        private val MIGRATION_8_9 = object : Migration(8, 9) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 8 to 9")
                // Add pingDelivered column with default value false
                database.execSQL("ALTER TABLE messages ADD COLUMN pingDelivered INTEGER NOT NULL DEFAULT 0")
                Log.i(TAG, "Migration completed: Added pingDelivered column for ACK tracking")
            }
        }

        /**
         * Migration from version 9 to 10: Add messageDelivered field for ACK tracking
         */
        private val MIGRATION_9_10 = object : Migration(9, 10) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 9 to 10")
                // Add messageDelivered column with default value false
                database.execSQL("ALTER TABLE messages ADD COLUMN messageDelivered INTEGER NOT NULL DEFAULT 0")
                Log.i(TAG, "Migration completed: Added messageDelivered column for ACK tracking")
            }
        }

        /**
         * Migration from version 10 to 11: Add received_ids table for deduplication
         */
        private val MIGRATION_10_11 = object : Migration(10, 11) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 10 to 11")
                // Create received_ids table for tracking all received ping/pong/message IDs
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS received_ids (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        receivedId TEXT NOT NULL,
                        idType TEXT NOT NULL,
                        receivedTimestamp INTEGER NOT NULL,
                        processed INTEGER NOT NULL DEFAULT 0
                    )
                """.trimIndent())
                // Create unique index to prevent duplicate IDs
                database.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_received_ids_receivedId ON received_ids(receivedId)")
                Log.i(TAG, "Migration completed: Added received_ids table for deduplication")
            }
        }

        /**
         * Migration from version 11 to 12: Add friendshipStatus field
         */
        private val MIGRATION_11_12 = object : Migration(11, 12) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 11 to 12")
                // Add friendshipStatus column with default value PENDING_SENT
                database.execSQL("ALTER TABLE contacts ADD COLUMN friendshipStatus TEXT NOT NULL DEFAULT 'PENDING_SENT'")
                Log.i(TAG, "Migration completed: Added friendshipStatus column")
            }
        }

        /**
         * Migration from version 12 to 13: Add pingWireBytes field to prevent ghost pings
         */
        private val MIGRATION_12_13 = object : Migration(12, 13) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 12 to 13")
                // Add pingWireBytes column (nullable) to store encrypted Ping token for retry
                database.execSQL("ALTER TABLE messages ADD COLUMN pingWireBytes TEXT")
                Log.i(TAG, "Migration completed: Added pingWireBytes column to prevent ghost pings on retry")
            }
        }

        /**
         * Migration from version 13 to 14: Add tapDelivered and pongDelivered for complete ACK tracking
         */
        private val MIGRATION_13_14 = object : Migration(13, 14) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 13 to 14")
                // Add tapDelivered column with default value false
                database.execSQL("ALTER TABLE messages ADD COLUMN tapDelivered INTEGER NOT NULL DEFAULT 0")
                // Add pongDelivered column with default value false
                database.execSQL("ALTER TABLE messages ADD COLUMN pongDelivered INTEGER NOT NULL DEFAULT 0")
                Log.i(TAG, "Migration completed: Added tapDelivered and pongDelivered columns for complete ACK tracking")
            }
        }

        /**
         * Migration from version 14 to 15: Add Zcash address support
         */
        private val MIGRATION_14_15 = object : Migration(14, 15) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 14 to 15")
                // Add zcashAddress column (nullable for backward compatibility)
                database.execSQL("ALTER TABLE wallets ADD COLUMN zcashAddress TEXT")
                Log.i(TAG, "Migration completed: Added zcashAddress column for multi-chain wallet support")
            }
        }

        /**
         * Migration from version 15 to 16: Add NLx402 payment fields
         */
        private val MIGRATION_15_16 = object : Migration(15, 16) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 15 to 16")
                // Add NLx402 payment fields to messages table
                database.execSQL("ALTER TABLE messages ADD COLUMN paymentQuoteJson TEXT")
                database.execSQL("ALTER TABLE messages ADD COLUMN paymentStatus TEXT")
                database.execSQL("ALTER TABLE messages ADD COLUMN txSignature TEXT")
                database.execSQL("ALTER TABLE messages ADD COLUMN paymentToken TEXT")
                database.execSQL("ALTER TABLE messages ADD COLUMN paymentAmount INTEGER")
                Log.i(TAG, "Migration completed: Added NLx402 payment fields")
            }
        }

        /**
         * Migration from version 16 to 17: Add used_signatures table for replay protection
         */
        private val MIGRATION_16_17 = object : Migration(16, 17) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 16 to 17")
                // Create used_signatures table for NLx402 replay protection
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS used_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        signature TEXT NOT NULL,
                        quoteId TEXT NOT NULL,
                        token TEXT NOT NULL,
                        amount INTEGER NOT NULL,
                        usedAt INTEGER NOT NULL
                    )
                """.trimIndent())
                // Create unique index on signature
                database.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_used_signatures_signature ON used_signatures(signature)")
                Log.i(TAG, "Migration completed: Added used_signatures table for replay protection")
            }
        }

        /**
         * Migration from version 17 to 18: Add two .onion system fields for v2.0 contact system
         */
        private val MIGRATION_17_18 = object : Migration(17, 18) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 17 to 18")

                // Add new fields for two .onion system
                database.execSQL("ALTER TABLE contacts ADD COLUMN friendRequestOnion TEXT NOT NULL DEFAULT ''")
                database.execSQL("ALTER TABLE contacts ADD COLUMN messagingOnion TEXT")
                database.execSQL("ALTER TABLE contacts ADD COLUMN ipfsCid TEXT")
                database.execSQL("ALTER TABLE contacts ADD COLUMN contactPin TEXT")

                // Migrate existing data: torOnionAddress → messagingOnion
                database.execSQL("UPDATE contacts SET messagingOnion = torOnionAddress WHERE torOnionAddress IS NOT NULL")

                // Create new indices
                database.execSQL("CREATE INDEX IF NOT EXISTS index_contacts_friendRequestOnion ON contacts(friendRequestOnion)")
                database.execSQL("CREATE INDEX IF NOT EXISTS index_contacts_messagingOnion ON contacts(messagingOnion)")

                Log.i(TAG, "Migration completed: Added two .onion system (friendRequestOnion, messagingOnion, ipfsCid, contactPin)")
            }
        }

        /**
         * Migration from version 19 to 20: Add voiceOnion field for voice calling
         */
        private val MIGRATION_19_20 = object : Migration(19, 20) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 19 to 20")
                database.execSQL("ALTER TABLE contacts ADD COLUMN voiceOnion TEXT")
                Log.i(TAG, "Migration completed: Added voiceOnion column for voice calling")
            }
        }

        /**
         * Migration from version 21 to 22: Add call history table
         */
        private val MIGRATION_21_22 = object : Migration(21, 22) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 21 to 22")

                // Create call_history table
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS call_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        contactId INTEGER NOT NULL,
                        contactName TEXT NOT NULL,
                        callId TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        type TEXT NOT NULL,
                        duration INTEGER NOT NULL DEFAULT 0,
                        missedReason TEXT
                    )
                """.trimIndent())

                // Create index on timestamp for fast recent call queries
                database.execSQL("CREATE INDEX IF NOT EXISTS index_call_history_timestamp ON call_history(timestamp)")

                // Create index on contactId for fast contact-specific queries
                database.execSQL("CREATE INDEX IF NOT EXISTS index_call_history_contactId ON call_history(contactId)")

                Log.i(TAG, "Migration completed: Added call_history table")
            }
        }

        /**
         * Migration from version 22 to 23: Add profile picture support
         */
        private val MIGRATION_22_23 = object : Migration(22, 23) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 22 to 23")
                // Add profilePictureBase64 column (nullable for contacts without pictures)
                database.execSQL("ALTER TABLE contacts ADD COLUMN profilePictureBase64 TEXT")
                Log.i(TAG, "Migration completed: Added profilePictureBase64 column for profile pictures")
            }
        }

        /**
         * Migration from version 23 to 24: Add call quality logs table
         */
        private val MIGRATION_23_24 = object : Migration(23, 24) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 23 to 24")

                // Create call_quality_logs table
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS call_quality_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        callId TEXT NOT NULL,
                        contactName TEXT NOT NULL,
                        timestamp INTEGER NOT NULL,
                        durationSeconds INTEGER NOT NULL,
                        qualityScore INTEGER NOT NULL,
                        totalFrames INTEGER NOT NULL,
                        latePercent REAL NOT NULL,
                        plcPercent REAL NOT NULL,
                        fecSuccessPercent REAL NOT NULL,
                        outOfOrderPercent REAL NOT NULL,
                        jitterBufferMs INTEGER NOT NULL,
                        audioUnderruns INTEGER NOT NULL,
                        circuitStatsJson TEXT NOT NULL
                    )
                """.trimIndent())

                // Create index on timestamp for fast queries
                database.execSQL("CREATE INDEX IF NOT EXISTS index_call_quality_logs_timestamp ON call_quality_logs(timestamp)")

                Log.i(TAG, "Migration completed: Added call_quality_logs table")
            }
        }

        /**
         * Migration from version 24 to 25: Add ping_inbox table for idempotent message delivery
         */
        private val MIGRATION_24_25 = object : Migration(24, 25) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 24 to 25")

                // Create ping_inbox table
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS ping_inbox (
                        pingId TEXT PRIMARY KEY NOT NULL,
                        contactId INTEGER NOT NULL,
                        state INTEGER NOT NULL,
                        firstSeenAt INTEGER NOT NULL,
                        lastUpdatedAt INTEGER NOT NULL,
                        lastPingAt INTEGER NOT NULL,
                        pingAckedAt INTEGER,
                        pongSentAt INTEGER,
                        msgAckedAt INTEGER,
                        attemptCount INTEGER NOT NULL DEFAULT 1
                    )
                """.trimIndent())

                // Create indices for common queries
                database.execSQL("CREATE INDEX IF NOT EXISTS index_ping_inbox_contactId_state ON ping_inbox(contactId, state)")
                database.execSQL("CREATE INDEX IF NOT EXISTS index_ping_inbox_state ON ping_inbox(state)")

                Log.i(TAG, "Migration completed: Added ping_inbox table for idempotent message delivery over Tor")
            }
        }

        /**
         * Migration from version 25 to 26: Add unique index on pingId for ultimate deduplication
         */
        private val MIGRATION_25_26 = object : Migration(25, 26) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 25 to 26")

                // Add unique index on pingId (ultimate dedup authority)
                // Note: Unique index on nullable column allows multiple NULLs (for sent messages)
                database.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_messages_pingId ON messages(pingId)")

                Log.i(TAG, "Migration completed: Added unique index on pingId for deduplication")
            }
        }

        /**
         * Migration from version 26 to 27: Add contact_key_chains table for progressive ephemeral key evolution
         */
        private val MIGRATION_26_27 = object : Migration(26, 27) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 26 to 27")

                // Create contact_key_chains table for per-message forward secrecy
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS contact_key_chains (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        contactId INTEGER NOT NULL,
                        rootKeyBase64 TEXT NOT NULL,
                        sendChainKeyBase64 TEXT NOT NULL,
                        receiveChainKeyBase64 TEXT NOT NULL,
                        sendCounter INTEGER NOT NULL DEFAULT 0,
                        receiveCounter INTEGER NOT NULL DEFAULT 0,
                        createdTimestamp INTEGER NOT NULL,
                        lastEvolutionTimestamp INTEGER NOT NULL,
                        FOREIGN KEY(contactId) REFERENCES contacts(id) ON DELETE CASCADE
                    )
                """.trimIndent())

                // Create unique index on contactId (one key chain per contact)
                database.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_contact_key_chains_contactId ON contact_key_chains(contactId)")

                Log.i(TAG, "Migration completed: Added contact_key_chains table for progressive ephemeral key evolution")
            }
        }

        /**
         * Migration from version 27 to 28: Add Kyber-1024 public key for post-quantum cryptography
         */
        private val MIGRATION_27_28 = object : Migration(27, 28) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 27 to 28")
                // Add kyberPublicKeyBase64 column (nullable for backward compatibility)
                database.execSQL("ALTER TABLE contacts ADD COLUMN kyberPublicKeyBase64 TEXT")
                Log.i(TAG, "Migration completed: Added kyberPublicKeyBase64 column for post-quantum cryptography (ML-KEM-1024)")
            }
        }

        /**
         * Migration from version 28 to 29: Add per-wallet Zcash support and active wallet tracking
         */
        private val MIGRATION_28_29 = object : Migration(28, 29) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 28 to 29")
                // Add Zcash per-wallet fields
                database.execSQL("ALTER TABLE wallets ADD COLUMN zcashUnifiedAddress TEXT")
                database.execSQL("ALTER TABLE wallets ADD COLUMN zcashAccountIndex INTEGER NOT NULL DEFAULT 0")
                database.execSQL("ALTER TABLE wallets ADD COLUMN zcashBirthdayHeight INTEGER")
                database.execSQL("ALTER TABLE wallets ADD COLUMN isActiveZcash INTEGER NOT NULL DEFAULT 0")
                Log.i(TAG, "Migration completed: Added per-wallet Zcash support (zcashUnifiedAddress, zcashAccountIndex, zcashBirthdayHeight, isActiveZcash)")
            }
        }

        /**
         * Migration from version 29 to 30: Add skipped message keys table for out-of-order message handling
         */
        private val MIGRATION_29_30 = object : Migration(29, 30) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 29 to 30")

                // Create skipped_message_keys table
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS skipped_message_keys (
                        id TEXT PRIMARY KEY NOT NULL,
                        contactId INTEGER NOT NULL,
                        sequence INTEGER NOT NULL,
                        messageKey BLOB NOT NULL,
                        timestamp INTEGER NOT NULL
                    )
                """.trimIndent())

                // Create indices for efficient lookup and cleanup
                database.execSQL("""
                    CREATE INDEX IF NOT EXISTS index_skipped_message_keys_contactId_sequence
                    ON skipped_message_keys(contactId, sequence)
                """.trimIndent())

                database.execSQL("""
                    CREATE INDEX IF NOT EXISTS index_skipped_message_keys_timestamp
                    ON skipped_message_keys(timestamp)
                """.trimIndent())

                Log.i(TAG, "Migration completed: Added skipped_message_keys table for out-of-order message handling")
            }
        }

        /**
         * Migration from version 30 to 31: Add messageNonce field for deterministic message IDs
         * PHASE 1.1: STABLE IDENTITY
         *
         * messageNonce enables stable message identity across retries and crashes:
         * - Generated once per message (random 64-bit value)
         * - Used in deterministic messageId hash calculation
         * - Ensures same message = same ID (no ghost duplicates on retry)
         * - Enables crash recovery with deterministic ID reconstruction
         */
        private val MIGRATION_30_31 = object : Migration(30, 31) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 30 to 31")
                Log.i(TAG, "PHASE 1.1: Adding messageNonce field for stable message identity")

                // Add messageNonce column (64-bit random nonce, required field)
                // Default to random value for existing messages to maintain DB integrity
                database.execSQL("ALTER TABLE messages ADD COLUMN messageNonce INTEGER NOT NULL DEFAULT 0")

                Log.i(TAG, "Migration completed: Added messageNonce column")
                Log.i(TAG, "Note: Existing messages have messageNonce=0 (default). New messages will use SecureRandom nonces.")
            }
        }

        /**
         * Migration from version 31 to 32: Add pending_friend_requests table for friend request retry infrastructure
         */
        private val MIGRATION_31_32 = object : Migration(31, 32) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 31 to 32")

                // Create pending_friend_requests table for tracking friend request state
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS pending_friend_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        recipientOnion TEXT NOT NULL,
                        recipientPin TEXT,
                        phase INTEGER NOT NULL,
                        direction TEXT NOT NULL,
                        needsRetry INTEGER NOT NULL DEFAULT 0,
                        isCompleted INTEGER NOT NULL DEFAULT 0,
                        isFailed INTEGER NOT NULL DEFAULT 0,
                        lastSentAt INTEGER,
                        nextRetryAt INTEGER NOT NULL DEFAULT 0,
                        retryCount INTEGER NOT NULL DEFAULT 0,
                        phase1PayloadJson TEXT,
                        phase2PayloadBase64 TEXT,
                        contactCardJson TEXT,
                        hybridSharedSecretBase64 TEXT,
                        createdAt INTEGER NOT NULL,
                        completedAt INTEGER,
                        contactId INTEGER
                    )
                """.trimIndent())

                // Create indices for common queries
                database.execSQL("CREATE INDEX IF NOT EXISTS index_pending_friend_requests_recipientOnion ON pending_friend_requests(recipientOnion)")
                database.execSQL("CREATE INDEX IF NOT EXISTS index_pending_friend_requests_phase ON pending_friend_requests(phase)")
                database.execSQL("CREATE INDEX IF NOT EXISTS index_pending_friend_requests_needsRetry ON pending_friend_requests(needsRetry)")

                Log.i(TAG, "Migration completed: Added pending_friend_requests table for friend request retry infrastructure")
            }
        }

        /**
         * Migration from version 32 to 33: Add message retry tracking fields
         */
        private val MIGRATION_32_33 = object : Migration(32, 33) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 32 to 33")

                // Add nextRetryAtMs column for scheduling retries with exponential backoff
                database.execSQL("ALTER TABLE messages ADD COLUMN nextRetryAtMs INTEGER")

                // Add lastError column for diagnostic information
                database.execSQL("ALTER TABLE messages ADD COLUMN lastError TEXT")

                Log.i(TAG, "Migration completed: Added nextRetryAtMs and lastError columns to messages table")
            }
        }

        /**
         * Migration from version 33 to 34: Add correlationId for stress test tracing
         */
        private val MIGRATION_33_34 = object : Migration(33, 34) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 33 to 34")

                // Add correlationId column for stress test tracing and debugging
                // Tracks message through entire lifecycle to diagnose SOCKS timeout + MESSAGE_TX race
                database.execSQL("ALTER TABLE messages ADD COLUMN correlationId TEXT")

                Log.i(TAG, "Migration completed: Added correlationId column for stress test tracing")
            }
        }

        /**
         * Migration from version 34 to 35: Add pingWireBytesBase64 to ping_inbox
         * Store encrypted ping wire bytes in DB instead of SharedPreferences for reliability
         */
        private val MIGRATION_34_35 = object : Migration(34, 35) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 34 to 35")

                // Add pingWireBytesBase64 column to store encrypted ping payload
                // Format: [type_byte][sender_x25519_pubkey (32 bytes)][encrypted_payload]
                database.execSQL("ALTER TABLE ping_inbox ADD COLUMN pingWireBytesBase64 TEXT")

                Log.i(TAG, "Migration completed: Added pingWireBytesBase64 to ping_inbox (DB source of truth)")
            }
        }

        /**
         * Migration from version 35 to 36: Add downloadQueuedAt to ping_inbox
         * Supports auto-download queue with watchdog timeout for stuck claims.
         * New states (10, 11, 12) use existing Int column — no schema change needed for those.
         */
        private val MIGRATION_35_36 = object : Migration(35, 36) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 35 to 36")

                // Add downloadQueuedAt column for watchdog timeout on auto-download claims
                database.execSQL("ALTER TABLE ping_inbox ADD COLUMN downloadQueuedAt INTEGER")

                Log.i(TAG, "Migration completed: Added downloadQueuedAt to ping_inbox (auto-download watchdog)")
            }
        }

        /**
         * Migration from version 20 to 21: Add group messaging tables
         */
        private val MIGRATION_20_21 = object : Migration(20, 21) {
            override fun migrate(database: SupportSQLiteDatabase) {
                Log.i(TAG, "Migrating database from version 20 to 21")

                // Create groups table
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS groups (
                        groupId TEXT PRIMARY KEY NOT NULL,
                        name TEXT NOT NULL,
                        encryptedGroupKeyBase64 TEXT NOT NULL,
                        groupPin TEXT NOT NULL,
                        groupIcon TEXT,
                        createdAt INTEGER NOT NULL,
                        lastActivityTimestamp INTEGER NOT NULL,
                        isAdmin INTEGER NOT NULL DEFAULT 1,
                        isMuted INTEGER NOT NULL DEFAULT 0,
                        description TEXT
                    )
                """.trimIndent())
                database.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_groups_groupId ON groups(groupId)")

                // Create group_members table
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS group_members (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        groupId TEXT NOT NULL,
                        contactId INTEGER NOT NULL,
                        isAdmin INTEGER NOT NULL DEFAULT 0,
                        addedAt INTEGER NOT NULL,
                        addedBy INTEGER,
                        FOREIGN KEY(groupId) REFERENCES groups(groupId) ON DELETE CASCADE,
                        FOREIGN KEY(contactId) REFERENCES contacts(id) ON DELETE CASCADE
                    )
                """.trimIndent())
                database.execSQL("CREATE INDEX IF NOT EXISTS index_group_members_groupId ON group_members(groupId)")
                database.execSQL("CREATE INDEX IF NOT EXISTS index_group_members_contactId ON group_members(contactId)")
                database.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_group_members_groupId_contactId ON group_members(groupId, contactId)")

                // Create group_messages table
                database.execSQL("""
                    CREATE TABLE IF NOT EXISTS group_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                        groupId TEXT NOT NULL,
                        senderContactId INTEGER,
                        senderName TEXT NOT NULL,
                        messageId TEXT NOT NULL,
                        encryptedContent TEXT NOT NULL,
                        isSentByMe INTEGER NOT NULL,
                        timestamp INTEGER NOT NULL,
                        status INTEGER NOT NULL DEFAULT 0,
                        signatureBase64 TEXT NOT NULL,
                        nonceBase64 TEXT NOT NULL,
                        messageType TEXT NOT NULL DEFAULT 'TEXT',
                        voiceDuration INTEGER,
                        voiceFilePath TEXT,
                        attachmentType TEXT,
                        encryptedAttachment TEXT,
                        selfDestructSeconds INTEGER,
                        FOREIGN KEY(groupId) REFERENCES groups(groupId) ON DELETE CASCADE,
                        FOREIGN KEY(senderContactId) REFERENCES contacts(id) ON DELETE CASCADE
                    )
                """.trimIndent())
                database.execSQL("CREATE INDEX IF NOT EXISTS index_group_messages_groupId ON group_messages(groupId)")
                database.execSQL("CREATE INDEX IF NOT EXISTS index_group_messages_senderContactId ON group_messages(senderContactId)")
                database.execSQL("CREATE INDEX IF NOT EXISTS index_group_messages_timestamp ON group_messages(timestamp)")
                database.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS index_group_messages_messageId ON group_messages(messageId)")

                Log.i(TAG, "Migration completed: Added groups, group_members, and group_messages tables for group messaging")
            }
        }

        /**
         * Get database instance
         * @param context Application context
         * @param passphrase Encryption passphrase (should be derived from KeyManager)
         *
         * SECURITY: The passphrase will be zeroized after database initialization
         */
        fun getInstance(context: Context, passphrase: ByteArray): SecureLegionDatabase {
            // Double-checked locking to prevent race conditions
            val currentInstance = INSTANCE
            if (currentInstance != null) {
                // SECURITY: Zeroize passphrase even if instance already exists
                java.util.Arrays.fill(passphrase, 0.toByte())
                return currentInstance
            }

            return synchronized(this) {
                // Check again inside synchronized block
                val newInstance = INSTANCE
                if (newInstance != null) {
                    // SECURITY: Zeroize passphrase if instance was created by another thread
                    java.util.Arrays.fill(passphrase, 0.toByte())
                    newInstance
                } else {
                    try {
                        val instance = buildDatabase(context, passphrase)
                        INSTANCE = instance
                        instance
                    } finally {
                        // SECURITY: Always zeroize passphrase after use
                        java.util.Arrays.fill(passphrase, 0.toByte())
                    }
                }
            }
        }

        /**
         * Clear database instance (call after wipe)
         */
        fun clearInstance() {
            synchronized(this) {
                INSTANCE?.close()
                INSTANCE = null
                Log.i(TAG, "Database instance cleared")
            }
        }

        /**
         * Build encrypted database with SQLCipher
         */
        private fun buildDatabase(context: Context, passphrase: ByteArray): SecureLegionDatabase {
            Log.i(TAG, "Building encrypted database with SQLCipher")

            // Initialize SQLCipher native library
            System.loadLibrary("sqlcipher")

            // Create SQLCipher factory with passphrase
            val factory = SupportOpenHelperFactory(passphrase)

            return try {
                Room.databaseBuilder(
                    context.applicationContext,
                    SecureLegionDatabase::class.java,
                    DATABASE_NAME
                )
                    .openHelperFactory(factory)
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10, MIGRATION_10_11, MIGRATION_11_12, MIGRATION_12_13, MIGRATION_13_14, MIGRATION_14_15, MIGRATION_15_16, MIGRATION_16_17, MIGRATION_17_18, MIGRATION_19_20, MIGRATION_20_21, MIGRATION_21_22, MIGRATION_22_23, MIGRATION_23_24, MIGRATION_24_25, MIGRATION_25_26, MIGRATION_26_27, MIGRATION_27_28, MIGRATION_28_29, MIGRATION_29_30, MIGRATION_30_31, MIGRATION_31_32, MIGRATION_32_33, MIGRATION_33_34, MIGRATION_34_35, MIGRATION_35_36)
                    .addCallback(object : RoomDatabase.Callback() {
                        override fun onCreate(db: SupportSQLiteDatabase) {
                            super.onCreate(db)
                            Log.i(TAG, "Database created")

                        try {
                            // Enable secure deletion (must use query() with SQLCipher)
                            var cursor = db.query("PRAGMA secure_delete = ON")
                            try {
                                if (cursor.moveToFirst()) {
                                    Log.i(TAG, "Secure delete: ${cursor.getString(0)}")
                                }
                            } finally {
                                cursor.close()
                            }

                            // Set journal mode
                            cursor = db.query("PRAGMA journal_mode = DELETE")
                            try {
                                if (cursor.moveToFirst()) {
                                    val mode = cursor.getString(0)
                                    Log.i(TAG, "Journal mode: $mode")
                                }
                            } finally {
                                cursor.close()
                            }

                            Log.i(TAG, "Security PRAGMAs applied successfully")
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to apply PRAGMAs", e)
                            throw e // Re-throw to see the actual error
                        }
                    }

                    override fun onOpen(db: SupportSQLiteDatabase) {
                        super.onOpen(db)
                        Log.i(TAG, "Database opened")
                    }
                })
                .build()
            } catch (e: Exception) {
                // If database creation fails (e.g., corrupted file), delete it and try again
                Log.e(TAG, "Failed to open database, attempting recovery", e)

                if (e.message?.contains("file is not a database") == true ||
                    e.message?.contains("not a database") == true ||
                    e.message?.contains("file is encrypted") == true) {

                    Log.w(TAG, "Detected corrupted database file, attempting secure deletion before recreating")

                    // Securely delete corrupted database files
                    try {
                        val dbPath = context.getDatabasePath(DATABASE_NAME)
                        if (dbPath.exists()) {
                            com.securelegion.utils.SecureWipe.secureDeleteFile(dbPath)
                            Log.i(TAG, "Securely deleted corrupted database file")
                        }

                        // Securely delete associated files
                        val dbJournal = context.getDatabasePath("$DATABASE_NAME-journal")
                        if (dbJournal.exists()) {
                            com.securelegion.utils.SecureWipe.secureDeleteFile(dbJournal)
                        }

                        val dbWal = context.getDatabasePath("$DATABASE_NAME-wal")
                        if (dbWal.exists()) {
                            com.securelegion.utils.SecureWipe.secureDeleteFile(dbWal)
                        }

                        val dbShm = context.getDatabasePath("$DATABASE_NAME-shm")
                        if (dbShm.exists()) {
                            com.securelegion.utils.SecureWipe.secureDeleteFile(dbShm)
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Secure deletion failed, using simple delete as fallback", e)
                        // Fallback to simple delete if secure wipe fails
                        context.getDatabasePath(DATABASE_NAME).delete()
                        context.getDatabasePath("$DATABASE_NAME-journal").delete()
                        context.getDatabasePath("$DATABASE_NAME-wal").delete()
                        context.getDatabasePath("$DATABASE_NAME-shm").delete()
                    }

                    // Try creating database again
                    Log.i(TAG, "Attempting to create fresh database")
                    return Room.databaseBuilder(
                        context.applicationContext,
                        SecureLegionDatabase::class.java,
                        DATABASE_NAME
                    )
                        .openHelperFactory(SupportOpenHelperFactory(passphrase))
                        .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10, MIGRATION_10_11, MIGRATION_11_12, MIGRATION_12_13, MIGRATION_13_14, MIGRATION_14_15, MIGRATION_15_16, MIGRATION_16_17, MIGRATION_17_18, MIGRATION_19_20, MIGRATION_20_21, MIGRATION_21_22, MIGRATION_22_23, MIGRATION_23_24, MIGRATION_24_25, MIGRATION_25_26, MIGRATION_26_27, MIGRATION_27_28, MIGRATION_28_29, MIGRATION_29_30, MIGRATION_30_31, MIGRATION_31_32, MIGRATION_32_33, MIGRATION_33_34, MIGRATION_34_35, MIGRATION_35_36)
                        .addCallback(object : RoomDatabase.Callback() {
                            override fun onCreate(db: SupportSQLiteDatabase) {
                                super.onCreate(db)
                                Log.i(TAG, "Database created after recovery")
                            }
                        })
                        .build()
                } else {
                    // Unknown error, rethrow
                    throw e
                }
            }
        }

        /**
         * Close and clear instance (for testing or account wipe)
         */
        fun closeDatabase() {
            synchronized(this) {
                INSTANCE?.close()
                INSTANCE = null
                Log.i(TAG, "Database closed")
            }
        }

        /**
         * Verify database encryption
         * @return true if database is encrypted
         */
        fun isDatabaseEncrypted(context: Context): Boolean {
            try {
                val dbFile = context.getDatabasePath(DATABASE_NAME)
                if (!dbFile.exists()) {
                    Log.d(TAG, "Database file does not exist yet")
                    return false
                }

                // Try to open database without passphrase (should fail if encrypted)
                SQLiteDatabase.openOrCreateDatabase(
                    dbFile,
                    ByteArray(0),  // Empty passphrase - will fail if database is encrypted
                    null,
                    null
                ).close()

                Log.e(TAG, "WARNING: Database is NOT encrypted!")
                return false
            } catch (e: Exception) {
                // Exception expected if database is encrypted
                Log.i(TAG, "Database encryption verified")
                return true
            }
        }

        /**
         * Delete database file (for testing or account wipe)
         */
        fun deleteDatabase(context: Context): Boolean {
            closeDatabase()
            val dbFile = context.getDatabasePath(DATABASE_NAME)
            val deleted = dbFile.delete()
            if (deleted) {
                Log.i(TAG, "Database file deleted")
            } else {
                Log.w(TAG, "Failed to delete database file")
            }
            return deleted
        }
    }
}
