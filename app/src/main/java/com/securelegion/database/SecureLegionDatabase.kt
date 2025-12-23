package com.securelegion.database

import android.content.Context
import android.util.Log
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.database.dao.ContactDao
import com.securelegion.database.dao.MessageDao
import com.securelegion.database.dao.ReceivedIdDao
import com.securelegion.database.dao.UsedSignatureDao
import com.securelegion.database.dao.WalletDao
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.Message
import com.securelegion.database.entities.ReceivedId
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
    entities = [Contact::class, Message::class, Wallet::class, ReceivedId::class, UsedSignature::class],
    version = 19,
    exportSchema = false
)
abstract class SecureLegionDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun messageDao(): MessageDao
    abstract fun walletDao(): WalletDao
    abstract fun receivedIdDao(): ReceivedIdDao
    abstract fun usedSignatureDao(): UsedSignatureDao

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
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10, MIGRATION_10_11, MIGRATION_11_12, MIGRATION_12_13, MIGRATION_13_14, MIGRATION_14_15, MIGRATION_15_16, MIGRATION_16_17, MIGRATION_17_18)
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
                        .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10, MIGRATION_10_11, MIGRATION_11_12, MIGRATION_12_13, MIGRATION_13_14, MIGRATION_14_15, MIGRATION_15_16, MIGRATION_16_17, MIGRATION_17_18)
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
