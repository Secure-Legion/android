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
import com.securelegion.database.dao.WalletDao
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.Message
import com.securelegion.database.entities.Wallet
import net.sqlcipher.database.SQLiteDatabase
import net.sqlcipher.database.SupportFactory

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
    entities = [Contact::class, Message::class, Wallet::class],
    version = 5,
    exportSchema = false
)
abstract class SecureLegionDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun messageDao(): MessageDao
    abstract fun walletDao(): WalletDao

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
         * Get database instance
         * @param context Application context
         * @param passphrase Encryption passphrase (should be derived from KeyManager)
         */
        fun getInstance(context: Context, passphrase: ByteArray): SecureLegionDatabase {
            // Double-checked locking to prevent race conditions
            val currentInstance = INSTANCE
            if (currentInstance != null) {
                return currentInstance
            }

            return synchronized(this) {
                // Check again inside synchronized block
                val newInstance = INSTANCE
                if (newInstance != null) {
                    newInstance
                } else {
                    val instance = buildDatabase(context, passphrase)
                    INSTANCE = instance
                    instance
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

            // Initialize SQLCipher
            SQLiteDatabase.loadLibs(context)

            // Create SQLCipher factory with passphrase
            val factory = SupportFactory(passphrase)

            return try {
                Room.databaseBuilder(
                    context.applicationContext,
                    SecureLegionDatabase::class.java,
                    DATABASE_NAME
                )
                    .openHelperFactory(factory)
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5)
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
                        .openHelperFactory(SupportFactory(passphrase))
                        .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4, MIGRATION_4_5)
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
                SQLiteDatabase.openDatabase(
                    dbFile.absolutePath,
                    "",
                    null,
                    SQLiteDatabase.OPEN_READONLY
                )?.close()

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
