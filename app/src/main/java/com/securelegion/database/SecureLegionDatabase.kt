package com.securelegion.database

import android.content.Context
import android.util.Log
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import com.securelegion.database.dao.ContactDao
import com.securelegion.database.dao.MessageDao
import com.securelegion.database.entities.Contact
import com.securelegion.database.entities.Message
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
    entities = [Contact::class, Message::class],
    version = 1,
    exportSchema = false
)
abstract class SecureLegionDatabase : RoomDatabase() {

    abstract fun contactDao(): ContactDao
    abstract fun messageDao(): MessageDao

    companion object {
        private const val TAG = "SecureLegionDatabase"
        private const val DATABASE_NAME = "secure_legion.db"

        @Volatile
        private var INSTANCE: SecureLegionDatabase? = null

        /**
         * Get database instance
         * @param context Application context
         * @param passphrase Encryption passphrase (should be derived from KeyManager)
         */
        fun getInstance(context: Context, passphrase: ByteArray): SecureLegionDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = buildDatabase(context, passphrase)
                INSTANCE = instance
                instance
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

            return Room.databaseBuilder(
                context.applicationContext,
                SecureLegionDatabase::class.java,
                DATABASE_NAME
            )
                .openHelperFactory(factory)
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
