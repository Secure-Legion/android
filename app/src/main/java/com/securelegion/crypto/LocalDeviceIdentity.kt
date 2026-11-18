package com.securelegion.crypto

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import com.goterl.lazysodium.interfaces.Sign
import org.json.JSONObject
import java.io.Closeable
import java.security.MessageDigest
import java.security.SecureRandom

/** Four independent, random installation seeds; no account seed or chat ratchet is used. */
class LocalDeviceIdentity private constructor(private val seeds: ByteArray) : Closeable {
    val signingPublicKey: ByteArray
    val encryptionPublicKey: ByteArray
    val deviceId: String
    val onionAddress: String

    private val sodium = LazySodiumAndroid(SodiumAndroid())
    private var closed = false

    init {
        require(seeds.size == RECORD_SIZE && seeds.copyOfRange(0, 6).contentEquals(MAGIC))
        val edPublic = ByteArray(32)
        val edSecret = ByteArray(64)
        val edSeed = seeds.copyOfRange(6, 38)
        try {
            check(sodium.cryptoSignSeedKeypair(edPublic, edSecret, edSeed))
        } finally {
            edSecret.fill(0)
            edSeed.fill(0)
        }
        val xPublic = ByteArray(32)
        val xSeed = seeds.copyOfRange(38, 70)
        try { check(sodium.cryptoScalarMultBase(xPublic, xSeed)) }
        finally { xSeed.fill(0) }
        signingPublicKey = edPublic
        encryptionPublicKey = xPublic
        val identifier = MessageDigest.getInstance("SHA-256").digest(
            "secure-legion-device-v1".toByteArray(Charsets.US_ASCII) + edPublic + xPublic
        )
        deviceId = Base64.encodeToString(identifier,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        check(deviceId.length == 43)
        val torPublic = ByteArray(32)
        val torSecret = ByteArray(64)
        val torSeed = seeds.copyOfRange(70, 102)
        try {
            check(sodium.cryptoSignSeedKeypair(torPublic, torSecret, torSeed))
        } finally {
            torSecret.fill(0)
            torSeed.fill(0)
        }
        val request = JSONObject().put("operation", "onion_from_public_key")
            .put("service_ed", Base64.encodeToString(torPublic, Base64.NO_WRAP))
        val response = JSONObject(RustBridge.deviceAuthorization(
            request.toString().toByteArray(Charsets.UTF_8), null
        ).toString(Charsets.UTF_8))
        onionAddress = response.getString("onion")
        check(onionAddress.length == 62 && onionAddress.endsWith(".onion"))
    }

    @Synchronized
    fun <T> withSyncKeys(block: (ByteArray, ByteArray) -> T): T {
        check(!closed)
        val ed = seeds.copyOfRange(6, 38)
        val x = seeds.copyOfRange(38, 70)
        try { return block(ed, x) } finally { ed.fill(0); x.fill(0) }
    }

    @Synchronized
    fun sign(message: ByteArray): ByteArray {
        check(!closed)
        val seed = seeds.copyOfRange(6, 38)
        return try { RustBridge.signData(message, seed) } finally { seed.fill(0) }
    }

    @Synchronized
    fun deriveSharedSecret(peerPublicKey: ByteArray): ByteArray {
        check(!closed && peerPublicKey.size == 32)
        val privateKey = seeds.copyOfRange(38, 70)
        val secret = try { RustBridge.deriveSharedSecret(privateKey, peerPublicKey) }
            finally { privateKey.fill(0) }
        if (secret.size != 32 || secret.all { it == 0.toByte() }) {
            secret.fill(0)
            throw IllegalArgumentException("Invalid device key exchange")
        }
        return secret
    }

    @Synchronized
    fun <T> withTorServiceSeed(block: (ByteArray) -> T): T {
        check(!closed)
        val seed = seeds.copyOfRange(70, 102)
        try { return block(seed) } finally { seed.fill(0) }
    }

    @Synchronized
    fun mlKemPublicKey(): ByteArray {
        check(!closed)
        val seed = seeds.copyOfRange(102, 134)
        val pair = try { RustBridge.generateHybridKEMKeypairFromSeed(seed) }
            finally { seed.fill(0) }
        try {
            check(pair.size == 32 + 32 + 1568 + 3168)
            return pair.copyOfRange(64, 64 + 1568)
        } finally { pair.fill(0) }
    }

    @Synchronized
    fun <T> withMLKemPrivateKey(block: (ByteArray) -> T): T {
        check(!closed)
        val seed = seeds.copyOfRange(102, 134)
        val pair = try { RustBridge.generateHybridKEMKeypairFromSeed(seed) }
            finally { seed.fill(0) }
        try {
            check(pair.size == 32 + 32 + 1568 + 3168)
            val privateKey = pair.copyOfRange(64 + 1568, pair.size)
            try { return block(privateKey) } finally { privateKey.fill(0) }
        } finally { pair.fill(0) }
    }

    @Synchronized
    override fun close() {
        if (!closed) { seeds.fill(0); closed = true }
    }

    companion object {
        private val MAGIC = "SLDI02".toByteArray(Charsets.US_ASCII)
        private const val RECORD_SIZE = 6 + 4 * 32
        private const val PREFS_NAME = "secure_legion_keys"
        private const val RECORD_KEY = "securelegion_independent_device_identity_v2"
        private val creationLock = Any()

        private fun preferences(context: Context) = EncryptedSharedPreferences.create(
            context.applicationContext, PREFS_NAME,
            MasterKey.Builder(context.applicationContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        fun loadExisting(context: Context): LocalDeviceIdentity {
            val encoded = preferences(context).getString(RECORD_KEY, null)
                ?: throw IllegalStateException("Installation identity unavailable")
            return LocalDeviceIdentity(Base64.decode(encoded, Base64.DEFAULT))
        }

        fun loadOrCreate(context: Context): LocalDeviceIdentity = synchronized(creationLock) {
            val prefs = preferences(context)
            val existing = prefs.getString(RECORD_KEY, null)
            if (existing != null) return@synchronized LocalDeviceIdentity(Base64.decode(existing, Base64.DEFAULT))
            val record = ByteArray(RECORD_SIZE)
            MAGIC.copyInto(record)
            val random = ByteArray(4 * 32)
            try {
                SecureRandom().nextBytes(random)
                random.copyInto(record, MAGIC.size)
            } finally { random.fill(0) }
            try {
                val identity = LocalDeviceIdentity(record.copyOf())
                val encoded = Base64.encodeToString(record, Base64.NO_WRAP)
                if (!prefs.edit().putString(RECORD_KEY, encoded).commit()) {
                    identity.close()
                    throw IllegalStateException("Could not protect installation identity")
                }
                identity
            } finally { record.fill(0) }
        }
    }
}
