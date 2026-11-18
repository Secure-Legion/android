package com.securelegion.services

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.security.MessageDigest
import java.util.UUID

/** Bounded, session-scoped dispatch for exact native Noise control replies. */
internal class DeviceSyncControlQueue(
    private val scope: CoroutineScope,
    account: ByteArray,
    private val localDeviceId: String,
    private val valid: (String) -> Boolean,
    private val send: (String, ByteArray) -> Boolean,
    private val onFailure: (String, Throwable?) -> Unit = { _, _ -> }
) {
    private data class Key(val session: String, val account: String, val local: String,
                           val remote: String, val digest: String)

    private val session = UUID.randomUUID().toString()
    private val accountKey = account.toHex()
    private val permits = Semaphore(4)
    private val pending = HashSet<Key>()

    /** Returns false only when work is invalid or the bounded queue is full. */
    fun enqueue(remoteDeviceId: String, packets: List<ByteArray>,
                validWork: () -> Boolean = { true }): Boolean {
        if (remoteDeviceId.length != 43 || packets.isEmpty() || packets.size > 2 ||
            packets.any { it.size !in 6..8192 || it[0].toInt() and 255 !in 0xB6..0xB7 })
            return false
        val exact = packets.map { it.copyOf() }
        val digest = MessageDigest.getInstance("SHA-256")
        for (packet in exact) {
            digest.update(byteArrayOf((packet.size ushr 24).toByte(),
                (packet.size ushr 16).toByte(), (packet.size ushr 8).toByte(),
                packet.size.toByte()))
            digest.update(packet)
        }
        val key = Key(session, accountKey, localDeviceId, remoteDeviceId,
            digest.digest().toHex())
        synchronized(pending) {
            if (key in pending) return true // Exact duplicate already queued or in flight.
            if (pending.size >= 128) return false
            pending.add(key)
        }
        scope.launch {
            try {
                permits.withPermit {
                    for (packet in exact) {
                        if (!validWork() || !valid(remoteDeviceId) ||
                            !send(remoteDeviceId, packet)) {
                            onFailure(remoteDeviceId, null)
                            break
                        }
                    }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                onFailure(remoteDeviceId, error)
            } finally {
                synchronized(pending) { pending.remove(key) }
            }
        }
        return true
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
