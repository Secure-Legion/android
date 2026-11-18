package com.securelegion.services

import com.securelegion.sync.DeviceRosterExchange
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit

/** Public roster announcements use bounded control work, independent of history. */
internal class ContactRosterSendQueue(
    private val scope: CoroutineScope,
    private val valid: (DeviceRosterExchange.ContactBootstrap) -> Boolean,
    private val send: (DeviceRosterExchange.ContactBootstrap) -> Boolean
) {
    private val permits = Semaphore(2)
    private val pending = HashSet<String>()

    fun enqueue(item: DeviceRosterExchange.ContactBootstrap): Boolean {
        val key = item.contactAccount + "|" + item.onion + "|" +
            item.rosterHash.joinToString("") { "%02x".format(it) }
        synchronized(pending) {
            if (key in pending) return true
            if (pending.size >= 16) return false
            pending.add(key)
        }
        scope.launch {
            try {
                permits.withPermit { if (valid(item)) send(item) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                Log.w("ContactRosterSendQueue", "Public roster send deferred: ${error.message}")
            } finally {
                synchronized(pending) { pending.remove(key) }
            }
        }
        return true
    }
}
