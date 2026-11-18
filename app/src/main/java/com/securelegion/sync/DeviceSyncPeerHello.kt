package com.securelegion.sync

import org.json.JSONArray
import org.json.JSONObject

/** Exact iOS build-48 HELLO shape; parsing does not activate any capability. */
internal object DeviceSyncPeerHello {
    private val topics = listOf("messages", "receipts", "contacts", "settings",
        "groups", "group_links", "typing")

    data class Peer(val capabilities: Set<String>, val received: Map<String, Long>)

    fun parse(payload: JSONObject): Peer {
        require(payload.keys().asSequence().toSet() == setOf("capabilities", "cursors"))
        val rawCapabilities = payload.getJSONArray("capabilities")
        require(rawCapabilities.length() <= 32)
        val capabilities = LinkedHashSet<String>()
        for (index in 0 until rawCapabilities.length()) {
            val value = rawCapabilities.get(index)
            require(value is String && value.isNotEmpty() &&
                value.toByteArray(Charsets.UTF_8).size <= 64 && capabilities.add(value))
        }
        val rawCursors = payload.getJSONObject("cursors")
        require(rawCursors.keys().asSequence().toSet().all { it in topics })
        val received = LinkedHashMap<String, Long>()
        for (topic in topics) {
            if (topic == "group_links" && !rawCursors.has(topic)) {
                received[topic] = 0
                continue
            }
            val cursor = rawCursors.getJSONObject(topic)
            require(cursor.keys().asSequence().toSet() == setOf("pushed", "received"))
            val pushed = integer(cursor.opt("pushed"))
            val seen = integer(cursor.opt("received"))
            require(pushed >= 0 && seen >= 0)
            received[topic] = seen
        }
        return Peer(capabilities, received)
    }

    fun emptyLocal(): JSONObject {
        val cursors = JSONObject()
        for (topic in topics) cursors.put(topic, JSONObject().put("pushed", 0)
            .put("received", 0))
        return JSONObject().put("capabilities", JSONArray()).put("cursors", cursors)
    }

    private fun integer(value: Any?): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong()
    }
}
