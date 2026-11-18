package com.securelegion.sync

import org.json.JSONArray
import org.json.JSONObject

/** The authenticated HELLO/HELLO_ACK shape shared with iOS history-v2. */
internal object DeviceSyncHelloWire {
    private val topics = listOf("messages", "receipts", "contacts", "settings", "groups",
        "group_links", "typing")
    private val fields = setOf("capabilities", "cursors")
    private val cursorFields = setOf("pushed", "received")

    data class Hello(val capabilities: Set<String>, val received: Map<String, Long>)

    fun parse(payload: JSONObject): Hello {
        require(payload.keys().asSequence().toSet() == fields)
        val rawCapabilities = payload.getJSONArray("capabilities")
        require(rawCapabilities.length() <= 32)
        val capabilities = HashSet<String>()
        for (i in 0 until rawCapabilities.length()) {
            require(rawCapabilities.opt(i) is String)
            val name = rawCapabilities.getString(i)
            require(name.isNotEmpty() && name.toByteArray(Charsets.UTF_8).size <= 64 &&
                capabilities.add(name))
        }
        val cursors = payload.getJSONObject("cursors")
        require(cursors.keys().asSequence().toSet() == topics.toSet() ||
            cursors.keys().asSequence().toSet() == topics.toSet() - "group_links")
        val received = HashMap<String, Long>()
        for (topic in topics) {
            if (topic == "group_links" && !cursors.has(topic)) {
                received[topic] = 0
                continue
            }
            val cursor = cursors.getJSONObject(topic)
            require(cursor.keys().asSequence().toSet() == cursorFields)
            val pushed = integer(cursor.opt("pushed"))
            val applied = integer(cursor.opt("received"))
            require(pushed >= 0 && applied >= 0)
            received[topic] = applied
        }
        return Hello(capabilities, received)
    }

    fun payload(capabilities: Set<String>, cursors: Map<String, Pair<Long, Long>>): JSONObject {
        require(capabilities.size <= 32 && capabilities.all {
            it.isNotEmpty() && it.toByteArray(Charsets.UTF_8).size <= 64
        })
        require(cursors.keys.all { it in topics } && cursors.values.all {
            it.first >= 0 && it.second >= 0
        })
        val rawCursors = JSONObject()
        for (topic in topics) {
            val cursor = cursors[topic] ?: (0L to 0L)
            rawCursors.put(topic, JSONObject().put("pushed", cursor.first)
                .put("received", cursor.second))
        }
        return JSONObject().put("capabilities", JSONArray().also { array ->
            capabilities.sorted().forEach(array::put)
        }).put("cursors", rawCursors)
    }

    private fun integer(value: Any?): Long {
        require(value is Int || value is Long)
        return (value as Number).toLong().also {
            require(it <= 9_007_199_254_740_991L)
        }
    }
}
