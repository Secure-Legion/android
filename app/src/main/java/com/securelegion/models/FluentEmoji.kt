package com.securelegion.models

import android.content.Context
import android.util.Log
import org.json.JSONObject

/**
 * Single Fluent emoji entry loaded from assets/fluent_emoji/_categories.json.
 *
 * The wire-format `assetPath` is always `"fluent_emoji/" + file`.
 */
data class FluentEmojiEntry(
    val codepoint: String, // e.g. "1f600" or "2764_200d_1f525"
    val name: String,      // CLDR name, e.g. "grinning face"
    val glyph: String,     // raw unicode glyph, e.g. "😀"
    val file: String       // PNG filename, e.g. "1f600_grinning_face.png"
) {
    val assetPath: String get() = "fluent_emoji/$file"
}

/**
 * In-memory loader for the bundled Fluent 3D emoji set.
 * Reads `assets/fluent_emoji/_categories.json` once and exposes a category-ordered map.
 */
object FluentEmojiCatalog {

    private const val TAG = "FluentEmojiCatalog"
    private const val CATEGORIES_PATH = "fluent_emoji/_categories.json"

    /** Display order matching iOS. Categories not in this list are appended alphabetically. */
    val DISPLAY_ORDER = listOf(
        "Smileys", "Hearts", "Hand gestures", "People",
        "Animals", "Food and drink", "Activities", "Travel",
        "Objects", "Symbols", "Nature", "Flags"
    )

    @Volatile
    private var cached: LinkedHashMap<String, List<FluentEmojiEntry>>? = null

    /**
     * Returns the catalog, ordered by [DISPLAY_ORDER]. Loads from assets on first call.
     * Returns an empty map if the bundle is missing or fails to parse.
     */
    fun load(context: Context): LinkedHashMap<String, List<FluentEmojiEntry>> {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val parsed = try {
                parseCategories(context)
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load Fluent emoji catalog", e)
                LinkedHashMap()
            }
            cached = parsed
            return parsed
        }
    }

    private fun parseCategories(context: Context): LinkedHashMap<String, List<FluentEmojiEntry>> {
        val json = context.assets.open(CATEGORIES_PATH).bufferedReader().use { it.readText() }
        val obj = JSONObject(json)
        val raw = mutableMapOf<String, List<FluentEmojiEntry>>()

        val keys = obj.keys()
        while (keys.hasNext()) {
            val category = keys.next()
            val arr = obj.getJSONArray(category)
            val list = mutableListOf<FluentEmojiEntry>()
            for (i in 0 until arr.length()) {
                val entry = arr.getJSONObject(i)
                list.add(
                    FluentEmojiEntry(
                        codepoint = entry.optString("codepoint"),
                        name = entry.optString("name"),
                        glyph = entry.optString("glyph"),
                        file = entry.optString("file")
                    )
                )
            }
            raw[category] = list
        }

        // Apply display order: known categories first (in order), then unknown alphabetically
        val ordered = LinkedHashMap<String, List<FluentEmojiEntry>>()
        for (cat in DISPLAY_ORDER) {
            raw[cat]?.let { ordered[cat] = it }
        }
        raw.keys.filter { it !in DISPLAY_ORDER }.sorted().forEach { cat ->
            ordered[cat] = raw[cat]!!
        }
        return ordered
    }
}
