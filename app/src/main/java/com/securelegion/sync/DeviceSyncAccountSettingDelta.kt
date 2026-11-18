package com.securelegion.sync

import android.graphics.BitmapFactory
import android.util.Base64
import org.json.JSONObject

/** Strict iOS build-48 account profile delta; no device-local preferences. */
internal object DeviceSyncAccountSettingDelta {
    data class Setting(val id: String, val value: String?)

    fun parse(delta: JSONObject): Setting {
        require(delta.keys().asSequence().toSet() == setOf("settings_id", "version", "value"))
        require(delta.opt("version") is Int && delta.getInt("version") == 1)
        require(delta.opt("settings_id") is String)
        val id = delta.getString("settings_id")
        require(id == "account:name" || id == "account:photo")
        val raw = delta.opt("value")
        if (id == "account:name") {
            require(raw is String && raw.isNotEmpty() &&
                raw == raw.trim() && raw.toByteArray(Charsets.UTF_8).size <= 64 &&
                raw.codePoints().toArray().none { it < 32 || it in 127..159 })
            return Setting(id, raw)
        }
        if (raw == JSONObject.NULL) return Setting(id, null)
        require(raw is String && raw.length <= 349_528)
        val image = Base64.decode(raw, Base64.NO_WRAP)
        require(image.isNotEmpty() && image.size <= 256 * 1024 &&
            Base64.encodeToString(image, Base64.NO_WRAP) == raw)
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(image, 0, image.size, bounds)
        require(bounds.outWidth in 1..512 && bounds.outHeight in 1..512 &&
            bounds.outWidth.toLong() * bounds.outHeight <= 512L * 512)
        return Setting(id, raw)
    }
}
