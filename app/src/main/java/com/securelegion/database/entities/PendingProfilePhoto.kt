package com.securelegion.database.entities

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Pending profile photo delivery queue.
 *
 * Profile photos are sent fire-and-forget. If the Tor circuit fails, the
 * photo is silently lost. This table tracks failed deliveries so they can
 * be retried with exponential backoff.
 *
 * Design notes:
 * - No photo blob stored — the processor loads the CURRENT photo at retry
 *   time, so changing the photo mid-retry automatically uses the latest.
 * - `contactId` is the primary key — deduplicates naturally. Multiple
 *   failed sends to the same contact collapse into one retry entry.
 * - Retry schedule: 30s, 60s, 120s, 240s, 300s (cap), up to 10 attempts.
 */
@Entity(tableName = "pending_profile_photo")
data class PendingProfilePhoto(
    @PrimaryKey
    val contactId: Long,
    val retryCount: Int = 0,
    val nextRetryAtMs: Long,
    val createdAtMs: Long
)
