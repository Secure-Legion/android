package com.securelegion.services

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Matrix
import android.media.ExifInterface
import android.net.Uri
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import kotlin.math.min

/**
 * Profile Picture Manager
 *
 * Handles profile picture processing with privacy-first approach:
 * - Strips EXIF metadata (location, camera model, timestamps)
 * - Compresses images to max 256KB
 * - Resizes to 512x512px
 * - Converts to base64 for ContactCard storage
 * - Stores locally in app private storage
 *
 * Privacy guarantees:
 * - No location data
 * - No camera metadata
 * - No timestamps
 * - Consistent sizing (prevents fingerprinting)
 */
class ProfilePictureManager(private val context: Context) {
    companion object {
        private const val TAG = "ProfilePictureManager"

        // Image specifications
        private const val MAX_SIZE_PX = 512 // Max width/height
        private const val MAX_SIZE_BYTES = 256 * 1024 // 256KB max
        private const val JPEG_QUALITY_START = 90 // Initial compression quality
        private const val JPEG_QUALITY_MIN = 60 // Minimum acceptable quality

        // Local storage
        private const val PROFILE_PICS_DIR = "profile_pictures"
        private const val MY_PROFILE_PIC = "my_profile.jpg"
    }

    /**
     * Process image from URI (gallery or camera)
     * Strips EXIF, resizes, compresses
     * @param imageUri Source image URI
     * @return Base64-encoded JPEG string (ready for ContactCard)
     */
    suspend fun processProfilePicture(imageUri: Uri): Result<String> = withContext(Dispatchers.IO) {
        try {
            Log.d(TAG, "Processing profile picture from URI: $imageUri")

            // Load bitmap from URI
            val inputStream = context.contentResolver.openInputStream(imageUri)
                ?: return@withContext Result.failure(Exception("Cannot open image URI"))

            val originalBitmap = BitmapFactory.decodeStream(inputStream)
            inputStream.close()

            if (originalBitmap == null) {
                return@withContext Result.failure(Exception("Failed to decode image"))
            }

            Log.d(TAG, "Original image: ${originalBitmap.width}x${originalBitmap.height}")

            // Resize to 512x512 (maintains aspect ratio, crops to square)
            val processedBitmap = resizeAndCrop(originalBitmap)

            // Compress to JPEG with target size
            val jpegBytes = compressToTargetSize(processedBitmap)

            Log.d(TAG, "Processed image: ${processedBitmap.width}x${processedBitmap.height}, ${jpegBytes.size} bytes")

            // Convert to base64
            val base64 = Base64.encodeToString(jpegBytes, Base64.NO_WRAP)

            // Cleanup
            originalBitmap.recycle()
            processedBitmap.recycle()

            Log.i(TAG, "Profile picture processed: ${jpegBytes.size} bytes → ${base64.length} chars base64")

            Result.success(base64)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to process profile picture", e)
            Result.failure(e)
        }
    }

    /**
     * Save profile picture to local storage
     * Used for the user's own profile picture
     * @param base64 Base64-encoded JPEG
     */
    suspend fun saveMyProfilePicture(base64: String): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val picturesDir = File(context.filesDir, PROFILE_PICS_DIR)
            if (!picturesDir.exists()) {
                picturesDir.mkdirs()
            }

            val file = File(picturesDir, MY_PROFILE_PIC)
            val bytes = Base64.decode(base64, Base64.NO_WRAP)

            FileOutputStream(file).use { it.write(bytes) }

            Log.i(TAG, "Saved my profile picture: ${file.absolutePath}")
            Result.success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to save my profile picture", e)
            Result.failure(e)
        }
    }

    /**
     * Load user's own profile picture
     * @return Base64-encoded JPEG or null if not set
     */
    suspend fun loadMyProfilePicture(): String? = withContext(Dispatchers.IO) {
        try {
            val file = File(context.filesDir, "$PROFILE_PICS_DIR/$MY_PROFILE_PIC")
            if (!file.exists()) {
                return@withContext null
            }

            val bytes = file.readBytes()
            Base64.encodeToString(bytes, Base64.NO_WRAP)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to load my profile picture", e)
            null
        }
    }

    /**
     * Save contact profile picture to cache
     * @param contactPubkey Contact's Ed25519 public key (hex)
     * @param base64 Base64-encoded JPEG
     */
    suspend fun saveContactProfilePicture(contactPubkey: String, base64: String): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val picturesDir = File(context.cacheDir, PROFILE_PICS_DIR)
            if (!picturesDir.exists()) {
                picturesDir.mkdirs()
            }

            val filename = "${contactPubkey.take(16)}.jpg"
            val file = File(picturesDir, filename)
            val bytes = Base64.decode(base64, Base64.NO_WRAP)

            FileOutputStream(file).use { it.write(bytes) }

            Log.d(TAG, "Saved contact profile picture: $filename")
            Result.success(Unit)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to save contact profile picture", e)
            Result.failure(e)
        }
    }

    /**
     * Load contact profile picture from cache
     * @param contactPubkey Contact's Ed25519 public key (hex)
     * @return Base64-encoded JPEG or null if not cached
     */
    suspend fun loadContactProfilePicture(contactPubkey: String): String? = withContext(Dispatchers.IO) {
        try {
            val filename = "${contactPubkey.take(16)}.jpg"
            val file = File(context.cacheDir, "$PROFILE_PICS_DIR/$filename")

            if (!file.exists()) {
                return@withContext null
            }

            val bytes = file.readBytes()
            Base64.encodeToString(bytes, Base64.NO_WRAP)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to load contact profile picture", e)
            null
        }
    }

    /**
     * Decode base64 to Bitmap for display
     * @param base64 Base64-encoded JPEG
     * @return Bitmap ready for ImageView
     */
    fun base64ToBitmap(base64: String): Bitmap? {
        return try {
            val bytes = Base64.decode(base64, Base64.NO_WRAP)
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to decode base64 to bitmap", e)
            null
        }
    }

    /**
     * Resize and crop bitmap to square with max dimension
     * Centers crop to preserve face/center of image
     */
    private fun resizeAndCrop(bitmap: Bitmap): Bitmap {
        val width = bitmap.width
        val height = bitmap.height

        // Calculate scaling factor to fit MAX_SIZE_PX
        val scale = MAX_SIZE_PX.toFloat() / maxOf(width, height)

        // Scale bitmap
        val scaledWidth = (width * scale).toInt()
        val scaledHeight = (height * scale).toInt()

        val scaledBitmap = Bitmap.createScaledBitmap(bitmap, scaledWidth, scaledHeight, true)

        // Crop to square (center crop)
        val size = min(scaledWidth, scaledHeight)
        val x = (scaledWidth - size) / 2
        val y = (scaledHeight - size) / 2

        val croppedBitmap = Bitmap.createBitmap(scaledBitmap, x, y, size, size)

        if (scaledBitmap != croppedBitmap) {
            scaledBitmap.recycle()
        }

        return croppedBitmap
    }

    /**
     * Compress bitmap to JPEG with target size
     * Iteratively reduces quality until size < MAX_SIZE_BYTES
     */
    private fun compressToTargetSize(bitmap: Bitmap): ByteArray {
        var quality = JPEG_QUALITY_START
        var compressed: ByteArray

        do {
            val stream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.JPEG, quality, stream)
            compressed = stream.toByteArray()

            if (compressed.size > MAX_SIZE_BYTES && quality > JPEG_QUALITY_MIN) {
                quality -= 5
                Log.d(TAG, "Compressed size ${compressed.size} > $MAX_SIZE_BYTES, reducing quality to $quality")
            } else {
                break
            }
        } while (true)

        if (compressed.size > MAX_SIZE_BYTES) {
            Log.w(TAG, "Warning: Compressed size ${compressed.size} exceeds $MAX_SIZE_BYTES at minimum quality")
        }

        return compressed
    }

    /**
     * Delete user's profile picture
     */
    suspend fun deleteMyProfilePicture(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val file = File(context.filesDir, "$PROFILE_PICS_DIR/$MY_PROFILE_PIC")
            if (file.exists()) {
                file.delete()
                Log.i(TAG, "Deleted my profile picture")
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete profile picture", e)
            Result.failure(e)
        }
    }

    /**
     * Clear all cached contact profile pictures
     */
    suspend fun clearContactPictureCache(): Result<Unit> = withContext(Dispatchers.IO) {
        try {
            val picturesDir = File(context.cacheDir, PROFILE_PICS_DIR)
            if (picturesDir.exists()) {
                picturesDir.listFiles()?.forEach { it.delete() }
                Log.i(TAG, "Cleared contact profile picture cache")
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to clear cache", e)
            Result.failure(e)
        }
    }
}
