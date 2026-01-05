package com.securelegion.utils

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.MediaStore
import android.util.Base64
import androidx.activity.result.ActivityResultLauncher
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream

/**
 * ImagePicker - Utility for selecting and processing profile photos
 * Supports gallery and camera selection with automatic resizing
 */
object ImagePicker {

    // Max dimensions for profile photos (512x512)
    private const val MAX_SIZE = 512
    // Max file size (256KB)
    private const val MAX_FILE_SIZE_KB = 256

    /**
     * Launch gallery picker
     */
    fun pickFromGallery(launcher: ActivityResultLauncher<Intent>) {
        val intent = Intent(Intent.ACTION_PICK, MediaStore.Images.Media.EXTERNAL_CONTENT_URI)
        intent.type = "image/*"
        launcher.launch(intent)
    }

    /**
     * Launch camera
     */
    fun pickFromCamera(launcher: ActivityResultLauncher<Intent>) {
        val intent = Intent(MediaStore.ACTION_IMAGE_CAPTURE)
        launcher.launch(intent)
    }

    /**
     * Process selected image URI and return Base64-encoded JPEG
     * Returns null if processing fails
     */
    fun processImageUri(context: Context, uri: Uri?): String? {
        if (uri == null) return null

        return try {
            val inputStream = context.contentResolver.openInputStream(uri) ?: return null
            val bitmap = BitmapFactory.decodeStream(inputStream)
            inputStream.close()

            processImageBitmap(bitmap)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Process bitmap from camera and return Base64-encoded JPEG
     * Returns null if processing fails
     */
    fun processImageBitmap(bitmap: Bitmap?): String? {
        if (bitmap == null) return null

        return try {
            // Resize to max dimensions
            val resized = resizeBitmap(bitmap, MAX_SIZE, MAX_SIZE)

            // Compress to JPEG with quality adjustment to meet size limit
            val outputStream = ByteArrayOutputStream()
            var quality = 90
            do {
                outputStream.reset()
                resized.compress(Bitmap.CompressFormat.JPEG, quality, outputStream)
                quality -= 10
            } while (outputStream.size() > MAX_FILE_SIZE_KB * 1024 && quality > 10)

            val bytes = outputStream.toByteArray()
            Base64.encodeToString(bytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Resize bitmap to fit within max dimensions while maintaining aspect ratio
     */
    private fun resizeBitmap(bitmap: Bitmap, maxWidth: Int, maxHeight: Int): Bitmap {
        val width = bitmap.width
        val height = bitmap.height

        if (width <= maxWidth && height <= maxHeight) {
            return bitmap
        }

        val ratio = minOf(maxWidth.toFloat() / width, maxHeight.toFloat() / height)
        val newWidth = (width * ratio).toInt()
        val newHeight = (height * ratio).toInt()

        return Bitmap.createScaledBitmap(bitmap, newWidth, newHeight, true)
    }

    /**
     * Decode Base64 image to Bitmap
     */
    fun decodeBase64ToBitmap(base64: String?): Bitmap? {
        if (base64.isNullOrEmpty()) return null

        return try {
            val bytes = Base64.decode(base64, Base64.NO_WRAP)
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Save bitmap to encrypted file storage
     * Returns file path or null if failed
     */
    fun saveBitmapToFile(context: Context, bitmap: Bitmap, filename: String): String? {
        return try {
            val file = File(context.filesDir, filename)
            val outputStream = FileOutputStream(file)
            bitmap.compress(Bitmap.CompressFormat.JPEG, 90, outputStream)
            outputStream.flush()
            outputStream.close()
            file.absolutePath
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * Load bitmap from file
     */
    fun loadBitmapFromFile(path: String?): Bitmap? {
        if (path.isNullOrEmpty()) return null

        return try {
            BitmapFactory.decodeFile(path)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
