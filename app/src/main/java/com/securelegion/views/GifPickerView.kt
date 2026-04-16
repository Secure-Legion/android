package com.securelegion.views

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import android.util.AttributeSet
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import pl.droidsonroids.gif.GifDrawable
import pl.droidsonroids.gif.GifImageView

/**
 * GIF picker that pulls animated GIFs from the device's photo library.
 *
 * Replaces the previous bundled-assets approach (Giphy ToS compliance).
 * Returns raw GIF bytes via callback so they can be sent through the
 * existing image pipeline (wire type 0x09) without re-encoding.
 */
class GifPickerView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    private val gifGrid: RecyclerView
    private val placeholder: TextView
    private var onGifSelected: ((ByteArray) -> Unit)? = null

    private val gifUris = mutableListOf<Uri>()

    companion object {
        private const val TAG = "GifPicker"
        private const val MAX_GIF_BYTES = 4_194_304 // 4MB — matches iOS image cap
        const val REQUEST_CODE_MEDIA_PERMISSION = 8817
    }

    init {
        LayoutInflater.from(context).inflate(R.layout.view_gif_picker, this, true)
        gifGrid = findViewById(R.id.gifGrid)
        placeholder = findViewById(R.id.gifPlaceholder)

        gifGrid.layoutManager = GridLayoutManager(context, 3)

        refreshPickerState()
    }

    fun setOnGifSelectedListener(listener: (ByteArray) -> Unit) {
        onGifSelected = listener
    }

    /**
     * Public entry point — call this after the host activity receives a permission
     * grant result, so the picker reloads device GIFs without requiring a reopen.
     */
    fun refreshPickerState() {
        if (hasMediaPermission()) {
            loadDeviceGifs()
        } else {
            gifUris.clear()
            gifGrid.visibility = View.GONE
            placeholder.visibility = View.VISIBLE
            placeholder.text = "Tap to allow GIF access"
            placeholder.setOnClickListener {
                requestMediaPermission()
            }
        }
    }

    private fun hasMediaPermission(): Boolean {
        val permission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.READ_MEDIA_IMAGES
        } else {
            Manifest.permission.READ_EXTERNAL_STORAGE
        }
        return ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }

    private fun requestMediaPermission() {
        val activity = findActivity() ?: return
        val permission = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.READ_MEDIA_IMAGES
        } else {
            Manifest.permission.READ_EXTERNAL_STORAGE
        }
        activity.requestPermissions(arrayOf(permission), REQUEST_CODE_MEDIA_PERMISSION)
    }

    private fun findActivity(): android.app.Activity? {
        var ctx: Context? = context
        while (ctx is android.content.ContextWrapper) {
            if (ctx is android.app.Activity) return ctx
            ctx = ctx.baseContext
        }
        return null
    }

    private fun loadDeviceGifs() {
        try {
            val collection = MediaStore.Images.Media.EXTERNAL_CONTENT_URI
            val projection = arrayOf(
                MediaStore.Images.Media._ID,
                MediaStore.Images.Media.MIME_TYPE
            )
            // Filter for image/gif MIME type
            val selection = "${MediaStore.Images.Media.MIME_TYPE} = ?"
            val selectionArgs = arrayOf("image/gif")
            val sortOrder = "${MediaStore.Images.Media.DATE_ADDED} DESC"

            context.contentResolver.query(
                collection, projection, selection, selectionArgs, sortOrder
            )?.use { cursor ->
                val idCol = cursor.getColumnIndexOrThrow(MediaStore.Images.Media._ID)
                while (cursor.moveToNext()) {
                    val id = cursor.getLong(idCol)
                    val uri = android.content.ContentUris.withAppendedId(collection, id)
                    gifUris.add(uri)
                }
            }
            Log.d(TAG, "Loaded ${gifUris.size} GIFs from device photo library")
        } catch (e: Exception) {
            // Permission denied or no GIFs available
            Log.w(TAG, "Failed to load device GIFs: ${e.message}")
        }

        if (gifUris.isEmpty()) {
            gifGrid.visibility = View.GONE
            placeholder.visibility = View.VISIBLE
            placeholder.text = "No GIFs found on device"
        } else {
            gifGrid.visibility = View.VISIBLE
            placeholder.visibility = View.GONE
            gifGrid.adapter = GifAdapter(gifUris) { uri ->
                loadAndEmitGif(uri)
            }
        }
    }

    private fun loadAndEmitGif(uri: Uri) {
        try {
            val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
                input.readBytes()
            } ?: return

            if (bytes.size > MAX_GIF_BYTES) {
                val mb = bytes.size / 1024 / 1024
                Log.w(TAG, "GIF too large: ${mb}MB (max 4MB)")
                com.securelegion.utils.ThemedToast.show(context, "GIF too large (${mb}MB). Max 4MB.")
                return
            }

            // Validate GIF magic bytes
            if (bytes.size < 4 || bytes[0] != 0x47.toByte() || bytes[1] != 0x49.toByte() ||
                bytes[2] != 0x46.toByte() || bytes[3] != 0x38.toByte()) {
                Log.w(TAG, "File is not a valid GIF")
                return
            }

            onGifSelected?.invoke(bytes)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load GIF bytes from $uri", e)
        }
    }

    private inner class GifAdapter(
        private val gifs: List<Uri>,
        private val onClick: (Uri) -> Unit
    ) : RecyclerView.Adapter<GifAdapter.ViewHolder>() {

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val gifView: GifImageView = view.findViewById(R.id.gifPreview)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_gif, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val uri = gifs[position]
            try {
                // Load preview thumbnail from URI
                val fd = holder.gifView.context.contentResolver.openFileDescriptor(uri, "r")?.fileDescriptor
                if (fd != null) {
                    val drawable = GifDrawable(fd)
                    holder.gifView.setImageDrawable(drawable)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to preview GIF", e)
            }
            holder.itemView.setOnClickListener {
                onClick(uri)
            }
        }

        override fun getItemCount() = gifs.size

        override fun onViewRecycled(holder: ViewHolder) {
            super.onViewRecycled(holder)
            (holder.gifView.drawable as? GifDrawable)?.recycle()
        }
    }
}
