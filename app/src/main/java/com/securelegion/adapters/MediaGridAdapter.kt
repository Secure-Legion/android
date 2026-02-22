package com.securelegion.adapters

import android.graphics.BitmapFactory
import android.util.Base64
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import java.io.File

class MediaGridAdapter(
    private val mediaItems: List<MediaItem>,
    private val decryptImage: ((ByteArray) -> ByteArray)?,
    private val onItemClick: ((Int) -> Unit)? = null
) : RecyclerView.Adapter<MediaGridAdapter.ViewHolder>() {

    data class MediaItem(
        val attachmentData: String,
        val messageId: String,
        val timestamp: Long
    )

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val mediaImage: ImageView = view.findViewById(R.id.mediaImage)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_media_grid, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = mediaItems[position]

        // Make item square based on column width
        holder.itemView.post {
            val width = holder.itemView.width
            if (width > 0) {
                val params = holder.mediaImage.layoutParams
                params.height = width
                holder.mediaImage.layoutParams = params
            }
        }

        // Load image
        loadImage(holder.mediaImage, item.attachmentData)

        holder.itemView.setOnClickListener {
            onItemClick?.invoke(position)
        }
    }

    override fun getItemCount(): Int = mediaItems.size

    private fun loadImage(imageView: ImageView, imageData: String) {
        try {
            val rawBytes = if (imageData.startsWith("/")) {
                val file = File(imageData)
                if (file.exists()) file.readBytes() else null
            } else {
                Base64.decode(imageData, Base64.DEFAULT)
            }

            if (rawBytes == null) {
                imageView.setImageResource(R.drawable.ic_image_placeholder)
                return
            }

            val imageBytes = if (imageData.endsWith(".enc") && decryptImage != null) {
                try {
                    decryptImage.invoke(rawBytes)
                } catch (e: Exception) {
                    Log.e("MediaGrid", "Failed to decrypt image", e)
                    null
                }
            } else {
                rawBytes
            }

            if (imageBytes == null) {
                imageView.setImageResource(R.drawable.ic_image_placeholder)
                return
            }

            // Decode with downsampling for grid thumbnails
            val options = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size, options)

            // Target 200px thumbnails for grid
            val targetSize = 200
            var sampleSize = 1
            while (options.outWidth / sampleSize > targetSize * 2 ||
                   options.outHeight / sampleSize > targetSize * 2) {
                sampleSize *= 2
            }

            val decodeOptions = BitmapFactory.Options().apply {
                inSampleSize = sampleSize
            }
            val bitmap = BitmapFactory.decodeByteArray(imageBytes, 0, imageBytes.size, decodeOptions)

            if (bitmap != null) {
                imageView.setImageBitmap(bitmap)
            } else {
                imageView.setImageResource(R.drawable.ic_image_placeholder)
            }
        } catch (e: Exception) {
            Log.e("MediaGrid", "Failed to load image", e)
            imageView.setImageResource(R.drawable.ic_image_placeholder)
        }
    }
}
