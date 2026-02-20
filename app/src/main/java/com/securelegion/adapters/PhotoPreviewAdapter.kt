package com.securelegion.adapters

import android.graphics.BitmapFactory
import android.net.Uri
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PhotoPreviewAdapter(
    private val photos: List<Uri>,
    private val onClick: (Uri) -> Unit
) : RecyclerView.Adapter<PhotoPreviewAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val thumbnail: ImageView = view.findViewById(R.id.photoThumbnail)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_photo_preview, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val uri = photos[position]

        // Load thumbnail asynchronously
        CoroutineScope(Dispatchers.Main).launch {
            val bitmap = withContext(Dispatchers.IO) {
                try {
                    val options = BitmapFactory.Options().apply {
                        inSampleSize = 4 // Load at 1/4 resolution for thumbnails
                    }
                    holder.thumbnail.context.contentResolver.openInputStream(uri)?.use { stream ->
                        BitmapFactory.decodeStream(stream, null, options)
                    }
                } catch (e: Exception) {
                    null
                }
            }
            bitmap?.let { holder.thumbnail.setImageBitmap(it) }
        }

        holder.itemView.setOnClickListener { onClick(uri) }
    }

    override fun getItemCount() = photos.size
}
