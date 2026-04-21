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
        val ctx = holder.thumbnail.context

        // Load thumbnail asynchronously. Sample size is computed against the actual
        // target ImageView dimensions (preview item is 120dp wide) so we decode just
        // enough pixels — fixes the "blurry thumbnail" you get with a hard-coded
        // inSampleSize = 4, which under-resolved anything larger than ~480px source.
        CoroutineScope(Dispatchers.Main).launch {
            val bitmap = withContext(Dispatchers.IO) {
                try {
                    val targetPx = (240 * ctx.resources.displayMetrics.density).toInt() // ~2x 120dp for sharp scaling

                    // Pass 1: read bounds only
                    val boundsOpts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                    ctx.contentResolver.openInputStream(uri)?.use { stream ->
                        BitmapFactory.decodeStream(stream, null, boundsOpts)
                    }

                    // Compute largest power-of-two sample size that still leaves both dims >= targetPx
                    var sample = 1
                    val maxSrc = maxOf(boundsOpts.outWidth, boundsOpts.outHeight)
                    while (maxSrc / (sample * 2) >= targetPx) sample *= 2

                    val decodeOpts = BitmapFactory.Options().apply { inSampleSize = sample }
                    ctx.contentResolver.openInputStream(uri)?.use { stream ->
                        BitmapFactory.decodeStream(stream, null, decodeOpts)
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
