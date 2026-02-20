package com.securelegion.views

import android.content.Context
import android.util.AttributeSet
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import pl.droidsonroids.gif.GifDrawable
import pl.droidsonroids.gif.GifImageView

class GifPickerView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    private val gifGrid: RecyclerView
    private val placeholder: TextView
    private var onGifSelected: ((String) -> Unit)? = null

    private val gifAssets = mutableListOf<String>()

    init {
        LayoutInflater.from(context).inflate(R.layout.view_gif_picker, this, true)
        gifGrid = findViewById(R.id.gifGrid)
        placeholder = findViewById(R.id.gifPlaceholder)

        gifGrid.layoutManager = GridLayoutManager(context, 3)

        loadGifAssets()
    }

    fun setOnGifSelectedListener(listener: (String) -> Unit) {
        onGifSelected = listener
    }

    private fun loadGifAssets() {
        try {
            val gifs = context.assets.list("gifs") ?: emptyArray()
            gifAssets.addAll(gifs.filter { it.endsWith(".gif") }.map { "gifs/$it" })
        } catch (e: Exception) {
            // No gifs directory yet — that's fine
            Log.d("GifPicker", "No bundled GIFs found")
        }

        if (gifAssets.isEmpty()) {
            gifGrid.visibility = View.GONE
            placeholder.visibility = View.VISIBLE
        } else {
            gifGrid.visibility = View.VISIBLE
            placeholder.visibility = View.GONE
            gifGrid.adapter = GifAdapter(gifAssets) { assetPath ->
                onGifSelected?.invoke(assetPath)
            }
        }
    }

    private inner class GifAdapter(
        private val gifs: List<String>,
        private val onClick: (String) -> Unit
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
            val assetPath = gifs[position]
            try {
                val drawable = GifDrawable(holder.gifView.context.assets, assetPath)
                holder.gifView.setImageDrawable(drawable)
            } catch (e: Exception) {
                // Failed to load GIF — leave placeholder bg
            }
            holder.itemView.setOnClickListener {
                // Send asset path as text code — both devices have the bundled GIF
                onGifSelected?.invoke(assetPath)
            }
        }

        override fun getItemCount() = gifs.size

        override fun onViewRecycled(holder: ViewHolder) {
            super.onViewRecycled(holder)
            (holder.gifView.drawable as? GifDrawable)?.recycle()
        }
    }
}
