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
import com.airbnb.lottie.LottieAnimationView
import com.securelegion.R
import org.json.JSONObject

class StickerPickerView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    private val stickerGrid: RecyclerView
    private val categoryChips: LinearLayout
    private var onStickerSelected: ((String) -> Unit)? = null // asset path

    // All stickers grouped by category
    private val categories = mutableMapOf<String, List<StickerItem>>()

    // Currently highlighted category (for active/inactive chip styling that
    // matches the emoji picker). Null until the first chip is built.
    private var selectedCategory: String? = null

    data class StickerItem(
        val assetPath: String,
        val codepoint: String,
        val name: String,
        val tags: List<String>,
        val popularity: Int
    )

    init {
        LayoutInflater.from(context).inflate(R.layout.view_sticker_picker, this, true)
        stickerGrid = findViewById(R.id.stickerGrid)
        categoryChips = findViewById(R.id.categoryChips)

        stickerGrid.layoutManager = GridLayoutManager(context, 5)

        loadCustomStickers()
        loadNotoStickers()
    }

    fun setOnStickerSelectedListener(listener: (String) -> Unit) {
        onStickerSelected = listener
    }

    private fun loadCustomStickers() {
        try {
            val files = context.assets.list("stickers") ?: emptyArray()
            val items = files.filter { it.endsWith(".lottie") || it.endsWith(".json") }
                .map { filename ->
                    val name = filename.substringBeforeLast(".")
                        .replace("_", " ").replace("-", " ")
                    StickerItem(
                        assetPath = "stickers/$filename",
                        codepoint = "",
                        name = name,
                        tags = listOf(name),
                        popularity = 100
                    )
                }
            if (items.isNotEmpty()) {
                categories["Custom"] = items
            }
        } catch (e: Exception) {
            Log.d("StickerPicker", "No custom stickers found")
        }
    }

    private fun loadNotoStickers() {
        try {
            val categoriesJson = context.assets.open("reactions/noto/_categories.json")
                .bufferedReader().use { it.readText() }
            val json = JSONObject(categoriesJson)

            json.keys().forEach { category ->
                val items = mutableListOf<StickerItem>()
                val array = json.getJSONArray(category)
                for (i in 0 until array.length()) {
                    val emoji = array.getJSONObject(i)
                    val codepoint = emoji.getString("codepoint")
                    val name = emoji.getString("name")
                    val popularity = emoji.optInt("popularity", 0)
                    val tags = mutableListOf<String>()
                    val tagsArray = emoji.optJSONArray("tags")
                    if (tagsArray != null) {
                        for (j in 0 until tagsArray.length()) {
                            tags.add(tagsArray.getString(j))
                        }
                    }

                    // Build the asset filename (matches download script output)
                    val tag = if (tags.isNotEmpty()) tags[0].trim(':').replace('-', '_') else name
                    val assetPath = "reactions/noto/${codepoint}_${tag}.json"

                    // Verify asset exists before adding
                    try {
                        context.assets.open(assetPath).close()
                        items.add(StickerItem(assetPath, codepoint, name, tags, popularity))
                    } catch (e: Exception) {
                        // Asset doesn't exist — skip silently
                    }
                }
                if (items.isNotEmpty()) {
                    categories[category] = items.sortedByDescending { it.popularity }
                }
            }

            setupCategoryChips()

            // Show first category by default
            if (categories.isNotEmpty()) {
                showCategory(categories.keys.first())
            }
        } catch (e: Exception) {
            Log.e("StickerPicker", "Failed to load stickers", e)
        }
    }

    private fun setupCategoryChips() {
        categoryChips.removeAllViews()
        if (selectedCategory == null) {
            selectedCategory = categories.keys.firstOrNull()
        }

        // Match the emoji picker's pill styling: dark-gray #1A1A1A inactive,
        // dodger-blue #1E90FF active, white 13sp Poppins Medium text.
        val density = context.resources.displayMetrics.density
        val hPad = (14 * density).toInt()
        val vPad = (4 * density).toInt()
        val marginEnd = (6 * density).toInt()

        categories.keys.forEach { category ->
            val chip = TextView(context).apply {
                text = category.replace(" and ", " & ")
                textSize = 13f
                setPadding(hPad, vPad, hPad, vPad)
                setTextColor(context.getColor(android.R.color.white))
                typeface = androidx.core.content.res.ResourcesCompat.getFont(
                    context, R.font.poppins_medium
                )
                setBackgroundResource(
                    if (category == selectedCategory) R.drawable.category_pill_active_bg
                    else R.drawable.category_pill_inactive_bg
                )
                val params = MarginLayoutParams(
                    LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT
                )
                params.marginEnd = marginEnd
                layoutParams = params
                setOnClickListener { showCategory(category) }
            }
            categoryChips.addView(chip)
        }
    }

    private fun showCategory(category: String) {
        val stickers = categories[category] ?: return
        selectedCategory = category
        refreshChipBackgrounds()
        stickerGrid.adapter = StickerAdapter(stickers) { assetPath ->
            onStickerSelected?.invoke(assetPath)
        }
    }

    /** Update background of every chip to reflect the current `selectedCategory`. */
    private fun refreshChipBackgrounds() {
        val keys = categories.keys.toList()
        for (i in 0 until categoryChips.childCount) {
            val chip = categoryChips.getChildAt(i) as? TextView ?: continue
            val cat = keys.getOrNull(i) ?: continue
            chip.setBackgroundResource(
                if (cat == selectedCategory) R.drawable.category_pill_active_bg
                else R.drawable.category_pill_inactive_bg
            )
        }
    }

    private inner class StickerAdapter(
        private val stickers: List<StickerItem>,
        private val onClick: (String) -> Unit
    ) : RecyclerView.Adapter<StickerAdapter.ViewHolder>() {

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val lottieView: LottieAnimationView = view.findViewById(R.id.stickerLottie)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_sticker, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val sticker = stickers[position]
            holder.lottieView.setAnimation(sticker.assetPath)
            holder.lottieView.playAnimation()
            holder.itemView.setOnClickListener { onClick(sticker.assetPath) }
        }

        override fun getItemCount() = stickers.size

        override fun onViewRecycled(holder: ViewHolder) {
            super.onViewRecycled(holder)
            holder.lottieView.cancelAnimation()
        }
    }
}
