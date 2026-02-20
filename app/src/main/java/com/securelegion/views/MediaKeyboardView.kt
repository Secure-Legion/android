package com.securelegion.views

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.ViewFlipper
import androidx.recyclerview.widget.GridLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.securelegion.R
import com.vanniktech.emoji.EmojiTextView

class MediaKeyboardView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : LinearLayout(context, attrs, defStyleAttr) {

    private val tabEmoji: View
    private val tabSticker: View
    private val tabGif: View
    private val tabEmojiIcon: ImageView
    private val tabStickerIcon: ImageView
    private val tabGifIcon: TextView
    private val mediaFlipper: ViewFlipper
    private val emojiGrid: RecyclerView
    private val stickerPicker: StickerPickerView
    private val gifPicker: GifPickerView

    private var onEmojiSelected: ((String) -> Unit)? = null
    private var onStickerSelected: ((String) -> Unit)? = null
    private var onGifSelected: ((String) -> Unit)? = null

    private var currentTab = 0

    init {
        orientation = VERTICAL
        LayoutInflater.from(context).inflate(R.layout.view_media_keyboard, this, true)

        tabEmoji = findViewById(R.id.tabEmoji)
        tabSticker = findViewById(R.id.tabSticker)
        tabGif = findViewById(R.id.tabGif)
        tabEmojiIcon = findViewById(R.id.tabEmojiIcon)
        tabStickerIcon = findViewById(R.id.tabStickerIcon)
        tabGifIcon = findViewById(R.id.tabGifIcon)
        mediaFlipper = findViewById(R.id.mediaFlipper)
        emojiGrid = findViewById(R.id.emojiGrid)
        stickerPicker = findViewById(R.id.stickerPicker)
        gifPicker = findViewById(R.id.gifPicker)

        setupEmojiGrid()
        setupTabs()
    }

    fun setOnEmojiSelectedListener(listener: (String) -> Unit) {
        onEmojiSelected = listener
    }

    fun setOnStickerSelectedListener(listener: (String) -> Unit) {
        onStickerSelected = listener
        stickerPicker.setOnStickerSelectedListener(listener)
    }

    fun setOnGifSelectedListener(listener: (String) -> Unit) {
        onGifSelected = listener
        gifPicker.setOnGifSelectedListener(listener)
    }

    fun selectTab(index: Int) {
        currentTab = index
        mediaFlipper.displayedChild = index
        updateTabHighlights()
    }

    private fun setupTabs() {
        tabEmoji.setOnClickListener { selectTab(0) }
        tabSticker.setOnClickListener { selectTab(1) }
        tabGif.setOnClickListener { selectTab(2) }
        updateTabHighlights()
    }

    private fun updateTabHighlights() {
        val activeColor = context.getColor(android.R.color.white)
        val inactiveColor = 0x99FFFFFF.toInt()

        tabEmojiIcon.setColorFilter(if (currentTab == 0) activeColor else inactiveColor)
        tabStickerIcon.setColorFilter(if (currentTab == 1) activeColor else inactiveColor)
        tabGifIcon.setTextColor(if (currentTab == 2) activeColor else inactiveColor)
    }

    private fun setupEmojiGrid() {
        emojiGrid.layoutManager = GridLayoutManager(context, 8)
        emojiGrid.adapter = EmojiAdapter(EMOJI_LIST) { emoji ->
            onEmojiSelected?.invoke(emoji)
        }
    }

    private inner class EmojiAdapter(
        private val emojis: List<String>,
        private val onClick: (String) -> Unit
    ) : RecyclerView.Adapter<EmojiAdapter.ViewHolder>() {

        inner class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
            val emojiText: EmojiTextView = view.findViewById(R.id.emojiText)
        }

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
            val view = LayoutInflater.from(parent.context)
                .inflate(R.layout.item_emoji, parent, false)
            return ViewHolder(view)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val emoji = emojis[position]
            holder.emojiText.text = emoji
            holder.itemView.setOnClickListener { onClick(emoji) }
        }

        override fun getItemCount() = emojis.size
    }

    companion object {
        // Common emojis organized by frequency of use
        val EMOJI_LIST = listOf(
            // Smileys & People
            "\uD83D\uDE00", "\uD83D\uDE02", "\uD83D\uDE05", "\uD83D\uDE06",
            "\uD83D\uDE09", "\uD83D\uDE0A", "\uD83D\uDE0D", "\uD83D\uDE18",
            "\uD83D\uDE17", "\uD83D\uDE19", "\uD83D\uDE1A", "\uD83D\uDE0B",
            "\uD83D\uDE1C", "\uD83D\uDE1D", "\uD83D\uDE1B", "\uD83E\uDD11",
            "\uD83E\uDD17", "\uD83E\uDD14", "\uD83E\uDD10", "\uD83D\uDE11",
            "\uD83D\uDE36", "\uD83D\uDE44", "\uD83D\uDE0F", "\uD83D\uDE23",
            "\uD83D\uDE25", "\uD83D\uDE2E", "\uD83D\uDE2F", "\uD83D\uDE32",
            "\uD83D\uDE31", "\uD83D\uDE28", "\uD83D\uDE30", "\uD83D\uDE22",
            "\uD83D\uDE2D", "\uD83D\uDE24", "\uD83D\uDE21", "\uD83D\uDE20",
            "\uD83D\uDE08", "\uD83D\uDC7F", "\uD83D\uDC80", "\u2620\uFE0F",
            "\uD83D\uDCA9", "\uD83E\uDD21", "\uD83D\uDC7B", "\uD83D\uDC7D",
            "\uD83E\uDD16", "\uD83D\uDE3A", "\uD83D\uDE38", "\uD83D\uDE39",
            // Gestures
            "\uD83D\uDC4D", "\uD83D\uDC4E", "\u270A", "\uD83D\uDC4A",
            "\uD83E\uDD1B", "\uD83E\uDD1C", "\uD83E\uDD1E", "\u270C\uFE0F",
            "\uD83E\uDD18", "\uD83D\uDC4C", "\uD83D\uDC4B", "\uD83E\uDD1A",
            "\uD83D\uDCAA", "\uD83D\uDE4F", "\u261D\uFE0F", "\uD83D\uDC46",
            "\uD83D\uDC47", "\uD83D\uDC48", "\uD83D\uDC49", "\uD83D\uDD95",
            "\uD83D\uDC4F", "\uD83E\uDD1D", "\u2764\uFE0F", "\uD83D\uDC94",
            "\uD83D\uDC95", "\uD83D\uDC9E", "\uD83D\uDC93", "\uD83D\uDC97",
            // Objects & Symbols
            "\uD83D\uDD25", "\u2B50", "\uD83C\uDF1F", "\u2728",
            "\uD83C\uDF08", "\u2600\uFE0F", "\uD83C\uDF24", "\u26A1",
            "\uD83D\uDCA5", "\uD83C\uDF89", "\uD83C\uDF8A", "\uD83D\uDC8E",
            "\uD83D\uDCB0", "\uD83D\uDCB5", "\uD83D\uDCB8", "\uD83D\uDCB3",
            "\uD83D\uDCF1", "\uD83D\uDCBB", "\uD83C\uDFAE", "\uD83D\uDD12",
            "\uD83D\uDD13", "\uD83D\uDEE1\uFE0F", "\u2705", "\u274C",
            "\u2757", "\u2753", "\uD83D\uDCAF", "\uD83D\uDCA4",
            // Food & Nature
            "\uD83C\uDF55", "\uD83C\uDF54", "\uD83C\uDF7F", "\uD83C\uDF70",
            "\uD83C\uDF7A", "\u2615", "\uD83C\uDF77", "\uD83C\uDF79",
            "\uD83C\uDF31", "\uD83C\uDF3B", "\uD83C\uDF39", "\uD83C\uDF3A",
            "\uD83C\uDF32", "\uD83C\uDF34", "\uD83C\uDF35", "\uD83C\uDF40",
            "\uD83D\uDC36", "\uD83D\uDC31", "\uD83D\uDC2D", "\uD83D\uDC39",
            "\uD83D\uDC30", "\uD83E\uDD8A", "\uD83D\uDC3B", "\uD83D\uDC28",
            "\uD83D\uDC2F", "\uD83E\uDD81", "\uD83D\uDC2E", "\uD83D\uDC37",
            // Activities
            "\u26BD", "\uD83C\uDFC0", "\uD83C\uDFC8", "\u26BE",
            "\uD83C\uDFBE", "\uD83C\uDFB1", "\uD83C\uDFAF", "\uD83C\uDFC6",
            "\uD83C\uDFB5", "\uD83C\uDFB6", "\uD83C\uDFA4", "\uD83C\uDFB8",
            "\uD83D\uDE80", "\u2708\uFE0F", "\uD83D\uDE97", "\uD83D\uDE95"
        )
    }
}
