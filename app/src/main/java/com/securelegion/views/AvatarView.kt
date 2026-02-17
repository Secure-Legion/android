package com.securelegion.views

import android.content.Context
import android.graphics.*
import android.util.AttributeSet
import android.view.View
import com.google.android.material.color.MaterialColors
import com.securelegion.R
import com.securelegion.utils.ImagePicker
import kotlin.math.min

/**
 * AvatarView - Custom view that displays profile photos or colored initials
 * Automatically generates color from name if no photo is set
 */
class AvatarView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : View(context, attrs, defStyleAttr) {

    private var bitmap: Bitmap? = null
    private var initials: String = "?"
    private var backgroundColor: Int = 0

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.WHITE
        textAlign = Paint.Align.CENTER
        typeface = Typeface.create(Typeface.DEFAULT, Typeface.BOLD)
    }
    private val bitmapPaint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val rectF = RectF()

    /**
     * Set profile photo from Base64 string
     */
    fun setPhotoBase64(base64: String?) {
        bitmap = ImagePicker.decodeBase64ToBitmap(base64)
        invalidate()
    }

    /**
     * Set profile photo from file path
     */
    fun setPhotoPath(path: String?) {
        bitmap = ImagePicker.loadBitmapFromFile(path)
        invalidate()
    }

    /**
     * Set profile photo from Bitmap
     */
    fun setPhotoBitmap(bmp: Bitmap?) {
        bitmap = bmp
        invalidate()
    }

    /**
     * Set name (generates initials and color)
     */
    fun setName(name: String?) {
        if (name.isNullOrEmpty()) {
            initials = "?"
            backgroundColor = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOutlineVariant, Color.GRAY)
        } else {
            initials = generateInitials(name)
            backgroundColor = generateColor(name)
        }
        invalidate()
    }

    /**
     * Clear photo (shows initials only)
     */
    fun clearPhoto() {
        bitmap = null
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)

        val size = min(width, height)
        rectF.set(0f, 0f, size.toFloat(), size.toFloat())

        if (bitmap != null && !bitmap!!.isRecycled) {
            // Draw photo in square
            val shader = BitmapShader(bitmap!!, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP)
            val scale = size.toFloat() / min(bitmap!!.width, bitmap!!.height)
            val matrix = Matrix()
            matrix.setScale(scale, scale)
            shader.setLocalMatrix(matrix)

            bitmapPaint.shader = shader
            canvas.drawRect(rectF, bitmapPaint)
        } else {
            // Draw initials only (transparent background - shows parent background)
            textPaint.textSize = size * 0.4f
            textPaint.color = MaterialColors.getColor(this, com.google.android.material.R.attr.colorOnSurfaceVariant, Color.GRAY)
            val yPos = (height / 2f) - ((textPaint.descent() + textPaint.ascent()) / 2f)
            canvas.drawText(initials, width / 2f, yPos, textPaint)
        }
    }

    /**
     * Generate initials from name (e.g., "John Doe" -> "JD")
     */
    private fun generateInitials(name: String): String {
        val parts = name.trim().split(" ")
        return when {
            parts.isEmpty() -> "?"
            parts.size == 1 -> parts[0].take(1).uppercase()
            else -> "${parts[0].take(1)}${parts.last().take(1)}".uppercase()
        }
    }

    /**
     * Generate consistent color from name
     */
    private fun generateColor(name: String): Int {
        val colors = arrayOf(
            "#E57373", "#F06292", "#BA68C8", "#9575CD",
            "#7986CB", "#64B5F6", "#4FC3F7", "#4DD0E1",
            "#4DB6AC", "#81C784", "#AED581", "#FF8A65",
            "#A1887F", "#90A4AE"
        )

        val hash = name.hashCode()
        val index = (hash and 0x7FFFFFFF) % colors.size
        return Color.parseColor(colors[index])
    }
}
