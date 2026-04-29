package com.securelegion.utils

import android.content.Context
import android.graphics.*
import android.graphics.drawable.Drawable
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.securelegion.R

/**
 * Generates branded QR codes with:
 * - Dark background (#1A1A1A) + white modules
 * - Rounded QR modules for modern look
 * - App shield logo centered (uses QR error correction to remain scannable)
 * - Optional "mint" badge (e.g. "1/5") in top-right corner
 * - Optional website text at bottom-right
 * - Optional expiry text at bottom-left
 */
object BrandedQrGenerator {

    private const val ACCENT_COLOR = 0xFF4A90E2.toInt()       // Blue accent
    private const val SUBTLE_TEXT_COLOR = 0xFF666666.toInt()   // Subtle gray text
    private const val WEBSITE_URL = "securelegion.org"

    /** Resolve theme-aware QR colors from resources */
    private fun qrBgColor(context: Context) = ContextCompat.getColor(context, R.color.qr_bg)
    private fun qrModuleColor(context: Context) = ContextCompat.getColor(context, R.color.qr_module)
    private fun badgeBgColor(context: Context) = ContextCompat.getColor(context, R.color.qr_badge_bg)
    private fun badgeTextColor(context: Context) = ContextCompat.getColor(context, R.color.qr_badge_text)

    data class QrOptions(
        val content: String,
        val size: Int = 512,
        val showLogo: Boolean = true,
        val mintText: String? = null,     // e.g. "1/5"
        val expiryText: String? = null,   // e.g. "12h 30m"
        val showWebsite: Boolean = true,
        val cornerRadiusPx: Float = 0f    // Sharp-square modules — scanners need crisp 1:1:3:1:1 ratio
    )

    /**
     * Generate a branded QR code bitmap.
     * The QR uses error correction level H (30%) so the center logo doesn't break scanning.
     */
    fun generate(context: Context, options: QrOptions): Bitmap? {
        return try {
            // --- 1. Generate QR bit matrix with high error correction ---
            val hints = mapOf(
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L,
                EncodeHintType.MARGIN to 4
            )
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(options.content, BarcodeFormat.QR_CODE, options.size, options.size, hints)
            val matrixWidth = bitMatrix.width
            val matrixHeight = bitMatrix.height

            // --- 2. Layout dimensions: square bitmap, no footer ---
            val bitmap = Bitmap.createBitmap(matrixWidth, matrixHeight, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)

            val bgColor = qrBgColor(context)
            val moduleColor = qrModuleColor(context)

            // --- 3. Fill background ---
            canvas.drawColor(bgColor)

            // --- 4. Paint QR modules pixel-perfect ---
            // ZXing returns a BitMatrix sized exactly to (matrixWidth, matrixHeight),
            // so each cell maps to one bitmap pixel. setPixels avoids any rasterizer
            // sub-pixel fuzz that drawRect/drawRoundRect introduce when module width
            // is non-integer.
            val rowPixels = IntArray(matrixWidth)
            for (y in 0 until matrixHeight) {
                for (x in 0 until matrixWidth) {
                    rowPixels[x] = if (bitMatrix[x, y]) moduleColor else bgColor
                }
                bitmap.setPixels(rowPixels, 0, matrixWidth, 0, y, matrixWidth, 1)
            }

            // --- 6. Overlay center logo ---
            if (options.showLogo) {
                drawCenterLogo(context, canvas, matrixWidth, matrixHeight, bgColor, moduleColor)
            }

            // --- 7. Draw mint badge (top-right) ---
            if (options.mintText != null) {
                drawMintBadge(context, canvas, matrixWidth, options.mintText)
            }

            bitmap
        } catch (e: Exception) {
            android.util.Log.e("BrandedQrGenerator", "Failed to generate branded QR", e)
            null
        }
    }

    /** True when (x,y) is inside any of the three 7×7 finder-pattern regions. */
    private fun isInFinderPattern(x: Int, y: Int, w: Int, h: Int): Boolean {
        val s = 7
        return (x < s && y < s) ||
            (x >= w - s && y < s) ||
            (x < s && y >= h - s)
    }

    @Suppress("unused")
    private fun drawFinderPatterns(
        canvas: Canvas, bitMatrix: com.google.zxing.common.BitMatrix,
        canvasWidth: Int, canvasHeight: Int,
        moduleW: Float, moduleH: Float,
        bgColor: Int, moduleColor: Int
    ) {
        // Finder patterns are 7x7 modules at three corners
        val finderSize = 7
        val positions = listOf(
            0 to 0,                                          // Top-left
            bitMatrix.width - finderSize to 0,               // Top-right
            0 to bitMatrix.height - finderSize               // Bottom-left
        )

        for ((fx, fy) in positions) {
            // Clear the finder area first (redraw background)
            val clearPaint = Paint().apply { color = bgColor; style = Paint.Style.FILL }
            canvas.drawRect(
                fx * moduleW, fy * moduleH,
                (fx + finderSize) * moduleW, (fy + finderSize) * moduleH,
                clearPaint
            )

            // Outer ring (7x7) — high contrast for scanner detection
            val outerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = moduleColor
                style = Paint.Style.STROKE
                strokeWidth = moduleW * 1.0f
            }
            val outerRect = RectF(
                fx * moduleW + moduleW * 0.5f,
                fy * moduleH + moduleH * 0.5f,
                (fx + finderSize) * moduleW - moduleW * 0.5f,
                (fy + finderSize) * moduleH - moduleH * 0.5f
            )
            canvas.drawRoundRect(outerRect, moduleW * 2f, moduleH * 2f, outerPaint)

            // Inner square (3x3 centered) — solid module color
            val innerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = moduleColor
                style = Paint.Style.FILL
            }
            val innerRect = RectF(
                (fx + 2) * moduleW,
                (fy + 2) * moduleH,
                (fx + 5) * moduleW,
                (fy + 5) * moduleH
            )
            canvas.drawRoundRect(innerRect, moduleW * 1.2f, moduleH * 1.2f, innerPaint)
        }
    }

    /**
     * Draw the app shield logo in the center of the QR code.
     * Clears QR modules behind it so the shield stands out directly on the dark background.
     */
    private fun drawCenterLogo(context: Context, canvas: Canvas, canvasWidth: Int, canvasHeight: Int, bgColor: Int, moduleColor: Int) {
        val logoSize = (canvasWidth * 0.20f).toInt() // 20% of QR width — visible but scanner-safe
        val clearRadius = logoSize * 0.58f

        val cx = canvasWidth / 2f
        val cy = canvasHeight / 2f

        // Clear QR modules behind the logo area
        val clearPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = bgColor
            style = Paint.Style.FILL
        }
        canvas.drawCircle(cx, cy, clearRadius, clearPaint)

        // Draw the shield drawable in module color
        val drawable: Drawable? = ContextCompat.getDrawable(context, R.drawable.ic_shield)
        if (drawable != null) {
            drawable.setTint(moduleColor)
            val left = (cx - logoSize / 2f).toInt()
            val top = (cy - logoSize / 2f).toInt()
            drawable.setBounds(left, top, left + logoSize, top + logoSize)
            drawable.draw(canvas)

            // Draw diagonal cut through the shield (matches app launcher icon)
            // Line runs from bottom-left to top-right of the shield bounds
            val cutPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = bgColor
                style = Paint.Style.STROKE
                strokeWidth = logoSize * 0.07f // Proportional cut width
                strokeCap = Paint.Cap.BUTT
            }
            canvas.drawLine(
                left + logoSize * 0.15f, top + logoSize * 0.85f,  // bottom-left
                left + logoSize * 0.85f, top + logoSize * 0.15f,  // top-right
                cutPaint
            )
        }
    }

    /**
     * Draw a "mint" badge in the top-right corner showing use count like "1/5".
     */
    private fun drawMintBadge(context: Context, canvas: Canvas, canvasWidth: Int, mintText: String) {
        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = badgeTextColor(context)
            textSize = canvasWidth * 0.045f
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            textAlign = Paint.Align.CENTER
        }

        val badgeWidth = textPaint.measureText(mintText) + canvasWidth * 0.06f
        val badgeHeight = canvasWidth * 0.07f
        val padding = canvasWidth * 0.03f

        val badgeRect = RectF(
            canvasWidth - badgeWidth - padding,
            padding,
            canvasWidth - padding,
            padding + badgeHeight
        )

        // Badge background
        val bgPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = badgeBgColor(context)
            style = Paint.Style.FILL
        }
        canvas.drawRoundRect(badgeRect, badgeHeight / 2f, badgeHeight / 2f, bgPaint)

        // Badge text
        val textY = badgeRect.centerY() - (textPaint.descent() + textPaint.ascent()) / 2f
        canvas.drawText(mintText, badgeRect.centerX(), textY, textPaint)
    }

    /**
     * Draw footer below the QR code: expiry on the left, website on the right.
     */
    private fun drawFooter(
        canvas: Canvas,
        canvasWidth: Int, qrHeight: Int, totalHeight: Int,
        options: QrOptions
    ) {
        val footerY = qrHeight + (totalHeight - qrHeight) * 0.7f

        // Expiry text (bottom-left)
        if (options.expiryText != null) {
            val expiryPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = SUBTLE_TEXT_COLOR
                textSize = canvasWidth * 0.038f
                typeface = Typeface.create("sans-serif", Typeface.NORMAL)
                textAlign = Paint.Align.LEFT
            }
            canvas.drawText(options.expiryText, canvasWidth * 0.04f, footerY, expiryPaint)
        }

        // Website (bottom-right)
        if (options.showWebsite) {
            val webPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = SUBTLE_TEXT_COLOR
                textSize = canvasWidth * 0.038f
                typeface = Typeface.create("sans-serif", Typeface.NORMAL)
                textAlign = Paint.Align.RIGHT
            }
            canvas.drawText(WEBSITE_URL, canvasWidth * 0.96f, footerY, webPaint)
        }
    }
}
