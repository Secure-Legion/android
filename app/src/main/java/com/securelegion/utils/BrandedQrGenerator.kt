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

    private const val QR_BG_COLOR = 0xFF1A1A1A.toInt()      // Dark background
    private const val QR_MODULE_COLOR = 0xFFFFFFFF.toInt()   // White modules
    private const val BADGE_BG_COLOR = 0xFF2A2A2A.toInt()    // Badge background
    private const val BADGE_TEXT_COLOR = 0xFFCCCCCC.toInt()   // Badge text
    private const val ACCENT_COLOR = 0xFF4A90E2.toInt()       // Blue accent
    private const val SUBTLE_TEXT_COLOR = 0xFF666666.toInt()   // Subtle gray text
    private const val WEBSITE_URL = "securelegion.org"

    data class QrOptions(
        val content: String,
        val size: Int = 512,
        val showLogo: Boolean = true,
        val mintText: String? = null,     // e.g. "1/5"
        val expiryText: String? = null,   // e.g. "12h 30m"
        val showWebsite: Boolean = true,
        val cornerRadiusPx: Float = 3f    // Rounded module corners
    )

    /**
     * Generate a branded QR code bitmap.
     * The QR uses error correction level H (30%) so the center logo doesn't break scanning.
     */
    fun generate(context: Context, options: QrOptions): Bitmap? {
        return try {
            // --- 1. Generate QR bit matrix with high error correction ---
            val hints = mapOf(
                EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.H,
                EncodeHintType.MARGIN to 2
            )
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(options.content, BarcodeFormat.QR_CODE, options.size, options.size, hints)
            val matrixWidth = bitMatrix.width
            val matrixHeight = bitMatrix.height

            // --- 2. Calculate layout dimensions ---
            // Extra space below QR for footer text
            val footerHeight = if (options.showWebsite || options.expiryText != null) 36 else 0
            val totalHeight = matrixHeight + footerHeight

            val bitmap = Bitmap.createBitmap(matrixWidth, totalHeight, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)

            // --- 3. Fill dark background ---
            canvas.drawColor(QR_BG_COLOR)

            // --- 4. Draw rounded QR modules ---
            val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = QR_MODULE_COLOR
                style = Paint.Style.FILL
            }
            val moduleWidth = matrixWidth.toFloat() / bitMatrix.width
            val moduleHeight = matrixHeight.toFloat() / bitMatrix.height
            val radius = options.cornerRadiusPx

            for (x in 0 until bitMatrix.width) {
                for (y in 0 until bitMatrix.height) {
                    if (bitMatrix[x, y]) {
                        val left = x * moduleWidth
                        val top = y * moduleHeight
                        val rect = RectF(left, top, left + moduleWidth, top + moduleHeight)
                        canvas.drawRoundRect(rect, radius, radius, paint)
                    }
                }
            }

            // --- 5. Draw finder pattern accents (the three corner squares) ---
            drawFinderPatterns(canvas, bitMatrix, matrixWidth, matrixHeight, moduleWidth, moduleHeight)

            // --- 6. Overlay center logo ---
            if (options.showLogo) {
                drawCenterLogo(context, canvas, matrixWidth, matrixHeight)
            }

            // --- 7. Draw mint badge (top-right) ---
            if (options.mintText != null) {
                drawMintBadge(canvas, matrixWidth, options.mintText)
            }

            // --- 8. Draw footer (website + expiry) ---
            if (footerHeight > 0) {
                drawFooter(canvas, matrixWidth, matrixHeight, totalHeight, options)
            }

            bitmap
        } catch (e: Exception) {
            android.util.Log.e("BrandedQrGenerator", "Failed to generate branded QR", e)
            null
        }
    }

    /**
     * Redraw the three finder patterns (corner squares) with accent color and rounded outer.
     */
    private fun drawFinderPatterns(
        canvas: Canvas, bitMatrix: com.google.zxing.common.BitMatrix,
        canvasWidth: Int, canvasHeight: Int,
        moduleW: Float, moduleH: Float
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
            val clearPaint = Paint().apply { color = QR_BG_COLOR; style = Paint.Style.FILL }
            canvas.drawRect(
                fx * moduleW, fy * moduleH,
                (fx + finderSize) * moduleW, (fy + finderSize) * moduleH,
                clearPaint
            )

            // Outer ring (7x7) — accent color, rounded
            val outerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = ACCENT_COLOR
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

            // Inner square (3x3 centered) — solid accent
            val innerPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = ACCENT_COLOR
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
    private fun drawCenterLogo(context: Context, canvas: Canvas, canvasWidth: Int, canvasHeight: Int) {
        val logoSize = (canvasWidth * 0.28f).toInt() // 28% of QR width — large and prominent
        val clearRadius = logoSize * 0.58f

        val cx = canvasWidth / 2f
        val cy = canvasHeight / 2f

        // Clear QR modules behind the logo area (dark square, no circle border)
        val clearPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = QR_BG_COLOR
            style = Paint.Style.FILL
        }
        canvas.drawCircle(cx, cy, clearRadius, clearPaint)

        // Draw the shield drawable in white
        val drawable: Drawable? = ContextCompat.getDrawable(context, R.drawable.ic_shield)
        if (drawable != null) {
            drawable.setTint(QR_MODULE_COLOR)
            val left = (cx - logoSize / 2f).toInt()
            val top = (cy - logoSize / 2f).toInt()
            drawable.setBounds(left, top, left + logoSize, top + logoSize)
            drawable.draw(canvas)

            // Draw diagonal cut through the shield (matches app launcher icon)
            // Line runs from bottom-left to top-right of the shield bounds
            val cutPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
                color = QR_BG_COLOR
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
    private fun drawMintBadge(canvas: Canvas, canvasWidth: Int, mintText: String) {
        val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = BADGE_TEXT_COLOR
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
            color = BADGE_BG_COLOR
            style = Paint.Style.FILL
        }
        canvas.drawRoundRect(badgeRect, badgeHeight / 2f, badgeHeight / 2f, bgPaint)

        // Badge border
        val borderPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = ACCENT_COLOR
            style = Paint.Style.STROKE
            strokeWidth = 1.5f
        }
        canvas.drawRoundRect(badgeRect, badgeHeight / 2f, badgeHeight / 2f, borderPaint)

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
