package com.securelegion

import android.Manifest
import android.annotation.SuppressLint
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageProxy
import androidx.camera.view.CameraController
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.InvertedLuminanceSource
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.securelegion.utils.ThemedToast
import java.util.EnumMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class QRScannerActivity : AppCompatActivity() {
    private lateinit var previewView: PreviewView
    private lateinit var cameraController: LifecycleCameraController
    private lateinit var analyzerExecutor: ExecutorService
    @Volatile private var fired = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_scanner)
        previewView = findViewById(R.id.previewView)
        analyzerExecutor = Executors.newSingleThreadExecutor()

        cameraController = LifecycleCameraController(this).apply {
            setEnabledUseCases(CameraController.IMAGE_ANALYSIS)
            cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
            isTapToFocusEnabled = true
        }

        cameraController.setImageAnalysisAnalyzer(
            analyzerExecutor,
            QRCodeAnalyzer(QRCodeReader()) { text -> onQRCodeScanned(text) }
        )

        previewView.controller = cameraController

        findViewById<View>(R.id.backButton).setOnClickListener { finish() }

        if (allPermissionsGranted()) {
            cameraController.bindToLifecycle(this)
        } else {
            ActivityCompat.requestPermissions(
                this, arrayOf(Manifest.permission.CAMERA), REQUEST_CODE_PERMISSIONS
            )
        }
    }

    private fun onQRCodeScanned(text: String) {
        if (fired) return
        fired = true
        Log.i(TAG, "QR Code scanned")
        runOnUiThread {
            val intent = Intent().apply { putExtra("SCANNED_ADDRESS", text) }
            setResult(RESULT_OK, intent)
            finish()
        }
    }

    private fun allPermissionsGranted() = arrayOf(Manifest.permission.CAMERA).all {
        ContextCompat.checkSelfPermission(baseContext, it) == PackageManager.PERMISSION_GRANTED
    }

    override fun onRequestPermissionsResult(
        requestCode: Int, permissions: Array<String>, grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_CODE_PERMISSIONS) {
            if (allPermissionsGranted()) {
                cameraController.bindToLifecycle(this)
            } else {
                ThemedToast.show(this, "Camera permission required to scan QR codes")
                finish()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraController.clearImageAnalysisAnalyzer()
        cameraController.unbind()
        analyzerExecutor.shutdown()
    }

    /**
     * QR analyzer: four binarization passes (Hybrid, GlobalHistogram, plus inverted
     * variants for white-on-dark QRs). Handles arbitrary rowStride/pixelStride from
     * the YUV_420_888 Y plane.
     */
    private class QRCodeAnalyzer(
        private val qrCodeReader: QRCodeReader,
        private val onBarcodeScanned: (String) -> Unit,
    ) : androidx.camera.core.ImageAnalysis.Analyzer {

        @SuppressLint("UnsafeOptInUsageError")
        override fun analyze(image: ImageProxy) {
            try {
                val srcW = image.width
                val srcH = image.height
                val yPlane = image.planes[0]
                val rowStride = yPlane.rowStride
                val pixelStride = yPlane.pixelStride
                val buf = yPlane.buffer
                buf.rewind()

                // 1. Tightly-pack Y plane into srcW*srcH (strip stride padding).
                val ySrc = ByteArray(srcW * srcH)
                if (pixelStride == 1 && rowStride == srcW) {
                    buf.get(ySrc, 0, ySrc.size)
                } else {
                    val dup = buf.duplicate()
                    var dst = 0
                    for (row in 0 until srcH) {
                        val rowStart = row * rowStride
                        if (pixelStride == 1) {
                            dup.position(rowStart)
                            dup.get(ySrc, dst, srcW)
                            dst += srcW
                        } else {
                            for (col in 0 until srcW) {
                                ySrc[dst++] = dup.get(rowStart + col * pixelStride)
                            }
                        }
                    }
                }

                // 2. Rotate buffer to match display orientation. CameraX delivers
                //    analysis frames in sensor orientation (typically landscape) —
                //    ZXing's row-major detector is more reliable on upright frames.
                val rotation = image.imageInfo.rotationDegrees
                val (yRot, w, h) = rotateLuminance(ySrc, srcW, srcH, rotation)

                // 3. Center-crop to ~60% of the shorter side so we ignore the dim
                //    overlay edges and any background clutter outside the aim box.
                val side = (minOf(w, h) * 0.6f).toInt().coerceAtLeast(1)
                val left = ((w - side) / 2).coerceAtLeast(0)
                val top = ((h - side) / 2).coerceAtLeast(0)

                val base = PlanarYUVLuminanceSource(yRot, w, h, left, top, side, side, false)
                val hints = EnumMap<DecodeHintType, Any>(DecodeHintType::class.java).apply {
                    put(DecodeHintType.TRY_HARDER, true)
                    put(DecodeHintType.POSSIBLE_FORMATS, listOf(BarcodeFormat.QR_CODE))
                }

                val attempts = listOf(
                    BinaryBitmap(HybridBinarizer(base)),
                    BinaryBitmap(GlobalHistogramBinarizer(base)),
                    BinaryBitmap(HybridBinarizer(InvertedLuminanceSource(base))),
                    BinaryBitmap(GlobalHistogramBinarizer(InvertedLuminanceSource(base))),
                )

                for (bb in attempts) {
                    try {
                        val result = qrCodeReader.decode(bb, hints)
                        onBarcodeScanned(result.text)
                        return
                    } catch (_: NotFoundException) {
                        qrCodeReader.reset()
                    }
                }
            } catch (e: Exception) {
                Log.e("QR", "Analyzer error", e)
            } finally {
                qrCodeReader.reset()
                image.close()
            }
        }

        private fun rotateLuminance(
            src: ByteArray, w: Int, h: Int, degrees: Int
        ): Triple<ByteArray, Int, Int> {
            val deg = ((degrees % 360) + 360) % 360
            return when (deg) {
                0 -> Triple(src, w, h)
                90 -> {
                    val out = ByteArray(src.size)
                    for (yi in 0 until h) {
                        val rowStart = yi * w
                        for (xi in 0 until w) {
                            out[xi * h + (h - 1 - yi)] = src[rowStart + xi]
                        }
                    }
                    Triple(out, h, w)
                }
                180 -> {
                    val out = ByteArray(src.size)
                    val n = src.size
                    for (i in 0 until n) out[n - 1 - i] = src[i]
                    Triple(out, w, h)
                }
                270 -> {
                    val out = ByteArray(src.size)
                    for (yi in 0 until h) {
                        val rowStart = yi * w
                        for (xi in 0 until w) {
                            out[(w - 1 - xi) * h + yi] = src[rowStart + xi]
                        }
                    }
                    Triple(out, h, w)
                }
                else -> Triple(src, w, h)
            }
        }
    }

    companion object {
        private const val TAG = "QRScannerActivity"
        private const val REQUEST_CODE_PERMISSIONS = 10
    }
}
