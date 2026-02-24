package com.securelegion

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.MotionEvent
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.securelegion.utils.ThemedToast
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class QRScannerActivity : AppCompatActivity() {
    private lateinit var cameraExecutor: ExecutorService
    private var imageAnalyzer: ImageAnalysis? = null
    private var camera: Camera? = null
    private val autoFocusHandler = Handler(Looper.getMainLooper())
    private var autoFocusRunnable: Runnable? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_scanner)

        cameraExecutor = Executors.newSingleThreadExecutor()

        // Check camera permission
        if (allPermissionsGranted()) {
            startCamera()
        } else {
            ActivityCompat.requestPermissions(
                this, arrayOf(Manifest.permission.CAMERA), REQUEST_CODE_PERMISSIONS
            )
        }

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }
    }

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        val previewView = findViewById<PreviewView>(R.id.previewView)

        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            // Preview
            val preview = Preview.Builder()
                .build()
                .also {
                    it.setSurfaceProvider(previewView.surfaceProvider)
                }

            // Image analyzer for QR code scanning
            imageAnalyzer = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also {
                    it.setAnalyzer(cameraExecutor, QRCodeAnalyzer { qrCode ->
                        runOnUiThread {
                            onQRCodeScanned(qrCode)
                        }
                    })
                }

            // Select back camera
            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

            try {
                cameraProvider.unbindAll()
                camera = cameraProvider.bindToLifecycle(
                    this, cameraSelector, preview, imageAnalyzer
                )

                // Tap-to-focus: user touches screen → camera refocuses at that point
                setupTapToFocus(previewView)

                // Periodic auto-refocus every 2s (helps Samsung close-range scanning)
                startPeriodicAutoFocus(previewView)

            } catch (exc: Exception) {
                Log.e(TAG, "Use case binding failed", exc)
            }

        }, ContextCompat.getMainExecutor(this))
    }

    @Suppress("ClickableViewAccessibility")
    private fun setupTapToFocus(previewView: PreviewView) {
        previewView.setOnTouchListener { _, event ->
            if (event.action == MotionEvent.ACTION_DOWN) {
                triggerFocusAt(previewView, event.x, event.y)
            }
            true
        }
    }

    private fun triggerFocusAt(previewView: PreviewView, x: Float, y: Float) {
        val cam = camera ?: return
        val factory = previewView.meteringPointFactory
        val point = factory.createPoint(x, y)
        val action = FocusMeteringAction.Builder(point, FocusMeteringAction.FLAG_AF or FocusMeteringAction.FLAG_AE)
            .setAutoCancelDuration(3, TimeUnit.SECONDS)
            .build()
        cam.cameraControl.startFocusAndMetering(action)
        Log.d(TAG, "Tap-to-focus triggered at ($x, $y)")
    }

    private fun startPeriodicAutoFocus(previewView: PreviewView) {
        autoFocusRunnable = object : Runnable {
            override fun run() {
                val cam = camera ?: return
                // Focus on center of preview
                val centerX = previewView.width / 2f
                val centerY = previewView.height / 2f
                if (centerX > 0 && centerY > 0) {
                    val factory = previewView.meteringPointFactory
                    val centerPoint = factory.createPoint(centerX, centerY)
                    val action = FocusMeteringAction.Builder(centerPoint, FocusMeteringAction.FLAG_AF)
                        .setAutoCancelDuration(2, TimeUnit.SECONDS)
                        .build()
                    cam.cameraControl.startFocusAndMetering(action)
                }
                autoFocusHandler.postDelayed(this, AUTO_FOCUS_INTERVAL_MS)
            }
        }
        autoFocusHandler.postDelayed(autoFocusRunnable!!, AUTO_FOCUS_INTERVAL_MS)
    }

    private fun onQRCodeScanned(qrCode: String) {
        Log.i(TAG, "QR Code scanned: $qrCode")

        // Return the scanned address
        val resultIntent = Intent()
        resultIntent.putExtra("SCANNED_ADDRESS", qrCode)
        setResult(RESULT_OK, resultIntent)
        finish()
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
                startCamera()
            } else {
                ThemedToast.show(this, "Camera permission required to scan QR codes")
                finish()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        autoFocusRunnable?.let { autoFocusHandler.removeCallbacks(it) }
        cameraExecutor.shutdown()
    }

    private class QRCodeAnalyzer(private val onQRCodeScanned: (String) -> Unit) : ImageAnalysis.Analyzer {
        private val scanner = BarcodeScanning.getClient()

        @androidx.camera.core.ExperimentalGetImage
        override fun analyze(imageProxy: ImageProxy) {
            val mediaImage = imageProxy.image
            if (mediaImage != null) {
                val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)

                scanner.process(image)
                    .addOnSuccessListener { barcodes ->
                        for (barcode in barcodes) {
                            when (barcode.valueType) {
                                Barcode.TYPE_TEXT -> {
                                    barcode.rawValue?.let { value ->
                                        onQRCodeScanned(value)
                                    }
                                }
                                Barcode.TYPE_URL -> {
                                    barcode.rawValue?.let { value ->
                                        onQRCodeScanned(value)
                                    }
                                }
                            }
                        }
                    }
                    .addOnFailureListener {
                        Log.e(TAG, "Barcode scanning failed", it)
                    }
                    .addOnCompleteListener {
                        imageProxy.close()
                    }
            } else {
                imageProxy.close()
            }
        }
    }

    companion object {
        private const val TAG = "QRScannerActivity"
        private const val REQUEST_CODE_PERMISSIONS = 10
        private const val AUTO_FOCUS_INTERVAL_MS = 2000L
    }
}
