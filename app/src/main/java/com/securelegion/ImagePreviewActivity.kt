package com.securelegion

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import com.securelegion.utils.GlassDialog
import com.securelegion.utils.ThemedToast
import com.yalantis.ucrop.UCrop
import ja.burhanrashid52.photoeditor.PhotoEditor
import ja.burhanrashid52.photoeditor.PhotoEditorView
import ja.burhanrashid52.photoeditor.SaveFileResult
import ja.burhanrashid52.photoeditor.SaveSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class ImagePreviewActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "ImagePreview"
        private const val EXTRA_IMAGE_URI = "image_uri"
        const val RESULT_IMAGE_URI = "result_image_uri"

        fun createIntent(context: Context, imageUri: Uri): Intent {
            return Intent(context, ImagePreviewActivity::class.java).apply {
                putExtra(EXTRA_IMAGE_URI, imageUri.toString())
            }
        }
    }

    private lateinit var photoEditorView: PhotoEditorView
    private lateinit var photoEditor: PhotoEditor
    private lateinit var btnUndo: ImageView
    private lateinit var btnRedo: ImageView
    private var currentImageUri: Uri? = null
    private var isDrawMode = false
    private var currentBrushColor = Color.RED

    // UCrop result handler
    private val cropLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val resultUri = UCrop.getOutput(result.data ?: return@registerForActivityResult)
            if (resultUri != null) {
                currentImageUri = resultUri
                loadImageIntoEditor(resultUri)
            }
        } else if (result.resultCode == UCrop.RESULT_ERROR) {
            val error = UCrop.getError(result.data ?: return@registerForActivityResult)
            Log.e(TAG, "UCrop error: ${error?.message}", error)
            ThemedToast.show(this, "Crop failed")
        }
    }

    private val brushColors = intArrayOf(
        Color.WHITE,
        Color.RED,
        Color.parseColor("#FF6B00"),
        Color.YELLOW,
        Color.parseColor("#00E676"),
        Color.parseColor("#1E90FF"),
        Color.parseColor("#AA00FF"),
        Color.parseColor("#FF4081"),
        Color.BLACK
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.TRANSPARENT
        window.navigationBarColor = Color.BLACK

        setContentView(R.layout.activity_image_preview)

        photoEditorView = findViewById(R.id.photoEditorView)
        btnUndo = findViewById(R.id.btnUndo)
        btnRedo = findViewById(R.id.btnRedo)

        // Apply system bar insets to top bar and bottom bar
        val topBar = findViewById<View>(R.id.topBar)
        val bottomBar = findViewById<View>(R.id.bottomBar)
        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(
            findViewById(android.R.id.content)
        ) { _, windowInsets ->
            val insets = windowInsets.getInsets(
                androidx.core.view.WindowInsetsCompat.Type.systemBars()
                    or androidx.core.view.WindowInsetsCompat.Type.displayCutout()
            )
            topBar.setPadding(topBar.paddingLeft, insets.top, topBar.paddingRight, topBar.paddingBottom)
            bottomBar.setPadding(bottomBar.paddingLeft, bottomBar.paddingTop, bottomBar.paddingRight, insets.bottom)
            windowInsets
        }

        photoEditor = PhotoEditor.Builder(this, photoEditorView)
            .setPinchTextScalable(true)
            .build()

        val uriString = intent.getStringExtra(EXTRA_IMAGE_URI)
        if (uriString == null) {
            Log.e(TAG, "No image URI provided")
            finish()
            return
        }
        currentImageUri = Uri.parse(uriString)
        loadImageIntoEditor(currentImageUri!!)

        setupToolbar()
        setupColorPicker()
        updateUndoRedoVisibility()
    }

    private fun loadImageIntoEditor(uri: Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val bitmap = BitmapFactory.decodeStream(inputStream)
            inputStream?.close()
            if (bitmap != null) {
                photoEditorView.source.setImageBitmap(bitmap)
            } else {
                Log.e(TAG, "Failed to decode image")
                ThemedToast.show(this, "Failed to load image")
                finish()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error loading image", e)
            ThemedToast.show(this, "Failed to load image")
            finish()
        }
    }

    private fun setupToolbar() {
        findViewById<ImageView>(R.id.btnClose).setOnClickListener {
            setResult(RESULT_CANCELED)
            finish()
        }

        btnUndo.setOnClickListener {
            val undone = photoEditor.undo()
            Log.d(TAG, "Undo result: $undone")
            updateUndoRedoVisibility()
        }

        btnRedo.setOnClickListener {
            val redone = photoEditor.redo()
            Log.d(TAG, "Redo result: $redone")
            updateUndoRedoVisibility()
        }

        findViewById<FrameLayout>(R.id.btnDraw).setOnClickListener {
            toggleDrawMode()
        }

        findViewById<FrameLayout>(R.id.btnCrop).setOnClickListener {
            launchCrop()
        }

        findViewById<FrameLayout>(R.id.btnText).setOnClickListener {
            showAddTextDialog()
        }

        findViewById<FrameLayout>(R.id.btnSend).setOnClickListener {
            saveAndSend()
        }
    }

    private fun updateUndoRedoVisibility() {
        // Always show undo/redo in draw mode; otherwise show only if there are edits
        if (isDrawMode) {
            btnUndo.visibility = View.VISIBLE
            btnRedo.visibility = View.VISIBLE
        } else {
            btnUndo.visibility = View.GONE
            btnRedo.visibility = View.GONE
        }
    }

    private fun toggleDrawMode() {
        isDrawMode = !isDrawMode
        val btnDraw = findViewById<FrameLayout>(R.id.btnDraw)
        val colorStrip = findViewById<HorizontalScrollView>(R.id.colorPickerStrip)

        if (isDrawMode) {
            photoEditor.setBrushDrawingMode(true)
            photoEditor.brushColor = currentBrushColor
            photoEditor.brushSize = 8f
            btnDraw.setBackgroundResource(R.drawable.bg_tool_button_active)
            colorStrip.visibility = View.VISIBLE
        } else {
            photoEditor.setBrushDrawingMode(false)
            btnDraw.setBackgroundResource(R.drawable.bg_tool_button)
            colorStrip.visibility = View.GONE
        }
        updateUndoRedoVisibility()
    }

    private fun setupColorPicker() {
        val container = findViewById<LinearLayout>(R.id.colorPickerContainer)
        val dotSize = (32 * resources.displayMetrics.density).toInt()
        val margin = (6 * resources.displayMetrics.density).toInt()

        for (color in brushColors) {
            val dot = View(this).apply {
                layoutParams = LinearLayout.LayoutParams(dotSize, dotSize).apply {
                    marginEnd = margin
                }
                background = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(color)
                    if (color == Color.BLACK || color == Color.WHITE) {
                        setStroke(
                            (1.5f * resources.displayMetrics.density).toInt(),
                            if (color == Color.BLACK) Color.GRAY else Color.DKGRAY
                        )
                    }
                }
                setOnClickListener {
                    currentBrushColor = color
                    photoEditor.brushColor = color
                    updateColorSelection(container, this)
                }
            }
            container.addView(dot)
        }

        // Select red by default (index 1)
        if (container.childCount > 1) {
            updateColorSelection(container, container.getChildAt(1))
        }
    }

    private fun updateColorSelection(container: LinearLayout, selectedView: View) {
        val dotSize = (32 * resources.displayMetrics.density).toInt()
        val selectedSize = (38 * resources.displayMetrics.density).toInt()
        for (i in 0 until container.childCount) {
            val child = container.getChildAt(i)
            val params = child.layoutParams as LinearLayout.LayoutParams
            if (child == selectedView) {
                params.width = selectedSize
                params.height = selectedSize
            } else {
                params.width = dotSize
                params.height = dotSize
            }
            child.layoutParams = params
        }
    }

    private fun launchCrop() {
        // Exit draw mode if active
        if (isDrawMode) toggleDrawMode()

        lifecycleScope.launch {
            try {
                val tempFile = withContext(Dispatchers.IO) {
                    saveBitmapToTemp("crop_input")
                }
                if (tempFile != null && tempFile.exists() && tempFile.length() > 0) {
                    val sourceUri = Uri.fromFile(tempFile)
                    val destFile = File(File(cacheDir, "images").apply { mkdirs() },
                        "cropped_${System.currentTimeMillis()}.jpg")
                    val destUri = Uri.fromFile(destFile)

                    Log.d(TAG, "Launching UCrop: source=${tempFile.absolutePath} (${tempFile.length()} bytes)")

                    val uCropIntent = UCrop.of(sourceUri, destUri)
                        .withMaxResultSize(1920, 1920)
                        .withOptions(UCrop.Options().apply {
                            setToolbarColor(Color.BLACK)
                            setStatusBarLight(false)
                            setActiveControlsWidgetColor(Color.parseColor("#1E90FF"))
                            setToolbarWidgetColor(Color.WHITE)
                            setRootViewBackgroundColor(Color.BLACK)
                            setCompressionQuality(95)
                            setFreeStyleCropEnabled(true)
                        })
                        .getIntent(this@ImagePreviewActivity)

                    cropLauncher.launch(uCropIntent)
                } else {
                    Log.e(TAG, "saveBitmapToTemp returned null or empty file")
                    ThemedToast.show(this@ImagePreviewActivity, "Failed to prepare image for crop")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to launch crop", e)
                ThemedToast.show(this@ImagePreviewActivity, "Failed to start crop")
            }
        }
    }

    private fun showAddTextDialog() {
        // Exit draw mode if active
        if (isDrawMode) toggleDrawMode()

        val input = EditText(this).apply {
            hint = "Type text..."
            setTextColor(Color.WHITE)
            setHintTextColor(Color.GRAY)
            setBackgroundColor(Color.TRANSPARENT)
            setPadding(48, 24, 48, 24)
        }

        val dialog = GlassDialog.builder(this)
            .setTitle("Add Text")
            .setView(input)
            .setPositiveButton("Add") { _, _ ->
                val text = input.text.toString().trim()
                if (text.isNotEmpty()) {
                    photoEditor.addText(text, currentBrushColor)
                    updateUndoRedoVisibility()
                }
            }
            .setNegativeButton("Cancel", null)
            .create()
        GlassDialog.show(dialog)
    }

    private fun saveAndSend() {
        lifecycleScope.launch {
            try {
                val tempFile = withContext(Dispatchers.IO) {
                    saveBitmapToTemp("edited_image")
                }
                if (tempFile != null && tempFile.exists() && tempFile.length() > 0) {
                    Log.d(TAG, "Saved edited image: ${tempFile.absolutePath}, size: ${tempFile.length()} bytes")
                    val resultIntent = Intent().apply {
                        putExtra(RESULT_IMAGE_URI, tempFile.absolutePath)
                    }
                    setResult(RESULT_OK, resultIntent)
                    finish()
                } else {
                    Log.e(TAG, "Save produced null/empty file: exists=${tempFile?.exists()}, size=${tempFile?.length()}")
                    ThemedToast.show(this@ImagePreviewActivity, "Failed to save image")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to save edited image", e)
                ThemedToast.show(this@ImagePreviewActivity, "Failed to save image")
            }
        }
    }

    private suspend fun saveBitmapToTemp(prefix: String): File? {
        return try {
            val saveSettings = SaveSettings.Builder()
                .setClearViewsEnabled(false)
                .setTransparencyEnabled(false)
                .setCompressQuality(90)
                .build()

            val cacheDir = File(cacheDir, "images").apply { mkdirs() }
            val tempFile = File(cacheDir, "${prefix}_${System.currentTimeMillis()}.jpg")

            val result = photoEditor.saveAsFile(
                tempFile.absolutePath,
                saveSettings
            )
            when (result) {
                is SaveFileResult.Success -> {
                    Log.d(TAG, "PhotoEditor save success: ${tempFile.absolutePath}, size: ${tempFile.length()}")
                    tempFile
                }
                is SaveFileResult.Failure -> {
                    Log.e(TAG, "PhotoEditor saveAsFile failed: ${result.exception.message}")
                    null
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "saveBitmapToTemp failed", e)
            null
        }
    }
}
