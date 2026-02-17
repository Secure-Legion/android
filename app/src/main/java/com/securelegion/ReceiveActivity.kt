package com.securelegion

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.LinearLayout
import androidx.appcompat.app.AppCompatActivity
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.securelegion.crypto.KeyManager
import com.securelegion.services.ZcashService
import com.securelegion.utils.ThemedToast
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet

class ReceiveActivity : BaseActivity() {
    private var selectedCurrency = "ZEC" // Default to Zcash
    private var showTransparentAddress = false // For Zcash: false = unified, true = transparent
    private var currentQrBitmap: Bitmap? = null
    private var currentAddress: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_receive)

        setupAddressTypeToggle()
        loadCurrentWallet()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        // Copy address button
        findViewById<View>(R.id.copyAddressButton).setOnClickListener {
            // Use the full currentAddress instead of the truncated display text
            if (currentAddress.isEmpty() || currentAddress == "Loading...") {
                ThemedToast.show(this, "No address to copy")
                return@setOnClickListener
            }

            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", currentAddress)
            clipboard.setPrimaryClip(clip)

            ThemedToast.show(this, "Address copied to clipboard")
        }

        // Share QR button
        findViewById<View>(R.id.shareQrButton).setOnClickListener {
            if (currentQrBitmap != null && currentAddress.isNotEmpty() && currentAddress != "Loading...") {
                shareQrCode(currentQrBitmap!!, currentAddress)
            } else {
                ThemedToast.show(this, "No QR code to share")
            }
        }

        // Wallet settings button
        findViewById<View>(R.id.walletSettingsButton).setOnClickListener {
            val intent = Intent(this, WalletSettingsActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }
    }


    private fun setupAddressTypeToggle() {
        val unifiedButton = findViewById<Button>(R.id.unifiedAddressButton)
        val transparentButton = findViewById<Button>(R.id.transparentAddressButton)

        unifiedButton?.setOnClickListener {
            showTransparentAddress = false
            updateAddressTypeButtons()
            loadZcashAddress()
        }

        transparentButton?.setOnClickListener {
            showTransparentAddress = true
            updateAddressTypeButtons()
            loadZcashAddress()
        }
    }

    private fun updateAddressTypeButtons() {
        val unifiedButton = findViewById<Button>(R.id.unifiedAddressButton)
        val transparentButton = findViewById<Button>(R.id.transparentAddressButton)

        if (showTransparentAddress) {
            // Transparent selected
            unifiedButton?.setBackgroundResource(android.R.color.transparent)
            unifiedButton?.setTextColor(getColor(R.color.text_gray))
            transparentButton?.setBackgroundResource(R.drawable.wallet_action_button_bg)
            transparentButton?.setTextColor(getColor(android.R.color.white))
        } else {
            // Unified selected
            unifiedButton?.setBackgroundResource(R.drawable.wallet_action_button_bg)
            unifiedButton?.setTextColor(getColor(android.R.color.white))
            transparentButton?.setBackgroundResource(android.R.color.transparent)
            transparentButton?.setTextColor(getColor(R.color.text_gray))
        }
    }

    private fun loadCurrentWallet() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@ReceiveActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ReceiveActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet - it's hidden (used only for encryption keys)
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    val walletNameText = findViewById<TextView>(R.id.walletNameText)
                    val walletChainIcon = findViewById<ImageView>(R.id.walletChainIcon)

                    if (wallets.isNotEmpty()) {
                        // Get the most recently used wallet
                        val currentWallet = wallets.maxByOrNull { it.lastUsedAt }
                        walletNameText?.text = currentWallet?.name ?: "Wallet"

                        // Detect wallet type and load address
                        if (currentWallet != null) {
                            val isZcash = !currentWallet.zcashUnifiedAddress.isNullOrEmpty() || !currentWallet.zcashAddress.isNullOrEmpty()

                            if (isZcash) {
                                selectedCurrency = "ZEC"
                                walletChainIcon?.setImageResource(R.drawable.ic_zcash)
                                loadZcashAddress()
                            } else {
                                selectedCurrency = "SOL"
                                walletChainIcon?.setImageResource(R.drawable.ic_solana)
                                loadSolanaAddress()
                            }
                        }
                    } else {
                        walletNameText?.text = "No Wallet"
                        findViewById<TextView>(R.id.depositAddress)?.text = "No wallet found"
                    }
                }
            } catch (e: Exception) {
                Log.e("ReceiveActivity", "Failed to load current wallet", e)
            }
        }
    }


    private fun loadSolanaAddress() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@ReceiveActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ReceiveActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    // Hide address type toggle for Solana (only needed for Zcash)
                    hideAddressTypeToggle()
                }

                if (wallets.isEmpty()) {
                    withContext(Dispatchers.Main) {
                        findViewById<TextView>(R.id.depositAddress).text = "No Solana wallet found"
                        ThemedToast.show(this@ReceiveActivity, "No Solana wallet found")
                    }
                    return@launch
                }

                // Get the most recently used wallet
                val currentWallet = wallets.maxByOrNull { it.lastUsedAt }
                val solanaAddress = currentWallet?.solanaAddress

                if (solanaAddress != null) {
                    withContext(Dispatchers.Main) {
                        // Store full address
                        currentAddress = solanaAddress

                        // Update address text with truncated version
                        val shortAddress = if (solanaAddress.length > 16) {
                            "${solanaAddress.take(5)}.....${solanaAddress.takeLast(6)}"
                        } else {
                            solanaAddress
                        }
                        findViewById<TextView>(R.id.depositAddress).text = shortAddress

                        // Generate QR code with full address
                        generateQRCode(solanaAddress)

                        Log.i("ReceiveActivity", "Loaded Solana address")
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        findViewById<TextView>(R.id.depositAddress).text = "No Solana address available"
                        ThemedToast.show(this@ReceiveActivity, "No Solana address available")
                    }
                }

            } catch (e: Exception) {
                Log.e("ReceiveActivity", "Failed to load Solana address", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@ReceiveActivity, "Failed to load wallet address")
                }
            }
        }
    }

    private fun loadZcashAddress() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.d("ReceiveActivity", "Loading Zcash address (showTransparentAddress: $showTransparentAddress)")

                val keyManager = KeyManager.getInstance(this@ReceiveActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ReceiveActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet
                val wallets = allWallets.filter { it.walletId != "main" }

                if (wallets.isEmpty()) {
                    withContext(Dispatchers.Main) {
                        findViewById<TextView>(R.id.depositAddress).text = "No Zcash wallet found"
                        ThemedToast.show(this@ReceiveActivity, "No Zcash wallet found")
                        hideAddressTypeToggle()
                    }
                    return@launch
                }

                // Get the most recently used wallet
                val currentWallet = wallets.maxByOrNull { it.lastUsedAt }

                // Get unified address from wallet entity (use new zcashUnifiedAddress field)
                var unifiedAddress = currentWallet?.zcashUnifiedAddress ?: currentWallet?.zcashAddress ?: keyManager.getZcashAddress()
                Log.d("ReceiveActivity", "Unified address from database (new field): ${currentWallet?.zcashUnifiedAddress}")
                Log.d("ReceiveActivity", "Unified address from database (old field): ${currentWallet?.zcashAddress}")
                Log.d("ReceiveActivity", "Unified address from KeyManager: ${keyManager.getZcashAddress()}")

                if (unifiedAddress == null) {
                    Log.d("ReceiveActivity", "No unified address found, fetching from service...")
                    val zcashService = ZcashService.getInstance(this@ReceiveActivity)
                    unifiedAddress = zcashService.getUnifiedAddress()
                    Log.d("ReceiveActivity", "Unified address from Service: $unifiedAddress")
                }

                // Get transparent address (for exchanges)
                val zcashService = ZcashService.getInstance(this@ReceiveActivity)
                val transparentAddress = zcashService.getTransparentAddress()
                Log.d("ReceiveActivity", "Transparent address from KeyManager: $transparentAddress")

                // Determine which address to display
                val displayAddress = if (showTransparentAddress && transparentAddress != null) {
                    Log.d("ReceiveActivity", "Showing transparent address")
                    transparentAddress
                } else if (unifiedAddress != null) {
                    Log.d("ReceiveActivity", "Showing unified address")
                    unifiedAddress
                } else {
                    Log.w("ReceiveActivity", "No address available")
                    null
                }

                if (displayAddress != null) {
                    withContext(Dispatchers.Main) {
                        // Show address type toggle
                        showAddressTypeToggle()

                        // Store full address
                        currentAddress = displayAddress

                        // Update address text with truncated version
                        val shortAddress = if (displayAddress.length > 16) {
                            "${displayAddress.take(5)}.....${displayAddress.takeLast(6)}"
                        } else {
                            displayAddress
                        }
                        findViewById<TextView>(R.id.depositAddress).text = shortAddress

                        // Generate QR code with full address
                        generateQRCode(displayAddress)

                        Log.i("ReceiveActivity", "Loaded Zcash address (${if (showTransparentAddress) "transparent" else "unified"}): $displayAddress")
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        findViewById<TextView>(R.id.depositAddress).text = "Zcash wallet not initialized"
                        ThemedToast.show(this@ReceiveActivity, "Zcash wallet not initialized")
                        hideAddressTypeToggle()
                        Log.w("ReceiveActivity", "Zcash address not available")
                    }
                }

            } catch (e: Exception) {
                Log.e("ReceiveActivity", "Failed to load Zcash address", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@ReceiveActivity, "Failed to load Zcash address")
                    hideAddressTypeToggle()
                }
            }
        }
    }

    private fun showAddressTypeToggle() {
        findViewById<View>(R.id.addressTypeSelector)?.visibility = View.VISIBLE
        updateAddressTypeButtons()
    }

    private fun hideAddressTypeToggle() {
        findViewById<View>(R.id.addressTypeSelector)?.visibility = View.GONE
    }

    private fun generateQRCode(text: String) {
        try {
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(text, BarcodeFormat.QR_CODE, 512, 512)
            val width = bitMatrix.width
            val height = bitMatrix.height
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)

            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) Color.BLACK else Color.WHITE)
                }
            }

            // Store bitmap and address for sharing
            currentQrBitmap = bitmap
            currentAddress = text

            findViewById<ImageView>(R.id.qrCodeImage).setImageBitmap(bitmap)
            Log.i("ReceiveActivity", "QR code generated successfully")

        } catch (e: Exception) {
            Log.e("ReceiveActivity", "Failed to generate QR code", e)
            ThemedToast.show(this, "Failed to generate QR code")
        }
    }

    private fun shareQrCode(qrBitmap: Bitmap, address: String) {
        try {
            // Save bitmap to cache directory
            val cachePath = java.io.File(cacheDir, "images")
            cachePath.mkdirs()
            val file = java.io.File(cachePath, "qr_code.png")
            val stream = java.io.FileOutputStream(file)
            qrBitmap.compress(Bitmap.CompressFormat.PNG, 100, stream)
            stream.close()

            // Get content URI
            val contentUri = androidx.core.content.FileProvider.getUriForFile(
                this,
                "${applicationContext.packageName}.fileprovider",
                file
            )

            // Determine currency name
            val currencyName = if (selectedCurrency == "ZEC") {
                if (showTransparentAddress) "Zcash (Transparent)" else "Zcash (Unified)"
            } else {
                "Solana"
            }

            // Create share intent
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "image/png"
                putExtra(Intent.EXTRA_STREAM, contentUri)
                putExtra(Intent.EXTRA_TEXT, "$currencyName Address:\n$address")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            startActivity(Intent.createChooser(shareIntent, "Share $currencyName Address"))
        } catch (e: Exception) {
            Log.e("ReceiveActivity", "Failed to share QR code", e)
            ThemedToast.show(this, "Failed to share QR code")
        }
    }
}
