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

        setupBottomNavigation()
        setupCurrencySelector()
        setupWalletSelector()
        setupAddressTypeToggle()
        loadCurrentWalletName()

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
            val address = findViewById<TextView>(R.id.depositAddress).text.toString()

            if (address.isEmpty() || address == "Loading...") {
                ThemedToast.show(this, "No address to copy")
                return@setOnClickListener
            }

            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", address)
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
    }

    private fun setupCurrencySelector() {
        val currencyDropdown = findViewById<View>(R.id.currencyDropdown)

        currencyDropdown.setOnClickListener {
            // Toggle between SOL and ZEC
            if (selectedCurrency == "SOL") {
                selectCurrency("ZEC")
            } else {
                selectCurrency("SOL")
            }
        }
    }

    private fun setupWalletSelector() {
        val walletNameDropdown = findViewById<View>(R.id.walletNameDropdown)

        walletNameDropdown?.setOnClickListener {
            showWalletSelector()
        }
    }

    private fun setupAddressTypeToggle() {
        val unifiedButton = findViewById<Button>(R.id.unifiedAddressButton)
        val transparentButton = findViewById<Button>(R.id.transparentAddressButton)
        val addressTypeLabel = findViewById<TextView>(R.id.addressTypeLabel)

        unifiedButton?.setOnClickListener {
            showTransparentAddress = false
            updateAddressTypeButtons()
            addressTypeLabel?.text = "For private SecureLegion transfers"
            loadAddress()
        }

        transparentButton?.setOnClickListener {
            showTransparentAddress = true
            updateAddressTypeButtons()
            addressTypeLabel?.text = "For Kraken, Coinbase, and other exchanges"
            loadAddress()
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

    private fun loadCurrentWalletName() {
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
                    if (wallets.isNotEmpty()) {
                        // Get the most recently used wallet
                        val currentWallet = wallets.maxByOrNull { it.lastUsedAt }
                        walletNameText?.text = currentWallet?.name ?: "Wallet"

                        // Detect wallet type and update currency selector
                        if (currentWallet != null) {
                            val currency = if (!currentWallet.zcashUnifiedAddress.isNullOrEmpty() || !currentWallet.zcashAddress.isNullOrEmpty()) {
                                "ZEC"
                            } else {
                                "SOL"
                            }
                            selectCurrency(currency)
                        }
                    } else {
                        walletNameText?.text = "No Wallet"
                    }
                }
            } catch (e: Exception) {
                Log.e("ReceiveActivity", "Failed to load current wallet name", e)
            }
        }
    }

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@ReceiveActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ReceiveActivity, dbPassphrase)
                val allWallets = database.walletDao().getAllWallets()

                // Filter out "main" wallet - it's hidden (used only for encryption keys)
                val wallets = allWallets.filter { it.walletId != "main" }

                withContext(Dispatchers.Main) {
                    if (wallets.isEmpty()) {
                        ThemedToast.show(this@ReceiveActivity, "No wallets found")
                        return@withContext
                    }

                    // Create bottom sheet dialog
                    val bottomSheet = BottomSheetDialog(this@ReceiveActivity)
                    val view = layoutInflater.inflate(R.layout.bottom_sheet_wallet_selector, null)

                    // Set minimum height on the view itself
                    val displayMetrics = resources.displayMetrics
                    val screenHeight = displayMetrics.heightPixels
                    val desiredHeight = (screenHeight * 0.6).toInt()
                    view.minimumHeight = desiredHeight

                    bottomSheet.setContentView(view)

                    // Configure bottom sheet behavior
                    bottomSheet.behavior.isDraggable = true
                    bottomSheet.behavior.isFitToContents = true
                    bottomSheet.behavior.skipCollapsed = true

                    // Make all backgrounds transparent
                    bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
                    bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

                    // Remove the white background box
                    view.post {
                        val parentView = view.parent as? View
                        parentView?.setBackgroundResource(android.R.color.transparent)
                    }

                    // Get container for wallet list
                    val walletListContainer = view.findViewById<LinearLayout>(R.id.walletListContainer)

                    // Add each wallet to the list
                    for (wallet in wallets) {
                        val walletItemView = layoutInflater.inflate(R.layout.item_wallet_selector, walletListContainer, false)

                        val walletName = walletItemView.findViewById<TextView>(R.id.walletName)
                        val walletBalance = walletItemView.findViewById<TextView>(R.id.walletBalance)
                        val settingsBtn = walletItemView.findViewById<View>(R.id.walletSettingsBtn)

                        walletName.text = wallet.name
                        walletBalance.text = "Loading..."

                        // Click on wallet item to switch
                        walletItemView.setOnClickListener {
                            switchToWallet(wallet)
                            bottomSheet.dismiss()
                        }

                        // Click on settings button
                        settingsBtn.setOnClickListener {
                            val intent = Intent(this@ReceiveActivity, WalletSettingsActivity::class.java)
                            intent.putExtra("WALLET_ID", wallet.walletId)
                            intent.putExtra("WALLET_NAME", wallet.name)
                            intent.putExtra("IS_MAIN_WALLET", wallet.walletId == "main")
                            startActivity(intent)
                            bottomSheet.dismiss()
                        }

                        walletListContainer.addView(walletItemView)
                    }

                    bottomSheet.show()
                }
            } catch (e: Exception) {
                Log.e("ReceiveActivity", "Failed to load wallets", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@ReceiveActivity, "Failed to load wallets")
                }
            }
        }
    }

    private fun switchToWallet(wallet: Wallet) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("ReceiveActivity", "Switching to wallet: ${wallet.name}")

                // Update last used timestamp
                val keyManager = KeyManager.getInstance(this@ReceiveActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ReceiveActivity, dbPassphrase)
                database.walletDao().updateLastUsed(wallet.walletId, System.currentTimeMillis())

                withContext(Dispatchers.Main) {
                    // Update wallet name
                    val walletNameText = findViewById<TextView>(R.id.walletNameText)
                    walletNameText?.text = wallet.name

                    // Detect wallet type and update currency selector
                    val currency = if (!wallet.zcashUnifiedAddress.isNullOrEmpty() || !wallet.zcashAddress.isNullOrEmpty()) {
                        "ZEC"
                    } else {
                        "SOL"
                    }
                    selectCurrency(currency)
                }
            } catch (e: Exception) {
                Log.e("ReceiveActivity", "Failed to switch wallet", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@ReceiveActivity, "Failed to switch wallet")
                }
            }
        }
    }

    private fun selectCurrency(currency: String) {
        selectedCurrency = currency

        val selectedIcon = findViewById<ImageView>(R.id.selectedCurrencyIcon)
        val selectedSymbol = findViewById<TextView>(R.id.selectedCurrencySymbol)
        val selectedName = findViewById<TextView>(R.id.selectedCurrencyName)

        when (currency) {
            "SOL" -> {
                // Update selected currency display
                selectedIcon.setImageResource(R.drawable.ic_solana)
                selectedSymbol.text = "SOL"
                selectedName.text = "Solana"

                Log.d("ReceiveActivity", "Selected currency: Solana")
            }
            "ZEC" -> {
                // Update selected currency display
                selectedIcon.setImageResource(R.drawable.ic_zcash)
                selectedSymbol.text = "ZEC"
                selectedName.text = "Zcash"

                Log.d("ReceiveActivity", "Selected currency: Zcash")
            }
        }

        // Load the appropriate address
        loadAddress()
    }

    private fun loadAddress() {
        when (selectedCurrency) {
            "SOL" -> loadSolanaAddress()
            "ZEC" -> loadZcashAddress()
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
                        // Update address text
                        findViewById<TextView>(R.id.depositAddress).text = solanaAddress

                        // Update short address
                        val shortAddress = if (solanaAddress.length > 16) {
                            "${solanaAddress.take(5)}...${solanaAddress.takeLast(6)}"
                        } else {
                            solanaAddress
                        }
                        findViewById<TextView>(R.id.walletAddressShort)?.text = shortAddress

                        // Generate QR code
                        generateQRCode(solanaAddress)

                        Log.i("ReceiveActivity", "Loaded Solana address: $solanaAddress")
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

                // Show debug toast
                withContext(Dispatchers.Main) {
                    if (transparentAddress == null) {
                        ThemedToast.show(this@ReceiveActivity, "DEBUG: No transparent address found! It was not generated.")
                    } else {
                        ThemedToast.show(this@ReceiveActivity, "DEBUG: Found transparent address: ${transparentAddress.take(10)}...")
                    }
                }

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

                        // Update address text
                        findViewById<TextView>(R.id.depositAddress).text = displayAddress

                        // Update short address
                        val shortAddress = if (displayAddress.length > 16) {
                            "${displayAddress.take(5)}...${displayAddress.takeLast(6)}"
                        } else {
                            displayAddress
                        }
                        findViewById<TextView>(R.id.walletAddressShort)?.text = shortAddress

                        // Generate QR code
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
        findViewById<TextView>(R.id.addressTypeLabel)?.visibility = View.VISIBLE
        updateAddressTypeButtons()
    }

    private fun hideAddressTypeToggle() {
        findViewById<View>(R.id.addressTypeSelector)?.visibility = View.GONE
        findViewById<TextView>(R.id.addressTypeLabel)?.visibility = View.GONE
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

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }
    }
}
