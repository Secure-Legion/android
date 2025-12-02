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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_receive)

        setupBottomNavigation()
        setupCurrencySelector()
        setupWalletSelector()
        loadAddress()

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

            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", address)
            clipboard.setPrimaryClip(clip)

            ThemedToast.show(this, "Address copied to clipboard")
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

    private fun showWalletSelector() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@ReceiveActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@ReceiveActivity, dbPassphrase)
                val wallets = database.walletDao().getAllWallets()

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

                    // Reload address for the new wallet
                    loadAddress()
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
        try {
            val keyManager = KeyManager.getInstance(this)
            val solanaAddress = keyManager.getSolanaAddress()

            // Update address text
            findViewById<TextView>(R.id.depositAddress).text = solanaAddress

            // Generate QR code
            generateQRCode(solanaAddress)

            Log.i("ReceiveActivity", "Loaded Solana address: $solanaAddress")

        } catch (e: Exception) {
            Log.e("ReceiveActivity", "Failed to load Solana address", e)
            ThemedToast.show(this, "Failed to load wallet address")
        }
    }

    private fun loadZcashAddress() {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@ReceiveActivity)
                var zcashAddress = keyManager.getZcashAddress()

                // If no address stored, try to get from ZcashService
                if (zcashAddress == null) {
                    Log.d("ReceiveActivity", "No Zcash address in KeyManager, fetching from service...")
                    val zcashService = ZcashService.getInstance(this@ReceiveActivity)
                    zcashAddress = zcashService.getUnifiedAddress()
                }

                if (zcashAddress != null) {
                    // Update address text
                    findViewById<TextView>(R.id.depositAddress).text = zcashAddress

                    // Generate QR code
                    generateQRCode(zcashAddress)

                    Log.i("ReceiveActivity", "Loaded Zcash address: $zcashAddress")
                } else {
                    findViewById<TextView>(R.id.depositAddress).text = "Zcash wallet not initialized"
                    ThemedToast.show(this@ReceiveActivity, "Zcash wallet not initialized. Please create a new account.")
                    Log.w("ReceiveActivity", "Zcash address not available")
                }

            } catch (e: Exception) {
                Log.e("ReceiveActivity", "Failed to load Zcash address", e)
                ThemedToast.show(this@ReceiveActivity, "Failed to load Zcash address")
            }
        }
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

            findViewById<ImageView>(R.id.qrCodeImage).setImageBitmap(bitmap)
            Log.i("ReceiveActivity", "QR code generated successfully")

        } catch (e: Exception) {
            Log.e("ReceiveActivity", "Failed to generate QR code", e)
            ThemedToast.show(this, "Failed to generate QR code")
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
