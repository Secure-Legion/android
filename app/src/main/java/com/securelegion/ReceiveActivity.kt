package com.securelegion

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.utils.BrandedQrGenerator
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

/** Shows the active Solana wallet address and its shareable QR code. */
class ReceiveActivity : BaseActivity() {

    private var currentQrBitmap: Bitmap? = null
    private var currentAddress = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_receive)
        loadCurrentWallet()

        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }
        findViewById<View>(R.id.copyAddressButton).setOnClickListener {
            if (currentAddress.isBlank()) {
                ThemedToast.show(this, "No address to copy")
                return@setOnClickListener
            }
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("Solana Address", currentAddress))
            ThemedToast.show(this, "Address copied to clipboard")
        }
        findViewById<View>(R.id.shareQrButton).setOnClickListener {
            val qr = currentQrBitmap
            if (qr == null || currentAddress.isBlank()) {
                ThemedToast.show(this, "No QR code to share")
            } else {
                shareQrCode(qr, currentAddress)
            }
        }
        findViewById<View>(R.id.walletSettingsButton).setOnClickListener {
            startActivity(Intent(this, WalletSettingsActivity::class.java))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }
    }

    private fun loadCurrentWallet() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@ReceiveActivity)
                val database = SecureLegionDatabase.getInstance(
                    this@ReceiveActivity,
                    keyManager.getDatabasePassphrase()
                )
                val wallet = database.walletDao().getAllWallets()
                    .asSequence()
                    .filter { it.walletId != "main" && it.solanaAddress.isNotBlank() }
                    .maxByOrNull { it.lastUsedAt }

                withContext(Dispatchers.Main) {
                    if (wallet == null) {
                        findViewById<TextView>(R.id.walletNameText).text = "No Wallet"
                        findViewById<TextView>(R.id.depositAddress).text = "No Solana wallet found"
                        return@withContext
                    }
                    findViewById<TextView>(R.id.walletNameText).text = wallet.name
                    findViewById<ImageView>(R.id.walletChainIcon).setImageResource(R.drawable.ic_solana)
                    displayAddress(wallet.solanaAddress)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load Solana receive address", e)
                withContext(Dispatchers.Main) {
                    ThemedToast.show(this@ReceiveActivity, "Failed to load wallet address")
                }
            }
        }
    }

    private fun displayAddress(address: String) {
        if (address.isBlank()) {
            findViewById<TextView>(R.id.depositAddress).text = "No Solana address available"
            return
        }
        currentAddress = address
        findViewById<TextView>(R.id.depositAddress).text =
            if (address.length > 16) address.take(5) + "....." + address.takeLast(6) else address
        generateQrCode(address)
    }

    private fun generateQrCode(address: String) {
        try {
            val bitmap = BrandedQrGenerator.generate(
                this,
                BrandedQrGenerator.QrOptions(
                    content = address,
                    size = 512,
                    showLogo = false,
                    mintText = null,
                    expiryText = null,
                    showWebsite = true
                )
            )
            currentQrBitmap = bitmap
            findViewById<ImageView>(R.id.qrCodeImage).apply {
                setImageBitmap(bitmap)
                (drawable as? android.graphics.drawable.BitmapDrawable)?.isFilterBitmap = false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to generate QR code", e)
            ThemedToast.show(this, "Failed to generate QR code")
        }
    }

    private fun shareQrCode(qrBitmap: Bitmap, address: String) {
        try {
            val cachePath = File(cacheDir, "images").apply { mkdirs() }
            val file = File(cachePath, "qr_code.png")
            FileOutputStream(file).use { qrBitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
            val contentUri = FileProvider.getUriForFile(
                this,
                applicationContext.packageName + ".fileprovider",
                file
            )
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "image/png"
                putExtra(Intent.EXTRA_STREAM, contentUri)
                putExtra(Intent.EXTRA_TEXT, "Solana Address:\n" + address)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(shareIntent, "Share Solana Address"))
        } catch (e: Exception) {
            Log.e(TAG, "Failed to share QR code", e)
            ThemedToast.show(this, "Failed to share QR code")
        }
    }

    private companion object {
        const val TAG = "ReceiveActivity"
    }
}
