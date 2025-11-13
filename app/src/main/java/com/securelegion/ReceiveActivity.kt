package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.securelegion.crypto.KeyManager

class ReceiveActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_receive)

        setupBottomNavigation()
        loadSolanaAddress()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            overridePendingTransition(0, 0)
        }

        // Copy address button
        findViewById<View>(R.id.copyAddressButton).setOnClickListener {
            val address = findViewById<TextView>(R.id.depositAddress).text.toString()

            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("Wallet Address", address)
            clipboard.setPrimaryClip(clip)

            Toast.makeText(this, "Address copied to clipboard", Toast.LENGTH_SHORT).show()
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
            Toast.makeText(this, "Failed to load wallet address", Toast.LENGTH_SHORT).show()
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
            Toast.makeText(this, "Failed to generate QR code", Toast.LENGTH_SHORT).show()
        }
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            overridePendingTransition(0, 0)
            finish()
        }
    }
}
