package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.ThemedToast

/**
 * AccountCreatedActivity - Shows account info after successful creation
 * Displays read-only information:
 * - Username
 * - Wallet address
 * - Contact card CID
 * - Contact card PIN
 */
class AccountCreatedActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_account_created)

        loadAccountInfo()
        setupClickListeners()
    }

    private fun loadAccountInfo() {
        try {
            val keyManager = KeyManager.getInstance(this)

            // Load username
            val username = keyManager.getUsername() ?: "Anonymous"
            findViewById<TextView>(R.id.usernameText).text = username
            Log.i("AccountCreated", "Loaded username: $username")

            // Load wallet address
            val walletAddress = keyManager.getSolanaAddress()
            findViewById<TextView>(R.id.walletAddressText).text = walletAddress
            Log.i("AccountCreated", "Loaded wallet address: $walletAddress")

            // Load contact card info
            val cid = keyManager.getContactCardCid()
            val pin = keyManager.getContactCardPin()

            if (cid != null && pin != null) {
                findViewById<TextView>(R.id.contactCardCid).text = cid
                findViewById<TextView>(R.id.contactCardPin).text = pin
                Log.i("AccountCreated", "Loaded contact card info")
                Log.i("AccountCreated", "CID: $cid")
                Log.i("AccountCreated", "PIN: $pin")
            } else {
                Log.w("AccountCreated", "Contact card info not available")
            }

        } catch (e: Exception) {
            Log.e("AccountCreated", "Failed to load account info", e)
            ThemedToast.showLong(this, "Error loading account info")
        }
    }

    private fun setupClickListeners() {
        // Make CID clickable to copy
        findViewById<TextView>(R.id.contactCardCid).setOnClickListener {
            val cid = (it as TextView).text.toString()
            copyToClipboard(cid, "CID")
        }

        // Continue button - navigate to MainActivity
        findViewById<View>(R.id.continueButton).setOnClickListener {
            Log.i("AccountCreated", "User clicked 'Continue to App'")

            val intent = Intent(this, MainActivity::class.java)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
            finish()
        }
    }

    private fun copyToClipboard(text: String, label: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        clipboard.setPrimaryClip(clip)
        ThemedToast.show(this, "$label copied to clipboard")
        Log.i("AccountCreated", "$label copied to clipboard")
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Disable back button - user must click Continue
        ThemedToast.show(this, "Please click 'Continue to App'")
    }
}
