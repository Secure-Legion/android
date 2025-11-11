package com.securelegion

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager

class WalletIdentityActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wallet_identity)

        loadWalletAddress()
        loadUsername()
        loadContactCardInfo()
        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Update Username button
        findViewById<View>(R.id.updateUsernameButton).setOnClickListener {
            val username = findViewById<EditText>(R.id.usernameInput).text.toString()
            Toast.makeText(this, "Username updated: $username", Toast.LENGTH_SHORT).show()
            // TODO: Update username on blockchain
        }

        // Create New Wallet button
        findViewById<View>(R.id.createNewWalletButton).setOnClickListener {
            Toast.makeText(this, "Creating new wallet...", Toast.LENGTH_SHORT).show()
            // TODO: Create new wallet
        }
    }

    private fun loadWalletAddress() {
        try {
            val keyManager = KeyManager.getInstance(this)
            if (keyManager.isInitialized()) {
                val walletAddress = keyManager.getSolanaAddress()
                findViewById<TextView>(R.id.walletAddressText).text = walletAddress
                Log.i("WalletIdentity", "Loaded wallet address: $walletAddress")
            } else {
                findViewById<TextView>(R.id.walletAddressText).text = "No wallet initialized"
                Log.w("WalletIdentity", "Wallet not initialized")
            }
        } catch (e: Exception) {
            Log.e("WalletIdentity", "Failed to load wallet address", e)
            findViewById<TextView>(R.id.walletAddressText).text = "Error loading address"
        }
    }

    private fun loadUsername() {
        try {
            val keyManager = KeyManager.getInstance(this)
            val username = keyManager.getUsername()
            if (username != null) {
                findViewById<EditText>(R.id.usernameInput).setText(username)
                Log.i("WalletIdentity", "Loaded username: $username")
            } else {
                Log.d("WalletIdentity", "No username stored yet")
            }
        } catch (e: Exception) {
            Log.e("WalletIdentity", "Failed to load username", e)
        }
    }

    private fun loadContactCardInfo() {
        try {
            val keyManager = KeyManager.getInstance(this)
            if (keyManager.hasContactCardInfo()) {
                val cid = keyManager.getContactCardCid()
                val pin = keyManager.getContactCardPin()

                if (cid != null && pin != null) {
                    findViewById<View>(R.id.contactCardSection).visibility = View.VISIBLE

                    val cidTextView = findViewById<TextView>(R.id.contactCardCid)
                    cidTextView.text = cid

                    // Make CID clickable to copy
                    cidTextView.setOnClickListener {
                        copyToClipboard(cid, "CID")
                    }

                    findViewById<TextView>(R.id.contactCardPin).text = pin
                    Log.i("WalletIdentity", "Loaded contact card info")
                }
            } else {
                Log.d("WalletIdentity", "No contact card info stored yet")
            }
        } catch (e: Exception) {
            Log.e("WalletIdentity", "Failed to load contact card info", e)
        }
    }

    private fun copyToClipboard(text: String, label: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        clipboard.setPrimaryClip(clip)
        Toast.makeText(this, "$label copied to clipboard", Toast.LENGTH_SHORT).show()
        Log.i("WalletIdentity", "$label copied to clipboard")
    }

    private fun setupBottomNavigation() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            val intent = Intent(this, AddFriendActivity::class.java)
            startActivity(intent)
            finish()
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            finish()
        }
    }
}
