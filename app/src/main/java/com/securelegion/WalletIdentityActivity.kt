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
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.models.ContactCard
import com.securelegion.services.ContactCardManager
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.web3j.crypto.MnemonicUtils
import java.security.SecureRandom

class WalletIdentityActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_wallet_identity)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        loadUsername()
        loadContactCardInfo()
        setupBottomNavigation()

        // New Identity button - Creates new wallet, CID, username, and onion address
        findViewById<View>(R.id.updateUsernameButton).setOnClickListener {
            showNewIdentityConfirmation()
        }

        // Copy CID button
        findViewById<View>(R.id.copyCidButton).setOnClickListener {
            val cid = findViewById<TextView>(R.id.contactCardCid).text.toString()
            if (cid.isNotEmpty()) {
                copyToClipboard(cid, "CID")
            }
        }

        // Copy PIN button
        findViewById<View>(R.id.copyPinButton).setOnClickListener {
            val pin = getPinFromDigits()
            if (pin.isNotEmpty()) {
                copyToClipboard(pin, "PIN")
            }
        }
    }

    private fun getPinFromDigits(): String {
        val digit1 = findViewById<TextView>(R.id.pinDigit1).text.toString()
        val digit2 = findViewById<TextView>(R.id.pinDigit2).text.toString()
        val digit3 = findViewById<TextView>(R.id.pinDigit3).text.toString()
        val digit4 = findViewById<TextView>(R.id.pinDigit4).text.toString()
        val digit5 = findViewById<TextView>(R.id.pinDigit5).text.toString()
        val digit6 = findViewById<TextView>(R.id.pinDigit6).text.toString()
        return "$digit1$digit2$digit3$digit4$digit5$digit6"
    }

    private fun showNewIdentityConfirmation() {
        AlertDialog.Builder(this, R.style.CustomAlertDialog)
            .setTitle("Create New Identity?")
            .setMessage("This will generate:\n\n• New Wallet Address\n• New Contact Card (CID/PIN)\n• New Tor Onion Address\n\nYour current identity will be replaced. Make sure to backup your seed phrase first!")
            .setPositiveButton("Create New Identity") { _, _ ->
                createNewIdentity()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun createNewIdentity() {
        lifecycleScope.launch {
            try {
                Log.i("WalletIdentity", "Creating new identity...")

                // Show loading
                findViewById<View>(R.id.updateUsernameButton).isEnabled = false
                ThemedToast.showLong(this@WalletIdentityActivity, "Creating new identity...")

                // Step 1: Generate new BIP39 mnemonic (12 words)
                val entropy = ByteArray(16)
                SecureRandom().nextBytes(entropy)
                val mnemonic = MnemonicUtils.generateMnemonic(entropy)
                Log.i("WalletIdentity", "Generated new mnemonic")

                // Step 2: Initialize KeyManager with new seed (creates new wallet & Tor address)
                val keyManager = KeyManager.getInstance(this@WalletIdentityActivity)
                withContext(Dispatchers.IO) {
                    keyManager.initializeFromSeed(mnemonic)
                }
                Log.i("WalletIdentity", "Initialized new wallet")

                // Get new addresses
                val newWalletAddress = keyManager.getSolanaAddress()
                val newOnionAddress = keyManager.getTorOnionAddress()
                Log.i("WalletIdentity", "New wallet: $newWalletAddress")
                Log.i("WalletIdentity", "New onion: $newOnionAddress")

                // Step 3: Generate username from current username text
                val usernameText = findViewById<TextView>(R.id.usernameText).text.toString().removePrefix("@")
                val username = usernameText.ifEmpty {
                    "User${System.currentTimeMillis().toString().takeLast(6)}"
                }

                // Step 4: Create and upload new contact card
                ThemedToast.show(this@WalletIdentityActivity, "Uploading contact card...")

                val contactCard = ContactCard(
                    displayName = username,
                    solanaPublicKey = keyManager.getSolanaPublicKey(),
                    x25519PublicKey = keyManager.getEncryptionPublicKey(),
                    solanaAddress = newWalletAddress,
                    torOnionAddress = newOnionAddress,
                    timestamp = System.currentTimeMillis()
                )

                val cardManager = ContactCardManager(this@WalletIdentityActivity)
                val newPin = cardManager.generateRandomPin()
                val publicKey = keyManager.getSolanaAddress() // Get Base58 public key

                val result = withContext(Dispatchers.IO) {
                    cardManager.uploadContactCard(contactCard, newPin, publicKey)
                }

                if (result.isSuccess) {
                    val (cid, size) = result.getOrThrow()

                    // Step 5: Store everything
                    keyManager.storeContactCardInfo(cid, newPin)
                    keyManager.storeUsername(username)

                    Log.i("WalletIdentity", "New identity created successfully!")
                    Log.i("WalletIdentity", "CID: $cid")
                    Log.i("WalletIdentity", "PIN: $newPin")

                    // Refresh UI
                    loadUsername()
                    loadContactCardInfo()

                    // Show seed phrase backup screen
                    ThemedToast.showLong(this@WalletIdentityActivity, "New identity created! Backup your seed phrase!")

                    val intent = Intent(this@WalletIdentityActivity, BackupSeedPhraseActivity::class.java)
                    intent.putExtra(BackupSeedPhraseActivity.EXTRA_SEED_PHRASE, mnemonic)
                    startActivity(intent)
                } else {
                    throw result.exceptionOrNull()!!
                }

                findViewById<View>(R.id.updateUsernameButton).isEnabled = true

            } catch (e: Exception) {
                Log.e("WalletIdentity", "Failed to create new identity", e)
                ThemedToast.showLong(this@WalletIdentityActivity, "Failed to create new identity: ${e.message}")
                findViewById<View>(R.id.updateUsernameButton).isEnabled = true
            }
        }
    }

    private fun loadUsername() {
        try {
            val keyManager = KeyManager.getInstance(this)
            val username = keyManager.getUsername()
            val usernameTextView = findViewById<TextView>(R.id.usernameText)

            if (username != null) {
                usernameTextView.text = "@$username"
                Log.i("WalletIdentity", "Loaded username: $username")
            } else {
                usernameTextView.text = "@USER"
                Log.d("WalletIdentity", "No username stored yet")
            }

            // Apply gradient text effect
            usernameTextView.post {
                applyGradientToText(usernameTextView)
            }
        } catch (e: Exception) {
            Log.e("WalletIdentity", "Failed to load username", e)
            findViewById<TextView>(R.id.usernameText).text = "@USER"
        }
    }

    private fun applyGradientToText(textView: TextView) {
        val width = textView.paint.measureText(textView.text.toString())
        if (width > 0) {
            val shader = android.graphics.LinearGradient(
                0f, 0f, width, 0f,
                intArrayOf(
                    0x4DFFFFFF.toInt(), // 30% white at start
                    0xE6FFFFFF.toInt(), // 90% white at center
                    0x4DFFFFFF.toInt()  // 30% white at end
                ),
                floatArrayOf(0f, 0.49f, 1f),
                android.graphics.Shader.TileMode.CLAMP
            )
            textView.paint.shader = shader
            textView.invalidate()
        }
    }

    private fun loadContactCardInfo() {
        try {
            val keyManager = KeyManager.getInstance(this)
            if (keyManager.hasContactCardInfo()) {
                val cid = keyManager.getContactCardCid()
                val pin = keyManager.getContactCardPin()

                if (cid != null && pin != null) {
                    // Set CID
                    findViewById<TextView>(R.id.contactCardCid).text = cid

                    // Set PIN digits
                    if (pin.length == 6) {
                        findViewById<TextView>(R.id.pinDigit1).text = pin[0].toString()
                        findViewById<TextView>(R.id.pinDigit2).text = pin[1].toString()
                        findViewById<TextView>(R.id.pinDigit3).text = pin[2].toString()
                        findViewById<TextView>(R.id.pinDigit4).text = pin[3].toString()
                        findViewById<TextView>(R.id.pinDigit5).text = pin[4].toString()
                        findViewById<TextView>(R.id.pinDigit6).text = pin[5].toString()
                    }

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
        ThemedToast.show(this, "$label copied to clipboard")
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
