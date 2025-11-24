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

        loadWalletAddress()
        loadUsername()
        loadContactCardInfo()
        setupBottomNavigation()

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // New Identity button - Creates new wallet, CID, username, and onion address
        findViewById<View>(R.id.updateUsernameButton).setOnClickListener {
            showNewIdentityConfirmation()
        }
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

                // Step 3: Generate username
                val username = findViewById<EditText>(R.id.usernameInput).text.toString().ifEmpty {
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
                    loadWalletAddress()
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
