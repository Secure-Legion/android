package com.securelegion

import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.securelegion.crypto.KeyManager
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Wallet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class CreateWalletActivity : AppCompatActivity() {

    private lateinit var walletNameInput: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_create_wallet)

        walletNameInput = findViewById(R.id.walletNameInput)

        setupClickListeners()
        setDefaultWalletName()
    }

    private fun setDefaultWalletName() {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val keyManager = KeyManager.getInstance(this@CreateWalletActivity)
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@CreateWalletActivity, dbPassphrase)
                val walletCount = database.walletDao().getWalletCount()
                val defaultName = "Wallet ${walletCount + 1}"

                withContext(Dispatchers.Main) {
                    walletNameInput.setText(defaultName)
                }
            } catch (e: Exception) {
                Log.e("CreateWallet", "Failed to get wallet count", e)
            }
        }
    }

    private fun setupClickListeners() {
        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Create button
        findViewById<View>(R.id.createWalletButton).setOnClickListener {
            val walletName = walletNameInput.text.toString().trim()
            if (walletName.isEmpty()) {
                return@setOnClickListener
            }
            createNewWallet(walletName)
        }
    }

    private fun createNewWallet(walletName: String) {
        // Disable button to prevent double clicks
        val createButton = findViewById<View>(R.id.createWalletButton)
        createButton.isEnabled = false

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Log.i("CreateWallet", "Creating new wallet: $walletName")

                val keyManager = KeyManager.getInstance(this@CreateWalletActivity)
                val (walletId, solanaAddress) = keyManager.generateNewWallet()

                // Create wallet entity
                val timestamp = System.currentTimeMillis()
                val wallet = Wallet(
                    walletId = walletId,
                    name = walletName,
                    solanaAddress = solanaAddress,
                    isMainWallet = false,
                    createdAt = timestamp,
                    lastUsedAt = timestamp
                )

                // Save to database
                val dbPassphrase = keyManager.getDatabasePassphrase()
                val database = SecureLegionDatabase.getInstance(this@CreateWalletActivity, dbPassphrase)
                database.walletDao().insertWallet(wallet)

                withContext(Dispatchers.Main) {
                    Log.i("CreateWallet", "Wallet created successfully: $walletId")

                    // Navigate back to wallet settings
                    finish()
                }

            } catch (e: Exception) {
                Log.e("CreateWallet", "Failed to create wallet", e)
                withContext(Dispatchers.Main) {
                    createButton.isEnabled = true
                }
            }
        }
    }
}
