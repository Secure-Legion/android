package com.securelegion

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.securelegion.crypto.KeyManager
import com.securelegion.models.ContactCard
import com.securelegion.services.ContactCardManager
import com.securelegion.utils.ImagePicker
import com.securelegion.utils.ThemedToast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.web3j.crypto.MnemonicUtils
import java.io.File
import java.io.FileOutputStream
import java.security.SecureRandom

class WalletIdentityActivity : AppCompatActivity() {

    private lateinit var profilePhotoAvatar: com.securelegion.views.AvatarView

    // Image picker launchers
    private val galleryLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val uri = result.data?.data
            val base64 = ImagePicker.processImageUri(this, uri)
            if (base64 != null) {
                saveProfilePhoto(base64)
                profilePhotoAvatar.setPhotoBase64(base64)
                ThemedToast.show(this, "Profile photo updated")
            } else {
                ThemedToast.show(this, "Failed to process image")
            }
        }
    }

    private val cameraLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val bitmap = result.data?.extras?.get("data") as? Bitmap
            val base64 = ImagePicker.processImageBitmap(bitmap)
            if (base64 != null) {
                saveProfilePhoto(base64)
                profilePhotoAvatar.setPhotoBase64(base64)
                ThemedToast.show(this, "Profile photo updated")
            } else {
                ThemedToast.show(this, "Failed to process image")
            }
        }
    }

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
        setupProfilePhoto()

        // New Identity button - Creates new wallet, CID, username, and onion address
        findViewById<View>(R.id.updateUsernameButton).setOnClickListener {
            showNewIdentityConfirmation()
        }

        // Copy friend request address button
        findViewById<View>(R.id.copyCidButton).setOnClickListener {
            val friendRequestAddress = findViewById<TextView>(R.id.contactCardCid).text.toString()
            if (friendRequestAddress.isNotEmpty()) {
                copyToClipboard(friendRequestAddress, "Friend Request Address")
            }
        }

        // Copy PIN button
        findViewById<View>(R.id.copyPinButton).setOnClickListener {
            val pin = getPinFromDigits()
            if (pin.isNotEmpty()) {
                copyToClipboard(pin, "PIN")
            }
        }

        // Identity QR Code button
        findViewById<View>(R.id.identityQrCodeButton).setOnClickListener {
            showIdentityQrCode()
        }
    }

    private fun showIdentityQrCode() {
        val keyManager = KeyManager.getInstance(this)
        val friendRequestOnion = keyManager.getFriendRequestOnion()

        if (friendRequestOnion == null) {
            ThemedToast.show(this, "No friend request address available")
            return
        }

        // Create bottom sheet dialog
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_identity_qr, null)

        // Set minimum height
        val displayMetrics = resources.displayMetrics
        val screenHeight = displayMetrics.heightPixels
        val desiredHeight = (screenHeight * 0.65).toInt()
        view.minimumHeight = desiredHeight

        bottomSheet.setContentView(view)

        // Configure bottom sheet behavior
        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.isFitToContents = true
        bottomSheet.behavior.skipCollapsed = true

        // Make backgrounds transparent
        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)?.setBackgroundResource(android.R.color.transparent)

        view.post {
            val parentView = view.parent as? View
            parentView?.setBackgroundResource(android.R.color.transparent)
        }

        // Generate QR code
        val qrCodeImage = view.findViewById<ImageView>(R.id.qrCodeImage)
        val qrBitmap = generateQrCode(friendRequestOnion, 512)
        if (qrBitmap != null) {
            qrCodeImage.setImageBitmap(qrBitmap)
        }

        // Set friend request address text
        view.findViewById<TextView>(R.id.cidText).text = friendRequestOnion

        // Share button
        view.findViewById<View>(R.id.shareQrButton).setOnClickListener {
            shareQrCode(qrBitmap, friendRequestOnion)
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun generateQrCode(content: String, size: Int): Bitmap? {
        return try {
            val writer = QRCodeWriter()
            val bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, size, size)
            val width = bitMatrix.width
            val height = bitMatrix.height
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.RGB_565)

            for (x in 0 until width) {
                for (y in 0 until height) {
                    bitmap.setPixel(x, y, if (bitMatrix[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
                }
            }
            bitmap
        } catch (e: Exception) {
            Log.e("WalletIdentity", "Failed to generate QR code", e)
            null
        }
    }

    private fun shareQrCode(bitmap: Bitmap?, cid: String) {
        if (bitmap == null) {
            ThemedToast.show(this, "Failed to generate QR code")
            return
        }

        try {
            // Save bitmap to cache directory
            val cachePath = File(cacheDir, "images")
            cachePath.mkdirs()
            val file = File(cachePath, "identity_qr.png")
            FileOutputStream(file).use { stream ->
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream)
            }

            // Get content URI via FileProvider
            val contentUri = FileProvider.getUriForFile(
                this,
                "${packageName}.fileprovider",
                file
            )

            // Create share intent
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "image/png"
                putExtra(Intent.EXTRA_STREAM, contentUri)
                putExtra(Intent.EXTRA_TEXT, "Add me on Secure!\nFriend Request Address: $cid")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }

            startActivity(Intent.createChooser(shareIntent, "Share Identity QR Code"))
        } catch (e: Exception) {
            Log.e("WalletIdentity", "Failed to share QR code", e)
            ThemedToast.show(this, "Failed to share QR code")
        }
    }

    private fun getPinFromDigits(): String {
        val digit1 = findViewById<TextView>(R.id.pinDigit1).text.toString()
        val digit2 = findViewById<TextView>(R.id.pinDigit2).text.toString()
        val digit3 = findViewById<TextView>(R.id.pinDigit3).text.toString()
        val digit4 = findViewById<TextView>(R.id.pinDigit4).text.toString()
        val digit5 = findViewById<TextView>(R.id.pinDigit5).text.toString()
        val digit6 = findViewById<TextView>(R.id.pinDigit6).text.toString()
        val digit7 = findViewById<TextView>(R.id.pinDigit7).text.toString()
        val digit8 = findViewById<TextView>(R.id.pinDigit8).text.toString()
        val digit9 = findViewById<TextView>(R.id.pinDigit9).text.toString()
        val digit10 = findViewById<TextView>(R.id.pinDigit10).text.toString()
        return "$digit1$digit2$digit3$digit4$digit5$digit6$digit7$digit8$digit9$digit10"
    }

    private fun showNewIdentityConfirmation() {
        // Create bottom sheet dialog
        val bottomSheet = BottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_new_identity_confirm, null)

        // Set minimum height on the view itself
        val displayMetrics = resources.displayMetrics
        val screenHeight = displayMetrics.heightPixels
        val desiredHeight = (screenHeight * 0.75).toInt()
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

        // Confirm button
        val confirmButton = view.findViewById<View>(R.id.confirmNewIdentityButton)
        confirmButton.setOnClickListener {
            bottomSheet.dismiss()
            createNewIdentity()
        }

        // Cancel button
        val cancelButton = view.findViewById<View>(R.id.cancelNewIdentityButton)
        cancelButton.setOnClickListener {
            bottomSheet.dismiss()
        }

        bottomSheet.show()
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

                // Step 4: Create friend request .onion and derive IPFS CID (v2.0)
                Log.i("WalletIdentity", "Creating friend request .onion address...")
                val friendRequestOnion = keyManager.createFriendRequestOnion()
                Log.i("WalletIdentity", "Friend request .onion: $friendRequestOnion")

                Log.i("WalletIdentity", "Deriving IPFS CID from seed...")
                val ipfsCid = keyManager.deriveIPFSCID(mnemonic)
                keyManager.storeIPFSCID(ipfsCid)
                Log.i("WalletIdentity", "IPFS CID: $ipfsCid")

                // Step 5: Create and upload new contact card
                ThemedToast.show(this@WalletIdentityActivity, "Uploading contact card...")

                val cardManager = ContactCardManager(this@WalletIdentityActivity)
                val newPin = cardManager.generateRandomPin()

                val torManager = com.securelegion.crypto.TorManager.getInstance(this@WalletIdentityActivity)
                val voiceOnion = torManager.getVoiceOnionAddress() ?: ""
                val contactCard = ContactCard(
                    displayName = username,
                    solanaPublicKey = keyManager.getSolanaPublicKey(),
                    x25519PublicKey = keyManager.getEncryptionPublicKey(),
                    kyberPublicKey = keyManager.getKyberPublicKey(),
                    solanaAddress = newWalletAddress,
                    friendRequestOnion = friendRequestOnion,
                    messagingOnion = newOnionAddress,
                    voiceOnion = voiceOnion,
                    contactPin = newPin,
                    ipfsCid = ipfsCid,
                    timestamp = System.currentTimeMillis()
                )

                // Store contact card info (CID is deterministic, not uploaded)
                keyManager.storeContactPin(newPin)
                keyManager.storeIPFSCID(ipfsCid)
                // Note: friendRequestOnion already stored by createFriendRequestOnion()
                keyManager.storeMessagingOnion(newOnionAddress)
                keyManager.storeUsername(username)

                Log.i("WalletIdentity", "New identity created successfully!")
                Log.i("WalletIdentity", "CID: $ipfsCid (deterministic from seed)")
                Log.i("WalletIdentity", "PIN: $newPin")

                // Refresh UI
                loadUsername()
                loadContactCardInfo()

                // Show seed phrase backup screen
                ThemedToast.showLong(this@WalletIdentityActivity, "New identity created! Backup your seed phrase!")

                val intent = Intent(this@WalletIdentityActivity, BackupSeedPhraseActivity::class.java)
                intent.putExtra(BackupSeedPhraseActivity.EXTRA_SEED_PHRASE, mnemonic)
                startActivity(intent)

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
                val friendRequestOnion = keyManager.getFriendRequestOnion()
                val pin = keyManager.getContactPin()

                if (friendRequestOnion != null && pin != null) {
                    // Set friend request .onion address
                    findViewById<TextView>(R.id.contactCardCid).text = friendRequestOnion

                    // Set PIN digits (10 digits)
                    if (pin.length == 10) {
                        findViewById<TextView>(R.id.pinDigit1).text = pin[0].toString()
                        findViewById<TextView>(R.id.pinDigit2).text = pin[1].toString()
                        findViewById<TextView>(R.id.pinDigit3).text = pin[2].toString()
                        findViewById<TextView>(R.id.pinDigit4).text = pin[3].toString()
                        findViewById<TextView>(R.id.pinDigit5).text = pin[4].toString()
                        findViewById<TextView>(R.id.pinDigit6).text = pin[5].toString()
                        findViewById<TextView>(R.id.pinDigit7).text = pin[6].toString()
                        findViewById<TextView>(R.id.pinDigit8).text = pin[7].toString()
                        findViewById<TextView>(R.id.pinDigit9).text = pin[8].toString()
                        findViewById<TextView>(R.id.pinDigit10).text = pin[9].toString()
                        Log.i("WalletIdentity", "Loaded 10-digit PIN")
                    } else {
                        Log.e("WalletIdentity", "Invalid PIN length: ${pin.length} (expected 10)")
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

        findViewById<View>(R.id.navPhone).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_PHONE", true)
            intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
            startActivity(intent)
            finish()
        }
    }

    // ==================== PROFILE PHOTO ====================

    private fun setupProfilePhoto() {
        profilePhotoAvatar = findViewById(R.id.profilePhotoAvatar)

        // Load existing photo
        val prefs = getSharedPreferences("secure_legion_settings", MODE_PRIVATE)
        val photoBase64 = prefs.getString("profile_photo_base64", null)
        val username = prefs.getString("username", "User")

        if (!photoBase64.isNullOrEmpty()) {
            profilePhotoAvatar.setPhotoBase64(photoBase64)
        }
        profilePhotoAvatar.setName(username)

        // Edit photo button
        findViewById<View>(R.id.editProfilePhotoButton).setOnClickListener {
            showImagePickerDialog()
        }
    }

    private fun showImagePickerDialog() {
        AlertDialog.Builder(this)
            .setTitle("Change Profile Photo")
            .setItems(arrayOf("Take Photo", "Choose from Gallery", "Remove Photo")) { _, which ->
                when (which) {
                    0 -> ImagePicker.pickFromCamera(cameraLauncher)
                    1 -> ImagePicker.pickFromGallery(galleryLauncher)
                    2 -> removeProfilePhoto()
                }
            }
            .show()
    }

    private fun saveProfilePhoto(base64: String) {
        val prefs = getSharedPreferences("secure_legion_settings", MODE_PRIVATE)
        prefs.edit().putString("profile_photo_base64", base64).apply()
    }

    private fun removeProfilePhoto() {
        val prefs = getSharedPreferences("secure_legion_settings", MODE_PRIVATE)
        prefs.edit().remove("profile_photo_base64").apply()
        profilePhotoAvatar.clearPhoto()
        ThemedToast.show(this, "Profile photo removed")
    }
}
