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
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.securelegion.utils.GlassBottomSheetDialog
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
        setupBottomNavigation()
        setupProfilePhoto()

        // Contact Card button
        findViewById<View>(R.id.identityQrCodeButton).setOnClickListener {
            showIdentityQrCode()
        }

        // Wallet button — hidden until wallet feature is ready for release
        findViewById<View>(R.id.walletButton).visibility = View.GONE

        // Change Friend Request Identity button
        findViewById<View>(R.id.changeFriendIdentityButton).setOnClickListener {
            showChangeIdentityConfirmation()
        }

        // Settings button
        findViewById<View>(R.id.settingsButton).setOnClickListener {
            val intent = android.content.Intent(this, SettingsActivity::class.java)
            startActivity(intent)
        }
    }

    private fun showIdentityQrCode() {
        val keyManager = KeyManager.getInstance(this)
        val friendRequestOnion = keyManager.getFriendRequestOnion()

        if (friendRequestOnion == null) {
            ThemedToast.show(this, "No friend request address available")
            return
        }

        val pin = keyManager.getContactPin() ?: ""

        // Create bottom sheet dialog
        val bottomSheet = GlassBottomSheetDialog(this)
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

        // Generate branded QR code — include username + PIN so one scan = everything
        val username = keyManager.getUsername() ?: ""
        val qrContent = buildString {
            if (username.isNotEmpty()) append("$username@")
            append(friendRequestOnion)
            if (pin.isNotEmpty()) append("@$pin")
        }

        // Compute mint count and expiry for QR badge
        val securityPrefs = getSharedPreferences("security_prefs", Context.MODE_PRIVATE)
        val decryptCount = keyManager.getPinDecryptCount()
        val maxUses = securityPrefs.getInt("pin_max_uses", 5)
        val mintText = if (maxUses > 0) "$decryptCount/$maxUses" else null

        val rotationIntervalMs = securityPrefs.getLong("pin_rotation_interval_ms", 24 * 60 * 60 * 1000L)
        val rotationTimestamp = keyManager.getPinRotationTimestamp()
        val expiryText = if (rotationIntervalMs > 0 && rotationTimestamp > 0) {
            val remainingMs = (rotationTimestamp + rotationIntervalMs) - System.currentTimeMillis()
            if (remainingMs > 0) {
                val hours = remainingMs / (60 * 60 * 1000)
                val minutes = (remainingMs % (60 * 60 * 1000)) / (60 * 1000)
                "Expires ${hours}h ${minutes}m"
            } else "Rotation pending"
        } else null

        val qrCodeImage = view.findViewById<ImageView>(R.id.qrCodeImage)
        val qrBitmap = com.securelegion.utils.BrandedQrGenerator.generate(
            this,
            com.securelegion.utils.BrandedQrGenerator.QrOptions(
                content = qrContent,
                size = 512,
                showLogo = true,
                mintText = mintText,
                expiryText = expiryText,
                showWebsite = true
            )
        )
        if (qrBitmap != null) {
            qrCodeImage.setImageBitmap(qrBitmap)
        }

        // Set friend request address text
        view.findViewById<TextView>(R.id.cidText).text = friendRequestOnion

        // Set PIN text formatted as XXX-XXX-XXXX
        if (pin.length == 10) {
            val formattedPin = "${pin.substring(0, 3)}-${pin.substring(3, 6)}-${pin.substring(6, 10)}"
            view.findViewById<TextView>(R.id.pinText).text = formattedPin
        } else {
            view.findViewById<TextView>(R.id.pinText).text = pin
        }

        // Copy friend request address button
        view.findViewById<View>(R.id.copyCidButton).setOnClickListener {
            copyToClipboard(friendRequestOnion, "Friend Request Address")
        }

        // Copy PIN button
        view.findViewById<View>(R.id.copyPinButton).setOnClickListener {
            if (pin.isNotEmpty()) {
                copyToClipboard(pin, "Contact PIN")
            }
        }

        // Toggle address/PIN visibility based on legacy setting
        val showManualFields = securityPrefs.getBoolean("legacy_manual_entry", false)
        val addressPinSection = view.findViewById<View>(R.id.addressPinSection)
        addressPinSection.visibility = if (showManualFields) View.VISIBLE else View.GONE

        // PIN uses counter
        val pinUsesText = view.findViewById<TextView>(R.id.pinUsesText)
        if (maxUses > 0) {
            pinUsesText.text = "PIN uses: $decryptCount/$maxUses"
        } else {
            pinUsesText.text = "PIN uses: $decryptCount (unlimited)"
        }

        // PIN expiration countdown
        val pinCountdownText = view.findViewById<TextView>(R.id.pinCountdownText)
        if (rotationIntervalMs > 0 && rotationTimestamp > 0) {
            val remainingMs = (rotationTimestamp + rotationIntervalMs) - System.currentTimeMillis()
            if (remainingMs > 0) {
                val hours = remainingMs / (60 * 60 * 1000)
                val minutes = (remainingMs % (60 * 60 * 1000)) / (60 * 1000)
                pinCountdownText.text = "PIN expires in ${hours}h ${minutes}m"
                pinCountdownText.visibility = View.VISIBLE
            } else {
                pinCountdownText.text = "PIN rotation pending"
                pinCountdownText.visibility = View.VISIBLE
            }
        } else {
            pinCountdownText.text = "PIN rotation: off"
            pinCountdownText.visibility = View.VISIBLE
        }

        // Share button
        view.findViewById<View>(R.id.shareQrButton).setOnClickListener {
            shareQrCode(qrBitmap, friendRequestOnion)
            bottomSheet.dismiss()
        }

        bottomSheet.show()
    }

    private fun showChangeIdentityConfirmation() {
        val dialog = com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
            .setBackground(androidx.core.content.ContextCompat.getDrawable(this, R.drawable.glass_dialog_bg))
            .setTitle("Rotate Identity?")
            .setMessage("This will generate a new .onion address and PIN for friend requests.\n\nAnyone with your old QR code will NOT be able to reach you.\n\nThis cannot be undone.")
            .setPositiveButton("Rotate") { _, _ ->
                performIdentityChange()
            }
            .setNegativeButton("Cancel", null)
            .create()

        dialog.setOnShowListener {
            // Strip all internal panel backgrounds so only our glass_dialog_bg shows
            (dialog.window?.decorView as? android.view.ViewGroup)?.let { decor ->
                stripChildBackgrounds(decor)
            }
        }
        dialog.show()
    }

    private fun stripChildBackgrounds(parent: android.view.ViewGroup) {
        for (i in 0 until parent.childCount) {
            val child = parent.getChildAt(i)
            if (child !is android.widget.Button) {
                child.background = null
            }
            if (child is android.view.ViewGroup) {
                stripChildBackgrounds(child)
            }
        }
    }

    private fun performIdentityChange() {
        lifecycleScope.launch {
            try {
                val keyManager = KeyManager.getInstance(this@WalletIdentityActivity)
                val cardManager = ContactCardManager(this@WalletIdentityActivity)

                // Increment rotation counter (changes the domain separator)
                keyManager.incrementFriendReqRotationCount()

                // Delete and recreate the hidden service directory
                val torDir = java.io.File(filesDir, "tor")
                val hsDir = java.io.File(torDir, "friend_request_hidden_service")
                if (hsDir.exists()) {
                    hsDir.deleteRecursively()
                }
                hsDir.mkdirs()

                // Re-seed with new domain separator (internally uses rotation counter)
                val seeded = keyManager.seedHiddenServiceDir(hsDir, "friend_req")
                if (!seeded) {
                    ThemedToast.show(this@WalletIdentityActivity, "Failed to generate new identity")
                    return@launch
                }

                // Read the new .onion address
                val hostnameFile = java.io.File(hsDir, "hostname")
                val newOnion = hostnameFile.readText().trim()
                keyManager.storeFriendRequestOnion(newOnion)

                // Generate a new PIN and reset rotation state
                val newPin = cardManager.generateRandomPin()
                keyManager.storeContactPin(newPin)
                keyManager.storePinRotationTimestamp(System.currentTimeMillis())
                keyManager.resetPinDecryptCount()
                keyManager.clearPreviousPin()

                Log.i("WalletIdentity", "Identity changed: new onion=$newOnion")

                // Request Tor restart to publish new .onion
                com.securelegion.services.TorService.requestRestart("friend request identity changed")

                ThemedToast.showLong(this@WalletIdentityActivity, "New identity active! Tor is publishing your new address.")

                // Re-show the QR bottom sheet with updated data
                showIdentityQrCode()

            } catch (e: Exception) {
                Log.e("WalletIdentity", "Identity change failed", e)
                ThemedToast.show(this@WalletIdentityActivity, "Failed: ${e.message}")
            }
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

    private fun showNewIdentityConfirmation() {
        // Create bottom sheet dialog
        val bottomSheet = GlassBottomSheetDialog(this)
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
                // findViewById<View>(R.id.updateUsernameButton).isEnabled = false
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

                // Show seed phrase backup screen
                ThemedToast.showLong(this@WalletIdentityActivity, "New identity created! Backup your seed phrase!")

                val intent = Intent(this@WalletIdentityActivity, BackupSeedPhraseActivity::class.java)
                intent.putExtra(BackupSeedPhraseActivity.EXTRA_SEED_PHRASE, mnemonic)
                startActivity(intent)

                // findViewById<View>(R.id.updateUsernameButton).isEnabled = true

            } catch (e: Exception) {
                Log.e("WalletIdentity", "Failed to create new identity", e)
                ThemedToast.showLong(this@WalletIdentityActivity, "Failed to create new identity: ${e.message}")
                // findViewById<View>(R.id.updateUsernameButton).isEnabled = true
            }
        }
    }

    private fun loadUsername() {
        val usernameTextView = findViewById<TextView>(R.id.usernameText)

        try {
            val keyManager = KeyManager.getInstance(this)
            val username = keyManager.getUsername()

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
            usernameTextView.text = "@USER"
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
                    0x4DFFFFFF.toInt() // 30% white at end
                ),
                floatArrayOf(0f, 0.49f, 1f),
                android.graphics.Shader.TileMode.CLAMP
            )
            textView.paint.shader = shader
            textView.invalidate()
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
        BottomNavigationHelper.setupBottomNavigation(this)
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
        val bottomSheet = GlassBottomSheetDialog(this)
        val view = layoutInflater.inflate(R.layout.bottom_sheet_photo_picker, null)
        bottomSheet.setContentView(view)

        bottomSheet.behavior.isDraggable = true
        bottomSheet.behavior.skipCollapsed = true

        bottomSheet.window?.setBackgroundDrawableResource(android.R.color.transparent)
        bottomSheet.window?.findViewById<View>(com.google.android.material.R.id.design_bottom_sheet)
            ?.setBackgroundResource(android.R.color.transparent)
        view.post {
            (view.parent as? View)?.setBackgroundResource(android.R.color.transparent)
        }

        view.findViewById<View>(R.id.optionTakePhoto).setOnClickListener {
            bottomSheet.dismiss()
            ImagePicker.pickFromCamera(cameraLauncher)
        }

        view.findViewById<View>(R.id.optionGallery).setOnClickListener {
            bottomSheet.dismiss()
            ImagePicker.pickFromGallery(galleryLauncher)
        }

        view.findViewById<View>(R.id.optionRemovePhoto).setOnClickListener {
            bottomSheet.dismiss()
            removeProfilePhoto()
        }

        bottomSheet.show()
    }

    private fun saveProfilePhoto(base64: String) {
        val prefs = getSharedPreferences("secure_legion_settings", MODE_PRIVATE)
        prefs.edit().putString("profile_photo_base64", base64).apply()

        // Broadcast profile photo update to all contacts via encrypted Tor pipeline
        // Use application-scoped coroutine so it survives activity navigation
        kotlinx.coroutines.CoroutineScope(Dispatchers.IO + kotlinx.coroutines.SupervisorJob()).launch {
            try {
                val messageService = com.securelegion.services.MessageService(this@WalletIdentityActivity)
                messageService.broadcastProfileUpdate(base64)
                Log.i("WalletIdentity", "Profile photo broadcasted to contacts")
            } catch (e: Exception) {
                Log.e("WalletIdentity", "Failed to broadcast profile update", e)
            }
        }
    }

    private fun removeProfilePhoto() {
        val prefs = getSharedPreferences("secure_legion_settings", MODE_PRIVATE)
        prefs.edit().remove("profile_photo_base64").apply()
        profilePhotoAvatar.clearPhoto()
        ThemedToast.show(this, "Profile photo removed")

        // Broadcast photo removal to all contacts via encrypted Tor pipeline
        // Use application-scoped coroutine so it survives activity navigation
        kotlinx.coroutines.CoroutineScope(Dispatchers.IO + kotlinx.coroutines.SupervisorJob()).launch {
            try {
                val messageService = com.securelegion.services.MessageService(this@WalletIdentityActivity)
                messageService.broadcastProfileUpdate("") // Empty = removal
                Log.i("WalletIdentity", "Profile photo removal broadcasted to contacts")
            } catch (e: Exception) {
                Log.e("WalletIdentity", "Failed to broadcast profile removal", e)
            }
        }
    }
}
