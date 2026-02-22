package com.securelegion

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.os.Bundle
import android.os.CountDownTimer
import android.util.Log
import android.view.View
import android.widget.ImageView
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.securelegion.utils.GlassBottomSheetDialog
import com.securelegion.utils.GlassDialog
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

    companion object {
        // In-memory QR cache — survives activity recreation within same process
        private var cachedQrBitmap: Bitmap? = null
        private var cachedExpiryMs: Long = 0L
        private var cachedSettingsHash: String = ""
        private var cachedDecryptCount: Int = 0
        private var cachedFriendRequestOnion: String? = null
    }

    private lateinit var profilePhotoAvatar: com.securelegion.views.AvatarView
    private var currentQrBitmap: Bitmap? = null
    private var currentFriendRequestOnion: String? = null
    private var countdownTimer: CountDownTimer? = null

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

        // Settings icon (top-right header)
        findViewById<View>(R.id.settingsButton).setOnClickListener {
            val intent = Intent(this, SettingsActivity::class.java)
            startActivity(intent)
        }

        // Tap QR code → goes to QrSettingsActivity
        findViewById<View>(R.id.qrCodeCard).setOnClickListener {
            startActivity(Intent(this, QrSettingsActivity::class.java))
        }

        // Share button
        findViewById<View>(R.id.shareQrButton).setOnClickListener {
            shareQrCode(currentQrBitmap, currentFriendRequestOnion ?: "")
        }

        loadUsername()
        setupBottomNavigation()
        setupProfilePhoto()
        // QR loaded in onResume via cache-first approach
    }

    override fun onResume() {
        super.onResume()
        loadOrGenerateQrCode()
    }

    override fun onPause() {
        super.onPause()
        countdownTimer?.cancel()
    }

    /**
     * Shows cached QR instantly if available, then checks in background
     * whether the cache is still valid. Only regenerates if expired,
     * uses changed, or settings changed.
     */
    private fun loadOrGenerateQrCode() {
        // Show cached bitmap immediately (prevents blank screen)
        if (cachedQrBitmap != null) {
            findViewById<ImageView>(R.id.qrCodeImage).setImageBitmap(cachedQrBitmap)
            currentQrBitmap = cachedQrBitmap
            currentFriendRequestOnion = cachedFriendRequestOnion
        }

        // Check freshness in background (KeyManager calls may touch JNI)
        lifecycleScope.launch {
            val needsRegeneration = withContext(Dispatchers.Default) {
                if (cachedQrBitmap == null) return@withContext true

                val securityPrefs = getSharedPreferences("security_prefs", Context.MODE_PRIVATE)
                val rotationIntervalMs = securityPrefs.getLong("pin_rotation_interval_ms", 24 * 60 * 60 * 1000L)
                val maxUses = securityPrefs.getInt("pin_max_uses", 5)
                val settingsHash = "$rotationIntervalMs:$maxUses"
                if (settingsHash != cachedSettingsHash) return@withContext true

                val keyManager = KeyManager.getInstance(this@WalletIdentityActivity)
                val decryptCount = keyManager.getPinDecryptCount()
                if (decryptCount != cachedDecryptCount) return@withContext true

                // Check if expired
                val rotationTimestamp = keyManager.getPinRotationTimestamp()
                val expiryMs = if (rotationIntervalMs > 0 && rotationTimestamp > 0) {
                    rotationTimestamp + rotationIntervalMs
                } else 0L
                if (expiryMs > 0 && expiryMs <= System.currentTimeMillis()) return@withContext true

                false
            }

            if (needsRegeneration) {
                generateQrCode()
            } else {
                // Cache still valid — just restart countdown
                startExpiryCountdown(cachedExpiryMs)
            }
        }
    }

    private data class QrGenResult(
        val bitmap: Bitmap?,
        val expiryMs: Long,
        val settingsHash: String,
        val decryptCount: Int,
        val friendRequestOnion: String?
    )

    private fun generateQrCode() {
        lifecycleScope.launch {
            val result = withContext(Dispatchers.Default) {
                val keyManager = KeyManager.getInstance(this@WalletIdentityActivity)
                val friendRequestOnion = keyManager.getFriendRequestOnion() ?: return@withContext null

                val pin = keyManager.getContactPin() ?: ""
                val username = keyManager.getUsername() ?: ""

                // Compute uses and expiry for QR badge
                val securityPrefs = getSharedPreferences("security_prefs", Context.MODE_PRIVATE)
                val decryptCount = keyManager.getPinDecryptCount()
                val maxUses = securityPrefs.getInt("pin_max_uses", 5)
                val mintText = if (maxUses > 0) "$decryptCount/$maxUses" else null

                val rotationIntervalMs = securityPrefs.getLong("pin_rotation_interval_ms", 24 * 60 * 60 * 1000L)
                val rotationTimestamp = keyManager.getPinRotationTimestamp()
                val expiryMs = if (rotationIntervalMs > 0 && rotationTimestamp > 0) {
                    rotationTimestamp + rotationIntervalMs
                } else 0L

                // Build QR content with optional expiry timestamp
                val qrContent = buildString {
                    if (username.isNotEmpty()) append("$username@")
                    append(friendRequestOnion)
                    if (pin.isNotEmpty()) append("@$pin")
                    if (expiryMs > 0) append("@exp$expiryMs")
                }

                // Generate branded QR code — expiry text is now a live overlay, not baked in
                val bitmap = com.securelegion.utils.BrandedQrGenerator.generate(
                    this@WalletIdentityActivity,
                    com.securelegion.utils.BrandedQrGenerator.QrOptions(
                        content = qrContent,
                        size = 512,
                        showLogo = true,
                        mintText = mintText,
                        expiryText = null,
                        showWebsite = true
                    )
                )

                val settingsHash = "$rotationIntervalMs:$maxUses"
                QrGenResult(bitmap, expiryMs, settingsHash, decryptCount, friendRequestOnion)
            }

            if (result != null) {
                // Update cache
                cachedQrBitmap = result.bitmap
                cachedExpiryMs = result.expiryMs
                cachedSettingsHash = result.settingsHash
                cachedDecryptCount = result.decryptCount
                cachedFriendRequestOnion = result.friendRequestOnion

                currentQrBitmap = result.bitmap
                currentFriendRequestOnion = result.friendRequestOnion
                result.bitmap?.let {
                    findViewById<ImageView>(R.id.qrCodeImage).setImageBitmap(it)
                }
                startExpiryCountdown(result.expiryMs)
            }
        }
    }

    /**
     * Live countdown that ticks every second inside the QR card footer.
     * When it hits zero, auto-regenerates the QR.
     */
    private fun startExpiryCountdown(expiryMs: Long) {
        countdownTimer?.cancel()
        val countdownText = findViewById<TextView>(R.id.expiryCountdownText)

        if (expiryMs <= 0) {
            countdownText.visibility = View.GONE
            return
        }

        val remaining = expiryMs - System.currentTimeMillis()
        if (remaining <= 0) {
            countdownText.text = "Expired"
            countdownText.visibility = View.VISIBLE
            return
        }

        countdownText.visibility = View.VISIBLE
        countdownTimer = object : CountDownTimer(remaining, 1000) {
            override fun onTick(millisUntilFinished: Long) {
                val totalSeconds = millisUntilFinished / 1000
                val days = totalSeconds / 86400
                val hours = (totalSeconds % 86400) / 3600
                val minutes = (totalSeconds % 3600) / 60
                val seconds = totalSeconds % 60

                countdownText.text = when {
                    days > 0 -> "Expires ${days}d ${hours}h ${minutes}m"
                    hours > 0 -> "Expires ${hours}h ${minutes}m ${seconds}s"
                    minutes > 0 -> "Expires ${minutes}m ${seconds}s"
                    else -> "Expires ${seconds}s"
                }
            }

            override fun onFinish() {
                countdownText.text = "Expired"
                // Invalidate cache and regenerate
                cachedQrBitmap = null
                generateQrCode()
            }
        }.start()
    }

    private fun showChangeIdentityConfirmation() {
        val dialog = GlassDialog.builder(this)
            .setTitle("Rotate Identity?")
            .setMessage("This will generate a new .onion address and PIN for friend requests.\n\nAnyone with your old QR code will NOT be able to reach you.\n\nThis cannot be undone.")
            .setPositiveButton("Rotate") { _, _ ->
                performIdentityChange()
            }
            .setNegativeButton("Cancel", null)
            .create()

        GlassDialog.show(dialog)
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

                // Invalidate cache and regenerate with new identity
                cachedQrBitmap = null
                generateQrCode()

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
                cachedQrBitmap = null // Force QR regeneration on return

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
