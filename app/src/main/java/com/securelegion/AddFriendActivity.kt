package com.securelegion

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import com.securelegion.crypto.KeyManager
import com.securelegion.utils.ThemedToast
import com.securelegion.utils.BadgeUtils
import com.securelegion.database.SecureLegionDatabase
import com.securelegion.database.entities.Contact
import com.securelegion.models.ContactCard
import com.securelegion.models.FriendRequest
import com.securelegion.services.ContactCardManager
import com.securelegion.crypto.RustBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AddFriendActivity : BaseActivity() {

    companion object {
        private const val TAG = "AddFriend"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_friend)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
        }

        // Add Friend button
        findViewById<View>(R.id.searchButton).setOnClickListener {
            val cid = findViewById<EditText>(R.id.cidInput).text.toString().trim()
            val pin = findViewById<EditText>(R.id.pinInput).text.toString().trim()

            if (cid.isEmpty()) {
                ThemedToast.show(this, "Please enter CID")
                return@setOnClickListener
            }

            if (pin.isEmpty()) {
                ThemedToast.show(this, "Please enter PIN")
                return@setOnClickListener
            }

            if (pin.length != 6 || !pin.all { it.isDigit() }) {
                ThemedToast.show(this, "PIN must be 6 digits")
                return@setOnClickListener
            }

            downloadContactCard(cid, pin)
        }

        setupBottomNav()
    }

    override fun onResume() {
        super.onResume()
        // Load and display pending friend requests
        loadPendingFriendRequests()
        updateFriendRequestBadge()
    }

    /**
     * Load pending friend requests from SharedPreferences and display them
     */
    private fun loadPendingFriendRequests() {
        try {
            val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests", mutableSetOf()) ?: mutableSetOf()

            Log.d(TAG, "Loading pending friend requests: ${pendingRequestsSet.size} requests")

            // Deduplicate based on CID (in case same request was received multiple times)
            val uniqueRequests = mutableMapOf<String, FriendRequest>()

            for (requestJson in pendingRequestsSet) {
                val friendRequest = FriendRequest.fromJson(requestJson)
                // Use CID as unique key - overwrites duplicates
                uniqueRequests[friendRequest.ipfsCid] = friendRequest
            }

            val friendRequests = uniqueRequests.values.toList()

            Log.d(TAG, "Loaded ${friendRequests.size} unique pending friend requests (${pendingRequestsSet.size} total, ${pendingRequestsSet.size - friendRequests.size} duplicates)")

            // Display friend requests in UI
            displayFriendRequests(friendRequests)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to load pending friend requests", e)
        }
    }

    /**
     * Display friend requests in the UI
     */
    private fun displayFriendRequests(friendRequests: List<FriendRequest>) {
        val requestsContainer = findViewById<View>(R.id.friendRequestsContainer)
        val requestsList = findViewById<android.widget.LinearLayout>(R.id.friendRequestsList)

        // Clear existing views
        requestsList.removeAllViews()

        if (friendRequests.isEmpty()) {
            requestsContainer.visibility = View.GONE
            return
        }

        requestsContainer.visibility = View.VISIBLE

        // Add each friend request as a clickable card
        for (friendRequest in friendRequests) {
            // Create horizontal layout for the request card
            val cardLayout = android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.HORIZONTAL
                setBackgroundResource(R.drawable.message_input_bg)
                setPadding(32, 24, 32, 24)
                layoutParams = android.widget.LinearLayout.LayoutParams(
                    android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                    android.widget.LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = 16
                }
            }

            // Create vertical layout for text content
            val textLayout = android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.VERTICAL
                layoutParams = android.widget.LinearLayout.LayoutParams(
                    0,
                    android.widget.LinearLayout.LayoutParams.WRAP_CONTENT,
                    1f // Weight 1 to fill remaining space
                )
            }

            // Name text
            val nameText = android.widget.TextView(this).apply {
                text = friendRequest.displayName
                textSize = 16f
                setTextColor(getColor(R.color.text_white))
                setTypeface(null, android.graphics.Typeface.BOLD)
            }

            // Hint text
            val hintText = android.widget.TextView(this).apply {
                text = "Tap to auto-fill CID"
                textSize = 13f
                setTextColor(getColor(R.color.text_gray))
            }

            textLayout.addView(nameText)
            textLayout.addView(hintText)

            // Delete button (X)
            val deleteButton = android.widget.TextView(this).apply {
                text = "✕"
                textSize = 24f
                setTextColor(getColor(R.color.text_gray))
                setPadding(16, 0, 0, 0)
                setOnClickListener {
                    declineFriendRequest(friendRequest)
                }
            }

            cardLayout.addView(textLayout)
            cardLayout.addView(deleteButton)

            // Handle card click - auto-fill CID field
            cardLayout.setOnClickListener {
                // Auto-fill CID (will show as dots due to password inputType)
                val cidInput = findViewById<EditText>(R.id.cidInput)
                cidInput.setText(friendRequest.ipfsCid)

                // Scroll to top so user sees the auto-filled CID
                val scrollView = findViewById<android.widget.ScrollView>(R.id.addFriendScrollView)
                scrollView?.post {
                    scrollView.smoothScrollTo(0, 0)
                }

                // Focus on PIN input
                val pinInput = findViewById<EditText>(R.id.pinInput)
                pinInput.requestFocus()

                // Show keyboard for PIN input
                val inputMethodManager = getSystemService(android.view.inputmethod.InputMethodManager::class.java)
                inputMethodManager.showSoftInput(pinInput, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)

                ThemedToast.show(this, "CID auto-filled. Enter PIN and tap 'Add Friend'")
            }

            requestsList.addView(cardLayout)
        }
    }

    /**
     * Prompt user for PIN and accept friend request
     */
    private fun promptForPinAndAcceptRequest(friendRequest: FriendRequest) {
        val pinInput = android.widget.EditText(this)
        pinInput.inputType = android.text.InputType.TYPE_CLASS_NUMBER
        pinInput.hint = "Enter 6-digit PIN"
        pinInput.setTextColor(getColor(R.color.text_white))
        pinInput.setHintTextColor(getColor(R.color.text_gray))
        pinInput.setPadding(32, 32, 32, 32)

        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Accept Friend Request")
            .setMessage("${friendRequest.displayName} wants to add you as a friend.\n\nEnter the PIN they gave you:")
            .setView(pinInput)
            .setPositiveButton("Accept") { _, _ ->
                val pin = pinInput.text.toString().trim()

                if (pin.length != 6 || !pin.all { it.isDigit() }) {
                    ThemedToast.show(this, "PIN must be 6 digits")
                    return@setPositiveButton
                }

                // Download contact card using CID and PIN
                acceptFriendRequest(friendRequest, pin)
            }
            .setNegativeButton("Decline") { _, _ ->
                declineFriendRequest(friendRequest)
            }
            .show()
    }

    /**
     * Accept friend request by downloading contact card
     */
    private fun acceptFriendRequest(friendRequest: FriendRequest, pin: String) {
        Log.d(TAG, "Accepting friend request from ${friendRequest.displayName}")

        // Use the existing downloadContactCard function
        downloadContactCard(friendRequest.ipfsCid, pin)

        // Remove from pending requests
        removeFriendRequest(friendRequest)
    }

    /**
     * Decline friend request
     */
    private fun declineFriendRequest(friendRequest: FriendRequest) {
        Log.d(TAG, "Declining friend request from ${friendRequest.displayName}")

        removeFriendRequest(friendRequest)

        ThemedToast.show(this, "Declined friend request from ${friendRequest.displayName}")
    }

    /**
     * Remove friend request from SharedPreferences
     */
    private fun removeFriendRequest(friendRequest: FriendRequest) {
        try {
            val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests", mutableSetOf()) ?: mutableSetOf()

            // Rebuild set without this request
            val newSet = mutableSetOf<String>()
            for (requestJson in pendingRequestsSet) {
                val request = FriendRequest.fromJson(requestJson)

                // Keep all requests except the one we're removing
                if (request.displayName != friendRequest.displayName ||
                    request.ipfsCid != friendRequest.ipfsCid) {
                    newSet.add(requestJson)
                }
            }

            // Save updated set
            prefs.edit()
                .putStringSet("pending_requests", newSet)
                .apply()

            Log.d(TAG, "Removed friend request - ${newSet.size} remaining")

            // Reload the UI
            loadPendingFriendRequests()
            updateFriendRequestBadge()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove friend request", e)
        }
    }

    /**
     * Remove friend request by CID
     */
    private fun removeFriendRequestByCid(cid: String) {
        try {
            val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests", mutableSetOf()) ?: mutableSetOf()

            // Rebuild set without requests matching this CID
            val newSet = mutableSetOf<String>()
            for (requestJson in pendingRequestsSet) {
                val request = FriendRequest.fromJson(requestJson)

                // Keep all requests except those matching this CID
                if (request.ipfsCid != cid) {
                    newSet.add(requestJson)
                }
            }

            // Save updated set
            prefs.edit()
                .putStringSet("pending_requests", newSet)
                .apply()

            Log.d(TAG, "Removed friend request with CID=$cid - ${newSet.size} remaining")

            // Reload the UI
            loadPendingFriendRequests()
            updateFriendRequestBadge()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove friend request by CID", e)
        }
    }

    /**
     * Update the friend request badge count
     */
    private fun updateFriendRequestBadge() {
        val rootView = findViewById<View>(android.R.id.content)
        BadgeUtils.updateFriendRequestBadge(this, rootView)
    }

    private fun downloadContactCard(cid: String, pin: String) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Downloading contact card from IPFS...")
                Log.d(TAG, "CID: $cid")
                Log.d(TAG, "PIN: $pin")

                ThemedToast.show(this@AddFriendActivity, "Downloading contact card...")

                val cardManager = ContactCardManager(this@AddFriendActivity)
                val result = withContext(Dispatchers.IO) {
                    cardManager.downloadContactCard(cid, pin)
                }

                if (result.isSuccess) {
                    val contactCard = result.getOrThrow()
                    handleContactCardDownloaded(contactCard, cid)
                } else {
                    throw result.exceptionOrNull()!!
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to download contact card", e)
                val errorMessage = when {
                    e.message?.contains("invalid PIN", ignoreCase = true) == true ||
                    e.message?.contains("decryption failed", ignoreCase = true) == true ->
                        "Invalid PIN. Please check and try again."
                    e.message?.contains("download failed", ignoreCase = true) == true ||
                    e.message?.contains("404", ignoreCase = true) == true ->
                        "Contact card not found. Check the CID."
                    else ->
                        "Failed to download contact: ${e.message}"
                }
                ThemedToast.showLong(this@AddFriendActivity, errorMessage)
            }
        }
    }

    private fun handleContactCardDownloaded(contactCard: ContactCard, cid: String) {
        Log.i(TAG, "Successfully downloaded contact card:")
        Log.i(TAG, "  Name: ${contactCard.displayName}")
        Log.i(TAG, "  Solana: ${contactCard.solanaAddress}")
        Log.i(TAG, "  Onion: ${contactCard.torOnionAddress}")

        // Save contact to encrypted database
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Step 1: Getting KeyManager instance...")
                val keyManager = KeyManager.getInstance(this@AddFriendActivity)

                Log.d(TAG, "Step 2: Getting database passphrase...")
                val dbPassphrase = keyManager.getDatabasePassphrase()
                Log.d(TAG, "Database passphrase obtained (${dbPassphrase.size} bytes)")

                Log.d(TAG, "Step 3: Getting database instance...")
                val database = SecureLegionDatabase.getInstance(this@AddFriendActivity, dbPassphrase)
                Log.d(TAG, "Database instance obtained")

                Log.d(TAG, "Step 4: Checking if contact already exists...")
                val existingContact = withContext(Dispatchers.IO) {
                    database.contactDao().getContactBySolanaAddress(contactCard.solanaAddress)
                }

                if (existingContact != null) {
                    Log.w(TAG, "Contact already exists in database")
                    ThemedToast.show(this@AddFriendActivity, "Contact already exists: ${contactCard.displayName}")
                    finish()
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
                    } else {
                        @Suppress("DEPRECATION")
                        overridePendingTransition(0, 0)
                    }
                    return@launch
                }

                Log.d(TAG, "Step 5: Check if this is accepting a friend request...")
                // Check if we have a pending friend request from this person
                val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
                val pendingRequests = prefs.getStringSet("pending_requests", mutableSetOf()) ?: mutableSetOf()
                val isAcceptingFriendRequest = pendingRequests.any { requestJson ->
                    try {
                        val request = com.securelegion.models.FriendRequest.fromJson(requestJson)
                        request.ipfsCid == cid
                    } catch (e: Exception) {
                        false
                    }
                }

                val friendshipStatus = if (isAcceptingFriendRequest) {
                    Log.i(TAG, "This is a friend request acceptance - setting status to CONFIRMED")
                    Contact.FRIENDSHIP_CONFIRMED
                } else {
                    Log.i(TAG, "This is a manual add - setting status to PENDING_SENT")
                    Contact.FRIENDSHIP_PENDING_SENT
                }

                Log.d(TAG, "Step 6: Creating Contact entity...")
                val contact = Contact(
                    displayName = contactCard.displayName,
                    solanaAddress = contactCard.solanaAddress,
                    publicKeyBase64 = Base64.encodeToString(
                        contactCard.solanaPublicKey,
                        Base64.NO_WRAP
                    ),
                    x25519PublicKeyBase64 = Base64.encodeToString(
                        contactCard.x25519PublicKey,
                        Base64.NO_WRAP
                    ),
                    torOnionAddress = contactCard.torOnionAddress,
                    addedTimestamp = System.currentTimeMillis(),
                    lastContactTimestamp = System.currentTimeMillis(),
                    trustLevel = Contact.TRUST_UNTRUSTED,
                    friendshipStatus = friendshipStatus
                )
                Log.d(TAG, "Contact entity created: ${contact.displayName} (friendshipStatus=$friendshipStatus)")

                Log.d(TAG, "Step 7: Inserting contact into database...")
                val contactId = withContext(Dispatchers.IO) {
                    database.contactDao().insertContact(contact)
                }

                Log.i(TAG, "SUCCESS! Contact saved to database with ID: $contactId")

                // Remove the friend request from pending list (if it exists)
                removeFriendRequestByCid(cid)

                // Send appropriate notification based on context
                if (isAcceptingFriendRequest) {
                    Log.i(TAG, "Sending FRIEND_REQUEST_ACCEPTED notification...")
                    sendFriendRequestAccepted(contactCard)
                } else {
                    Log.i(TAG, "Sending initial FRIEND_REQUEST...")
                    sendFriendRequest(contactCard)
                }

                ThemedToast.showLong(this@AddFriendActivity, "Contact added: ${contactCard.displayName}")

                // Navigate back to main screen (Messages view)
                val intent = Intent(this@AddFriendActivity, MainActivity::class.java)
                intent.flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
                startActivity(intent)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                    overrideActivityTransition(Activity.OVERRIDE_TRANSITION_CLOSE, 0, 0)
                } else {
                    @Suppress("DEPRECATION")
                    overridePendingTransition(0, 0)
                }
                finish()
            } catch (e: Exception) {
                Log.e(TAG, "DETAILED ERROR - Failed to save contact to database", e)
                Log.e(TAG, "Error type: ${e.javaClass.simpleName}")
                Log.e(TAG, "Error message: ${e.message}")
                Log.e(TAG, "Stack trace:", e)

                val errorMsg = when {
                    e.message?.contains("no such table") == true ->
                        "Database error: Table not created"
                    e.message?.contains("UNIQUE constraint") == true ->
                        "Contact already exists"
                    e.message != null ->
                        "Database error: ${e.message}"
                    else ->
                        "Database error: ${e.javaClass.simpleName}"
                }

                ThemedToast.showLong(this@AddFriendActivity, errorMsg)
            }
        }
    }

    /**
     * Send friend request to newly added contact
     * This notifies them that someone wants to add them as a friend
     */
    private fun sendFriendRequest(recipientContactCard: ContactCard) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Sending friend request to ${recipientContactCard.displayName}")

                // Get own account information (just username and CID)
                val keyManager = KeyManager.getInstance(this@AddFriendActivity)
                val ownDisplayName = keyManager.getUsername()
                    ?: throw Exception("Username not set")
                val ownCid = keyManager.getContactCardCid()
                    ?: throw Exception("Contact card CID not found")

                // Create friend request object (minimal data: username + CID only)
                val friendRequest = com.securelegion.models.FriendRequest(
                    displayName = ownDisplayName,
                    ipfsCid = ownCid
                )

                // Serialize to JSON
                val friendRequestJson = friendRequest.toJson()
                Log.d(TAG, "Friend request JSON: $friendRequestJson")

                // Encrypt the friend request using recipient's X25519 public key
                // Wire format: [Sender X25519 - 32 bytes][Encrypted Friend Request]
                // Note: Rust sendFriendRequest adds the 0x07 wire type byte automatically
                val encryptedFriendRequest = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.encryptMessage(
                        plaintext = friendRequestJson,
                        recipientX25519PublicKey = recipientContactCard.x25519PublicKey
                    )
                }

                // Send via Tor using fire-and-forget friend request function
                // Rust will add wire type 0x07 during transmission
                val success = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.sendFriendRequest(
                        recipientOnion = recipientContactCard.torOnionAddress,
                        encryptedFriendRequest = encryptedFriendRequest
                    )
                }

                if (success) {
                    Log.i(TAG, "Friend request sent successfully to ${recipientContactCard.displayName}")
                } else {
                    Log.w(TAG, "Failed to send friend request to ${recipientContactCard.displayName} (recipient may be offline)")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error sending friend request", e)
                // Don't show error to user - friend request sending is best-effort
                // The important part is that we added them to our contacts
            }
        }
    }

    /**
     * Send friend request accepted notification
     * Notifies the original requester that we've accepted their request
     */
    private fun sendFriendRequestAccepted(recipientContactCard: ContactCard) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Sending friend request accepted notification to ${recipientContactCard.displayName}")

                // Get own account information (just username and CID)
                val keyManager = KeyManager.getInstance(this@AddFriendActivity)
                val ownDisplayName = keyManager.getUsername()
                    ?: throw Exception("Username not set")
                val ownCid = keyManager.getContactCardCid()
                    ?: throw Exception("Contact card CID not found")

                // Create acceptance notification (same format as friend request for simplicity)
                val acceptance = com.securelegion.models.FriendRequest(
                    displayName = ownDisplayName,
                    ipfsCid = ownCid
                )

                // Serialize to JSON
                val acceptanceJson = acceptance.toJson()
                Log.d(TAG, "Acceptance notification JSON: $acceptanceJson")

                // Encrypt the acceptance using recipient's X25519 public key
                val encryptedAcceptance = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.encryptMessage(
                        plaintext = acceptanceJson,
                        recipientX25519PublicKey = recipientContactCard.x25519PublicKey
                    )
                }

                // Send via Tor using fire-and-forget acceptance function
                // Rust will add wire type 0x08 during transmission
                val success = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.sendFriendRequestAccepted(
                        recipientOnion = recipientContactCard.torOnionAddress,
                        encryptedAcceptance = encryptedAcceptance
                    )
                }

                if (success) {
                    Log.i(TAG, "Friend request accepted notification sent successfully to ${recipientContactCard.displayName}")
                } else {
                    Log.w(TAG, "Failed to send acceptance notification to ${recipientContactCard.displayName} (recipient may be offline)")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error sending friend request accepted notification", e)
                // Don't show error to user - notification sending is best-effort
            }
        }
    }

    private fun setupBottomNav() {
        findViewById<View>(R.id.navMessages).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navWallet).setOnClickListener {
            val intent = Intent(this, MainActivity::class.java)
            intent.putExtra("SHOW_WALLET", true)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }

        findViewById<View>(R.id.navAddFriend).setOnClickListener {
            // Already on Add Friend screen, do nothing
        }

        findViewById<View>(R.id.navLock).setOnClickListener {
            val intent = Intent(this, LockActivity::class.java)
            startActivity(intent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                overrideActivityTransition(Activity.OVERRIDE_TRANSITION_OPEN, 0, 0)
            } else {
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
            }
            finish()
        }
    }
}
