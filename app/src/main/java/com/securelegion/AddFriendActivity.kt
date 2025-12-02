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
import android.widget.FrameLayout
import android.widget.TextView
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

    private lateinit var loadingOverlay: FrameLayout
    private lateinit var loadingText: TextView
    private lateinit var loadingSubtext: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_friend)

        // Initialize loading overlay
        loadingOverlay = findViewById(R.id.loadingOverlay)
        loadingText = findViewById(R.id.loadingText)
        loadingSubtext = findViewById(R.id.loadingSubtext)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            finish()
        }

        // Setup PIN boxes with auto-advance
        setupPinBoxes()

        // Send Friend Request button (CID + PIN required)
        findViewById<View>(R.id.searchButton).setOnClickListener {
            val cid = findViewById<EditText>(R.id.cidInput).text.toString().trim()
            val pin = getPinFromBoxes().trim()

            if (cid.isEmpty()) {
                ThemedToast.show(this, "Please enter CID")
                return@setOnClickListener
            }

            if (pin.length != 6) {
                ThemedToast.show(this, "Please enter 6-digit PIN")
                return@setOnClickListener
            }

            if (!pin.all { it.isDigit() }) {
                ThemedToast.show(this, "PIN must be 6 digits")
                return@setOnClickListener
            }

            // Check if this is accepting an incoming request
            val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsV2 = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()
            val isAccepting = pendingRequestsV2.any { requestJson ->
                try {
                    val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    request.ipfsCid == cid && request.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING
                } catch (e: Exception) {
                    false
                }
            }

            downloadContactCard(cid, pin, isAccepting)
        }

        setupBottomNav()
    }

    private fun setupPinBoxes() {
        val pinBox1 = findViewById<EditText>(R.id.pinBox1)
        val pinBox2 = findViewById<EditText>(R.id.pinBox2)
        val pinBox3 = findViewById<EditText>(R.id.pinBox3)
        val pinBox4 = findViewById<EditText>(R.id.pinBox4)
        val pinBox5 = findViewById<EditText>(R.id.pinBox5)
        val pinBox6 = findViewById<EditText>(R.id.pinBox6)

        // Auto-advance to next box when digit is entered
        pinBox1.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox2.requestFocus()
            }
        })

        pinBox2.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox3.requestFocus()
                else if (s?.isEmpty() == true) pinBox1.requestFocus()
            }
        })

        pinBox3.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox4.requestFocus()
                else if (s?.isEmpty() == true) pinBox2.requestFocus()
            }
        })

        pinBox4.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox5.requestFocus()
                else if (s?.isEmpty() == true) pinBox3.requestFocus()
            }
        })

        pinBox5.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox6.requestFocus()
                else if (s?.isEmpty() == true) pinBox4.requestFocus()
            }
        })

        pinBox6.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.isEmpty() == true) pinBox5.requestFocus()
            }
        })
    }

    private fun getPinFromBoxes(): String {
        val pinBox1 = findViewById<EditText>(R.id.pinBox1).text.toString()
        val pinBox2 = findViewById<EditText>(R.id.pinBox2).text.toString()
        val pinBox3 = findViewById<EditText>(R.id.pinBox3).text.toString()
        val pinBox4 = findViewById<EditText>(R.id.pinBox4).text.toString()
        val pinBox5 = findViewById<EditText>(R.id.pinBox5).text.toString()
        val pinBox6 = findViewById<EditText>(R.id.pinBox6).text.toString()

        return pinBox1 + pinBox2 + pinBox3 + pinBox4 + pinBox5 + pinBox6
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
            val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

            Log.d(TAG, "Loading pending friend requests: ${pendingRequestsSet.size} requests")

            // Parse pending requests (new format with direction and status)
            val pendingRequests = mutableListOf<com.securelegion.models.PendingFriendRequest>()
            for (requestJson in pendingRequestsSet) {
                try {
                    val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    pendingRequests.add(request)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse pending request: $requestJson", e)
                }
            }

            // Also check for old format incoming requests and migrate them
            val oldRequestsSet = prefs.getStringSet("pending_requests", mutableSetOf()) ?: mutableSetOf()
            for (requestJson in oldRequestsSet) {
                try {
                    val oldRequest = FriendRequest.fromJson(requestJson)
                    // Convert to new format as incoming request
                    val newRequest = com.securelegion.models.PendingFriendRequest(
                        displayName = oldRequest.displayName,
                        ipfsCid = oldRequest.ipfsCid,
                        direction = com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING,
                        status = com.securelegion.models.PendingFriendRequest.STATUS_PENDING,
                        timestamp = oldRequest.timestamp
                    )
                    pendingRequests.add(newRequest)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to parse old request: $requestJson", e)
                }
            }

            // Deduplicate based on CID
            val uniqueRequests = pendingRequests.distinctBy { it.ipfsCid }

            Log.d(TAG, "Loaded ${uniqueRequests.size} unique pending friend requests")

            // Display friend requests in UI
            displayFriendRequests(uniqueRequests)

        } catch (e: Exception) {
            Log.e(TAG, "Failed to load pending friend requests", e)
        }
    }

    /**
     * Display friend requests in the UI
     */
    private fun displayFriendRequests(friendRequests: List<com.securelegion.models.PendingFriendRequest>) {
        val requestsContainer = findViewById<View>(R.id.friendRequestsContainer)
        val requestsList = findViewById<android.widget.LinearLayout>(R.id.friendRequestsList)

        // Clear existing views
        requestsList.removeAllViews()

        if (friendRequests.isEmpty()) {
            requestsContainer.visibility = View.GONE
            return
        }

        requestsContainer.visibility = View.VISIBLE

        // Add each friend request using the new layout
        for (friendRequest in friendRequests) {
            val requestView = layoutInflater.inflate(R.layout.item_friend_request, requestsList, false)

            val requestName = requestView.findViewById<android.widget.TextView>(R.id.requestName)
            val requestStatus = requestView.findViewById<android.widget.TextView>(R.id.requestStatus)
            val requestMenu = requestView.findViewById<android.widget.ImageView>(R.id.requestMenu)

            // Set name (remove @ prefix)
            requestName.text = friendRequest.displayName.removePrefix("@")

            // Set status based on direction and status
            when {
                friendRequest.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING -> {
                    requestStatus.text = "Accept"
                    requestStatus.setTextColor(getColor(R.color.text_gray))
                }
                friendRequest.status == com.securelegion.models.PendingFriendRequest.STATUS_FAILED -> {
                    requestStatus.text = "Retry"
                    requestStatus.setTextColor(getColor(android.R.color.holo_orange_light))
                }
                else -> {
                    requestStatus.text = "Pending"
                    requestStatus.setTextColor(getColor(R.color.text_gray))
                }
            }

            // Handle status badge click
            requestStatus.setOnClickListener {
                if (friendRequest.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING) {
                    // Outgoing request - resend using saved ContactCard
                    resendFriendRequest(friendRequest)
                } else {
                    // Incoming request - auto-fill CID for acceptance
                    val cidInput = findViewById<EditText>(R.id.cidInput)
                    cidInput.setText(friendRequest.ipfsCid)

                    // Disable the Accept button
                    requestStatus.isEnabled = false
                    requestStatus.alpha = 0.5f

                    // Change main button text to "Accept Friend Request"
                    val mainButton = findViewById<TextView>(R.id.searchButton)
                    mainButton.text = "Accept Friend Request"

                    val scrollView = findViewById<android.widget.ScrollView>(R.id.addFriendScrollView)
                    scrollView?.post {
                        scrollView.smoothScrollTo(0, 0)
                    }

                    val pinBox1 = findViewById<EditText>(R.id.pinBox1)
                    pinBox1.requestFocus()

                    val inputMethodManager = getSystemService(android.view.inputmethod.InputMethodManager::class.java)
                    inputMethodManager.showSoftInput(pinBox1, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)

                    ThemedToast.show(this, "CID auto-filled. Enter their PIN to accept friend request")
                }
            }

            // Handle card click - auto-fill CID field
            requestView.setOnClickListener {
                val cidInput = findViewById<EditText>(R.id.cidInput)
                cidInput.setText(friendRequest.ipfsCid)

                // If incoming request, disable Accept button and update main button
                if (friendRequest.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING) {
                    requestStatus.isEnabled = false
                    requestStatus.alpha = 0.5f

                    val mainButton = findViewById<TextView>(R.id.searchButton)
                    mainButton.text = "Accept Friend Request"
                }

                val scrollView = findViewById<android.widget.ScrollView>(R.id.addFriendScrollView)
                scrollView?.post {
                    scrollView.smoothScrollTo(0, 0)
                }

                val pinBox1 = findViewById<EditText>(R.id.pinBox1)
                pinBox1.requestFocus()

                val inputMethodManager = getSystemService(android.view.inputmethod.InputMethodManager::class.java)
                inputMethodManager.showSoftInput(pinBox1, android.view.inputmethod.InputMethodManager.SHOW_IMPLICIT)

                val statusText = if (friendRequest.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING) {
                    "CID auto-filled. Enter their PIN to accept friend request"
                } else {
                    "CID auto-filled. Enter PIN to complete request"
                }
                ThemedToast.show(this, statusText)
            }

            // Handle menu click - show delete option
            requestMenu.setOnClickListener {
                androidx.appcompat.app.AlertDialog.Builder(this, R.style.CustomAlertDialog)
                    .setTitle("Delete Request")
                    .setMessage("Remove this friend request?")
                    .setPositiveButton("Delete") { _, _ ->
                        removePendingFriendRequest(friendRequest)
                    }
                    .setNegativeButton("Cancel", null)
                    .show()
            }

            requestsList.addView(requestView)
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

    private fun showLoading(text: String, subtext: String = "Please wait") {
        loadingText.text = text
        loadingSubtext.text = subtext
        loadingOverlay.visibility = View.VISIBLE
    }

    private fun hideLoading() {
        loadingOverlay.visibility = View.GONE
    }

    private fun downloadContactCard(cid: String, pin: String, isAccepting: Boolean = false) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Downloading contact card from IPFS...")
                Log.d(TAG, "CID: $cid")
                Log.d(TAG, "PIN: $pin")

                val loadingText = if (isAccepting) "Accepting friend request..." else "Sending request..."
                showLoading(loadingText)

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
                hideLoading()
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
                    hideLoading()
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
                // Check if we have a pending INCOMING friend request from this person
                val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)

                // Check new format
                val pendingRequestsV2 = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()
                val incomingRequest = pendingRequestsV2.mapNotNull { requestJson ->
                    try {
                        com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    } catch (e: Exception) {
                        null
                    }
                }.find {
                    it.ipfsCid == cid &&
                    it.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING
                }

                // Also check old format for backwards compatibility
                val oldRequests = prefs.getStringSet("pending_requests", mutableSetOf()) ?: mutableSetOf()
                val hasOldIncomingRequest = oldRequests.any { requestJson ->
                    try {
                        val request = com.securelegion.models.FriendRequest.fromJson(requestJson)
                        request.ipfsCid == cid
                    } catch (e: Exception) {
                        false
                    }
                }

                val isAcceptingFriendRequest = (incomingRequest != null) || hasOldIncomingRequest
                Log.d(TAG, "Is accepting friend request: $isAcceptingFriendRequest")

                if (isAcceptingFriendRequest) {
                    // Accepting an incoming request - add to Contacts immediately
                    Log.d(TAG, "Step 6: Adding to Contacts (mutual friends)...")
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
                        friendshipStatus = Contact.FRIENDSHIP_CONFIRMED
                    )

                    val contactId = withContext(Dispatchers.IO) {
                        database.contactDao().insertContact(contact)
                    }

                    Log.i(TAG, "SUCCESS! Contact added with ID: $contactId")

                    // Remove the incoming request from pending
                    removeFriendRequestByCid(cid)

                    // Send acceptance notification
                    Log.i(TAG, "Sending FRIEND_REQUEST_ACCEPTED notification...")
                    sendFriendRequestAccepted(contactCard)

                    ThemedToast.showLong(this@AddFriendActivity, "Contact added: ${contactCard.displayName}")
                } else {
                    // Initiating a friend request - save to pending (NOT Contacts yet)
                    Log.d(TAG, "Step 6: Saving to pending outgoing requests (NOT adding to Contacts)...")

                    val pendingRequest = com.securelegion.models.PendingFriendRequest(
                        displayName = contactCard.displayName,
                        ipfsCid = cid,
                        direction = com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING,
                        status = com.securelegion.models.PendingFriendRequest.STATUS_PENDING,
                        timestamp = System.currentTimeMillis(),
                        contactCardJson = contactCard.toJson() // Save contact card for later
                    )

                    // Save to pending requests
                    savePendingFriendRequest(pendingRequest)

                    // Send friend request notification
                    Log.i(TAG, "Sending initial FRIEND_REQUEST...")
                    sendFriendRequest(contactCard)

                    ThemedToast.showLong(this@AddFriendActivity, "Friend request sent to ${contactCard.displayName}. Waiting for acceptance.")
                }

                hideLoading()

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

                hideLoading()
                ThemedToast.showLong(this@AddFriendActivity, errorMsg)

                // Navigate back to main screen even on error
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

                // Check if Tor is ready before attempting to send
                if (!com.securelegion.services.TorService.isMessagingReady()) {
                    Log.w(TAG, "Tor not ready - cannot send friend request. Will retry when Tor connects.")
                    ThemedToast.show(this@AddFriendActivity, "Tor not ready. Friend request will be sent when connected.")
                    return@launch
                }

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
     * Resend friend request from pending request (retry functionality)
     * Uses saved ContactCard data - no PIN needed, no re-download
     */
    private fun resendFriendRequest(pendingRequest: com.securelegion.models.PendingFriendRequest) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                Log.d(TAG, "Resending friend request to ${pendingRequest.displayName}")

                // Check if Tor is ready before attempting to send
                if (!com.securelegion.services.TorService.isMessagingReady()) {
                    Log.w(TAG, "Tor not ready - cannot resend friend request")
                    ThemedToast.showLong(this@AddFriendActivity, "Tor not ready. Please wait and try again.")
                    return@launch
                }

                // Check if we have saved ContactCard data
                if (pendingRequest.contactCardJson == null) {
                    ThemedToast.showLong(this@AddFriendActivity, "Cannot resend: Contact card data missing")
                    Log.e(TAG, "No ContactCard data saved with pending request")
                    return@launch
                }

                // Parse saved ContactCard
                val recipientContactCard = try {
                    com.securelegion.models.ContactCard.fromJson(pendingRequest.contactCardJson)
                } catch (e: Exception) {
                    ThemedToast.showLong(this@AddFriendActivity, "Cannot resend: Invalid contact card data")
                    Log.e(TAG, "Failed to parse saved ContactCard", e)
                    return@launch
                }

                // Get own account information
                val keyManager = KeyManager.getInstance(this@AddFriendActivity)
                val ownDisplayName = keyManager.getUsername()
                    ?: throw Exception("Username not set")
                val ownCid = keyManager.getContactCardCid()
                    ?: throw Exception("Contact card CID not found")

                // Create friend request object
                val friendRequest = com.securelegion.models.FriendRequest(
                    displayName = ownDisplayName,
                    ipfsCid = ownCid
                )

                // Serialize to JSON
                val friendRequestJson = friendRequest.toJson()

                // Encrypt the friend request using recipient's X25519 public key
                val encryptedFriendRequest = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.encryptMessage(
                        plaintext = friendRequestJson,
                        recipientX25519PublicKey = recipientContactCard.x25519PublicKey
                    )
                }

                // Send via Tor
                val success = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.sendFriendRequest(
                        recipientOnion = recipientContactCard.torOnionAddress,
                        encryptedFriendRequest = encryptedFriendRequest
                    )
                }

                if (success) {
                    Log.i(TAG, "Friend request resent successfully to ${recipientContactCard.displayName}")
                    ThemedToast.show(this@AddFriendActivity, "Friend request resent to ${pendingRequest.displayName}")
                } else {
                    Log.w(TAG, "Failed to resend friend request to ${recipientContactCard.displayName} (recipient may be offline)")
                    ThemedToast.showLong(this@AddFriendActivity, "Send failed - recipient may be offline. Try again later.")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error resending friend request", e)
                ThemedToast.showLong(this@AddFriendActivity, "Failed to resend friend request")
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

    /**
     * Save pending friend request to SharedPreferences
     */
    private fun savePendingFriendRequest(request: com.securelegion.models.PendingFriendRequest) {
        try {
            val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

            // Add new request
            val newSet = pendingRequestsSet.toMutableSet()
            newSet.add(request.toJson())

            prefs.edit()
                .putStringSet("pending_requests_v2", newSet)
                .apply()

            Log.d(TAG, "Saved pending friend request for ${request.displayName}")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to save pending friend request", e)
        }
    }

    /**
     * Remove pending friend request from SharedPreferences
     */
    private fun removePendingFriendRequest(request: com.securelegion.models.PendingFriendRequest) {
        try {
            val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

            // Rebuild set without this request
            val newSet = mutableSetOf<String>()
            for (requestJson in pendingRequestsSet) {
                val existingRequest = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)

                // Keep all requests except the one we're removing
                if (existingRequest.ipfsCid != request.ipfsCid) {
                    newSet.add(requestJson)
                }
            }

            prefs.edit()
                .putStringSet("pending_requests_v2", newSet)
                .apply()

            Log.d(TAG, "Removed pending friend request for ${request.displayName}")

            // Reload the UI
            loadPendingFriendRequests()
            updateFriendRequestBadge()

        } catch (e: Exception) {
            Log.e(TAG, "Failed to remove pending friend request", e)
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
