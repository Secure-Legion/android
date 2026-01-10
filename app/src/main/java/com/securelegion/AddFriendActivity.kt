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
        private const val QR_SCAN_REQUEST_CODE = 1001
    }

    private lateinit var loadingOverlay: FrameLayout
    private lateinit var loadingText: TextView
    private lateinit var loadingSubtext: TextView
    private var isDeleteMode = false
    private val selectedRequests = mutableSetOf<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_add_friend)

        // Initialize loading overlay
        loadingOverlay = findViewById(R.id.loadingOverlay)
        loadingText = findViewById(R.id.loadingText)
        loadingSubtext = findViewById(R.id.loadingSubtext)

        // Back button
        findViewById<View>(R.id.backButton).setOnClickListener {
            if (isDeleteMode) {
                exitDeleteMode()
            } else {
                finish()
            }
        }

        // Delete button
        findViewById<View>(R.id.deleteButton).setOnClickListener {
            if (isDeleteMode) {
                deleteSelectedRequests()
            } else {
                enterDeleteMode()
            }
        }

        // Scan QR button
        findViewById<View>(R.id.scanQrButton).setOnClickListener {
            val intent = Intent(this, QRScannerActivity::class.java)
            startActivityForResult(intent, QR_SCAN_REQUEST_CODE)
        }

        // Setup PIN boxes with auto-advance
        setupPinBoxes()

        // Send Friend Request button
        findViewById<View>(R.id.searchButton).setOnClickListener {
            val friendOnion = findViewById<EditText>(R.id.cidInput).text.toString().trim()
            val friendPin = getPinFromBoxes().trim()

            if (friendOnion.isEmpty()) {
                ThemedToast.show(this, "Please enter friend's .onion address")
                return@setOnClickListener
            }

            if (friendPin.length != 10) {
                ThemedToast.show(this, "Please enter 10-digit PIN")
                return@setOnClickListener
            }

            if (!friendPin.all { it.isDigit() }) {
                ThemedToast.show(this, "PIN must be 10 digits")
                return@setOnClickListener
            }

            // Check if we're accepting an incoming Phase 1 friend request
            val mainButton = findViewById<TextView>(R.id.searchButton)
            if (mainButton.text.toString() == "Accept Friend Request") {
                // PHASE 2: Accept incoming friend request
                acceptPhase2FriendRequest(friendOnion, friendPin)
            } else {
                // PHASE 1: Initiate friend request by sending YOUR contact card to the friend
                initiateFriendRequest(friendOnion, friendPin)
            }
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
        val pinBox7 = findViewById<EditText>(R.id.pinBox7)
        val pinBox8 = findViewById<EditText>(R.id.pinBox8)
        val pinBox9 = findViewById<EditText>(R.id.pinBox9)
        val pinBox10 = findViewById<EditText>(R.id.pinBox10)

        // Add key listener to handle backspace (moves to previous box and deletes)
        val boxes = listOf(pinBox1, pinBox2, pinBox3, pinBox4, pinBox5, pinBox6, pinBox7, pinBox8, pinBox9, pinBox10)

        boxes.forEachIndexed { index, box ->
            box.setOnKeyListener { _, keyCode, event ->
                if (keyCode == android.view.KeyEvent.KEYCODE_DEL && event.action == android.view.KeyEvent.ACTION_DOWN) {
                    if (box.text.isEmpty() && index > 0) {
                        // If current box is empty and backspace pressed, move to previous box and clear it
                        boxes[index - 1].text.clear()
                        boxes[index - 1].requestFocus()
                        return@setOnKeyListener true
                    }
                }
                false
            }
        }

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
            }
        })

        pinBox3.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox4.requestFocus()
            }
        })

        pinBox4.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox5.requestFocus()
            }
        })

        pinBox5.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox6.requestFocus()
            }
        })

        pinBox6.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox7.requestFocus()
            }
        })

        pinBox7.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox8.requestFocus()
            }
        })

        pinBox8.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox9.requestFocus()
            }
        })

        pinBox9.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                if (s?.length == 1) pinBox10.requestFocus()
            }
        })

        pinBox10.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                // Last box - no auto-advance
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
        val pinBox7 = findViewById<EditText>(R.id.pinBox7).text.toString()
        val pinBox8 = findViewById<EditText>(R.id.pinBox8).text.toString()
        val pinBox9 = findViewById<EditText>(R.id.pinBox9).text.toString()
        val pinBox10 = findViewById<EditText>(R.id.pinBox10).text.toString()

        return pinBox1 + pinBox2 + pinBox3 + pinBox4 + pinBox5 + pinBox6 + pinBox7 + pinBox8 + pinBox9 + pinBox10
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == QR_SCAN_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            val scannedData = data?.getStringExtra("SCANNED_ADDRESS")
            if (!scannedData.isNullOrEmpty()) {
                // Populate the friend request .onion address field
                findViewById<EditText>(R.id.cidInput).setText(scannedData)
                ThemedToast.show(this, "Scanned friend request address")
                Log.i(TAG, "QR code scanned: $scannedData")
            }
        }
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
        val deleteButton = findViewById<View>(R.id.deleteButton)

        // Clear existing views
        requestsList.removeAllViews()

        if (friendRequests.isEmpty()) {
            requestsContainer.visibility = View.GONE
            deleteButton.visibility = View.GONE
            return
        }

        requestsContainer.visibility = View.VISIBLE
        deleteButton.visibility = View.VISIBLE

        // Add each friend request using the new layout
        for (friendRequest in friendRequests) {
            val requestView = layoutInflater.inflate(R.layout.item_friend_request, requestsList, false)

            val requestName = requestView.findViewById<android.widget.TextView>(R.id.requestName)
            val requestStatus = requestView.findViewById<android.widget.TextView>(R.id.requestStatus)
            val requestContainer = requestView.findViewById<View>(R.id.requestContainer)
            val requestCheckbox = requestView.findViewById<android.widget.CheckBox>(R.id.requestCheckbox)

            // Set name (remove @ prefix)
            requestName.text = friendRequest.displayName.removePrefix("@")

            // Handle checkbox clicks
            requestCheckbox.setOnCheckedChangeListener { _, isChecked ->
                if (isChecked) {
                    selectedRequests.add(friendRequest.ipfsCid)
                } else {
                    selectedRequests.remove(friendRequest.ipfsCid)
                }
            }

            // Show checkbox if in delete mode
            if (isDeleteMode) {
                requestCheckbox.visibility = View.VISIBLE
            } else {
                requestCheckbox.visibility = View.GONE
            }

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

                    ThemedToast.show(this, "Friend request from ${friendRequest.displayName}. Enter PIN to accept")
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

            // Menu removed - deletion now handled via delete mode

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
        // Note: downloadContactCard will automatically call removeFriendRequestByCid()
        // when the download completes successfully, which will refresh the UI
        downloadContactCard(friendRequest.ipfsCid, pin)
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
            val pendingRequestsV2 = prefs.getStringSet("pending_requests_v2", mutableSetOf())?.toMutableSet() ?: mutableSetOf()

            // Remove requests matching this CID
            val updatedRequests = pendingRequestsV2.filter { requestJson ->
                try {
                    val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    request.ipfsCid != cid  // Keep if CID doesn't match
                } catch (e: Exception) {
                    true // Keep if can't parse
                }
            }.toMutableSet()

            // Save updated set
            prefs.edit()
                .putStringSet("pending_requests_v2", updatedRequests)
                .apply()

            Log.d(TAG, "Removed friend request with CID=$cid - ${updatedRequests.size} remaining")

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

    private fun downloadContactCard(cidOrOnion: String, pin: String, isAccepting: Boolean = false) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                // Detect if input is .onion address (v2.0) or IPFS CID (v1.0)
                val isOnion = cidOrOnion.endsWith(".onion")

                if (isOnion) {
                    Log.d(TAG, "Downloading contact card via Tor from .onion address...")
                    Log.d(TAG, "Friend Request .onion: $cidOrOnion")
                } else {
                    Log.d(TAG, "Downloading contact card from IPFS...")
                    Log.d(TAG, "CID: $cidOrOnion")
                }
                Log.d(TAG, "PIN: $pin")

                val loadingText = if (isAccepting) "Accepting friend request..." else "Downloading contact card..."
                val loadingSubtext = if (isOnion) "Connecting via Tor..." else "Downloading from IPFS..."
                showLoading(loadingText, loadingSubtext)

                val cardManager = ContactCardManager(this@AddFriendActivity)
                val result = withContext(Dispatchers.IO) {
                    if (isOnion) {
                        // v2.0: Download via Tor .onion address
                        cardManager.downloadContactCardViaTor(cidOrOnion, pin)
                    } else {
                        // v1.0: Download via IPFS CID
                        cardManager.downloadContactCard(cidOrOnion, pin)
                    }
                }

                if (result.isSuccess) {
                    val contactCard = result.getOrThrow()
                    handleContactCardDownloaded(contactCard, cidOrOnion, pin)
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
                    e.message?.contains("404", ignoreCase = true) == true ||
                    e.message?.contains("no response", ignoreCase = true) == true ->
                        "Could not reach contact. They may be offline."
                    e.message?.contains("SOCKS5", ignoreCase = true) == true ||
                    e.message?.contains("Tor", ignoreCase = true) == true ->
                        "Tor connection failed. Check network settings."
                    else ->
                        "Failed to download contact: ${e.message}"
                }
                ThemedToast.showLong(this@AddFriendActivity, errorMessage)
            }
        }
    }

    private fun handleContactCardDownloaded(contactCard: ContactCard, cid: String, pin: String) {
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

                // Step 4.5: IPFS Contact List Backup (v5 architecture)
                // After adding a friend, backup our updated contact list to IPFS mesh
                Log.d(TAG, "Step 4.5: Backing up contact list to IPFS mesh...")
                try {
                    val contactListManager = com.securelegion.services.ContactListManager.getInstance(this@AddFriendActivity)

                    // Backup our own contact list (now includes this new friend)
                    Log.d(TAG, "⬆ Starting OUR contact list backup...")
                    val backupResult = contactListManager.backupToIPFS()
                    if (backupResult.isSuccess) {
                        val ourCID = backupResult.getOrThrow()
                        Log.i(TAG, "✓✓✓ SUCCESS: OUR contact list backed up to IPFS: $ourCID")
                        Log.i(TAG, "  Friends can now fetch it via: http://[our-onion]/contact-list/$ourCID")
                    } else {
                        Log.e(TAG, "❌ FAILED to backup OUR contact list: ${backupResult.exceptionOrNull()?.message}")
                        backupResult.exceptionOrNull()?.printStackTrace()
                    }

                    // Pin friend's contact list for redundancy (v5 architecture)
                    // Fetch friend's contact list via their .onion HTTP and pin it locally
                    if (contactCard.ipfsCid != null) {
                        Log.d(TAG, "⬇ Starting contact list pinning for ${contactCard.displayName}")
                        Log.d(TAG, "  Friend's contact list CID: ${contactCard.ipfsCid}")
                        Log.d(TAG, "  Friend's .onion: ${contactCard.friendRequestOnion}")

                        val ipfsManager = com.securelegion.services.IPFSManager.getInstance(this@AddFriendActivity)
                        val pinResult = ipfsManager.pinFriendContactList(
                            friendCID = contactCard.ipfsCid,
                            displayName = contactCard.displayName,
                            friendOnion = contactCard.friendRequestOnion // Fetch via friend's .onion
                        )
                        if (pinResult.isSuccess) {
                            Log.i(TAG, "✓✓✓ SUCCESS: Pinned ${contactCard.displayName}'s contact list")
                        } else {
                            Log.e(TAG, "❌ FAILED to pin ${contactCard.displayName}'s contact list: ${pinResult.exceptionOrNull()?.message}")
                        }
                    } else {
                        Log.w(TAG, "⚠ Friend's contact list CID is NULL - cannot pin (they may be using old version)")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Non-critical error during contact list backup", e)
                    // Don't fail the entire friend add process if backup fails
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
                        kyberPublicKeyBase64 = Base64.encodeToString(
                            contactCard.kyberPublicKey,
                            Base64.NO_WRAP
                        ),
                        torOnionAddress = contactCard.torOnionAddress,
                        voiceOnion = contactCard.voiceOnion,
                        addedTimestamp = System.currentTimeMillis(),
                        lastContactTimestamp = System.currentTimeMillis(),
                        trustLevel = Contact.TRUST_UNTRUSTED,
                        friendshipStatus = Contact.FRIENDSHIP_CONFIRMED
                    )

                    val contactId = withContext(Dispatchers.IO) {
                        database.contactDao().insertContact(contact)
                    }

                    Log.i(TAG, "SUCCESS! Contact added with ID: $contactId")

                    // Initialize key chain for progressive ephemeral key evolution
                    try {
                        val keyManager = com.securelegion.crypto.KeyManager.getInstance(this@AddFriendActivity)
                        val ourMessagingOnion = keyManager.getMessagingOnion()
                        val theirMessagingOnion = contact.messagingOnion ?: contactCard.messagingOnion

                        if (ourMessagingOnion.isNullOrEmpty() || theirMessagingOnion.isNullOrEmpty()) {
                            Log.e(TAG, "Cannot initialize key chain: missing onion address (ours=$ourMessagingOnion, theirs=$theirMessagingOnion) for ${contact.displayName}")
                        } else {
                            com.securelegion.crypto.KeyChainManager.initializeKeyChain(
                                context = this@AddFriendActivity,
                                contactId = contactId,
                                theirX25519PublicKey = contactCard.x25519PublicKey,
                                theirKyberPublicKey = contactCard.kyberPublicKey,
                                ourMessagingOnion = ourMessagingOnion,
                                theirMessagingOnion = theirMessagingOnion
                            )
                            Log.i(TAG, "✓ Key chain initialized for ${contact.displayName}")
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to initialize key chain for ${contact.displayName}", e)
                    }

                    // Remove the incoming request from pending
                    removeFriendRequestByCid(cid)

                    // NOTE: OLD v1.0 friend request notification removed - use NEW Phase 1/2/2b flow instead
                    Log.i(TAG, "Contact added successfully (manual download flow)")
                    // TODO: Consider removing this entire manual download flow in favor of Phase 1/2/2b

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

                    // NOTE: OLD v1.0 friend request notification removed - use NEW Phase 1/2/2b flow instead
                    Log.i(TAG, "Contact card saved to pending (manual download flow)")
                    // TODO: Consider removing this entire manual download flow in favor of Phase 1/2/2b

                    ThemedToast.showLong(this@AddFriendActivity, "Contact card saved. Use Phase 1 flow to send friend request.")
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
     * PHASE 2: Accept incoming friend request
     * Decrypts Phase 1 payload, sends full contact card encrypted with sender's X25519 key
     */
    private fun acceptPhase2FriendRequest(senderOnion: String, senderPin: String) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                // Sanitize .onion address - remove https://, http://, and trailing slashes
                val sanitizedOnion = senderOnion
                    .replace("https://", "", ignoreCase = true)
                    .replace("http://", "", ignoreCase = true)
                    .removeSuffix("/")
                    .trim()

                showLoading("Accepting friend request...")
                Log.d(TAG, "Phase 2: Accepting friend request from: $sanitizedOnion (original: $senderOnion)")

                // Find the pending incoming request by onion address (stored in ipfsCid field for v2.0)
                val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
                val pendingRequestsSet = prefs.getStringSet("pending_requests_v2", mutableSetOf()) ?: mutableSetOf()

                val incomingRequest = pendingRequestsSet.mapNotNull { requestJson ->
                    try {
                        com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    } catch (e: Exception) {
                        null
                    }
                }.find {
                    it.direction == com.securelegion.models.PendingFriendRequest.DIRECTION_INCOMING &&
                    it.contactCardJson != null  // Must have Phase 1 encrypted data
                }

                if (incomingRequest == null || incomingRequest.contactCardJson == null) {
                    hideLoading()
                    ThemedToast.show(this@AddFriendActivity, "No pending friend request found")
                    return@launch
                }

                Log.d(TAG, "Found incoming request, loading Phase 1 payload...")

                // Phase 1 is already decrypted by TorService - just use the JSON directly
                val phase1Json = incomingRequest.contactCardJson ?: throw Exception("No Phase 1 data")

                Log.d(TAG, "Loaded Phase 1: $phase1Json")

                // Parse Phase 1 payload
                val phase1Obj = org.json.JSONObject(phase1Json)
                val senderUsername = phase1Obj.getString("username")
                val senderFriendRequestOnion = phase1Obj.getString("friend_request_onion")
                val senderX25519PublicKeyBase64 = phase1Obj.getString("x25519_public_key")
                val senderX25519PublicKey = Base64.decode(senderX25519PublicKeyBase64, Base64.NO_WRAP)

                // Extract Kyber public key (for quantum resistance)
                val senderKyberPublicKey = if (phase1Obj.has("kyber_public_key")) {
                    Base64.decode(phase1Obj.getString("kyber_public_key"), Base64.NO_WRAP)
                } else {
                    null
                }

                // Verify Ed25519 signature (defense-in-depth against .onion MitM)
                if (phase1Obj.has("signature") && phase1Obj.has("ed25519_public_key")) {
                    val signature = Base64.decode(phase1Obj.getString("signature"), Base64.NO_WRAP)
                    val senderEd25519PublicKey = Base64.decode(phase1Obj.getString("ed25519_public_key"), Base64.NO_WRAP)

                    // Reconstruct unsigned JSON to verify signature
                    val unsignedJson = org.json.JSONObject().apply {
                        put("username", senderUsername)
                        put("friend_request_onion", senderFriendRequestOnion)
                        put("x25519_public_key", senderX25519PublicKeyBase64)
                        put("kyber_public_key", phase1Obj.getString("kyber_public_key"))
                        put("phase", 1)
                    }.toString()

                    val signatureValid = com.securelegion.crypto.RustBridge.verifySignature(
                        unsignedJson.toByteArray(Charsets.UTF_8),
                        signature,
                        senderEd25519PublicKey
                    )

                    if (!signatureValid) {
                        hideLoading()
                        ThemedToast.show(this@AddFriendActivity, "Invalid signature - friend request rejected (possible MitM attack)")
                        Log.e(TAG, "Phase 1 signature verification FAILED - rejecting friend request")
                        return@launch
                    }
                    Log.i(TAG, "✓ Phase 1 signature verified (Ed25519)")
                } else {
                    Log.w(TAG, "⚠️  Phase 1 has no signature (legacy friend request)")
                }

                Log.i(TAG, "Phase 1 decrypted successfully:")
                Log.i(TAG, "  Sender: $senderUsername")
                Log.i(TAG, "  Sender .onion: $senderFriendRequestOnion")
                Log.i(TAG, "  Sender X25519 key: ${senderX25519PublicKey.size} bytes")
                Log.i(TAG, "  Sender Kyber key: ${senderKyberPublicKey?.size ?: 0} bytes (quantum=${senderKyberPublicKey != null})")

                // Build YOUR full contact card
                val keyManager = KeyManager.getInstance(this@AddFriendActivity)
                val torManager = com.securelegion.crypto.TorManager.getInstance(applicationContext)
                val ownContactCard = ContactCard(
                    displayName = keyManager.getUsername() ?: throw Exception("Username not set"),
                    solanaPublicKey = keyManager.getSolanaPublicKey(),
                    x25519PublicKey = keyManager.getEncryptionPublicKey(),
                    kyberPublicKey = keyManager.getKyberPublicKey(),
                    solanaAddress = keyManager.getSolanaAddress(),
                    friendRequestOnion = keyManager.getFriendRequestOnion() ?: throw Exception("Friend request .onion not set"),
                    messagingOnion = keyManager.getMessagingOnion() ?: throw Exception("Messaging .onion not set"),
                    voiceOnion = torManager.getVoiceOnionAddress() ?: throw Exception("Voice .onion not set"),
                    contactPin = keyManager.getContactPin() ?: throw Exception("Contact PIN not set"),
                    ipfsCid = keyManager.deriveContactListCID(), // v5: Send contact LIST CID for backup mesh
                    timestamp = System.currentTimeMillis() / 1000
                )

                Log.d(TAG, "Built own contact card for Phase 2")

                // Generate Kyber ciphertext for quantum-resistant key chain initialization
                var hybridSharedSecret: ByteArray? = null
                val kyberCiphertextBase64 = withContext(Dispatchers.IO) {
                    if (senderKyberPublicKey != null && senderKyberPublicKey.any { it != 0.toByte() }) {
                        // Perform hybrid encapsulation using sender's keys
                        Log.d(TAG, "Generating hybrid Kyber ciphertext for quantum resistance")
                        val encapResult = RustBridge.hybridEncapsulate(
                            senderX25519PublicKey,
                            senderKyberPublicKey
                        )
                        // Result: [combined_secret:64][x25519_ephemeral:32][kyber_ciphertext:1568]
                        // Extract shared secret (first 64 bytes) - WE NEED TO SAVE THIS for key chain init!
                        hybridSharedSecret = encapResult.copyOfRange(0, 64)
                        // Extract ciphertext (remaining bytes) - send to Device A
                        val ciphertext = encapResult.copyOfRange(64, encapResult.size)
                        Base64.encodeToString(ciphertext, Base64.NO_WRAP)
                    } else {
                        Log.w(TAG, "Sender has no Kyber key - using legacy X25519-only mode")
                        null
                    }
                }

                // Build Phase 2 payload with contact card + Kyber ciphertext
                val phase2UnsignedJson = org.json.JSONObject().apply {
                    put("contact_card", org.json.JSONObject(ownContactCard.toJson()))
                    if (kyberCiphertextBase64 != null) {
                        put("kyber_ciphertext", kyberCiphertextBase64)
                    }
                    put("phase", 2)
                }.toString()

                // Sign Phase 2 with our Ed25519 key (defense-in-depth)
                val ownSigningKey = keyManager.getSigningKeyBytes()
                val ownSigningPublicKey = keyManager.getSigningPublicKey()
                val phase2Signature = RustBridge.signData(
                    phase2UnsignedJson.toByteArray(Charsets.UTF_8),
                    ownSigningKey
                )

                // Add signature to payload
                val phase2Payload = org.json.JSONObject(phase2UnsignedJson).apply {
                    put("ed25519_public_key", Base64.encodeToString(ownSigningPublicKey, Base64.NO_WRAP))
                    put("signature", Base64.encodeToString(phase2Signature, Base64.NO_WRAP))
                }.toString()

                Log.d(TAG, "Phase 2 payload signed with Ed25519")

                // Encrypt Phase 2 payload with sender's X25519 public key
                val encryptedPhase2 = withContext(Dispatchers.IO) {
                    RustBridge.encryptMessage(
                        plaintext = phase2Payload,
                        recipientX25519PublicKey = senderX25519PublicKey
                    )
                }

                Log.d(TAG, "Encrypted Phase 2 payload: ${encryptedPhase2.size} bytes (quantum=${kyberCiphertextBase64 != null})")

                // Send Phase 2 to sender's friend-request.onion using dedicated channel
                val success = withContext(Dispatchers.IO) {
                    RustBridge.sendFriendRequestAccepted(
                        recipientOnion = senderFriendRequestOnion,
                        encryptedAcceptance = encryptedPhase2
                    )
                }

                if (success) {
                    Log.i(TAG, "✓ Phase 2 sent successfully to $senderUsername")

                    // Remove the pending incoming request
                    removeFriendRequestByCid(incomingRequest.ipfsCid)

                    // Save sender's partial info as pending (waiting for their Phase 2b with full card)
                    // For now, we have: username, friend-request.onion, X25519 key, Kyber key, shared secret
                    // We're waiting for: messaging.onion, solana address, full contact card
                    val partialContactJson = org.json.JSONObject().apply {
                        put("username", senderUsername)
                        put("friend_request_onion", senderFriendRequestOnion)
                        put("x25519_public_key", senderX25519PublicKeyBase64)
                        if (senderKyberPublicKey != null) {
                            put("kyber_public_key", Base64.encodeToString(senderKyberPublicKey, Base64.NO_WRAP))
                        }
                        // CRITICAL: Store the shared secret we generated during encapsulation
                        // This will be used to initialize the key chain when we receive their Phase 2b
                        if (hybridSharedSecret != null) {
                            put("hybrid_shared_secret", Base64.encodeToString(hybridSharedSecret, Base64.NO_WRAP))
                        }
                    }.toString()

                    val pendingContact = com.securelegion.models.PendingFriendRequest(
                        displayName = senderUsername,
                        ipfsCid = senderFriendRequestOnion,  // Store their onion as identifier
                        direction = com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING,
                        status = com.securelegion.models.PendingFriendRequest.STATUS_PENDING,
                        timestamp = System.currentTimeMillis(),
                        contactCardJson = partialContactJson
                    )
                    savePendingFriendRequest(pendingContact)

                    hideLoading()
                    ThemedToast.show(this@AddFriendActivity, "Friend request accepted! ${senderUsername} will be added to your contacts shortly.")

                    // Clear form
                    findViewById<EditText>(R.id.cidInput).setText("")
                    findViewById<EditText>(R.id.pinBox1).setText("")
                    findViewById<EditText>(R.id.pinBox2).setText("")
                    findViewById<EditText>(R.id.pinBox3).setText("")
                    findViewById<EditText>(R.id.pinBox4).setText("")
                    findViewById<EditText>(R.id.pinBox5).setText("")
                    findViewById<EditText>(R.id.pinBox6).setText("")
                    findViewById<EditText>(R.id.pinBox7).setText("")
                    findViewById<EditText>(R.id.pinBox8).setText("")
                    findViewById<EditText>(R.id.pinBox9).setText("")
                    findViewById<EditText>(R.id.pinBox10).setText("")

                    // Reset button text
                    findViewById<TextView>(R.id.searchButton).text = "Send Friend Request"

                    // Reload pending requests
                    loadPendingFriendRequests()

                } else {
                    hideLoading()
                    ThemedToast.show(this@AddFriendActivity, "Failed to send response to $senderUsername")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Phase 2 acceptance failed", e)
                hideLoading()
                val errorMsg = when {
                    e.message?.contains("invalid PIN", ignoreCase = true) == true ||
                    e.message?.contains("decryption failed", ignoreCase = true) == true ->
                        "Invalid PIN. Please check and try again."
                    else ->
                        "Failed to accept: ${e.message}"
                }
                ThemedToast.show(this@AddFriendActivity, errorMsg)
            }
        }
    }

    /**
     * PHASE 1: Initiate friend request with key exchange
     * Sends minimal info encrypted with PIN: username + friend-request.onion + X25519 public key
     */
    private fun initiateFriendRequest(friendOnion: String, friendPin: String) {
        CoroutineScope(Dispatchers.Main).launch {
            try {
                // Sanitize .onion address - remove https://, http://, and trailing slashes
                val sanitizedOnion = friendOnion
                    .replace("https://", "", ignoreCase = true)
                    .replace("http://", "", ignoreCase = true)
                    .removeSuffix("/")
                    .trim()

                showLoading("Sending friend request...")
                Log.d(TAG, "Phase 1: Initiating friend request to: $sanitizedOnion (original: $friendOnion)")

                // Get YOUR info for Phase 1
                val keyManager = KeyManager.getInstance(this@AddFriendActivity)
                val ownDisplayName = keyManager.getUsername()
                    ?: throw Exception("Username not set")
                val ownFriendRequestOnion = keyManager.getFriendRequestOnion()
                    ?: throw Exception("Friend request .onion not set")
                val ownX25519PublicKey = keyManager.getEncryptionPublicKey()
                val ownKyberPublicKey = keyManager.getKyberPublicKey()

                Log.d(TAG, "Sending Phase 1 key exchange as: $ownDisplayName")

                // Build Phase 1 payload (minimal public info + Kyber key for quantum resistance)
                val phase1UnsignedJson = org.json.JSONObject().apply {
                    put("username", ownDisplayName)
                    put("friend_request_onion", ownFriendRequestOnion)
                    put("x25519_public_key", android.util.Base64.encodeToString(ownX25519PublicKey, android.util.Base64.NO_WRAP))
                    put("kyber_public_key", android.util.Base64.encodeToString(ownKyberPublicKey, android.util.Base64.NO_WRAP))
                    put("phase", 1)
                }.toString()

                // Sign Phase 1 with our Ed25519 key (defense-in-depth against .onion MitM)
                val ownSigningKey = keyManager.getSigningKeyBytes()
                val ownSigningPublicKey = keyManager.getSigningPublicKey()
                val phase1Signature = com.securelegion.crypto.RustBridge.signData(
                    phase1UnsignedJson.toByteArray(Charsets.UTF_8),
                    ownSigningKey
                )

                // Add signature and signing public key to payload
                val phase1Payload = org.json.JSONObject(phase1UnsignedJson).apply {
                    put("ed25519_public_key", android.util.Base64.encodeToString(ownSigningPublicKey, android.util.Base64.NO_WRAP))
                    put("signature", android.util.Base64.encodeToString(phase1Signature, android.util.Base64.NO_WRAP))
                }.toString()

                Log.d(TAG, "Phase 1 payload signed with Ed25519")

                // Encrypt Phase 1 with PIN
                val cardManager = com.securelegion.services.ContactCardManager(this@AddFriendActivity)
                val encryptedPhase1 = withContext(Dispatchers.IO) {
                    cardManager.encryptWithPin(phase1Payload, friendPin)
                }

                Log.d(TAG, "Encrypted Phase 1 payload: ${encryptedPhase1.size} bytes")

                // Send Phase 1 via Tor using dedicated friend request channel
                val success = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.sendFriendRequest(
                        recipientOnion = sanitizedOnion,
                        encryptedFriendRequest = encryptedPhase1
                    )
                }

                if (success) {
                    Log.i(TAG, "✓ Phase 1 sent successfully")

                    // Save as outgoing pending request (awaiting Phase 2)
                    val pendingRequest = com.securelegion.models.PendingFriendRequest(
                        displayName = "Pending Friend",
                        ipfsCid = sanitizedOnion, // Store recipient's .onion address for retry
                        direction = com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING,
                        status = com.securelegion.models.PendingFriendRequest.STATUS_PENDING,
                        timestamp = System.currentTimeMillis(),
                        contactCardJson = phase1Payload // Store Phase 1 for Phase 2 matching
                    )
                    savePendingFriendRequest(pendingRequest)

                    hideLoading()
                    ThemedToast.show(this@AddFriendActivity, "Friend request sent!")

                    // Clear form
                    findViewById<EditText>(R.id.cidInput).setText("")
                    findViewById<EditText>(R.id.pinBox1).setText("")
                    findViewById<EditText>(R.id.pinBox2).setText("")
                    findViewById<EditText>(R.id.pinBox3).setText("")
                    findViewById<EditText>(R.id.pinBox4).setText("")
                    findViewById<EditText>(R.id.pinBox5).setText("")
                    findViewById<EditText>(R.id.pinBox6).setText("")
                    findViewById<EditText>(R.id.pinBox7).setText("")
                    findViewById<EditText>(R.id.pinBox8).setText("")
                    findViewById<EditText>(R.id.pinBox9).setText("")
                    findViewById<EditText>(R.id.pinBox10).setText("")

                    // Reload pending requests
                    loadPendingFriendRequests()
                } else {
                    hideLoading()

                    // Save as failed pending request so user can retry
                    val pendingRequest = com.securelegion.models.PendingFriendRequest(
                        displayName = "Pending Friend",
                        ipfsCid = friendOnion, // Store recipient's .onion address for retry
                        direction = com.securelegion.models.PendingFriendRequest.DIRECTION_OUTGOING,
                        status = com.securelegion.models.PendingFriendRequest.STATUS_FAILED,
                        timestamp = System.currentTimeMillis(),
                        contactCardJson = phase1Payload // Store Phase 1 for retry
                    )
                    savePendingFriendRequest(pendingRequest)

                    ThemedToast.show(this@AddFriendActivity, "Failed to send friend request - saved to retry later")

                    // Reload pending requests to show the failed request
                    loadPendingFriendRequests()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Phase 1 failed", e)
                hideLoading()
                ThemedToast.show(this@AddFriendActivity, "Failed to send: ${e.message}")
            }
        }
    }

    // OLD v1.0 sendFriendRequest() function REMOVED
    // Use NEW Phase 1/2/2b flow (initiateFriendRequest -> acceptPhase2FriendRequest) instead

    /**
     * Resend friend request from pending request (retry functionality)
     * Handles Phase 1 requests (NEW v2.0+ system)
     * OLD v1.0 full ContactCard format is NO LONGER SUPPORTED
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

                // Additional check: verify SOCKS proxy is actually running
                val socksRunning = withContext(Dispatchers.IO) {
                    com.securelegion.crypto.RustBridge.isSocksProxyRunning()
                }
                if (!socksRunning) {
                    Log.w(TAG, "SOCKS proxy not running - attempting to start")
                    val started = withContext(Dispatchers.IO) {
                        com.securelegion.crypto.RustBridge.startSocksProxy()
                    }
                    if (!started) {
                        Log.e(TAG, "Failed to start SOCKS proxy")
                        ThemedToast.showLong(this@AddFriendActivity, "Network proxy unavailable. Please restart the app.")
                        return@launch
                    }
                    // Wait a moment for SOCKS proxy to initialize
                    kotlinx.coroutines.delay(1000)
                }

                // Check if we have saved data
                if (pendingRequest.contactCardJson == null) {
                    ThemedToast.showLong(this@AddFriendActivity, "Cannot resend: Request data missing")
                    Log.e(TAG, "No data saved with pending request")
                    return@launch
                }

                // Detect if this is Phase 1 data (v2.0) or full ContactCard (v1.0)
                val jsonData = pendingRequest.contactCardJson
                val isPhase1 = try {
                    val obj = org.json.JSONObject(jsonData)
                    obj.has("phase") || (obj.has("username") && obj.has("friend_request_onion") && !obj.has("solanaAddress"))
                } catch (e: Exception) {
                    false
                }

                if (isPhase1) {
                    // v2.0 Phase 1 resend - just resend the saved Phase 1 payload
                    Log.d(TAG, "Resending as Phase 1 request (v2.0)")

                    // The saved contactCardJson IS the Phase 1 payload - just re-encrypt and resend
                    val phase1Payload = jsonData

                    // Need to get the recipient's onion from the ipfsCid field (where we stored it)
                    val recipientOnion = pendingRequest.ipfsCid
                    if (recipientOnion.isEmpty()) {
                        ThemedToast.showLong(this@AddFriendActivity, "Cannot resend: Recipient address missing")
                        return@launch
                    }

                    // Get the PIN - we need to prompt the user since we don't store it
                    ThemedToast.show(this@AddFriendActivity, "Please re-enter their friend request info to retry")

                    // Auto-fill the onion field
                    findViewById<EditText>(R.id.cidInput).setText(recipientOnion)

                    // Focus on first PIN box
                    val pinBox1 = findViewById<EditText>(R.id.pinBox1)
                    pinBox1.requestFocus()

                    return@launch
                } else {
                    // v1.0 full ContactCard resend (old format) - NO LONGER SUPPORTED
                    Log.w(TAG, "Cannot resend v1.0 request - old friend request system removed")
                    ThemedToast.showLong(this@AddFriendActivity, "Old friend request format not supported. Please use NEW Phase 1/2/2b flow.")
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error resending friend request", e)
                ThemedToast.showLong(this@AddFriendActivity, "Failed to resend friend request")
            }
        }
    }

    // OLD v1.0 sendFriendRequestAccepted() function REMOVED
    // Use NEW Phase 1/2/2b flow (acceptPhase2FriendRequest sends full contact card) instead

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

    private fun enterDeleteMode() {
        isDeleteMode = true
        selectedRequests.clear()

        // Show all checkboxes
        val requestsList = findViewById<android.widget.LinearLayout>(R.id.friendRequestsList)
        for (i in 0 until requestsList.childCount) {
            val requestView = requestsList.getChildAt(i)
            val checkbox = requestView.findViewById<android.widget.CheckBox>(R.id.requestCheckbox)
            checkbox?.visibility = View.VISIBLE
        }

        ThemedToast.show(this, "Select requests to delete")
    }

    private fun exitDeleteMode() {
        isDeleteMode = false
        selectedRequests.clear()

        // Hide all checkboxes
        val requestsList = findViewById<android.widget.LinearLayout>(R.id.friendRequestsList)
        for (i in 0 until requestsList.childCount) {
            val requestView = requestsList.getChildAt(i)
            val checkbox = requestView.findViewById<android.widget.CheckBox>(R.id.requestCheckbox)
            checkbox?.visibility = View.GONE
            checkbox?.isChecked = false
        }
    }

    private fun deleteSelectedRequests() {
        if (selectedRequests.isEmpty()) {
            ThemedToast.show(this, "No requests selected")
            return
        }

        try {
            val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsV2 = prefs.getStringSet("pending_requests_v2", mutableSetOf())?.toMutableSet() ?: mutableSetOf()

            // Remove selected requests
            val updatedRequests = pendingRequestsV2.filter { requestJson ->
                try {
                    val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    !selectedRequests.contains(request.ipfsCid)
                } catch (e: Exception) {
                    true // Keep if can't parse
                }
            }.toMutableSet()

            prefs.edit().putStringSet("pending_requests_v2", updatedRequests).apply()

            ThemedToast.show(this, "Deleted ${selectedRequests.size} request(s)")

            // Exit delete mode and reload
            exitDeleteMode()
            loadPendingFriendRequests()

        } catch (e: Exception) {
            Log.e(TAG, "Error deleting requests", e)
            ThemedToast.show(this, "Failed to delete requests")
        }
    }

    private fun markRequestAsFailed(ipfsCid: String) {
        try {
            val prefs = getSharedPreferences("friend_requests", Context.MODE_PRIVATE)
            val pendingRequestsV2 = prefs.getStringSet("pending_requests_v2", mutableSetOf())?.toMutableSet() ?: mutableSetOf()

            // Find and update the request to mark as failed
            val updatedRequests = pendingRequestsV2.map { requestJson ->
                try {
                    val request = com.securelegion.models.PendingFriendRequest.fromJson(requestJson)
                    if (request.ipfsCid == ipfsCid) {
                        // Create a copy with failed status
                        val failedRequest = request.copy(status = com.securelegion.models.PendingFriendRequest.STATUS_FAILED)
                        failedRequest.toJson()
                    } else {
                        requestJson
                    }
                } catch (e: Exception) {
                    requestJson
                }
            }.toMutableSet()

            prefs.edit().putStringSet("pending_requests_v2", updatedRequests).apply()

            // Reload to show updated status
            loadPendingFriendRequests()

        } catch (e: Exception) {
            Log.e(TAG, "Error marking request as failed", e)
        }
    }
}
