# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

#### Ghost Ping/Message Issue - ACK Listener JNI Binding
- **RustBridge.kt (line 375)**: Fixed startAckListener() JNI binding crash
  - Removed default parameter from external function declaration
  - Changed from `external fun startAckListener(port: Int = 9153)` to `external fun startAckListener(port: Int)`
  - JNI does not support Kotlin default parameters, causing UnsatisfiedLinkError
  - ACK listener now starts successfully on port 9153
  - PING_ACK and MESSAGE_ACK delivery now functional
  - Eliminates ghost pings caused by sender retries when ACKs fail to send
  - Root cause: sender never received ACK, assumed message failed, sent new ping with different ID
  - Each retry ping was legitimate (unique ID), so deduplication correctly allowed it

#### Database-Based Message Deduplication
- **database/entities/ReceivedId.kt**: Created entity for tracking all received ping/pong/message IDs
  - UNIQUE constraint on receivedId field for atomic deduplication
  - Tracks ID type (PING, PONG, MESSAGE) and timestamp
  - Prevents race conditions where same ID arrives before database insert completes

- **database/dao/ReceivedIdDao.kt**: Created DAO for deduplication operations
  - insertReceivedId() with OnConflictStrategy.IGNORE returns -1 for duplicates
  - Atomic INSERT operation using UNIQUE constraint prevents race conditions
  - exists() method for checking if ID was previously received
  - deleteOldIds() for cleanup of IDs older than 30 days

- **SecureLegionDatabase.kt (lines 34-35, 185-202)**: Added migration 10 to 11
  - Creates received_ids table with UNIQUE index on receivedId
  - Migration creates table and index for deduplication tracking
  - Database version bumped to 11

- **TorService.kt (lines 869-882, 936-962, 1189-1222)**: Implemented PRIMARY deduplication layer
  - Ping deduplication: Tracks each ping ID before processing
  - Pong deduplication: Tracks with "pong_" prefix before message send
  - Message blob deduplication: Uses encrypted payload hash as ID
  - All checks happen BEFORE notifications or database saves
  - Returns -1L from insertReceivedId() indicates duplicate, skips processing
  - Sends ACK for duplicates to stop sender retries

- **TorService.kt (lines 1214-1215, 1689-1690)**: Removed secondary duplicate checks
  - Deleted messageExists() check for blob messages
  - Deleted getMessageByMessageId() check for regular messages
  - Secondary checks were blocking rapid identical messages like "yo" "yo" "yo"
  - PRIMARY ReceivedId table deduplication is sufficient
  - Allows users to send same text multiple times quickly

- **TorService.kt (lines 1098-1101)**: Fixed blob message ID generation
  - Changed from content+timestamp hash to encrypted payload hash
  - Uses hash of encrypted bytes (includes random nonce)
  - Allows rapid messages with same text (each encryption produces different hash)
  - Blocks true network duplicates (same encrypted blob)

#### Bridge Configuration Persistence
- **TorManager.kt (lines 92-130)**: Fixed bridge configuration not applied on restart
  - Torrc file now ALWAYS written before Tor starts (even if already running)
  - Previously only wrote torrc if Tor wasn't running, causing race condition
  - Bridge configuration changes now persist across Tor restarts
  - Moved torrc write outside the "if not running" check

- **BridgeActivity.kt (line 117)**: Increased restart delay for clean shutdown
  - Changed delay from 2000ms to 3500ms
  - Ensures Tor fully stops before new configuration applied
  - Prevents race condition where new Tor starts before old one fully stopped

#### Notification Behavior
- **TorService.kt (lines 2050-2063)**: Minimized connected state notification
  - Changed to PRIORITY_MIN for normal "Connected" state (just icon in status bar)
  - Empty title and text when connected (completely silent)
  - PRIORITY_DEFAULT only for problem states (Connecting, Failed, Retrying)
  - Added setShowWhen(false) and setSilent(true) for connected state
  - Prevents swipeable notification entirely when working correctly
  - Users only see notification text when there's an issue requiring attention

### Added

#### Auto-Lock Timer Security Feature
- **AutoLockActivity.kt**: Created activity for configuring auto-lock timeout
  - Timer options: 30 seconds, 1 minute, 5 minutes, 15 minutes, 30 minutes, Never
  - Saves selection to SharedPreferences "security" with key "auto_lock_timeout_ms"
  - Companion object defines timeout constants
  - Shows confirmation toast with selected timeout
  - Automatically closes after selection with 500ms delay

- **activity_auto_lock.xml**: Created layout for auto-lock timer selection
  - RadioGroup with 6 options for different timeout intervals
  - Dark themed with settings_item_bg background
  - Warning color for "Never" option (not recommended)
  - Info text explaining auto-lock behavior

- **BaseActivity.kt**: Implemented auto-lock timer logic
  - Tracks app lifecycle with onPause() and onResume()
  - Records timestamp when app goes to background
  - Checks elapsed time when app returns to foreground
  - Locks app by navigating to LockActivity if timeout exceeded
  - Skips auto-lock for LockActivity, CreateAccountActivity, SplashActivity
  - Respects "Never" timeout setting (TIMEOUT_NEVER = -1L)
  - Uses separate SharedPreferences for lifecycle tracking

- **MainActivity.kt, ChatActivity.kt, AddFriendActivity.kt, SecurityModeActivity.kt**: Extended BaseActivity
  - Auto-lock timer now functional on all main app screens
  - Consistent security behavior across messaging, contacts, and settings

- **SecurityModeActivity.kt (lines 29-45)**: Added auto-lock settings integration
  - setupAutoLock() launches AutoLockActivity when item clicked
  - updateAutoLockStatus() displays current timeout selection
  - Updates status text in onResume() to reflect changes

- **activity_security_mode.xml**: Added App Security section
  - Auto-Lock Timer item shows current timeout
  - Tappable item navigates to AutoLockActivity
  - Arrow indicator for navigation

- **activity_settings.xml (lines 176-219)**: Added Advanced Security menu item
  - "Advanced Security" entry in Settings
  - Description: "Auto-lock timer, connection settings"
  - Navigates to SecurityModeActivity

#### Enhanced Deduplication Diagnostics
- **TorService.kt (lines 936-962)**: Added detailed logging for ping deduplication
  - Logs "DEDUPLICATION CHECK: Ping ID = X" for every ping
  - Logs "Attempting to insert Ping ID into received_ids table..."
  - Logs insert result with rowId (NEW or DUPLICATE status)
  - Try-catch block logs database exceptions with full details
  - Logs "NEW PING ACCEPTED" or "DUPLICATE PING BLOCKED" based on result
  - Helps diagnose deduplication failures and database issues

### Changed

#### Security UI Simplification
- **activity_security_mode.xml**: Removed non-configurable security features
  - Removed "Direct Ping-Pong" toggle (core feature, cannot be disabled)
  - Removed "Tor Connection" toggle (core feature, cannot be disabled)
  - Removed "About Direct Ping-Pong" info box
  - Advanced Security page now shows only Auto-Lock Timer
  - Cleaner interface focused on user-configurable security settings

- **SecurityModeActivity.kt**: Removed tor toggle setup
  - Removed setupTorToggle() method
  - Removed SwitchCompat import
  - Removed ThemedToast import
  - Simplified onCreate() to only setup auto-lock and bottom navigation

### Technical Details

#### Auto-Lock Timer Operation
- Records System.currentTimeMillis() in onPause() to SharedPreferences
- Calculates elapsed time in onResume() by subtracting stored timestamp from current time
- Compares elapsed time against configured timeout from "security" preferences
- Timeout values range from 30,000ms (30s) to 1,800,000ms (30m), or -1L for Never
- Navigates to LockActivity with FLAG_ACTIVITY_NEW_TASK and FLAG_ACTIVITY_CLEAR_TASK
- Uses separate "app_lifecycle" preferences to avoid conflicts with security settings

#### Database Migration 10 to 11
- Creates received_ids table with columns: id (autoincrement), receivedId (text), idType (text), receivedTimestamp (integer), processed (boolean)
- Creates UNIQUE INDEX on receivedId column for atomic duplicate detection
- Migration SQL uses "CREATE TABLE IF NOT EXISTS" for safety
- Index creation uses "CREATE UNIQUE INDEX IF NOT EXISTS"
- Room handles migration automatically on first app launch after upgrade

#### Deduplication Flow
1. Receive ping/pong/message from network
2. Create ReceivedId entity with unique ID and type
3. Call database.receivedIdDao().insertReceivedId() in runBlocking coroutine
4. If rowId == -1L, ID already exists (duplicate), return early
5. If rowId > 0, ID is new, continue processing (show notification, save message, etc)
6. Send ACK to sender to confirm receipt
7. Duplicate arrives later, step 4 catches it, ACK sent but no processing

#### ACK Listener Architecture
- Listener runs on port 9153 (separate from message listener on 9150)
- Accepts incoming ACK messages (PING_ACK, MESSAGE_ACK) from contacts
- Rust TorManager binds TCP socket to localhost:9153 via Tor hidden service
- ACKs encrypted with shared secret (ECDH using X25519 keys)
- Wire format: [Type Byte 0x06][Sender X25519 Public Key][Encrypted ACK]
- JNI function Java_com_securelegion_crypto_RustBridge_startAckListener must match exactly
- Default parameters in Kotlin external fun break JNI name mangling

### Files Modified

**Kotlin Files:**
- app/src/main/java/com/securelegion/BaseActivity.kt
- app/src/main/java/com/securelegion/MainActivity.kt
- app/src/main/java/com/securelegion/ChatActivity.kt
- app/src/main/java/com/securelegion/AddFriendActivity.kt
- app/src/main/java/com/securelegion/SecurityModeActivity.kt
- app/src/main/java/com/securelegion/crypto/RustBridge.kt
- app/src/main/java/com/securelegion/crypto/TorManager.kt
- app/src/main/java/com/securelegion/BridgeActivity.kt
- app/src/main/java/com/securelegion/services/TorService.kt
- app/src/main/java/com/securelegion/database/SecureLegionDatabase.kt

**New Kotlin Files:**
- app/src/main/java/com/securelegion/AutoLockActivity.kt
- app/src/main/java/com/securelegion/database/entities/ReceivedId.kt
- app/src/main/java/com/securelegion/database/dao/ReceivedIdDao.kt

**Layout Files:**
- app/src/main/res/layout/activity_security_mode.xml
- app/src/main/res/layout/activity_settings.xml

**New Layout Files:**
- app/src/main/res/layout/activity_auto_lock.xml

**Database:**
- Database version: 10 to 11
- New table: received_ids

---

## [0.1.3] - 2025-11-11 (Previous Version)

### Fixed

#### Message Deduplication and Delivery Tracking
- **TorService.kt (lines 1526-1616)**: Implemented deterministic message IDs to prevent duplicate messages
  - Changed from random UUID generation to deterministic ID based on pingId: "msg_$pingId"
  - Added duplicate detection check before message insertion
  - Implemented automatic MESSAGE_ACK sending after successful message save
  - Added MESSAGE_ACK response for duplicate messages to stop sender retries
  - Prevents ghost messages and notification spam

- **TorService.kt (lines 1098-1165)**: Fixed message blob deduplication
  - Changed from random nonce-based IDs to deterministic hash: "blob_" + Base64(SHA256(senderId:content:timestamp))
  - Timestamp rounded to nearest minute for deduplication window
  - Added messageExists() check before insertion
  - Implemented MESSAGE_ACK sending after saving blob messages
  - Prevents duplicate reception of direct messages

- **TorService.kt (lines 853-891)**: Added Pong deduplication to prevent duplicate sends
  - Added check for messageDelivered flag before processing Pong
  - Prevents sending message payload multiple times for duplicate Pongs
  - Logs duplicate Pong detection and skips processing
  - Eliminates ghost message sends on receiver side

- **MessageService.kt (lines 607-611)**: Fixed sender-side infinite retry loops
  - Added messageDelivered flag check before attempting message send
  - Skips messages that have already been acknowledged
  - Logs skipped messages to prevent silent failures
  - Prevents wasted bandwidth and battery on already-delivered messages

#### Service Stability
- **TorService.kt (lines 1901-1905)**: Fixed dismissible notification killing service on Android 12+
  - Added setForegroundServiceBehavior(FOREGROUND_SERVICE_IMMEDIATE) for Android 12+
  - Prevents service termination when user swipes notification
  - Ensures continuous operation for 24/7 message reception
  - Notification now truly non-dismissible as required for foreground services

#### Bridge Configuration
- **BridgeActivity.kt (lines 102-119)**: Implemented automatic Tor restart on bridge save
  - Added TorService stop/restart sequence when bridge configuration changes
  - Stops existing Tor connection before applying new bridge
  - Waits 2 seconds for clean shutdown before restart
  - Displays toast notification to inform user of restart

- **SplashActivity.kt (lines 335-350)**: Automated bridge connection testing flow
  - Automatically tests bridge connection after returning from BridgeActivity
  - Hides configuration buttons and shows progress bar
  - Initiates bootstrap monitoring without manual retry
  - Provides smooth user experience for censored network environments

#### Notification Handling
- **DownloadMessageService.kt (lines 96-97, 321-379)**: Fixed crash when clicking download notification
  - Added currentContactId and currentContactName instance variables
  - Properly passes contact information to ChatActivity via LockActivity
  - Uses unique pending intent request codes per contact
  - Eliminates "contact not found" crashes when tapping notification

#### Biometric Authentication
- **BiometricAuthHelper.kt (lines 219-277)**: Fixed biometric failure on non-Google devices
  - Implemented StrongBox with TEE fallback mechanism
  - Attempts StrongBox key creation first for highest security
  - Gracefully falls back to regular hardware-backed keystore if StrongBox unavailable
  - Added detailed logging for security level (StrongBox vs TEE)
  - Ensures compatibility with Samsung, OnePlus, Xiaomi, and other manufacturers

### Added

#### Boot Receiver for Background Operation
- **receivers/BootReceiver.kt**: Created boot receiver for automatic service startup
  - Listens for BOOT_COMPLETED, QUICKBOOT_POWERON, and LOCKED_BOOT_COMPLETED intents
  - Automatically starts TorService when device boots
  - Schedules MessageRetryWorker for background message processing
  - Only activates if user account is initialized (respects app state)
  - Enables message reception without user opening app

- **AndroidManifest.xml (line 27)**: Added RECEIVE_BOOT_COMPLETED permission
  - Required for boot receiver functionality
  - Standard Android permission, granted automatically

- **AndroidManifest.xml (lines 210-220)**: Registered BootReceiver component
  - Set as exported for system broadcasts
  - Enabled directBootAware for early boot support
  - Configured intent filters for multiple boot scenarios (standard, quick boot, locked boot)

#### Enhanced Background Message Processing
- **TorService.kt (lines 360-362, 401-403)**: Added MessageRetryWorker scheduling in TorService
  - Schedules worker when Tor initializes successfully
  - Schedules worker when Tor is already running (service restart case)
  - Ensures retry worker always active when service runs
  - Provides redundant scheduling for reliability

### Changed

#### Message ID Generation Strategy
- Ping-based messages: Deterministic ID format "msg_$pingId"
- Blob messages: Deterministic hash "blob_" + Base64(SHA256(senderId:content:timestamp))
- Ensures same message generates same ID for deduplication
- Maintains uniqueness across different messages

#### Retry Backoff Schedule
- Initial delay: 5 seconds
- Backoff multiplier: 2.0x per retry
- Maximum delay: 5 minutes (capped)
- Full schedule: 5s, 10s, 20s, 40s, 80s, 160s, 300s (capped at 5min)

#### MessageRetryWorker Scheduling Redundancy
Now scheduled in three independent locations for maximum reliability:
1. MainActivity - when app opens
2. TorService - when Tor connects (both fresh init and already-running cases)
3. BootReceiver - when device boots

#### Delivery Tracking Flags
- pingDelivered: Set to true when PING_ACK received from recipient
- messageDelivered: Set to true when MESSAGE_ACK received from recipient
- Both flags checked before retry attempts to prevent unnecessary retransmissions
- Flags persist in database for reliability across app restarts

### Technical Details

#### Boot Process Flow
1. Device boots and system broadcasts BOOT_COMPLETED
2. BootReceiver verifies account is initialized
3. BootReceiver starts TorService as foreground service
4. BootReceiver schedules MessageRetryWorker
5. TorService connects to Tor network
6. TorService starts hidden service listener
7. MessageRetryWorker begins polling every 5 minutes
8. User can receive messages without opening app

#### MessageRetryWorker Operation
- Interval: Every 5 minutes
- Network requirement: Connected network state
- Operations per cycle:
  1. Poll for received Pongs and send queued message payloads
  2. Retry pending Pings using exponential backoff
  3. Update retry counters and timestamps in database
- Respects delivery flags to prevent duplicate sends
- Logs all operations for debugging

#### Security Considerations
- StrongBox provides hardware isolation on supported devices (Pixel, some flagships)
- TEE fallback still provides hardware-backed security on all devices
- Both implementations use Android Keystore for key protection
- Biometric key never leaves secure hardware
- Password hash encrypted with biometric-protected key

#### Performance Impact
- Boot receiver: Negligible (<100ms execution time)
- MessageRetryWorker: Low CPU usage, runs max 5 minutes per hour
- Deterministic message IDs: No performance impact, same hash computation
- Deduplication checks: Fast database queries using indexed messageId field

### Files Modified

**Kotlin Files:**
- app/src/main/java/com/securelegion/services/TorService.kt
- app/src/main/java/com/securelegion/services/MessageService.kt
- app/src/main/java/com/securelegion/services/DownloadMessageService.kt
- app/src/main/java/com/securelegion/BridgeActivity.kt
- app/src/main/java/com/securelegion/SplashActivity.kt
- app/src/main/java/com/securelegion/utils/BiometricAuthHelper.kt

**New Files:**
- app/src/main/java/com/securelegion/receivers/BootReceiver.kt

**Configuration Files:**
- app/src/main/AndroidManifest.xml

---

## [0.1.3] - 2025-11-11

### Added
- **Encrypted Contact Database (SQLCipher + Room)**
  - AES-256 full database encryption using SQLCipher
  - Encryption key derived from BIP39 seed via KeyManager
  - Room database with ContactDao and MessageDao for type-safe queries
  - Contact entity with displayName, solanaAddress, publicKeyBase64, torOnionAddress
  - Message entity with encryption status, delivery tracking, and signatures
  - Secure deletion enabled (PRAGMA secure_delete = ON)
  - WAL mode disabled for maximum security (DELETE journal mode)
  - Database passphrase derived using SHA-256(seed + salt)

- **Contact Management UI**
  - Contacts now load from encrypted database in MainActivity
  - Custom dark-themed contact list item layout
  - Contacts displayed with name and truncated Solana address
  - Contact options screen with rounded corner info box
  - Delete contact functionality with confirmation dialog
  - Contact deletion removes from encrypted database
  - Automatic navigation back to main screen after deletion

### Changed
- **Contact List Display**
  - Replaced hardcoded sample contacts with real database queries
  - ContactAdapter now uses custom item_contact.xml layout
  - Dark card background (#151B26) matching app theme
  - Blue contact name text (#1E90FF) for visibility
  - Gray monospace address text for readability
  - Rounded corners (16dp) on contact info boxes

- **Contact Options Screen**
  - Contact info box now uses dark theme colors
  - Rounded corners on contact display card
  - Removed "Open Messages" button (simplified interface)
  - Delete button styled with subtle border and gray text

### Fixed
- **SQLCipher PRAGMA Errors**
  - Fixed "Queries cannot be performed using execSQL()" error
  - Changed both secure_delete and journal_mode to use query() instead of execSQL()
  - SQLCipher requires query() method even for PRAGMAs that don't return meaningful results

- **Contact Display Issues**
  - Fixed ContactAdapter not showing contact text
  - Added proper TextView binding in ViewHolder
  - Contacts now display correctly in RecyclerView

### Technical Details

**New Files:**
- app/src/main/java/com/securelegion/database/SecureLegionDatabase.kt - Encrypted database singleton
- app/src/main/java/com/securelegion/database/entities/Contact.kt - Contact entity
- app/src/main/java/com/securelegion/database/entities/Message.kt - Message entity
- app/src/main/java/com/securelegion/database/dao/ContactDao.kt - Contact DAO with queries
- app/src/main/java/com/securelegion/database/dao/MessageDao.kt - Message DAO with delivery tracking
- app/src/main/res/drawable/contact_info_box_bg.xml - Rounded corner background
- app/src/main/res/drawable/delete_button_bg.xml - Delete button styling

**Dependencies Added:**
- androidx.room:room-runtime:2.6.1 - Room database ORM
- androidx.room:room-ktx:2.6.1 - Kotlin coroutines support
- net.zetetic:android-database-sqlcipher:4.5.4 - SQLCipher encryption
- androidx.sqlite:sqlite:2.4.0 - SQLite support library

**Database Schema:**
```sql
CREATE TABLE contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  displayName TEXT NOT NULL,
  solanaAddress TEXT NOT NULL UNIQUE,
  publicKeyBase64 TEXT NOT NULL,
  torOnionAddress TEXT NOT NULL UNIQUE,
  addedTimestamp INTEGER NOT NULL,
  lastContactTimestamp INTEGER NOT NULL,
  trustLevel INTEGER NOT NULL DEFAULT 0,
  notes TEXT
);

CREATE TABLE messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  contactId INTEGER NOT NULL,
  messageId TEXT NOT NULL UNIQUE,
  encryptedContent BLOB NOT NULL,
  timestamp INTEGER NOT NULL,
  isOutgoing INTEGER NOT NULL,
  deliveryStatus TEXT NOT NULL,
  readTimestamp INTEGER,
  senderSignature BLOB,
  FOREIGN KEY (contactId) REFERENCES contacts(id) ON DELETE CASCADE
);
```

**Security Considerations:**
- Database file stored at /data/data/com.securelegion/databases/secure_legion.db
- No plaintext data ever touches disk
- Encryption key never stored, derived fresh from BIP39 seed on each session
- Database verification method confirms encryption is active
- Secure deletion ensures deleted data cannot be recovered

**Testing:**
- Contact successfully saved to encrypted database (ID: 1)
- Contact loaded and displayed in MainActivity contacts tab
- Contact deletion removes from database and updates UI
- Database encryption verified (cannot open without passphrase)
- PRAGMA statements execute correctly with SQLCipher

---

## [0.1.2] - 2025-11-11

### Added
- **IPFS Contact Card System** - Implemented decentralized contact sharing via IPFS (Pinata)
  - PIN-protected contact card encryption using libsodium (XSalsa20-Poly1305)
  - Argon2id key derivation for PIN-based encryption
  - Contact cards stored on IPFS with CID addressing
  - Share CID + PIN separately for defense-in-depth security
  - ContactCard model with display name, Solana address, and Tor onion address
  - ContactCardManager handles encryption, upload, download, and decryption
  - PinataService for IPFS gateway operations

- **Username Storage** - Persistent username across app sessions
  - Added username storage methods to KeyManager (encrypted storage)
  - Username automatically saved during account creation
  - Username displayed in Wallet Identity screen

- **Backup Seed Phrase Activity** - Interface for displaying and backing up 12-word mnemonic
  - Activity layout created for seed phrase display
  - BackupSeedPhraseActivity implementation ready for integration

- **Copy CID Functionality** - One-tap CID copying for easy sharing
  - CID text is clickable with visual indication (blue color)
  - Tap CID to copy to clipboard with confirmation toast
  - PIN remains non-copyable for security (manual sharing only)

### Fixed
- **CID Format Validation** - Fixed invalid CID format errors
  - Updated validation to accept all CIDv1 formats (baf* prefix)
  - Previously only accepted "bafy" but Pinata generates "bafkrei" (raw codec)
  - Now supports both CIDv0 (Qm*) and all CIDv1 variants (baf*)

- **Account Creation Flow** - Fixed contact card upload and navigation
  - App now waits for contact card upload before navigation
  - Fixed issue where CID/PIN were not displayed after creation
  - Navigates to Wallet Identity screen after successful upload
  - Shows "Creating Account..." loading state during upload
  - Proper error handling with retry option

- **Username Display** - Fixed username not appearing in Identity screen
  - Username now loads from encrypted storage on activity creation
  - Properly persists across app restarts
  - EditText pre-populated with stored username

### Changed
- **UI Improvements**
  - Changed "Update Username" button to "New Identity"
  - Contact Card section label: "CID (Public - Tap to Copy)"
  - CID displayed in blue with tap feedback
  - PIN displayed in white (non-interactive)

- **Contact Card Security Model**
  - CID is public and shareable (IPFS hash)
  - PIN provides additional authentication layer
  - Prevents spam and unauthorized contact card access
  - Generic IPFS filenames for privacy (no username in file info)

### Technical Details

**New Files:**
- app/src/main/java/com/securelegion/services/PinataService.kt - IPFS gateway integration
- app/src/main/java/com/securelegion/services/ContactCardManager.kt - Contact card encryption/decryption
- app/src/main/java/com/securelegion/models/ContactCard.kt - Contact card data model
- app/src/main/java/com/securelegion/BackupSeedPhraseActivity.kt - Seed phrase backup UI
- app/src/main/res/layout/activity_backup_seed_phrase.xml - Backup layout

**Dependencies Added:**
- OkHttp for IPFS API calls
- LazySodium for PIN-based encryption
- JSON serialization for contact cards

**Encryption Specs:**
- Algorithm: XSalsa20-Poly1305 (authenticated encryption)
- Key derivation: Argon2id with interactive parameters
- PIN format: 6-digit numeric PIN
- Encrypted format: [salt (16B)][nonce (24B)][ciphertext + MAC]

**Testing:**
- Contact card upload to IPFS
- CID + PIN generation and storage
- Contact card download and decryption
- CID validation for all formats
- Username persistence across restarts
- Copy CID functionality

---

## [0.1.1] - 2025-11-09

### Fixed
- **App crash on x86_64 emulators** - Built and packaged Rust native library for x86_64 architecture alongside existing ARM64 build. The app was crashing on Android emulators with `dlopen failed: library "libsecurelegion.so" not found` error.
- **Tor reconnection on every app launch** - Fixed SplashActivity redundantly re-initializing Tor every time the app opened. Now properly checks if Tor is already initialized and reuses existing connection, preventing 15-30 second bootstrap delays.
- **Memory leak warning in KeyManager** - Fixed singleton pattern to use applicationContext instead of Activity context to prevent memory leaks. Added proper `@Suppress("StaticFieldLeak")` annotation with safety justification.
- **Back navigation in account creation** - Fixed issue where pressing back button in CreateAccountActivity or RestoreAccountActivity would close the app. Now properly returns to lock screen.

### Added
- **Production cryptography integration** - Integrated real cryptographic libraries (LazySodium for Ed25519/X25519, web3j for BIP39, BouncyCastle) into KeyManager. Replaced all placeholder crypto implementations.
- **Wallet UI integration** - Connected wallet-related activities to KeyManager:
  - SplashActivity now checks wallet initialization status on startup
  - CreateAccountActivity generates real BIP39 12-word mnemonics and derives Solana addresses
  - WalletIdentityActivity displays actual wallet address from KeyManager
- **Multi-architecture native library support** - Added x86_64 native library build to jniLibs alongside ARM64, enabling app to run on both physical devices and emulators.
- **Proper authentication flow** - Implemented lock screen that appears after Tor connection. Shows password entry for existing wallets, or account creation/import options for new users. Prevents unauthorized access to the app.

### Changed
- **Code quality improvements** - Fixed all IDE warnings:
  - Removed unused imports
  - Changed to use Kotlin KTX extensions (`SharedPreferences.edit { }`)
  - Implemented proper equals/hashCode for KeyPair data class with ByteArray properties
  - Added `@Suppress("unused")` annotations to JNI-called methods with explanatory comments
- **Improved Tor persistence** - Modified `SplashActivity.testTorInitialization()` to `checkTorStatus()` which verifies existing connection instead of creating new one. TorService remains the single source of Tor initialization.
- **SplashActivity navigation** - Now always navigates to LockActivity after Tor connects, instead of directly to MainActivity or CreateAccountActivity. Ensures proper authentication on every app launch.
- **Account creation flow** - After successfully creating or restoring an account, the app now clears the back stack and navigates directly to MainActivity, preventing accidental return to account setup screens.

---

## [Unreleased]

### Added
- **Ping-Pong Wake Protocol - Incoming Request Handling**
  - Implemented persistent foreground service (TorService) that keeps Tor running 24/7
  - Added hidden service listener on localhost:9150 for incoming Ping tokens
  - Integrated Ping poller thread for continuous monitoring of incoming connections
  - Added WakeLock support to ensure reliable background operation
  - Implemented channel-based message passing from Rust to Kotlin for incoming Pings
  - Service persists when app is closed/swiped away from recents
  - Foreground notification shows connection status and .onion address

- **Arti Onion Service Configuration**
  - Configured proper onion service routing from .onion address to localhost:9150
  - Added HsNickname and OnionServiceConfig setup using tor-hsservice crate
  - Integrated persistent Ed25519 keypair for stable .onion addresses across app restarts
  - Implemented base32 encoding for v3 .onion address generation
  - Added SHA3-256 checksum calculation for onion address validation
  - Stores hidden service keys in `/data/data/com.securelegion/files/tor_hs/`
  - Detailed logging for onion service lifecycle events

- **Splash Screen Loading Indicator**
  - Added ProgressBar with circular loading animation during Tor initialization
  - Implemented real-time status text updates showing connection progress:
    - "Connecting to Tor network..." (initial state)
    - "Initializing Tor client..." (during initialization)
    - "Connected to Tor network!" (success state)
    - "Connection failed" (error state)
  - Styled with primary blue color theme (#2196F3)
  - Smooth fade-in and scale animations for logo and app name
  - Status updates via async callbacks from TorManager
  - Automatic navigation to MainActivity after initialization

- **JNI Bridge Enhancements** (secure-legion-core/src/ffi/android.rs)
  - Added `startHiddenServiceListener(port)` - Starts TCP listener for incoming connections
  - Added `stopHiddenServiceListener()` - Gracefully shuts down listener
  - Added `pollIncomingPing()` - Non-blocking retrieval of incoming Ping tokens
  - Implemented global `GLOBAL_PING_RECEIVER` channel using `OnceCell` for thread-safe access
  - Enhanced error handling with proper JNI exception throwing
  - Added Tokio runtime management for async operations

### Changed
- **Android Activity Launch Modes**
  - Set SplashActivity to `launchMode="singleTask"` to prevent multiple instances
  - Set MainActivity to `launchMode="singleTask"` for consistent app behavior
  - Ensures only one app instance appears in Android recents menu
  - Prevents duplicate tasks when app is launched multiple times

- **TorService Architecture Improvements**
  - Moved Tor initialization to background thread to prevent ANR (Application Not Responding)
  - Service now calls `startForeground()` immediately (<100ms) to avoid Android timeout
  - Added `stopWithTask="false"` to manifest to persist service when app is closed
  - Implemented `onTaskRemoved()` handler with logging for app closure events
  - Service type set to `dataSync` for appropriate foreground service permissions
  - Notification channel configured with low importance to minimize user interruption
  - START_STICKY return value ensures Android restarts service if killed

- **TorManager Rust Implementation** (secure-legion-core/src/network/tor.rs)
  - Enhanced `create_hidden_service()` with configurable service and local ports
  - Added port configuration fields: `hs_service_port` and `hs_local_port`
  - Implemented `start_listener()` method with Tokio TCP socket binding
  - Background async task spawned for accepting incoming connections
  - Added connection handler that reads data and forwards to mpsc channel
  - Implemented `stop_listener()` to abort listener task handle
  - Added `is_listening()` utility method to check listener state
  - Enhanced error handling with detailed logging at each step

- **SplashActivity Integration** (app/src/main/java/com/securelegion/SplashActivity.kt)
  - Added TorService startup call in `onCreate()` lifecycle method
  - Integrated status update callbacks from TorManager
  - Implemented `updateStatus()` helper for UI thread-safe text updates
  - Added graceful error handling with user-facing Toast messages
  - Auto-navigation to MainActivity with 500ms delay for UX smoothness

### Fixed
- **ANR Prevention**
  - Fixed service timeout by moving slow Tor initialization off main thread
  - Tor bootstrap now completes in background while foreground notification shows
  - Service starts in <100ms, well under Android's 20-second timeout
  - No more "Service not responding" dialogs

- **Multiple App Instances Issue**
  - Resolved duplicate task creation by implementing singleTask launch mode
  - Fixed recents menu showing 3-4 SecureLegion entries during testing
  - Now only one instance appears regardless of how many times app is launched
  - Existing task is brought to front instead of creating new one

- **Service Persistence After App Closure**
  - Verified TorService continues running after app is swiped away from recents
  - Confirmed WakeLock keeps CPU active for background socket operations
  - Tested foreground notification persists correctly in notification shade
  - Service process remains alive as verified by `ps` command
  - Ping poller thread continues monitoring for incoming connections

### Technical Details

**Android Manifest Updates:**
```xml
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
<uses-permission android:name="android.permission.WAKE_LOCK" />
<uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />

<service
    android:name=".services.TorService"
    android:foregroundServiceType="dataSync"
    android:stopWithTask="false" />
```

**Rust Dependencies Added:**
- `tokio::net::TcpListener` for socket operations
- `tokio::sync::mpsc` for async channel communication
- `tor-hsservice::{HsNickname, OnionServiceConfig}` for hidden service setup
- `std::sync::Arc` and `tokio::task::JoinHandle` for concurrency

**File Structure Changes:**
```
secure-legion-core/
├── src/network/tor.rs          (Modified - added listener methods)
├── src/ffi/android.rs          (Modified - added JNI bindings)

app/src/main/
├── java/com/securelegion/
│   ├── SplashActivity.kt       (Modified - added status updates)
│   ├── services/TorService.kt  (Modified - background thread init)
│   └── crypto/RustBridge.kt    (Modified - new native methods)
├── res/layout/
│   └── activity_splash.xml     (Modified - added ProgressBar)
└── AndroidManifest.xml         (Modified - permissions & launch modes)
```

**Testing Results:**
- ✅ Tor initialization: 15-20 seconds on first run, 5-8 seconds on subsequent runs
- ✅ Service persistence: Verified after app closure via recents swipe
- ✅ Socket listener: Active on 127.0.0.1:9150, accepting connections
- ✅ Single instance: Only one task in recents menu
- ✅ .onion address: Persistent across app restarts (v3 56-character address)
- ✅ Foreground notification: Shows in notification shade with app icon
- ✅ WakeLock: CPU stays active for background operations
- ✅ ANR prevention: Service starts <100ms, initialization in background

**Performance Metrics:**
- Memory footprint: ~80-210 MB (includes Tor client)
- CPU usage: <5% when idle, 15-25% during Tor bootstrap
- Network: Tor circuit establishment uses ~100-500 KB
- Battery impact: Low (foreground service with partial wake lock)

---

## [0.1.0] - Initial Release

### Core Features

**Tor Network Integration (Arti)**
- Full Tor client implementation using Arti (official Rust Tor implementation)
- Automatic Tor network bootstrap and circuit creation
- Persistent state management in `/data/data/com.securelegion/files/tor_state`
- Directory cache in `/data/data/com.securelegion/cache/tor_cache`
- Support for both clearnet and .onion address connections
- Ed25519-based v3 hidden service creation
- Cryptographically-derived .onion addresses (56 characters)

**Cryptography**
- **Message Encryption**: XChaCha20-Poly1305 AEAD cipher
  - 256-bit keys, 192-bit nonces
  - Authenticated encryption with additional data (AEAD)
  - Perfect forward secrecy with ephemeral keys
- **Digital Signatures**: Ed25519
  - 256-bit keys, 512-bit signatures
  - Fast verification, small signature size
- **Key Derivation**: HKDF-SHA256
  - Derives encryption keys from shared secrets
- **Password Hashing**: Argon2id
  - Memory-hard hashing for password storage
  - Configurable memory and iteration parameters
- **Random Number Generation**: ChaCha20-based CSPRNG
  - Cryptographically secure random generation

**Android UI Framework**
- **Activities**:
  - SplashActivity - App initialization and Tor bootstrap
  - MainActivity - Home screen with wallet and messages
  - ChatActivity - End-to-end encrypted messaging
  - ComposeActivity - New message composition
  - AddFriendActivity - Contact discovery and adding
  - SettingsActivity - App configuration
  - SecurityModeActivity - Security level selection
  - LockActivity - Biometric authentication screen
  - WalletIdentityActivity - Solana wallet management
  - ReceiveActivity - Generate payment QR codes
  - SendActivity - Send SOL/tokens
  - TransactionsActivity - Transaction history
  - ManageTokensActivity - SPL token management

- **UI Components**:
  - Material Design 3 theming
  - Dark mode support with gradient backgrounds
  - Custom card layouts for contacts and messages
  - Biometric authentication prompts
  - QR code generation and scanning
  - Swipe-to-delete gestures
  - Bottom navigation bar

**Wallet System (Solana)**
- HD wallet derivation (BIP39/BIP44)
- 12-word mnemonic seed phrase generation
- Ed25519 keypair derived from seed
- Solana mainnet/devnet/testnet support
- Native SOL balance tracking
- SPL token support (fungible tokens)
- Transaction signing and broadcasting
- QR code payment requests
- Transaction history with timestamps
- Fee estimation and management

**Contact Management**
- Contact storage in encrypted local database
- Contact attributes:
  - Display name
  - .onion address (hidden service)
  - Ed25519 public key
  - Trust level indicators
  - Last contact timestamp
- Contact verification through key exchange
- Search and filter capabilities
- Alphabetical sorting

**Messaging Features**
- End-to-end encrypted messages (XChaCha20-Poly1305)
- Ephemeral key exchange for perfect forward secrecy
- Message authentication (Ed25519 signatures)
- Offline message queue
- Read receipts
- Typing indicators
- Message timestamps
- Media attachments (encrypted)
- Message deletion (local only)

**Security Features**
- Biometric authentication (fingerprint/face)
- Duress PIN (wipes data under coercion)
- Secure enclave key storage (Android Keystore)
- Memory wiping on app exit
- Screenshot prevention
- Clipboard clearing after 60 seconds
- No analytics or telemetry
- No cloud backups (local only)

**Storage**
- SQLite database for contacts and messages
- AES-256-GCM encrypted database
- Secure file storage in app-private directory
- No external storage usage
- Auto-cleanup of temporary files

**Permissions**
- Internet (for Tor network)
- Biometric authentication
- Camera (for QR scanning)
- Minimal permission footprint

**Platform Support**
- Android 8.0+ (API 26+)
- ARM64-v8a architecture
- Kotlin + Rust hybrid architecture
- JNI bridge for Rust integration

**Dependencies**
- Arti 0.20.0 (Tor client)
- Tokio 1.48.0 (async runtime)
- ed25519-dalek 2.2.0 (signatures)
- chacha20poly1305 0.10.1 (encryption)
- argon2 0.5.3 (password hashing)
- AndroidX libraries
- Material Design Components
