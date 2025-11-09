# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
