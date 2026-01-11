<div align="center">

# Secure

**The first of its class private messaging app with Post-Quantum Cryptography, Private Payments, and Metadata Resistant with Patent Pending Technology**

[![Platform](https://img.shields.io/badge/platform-Android-green)](https://www.android.com/)
[![Language](https://img.shields.io/badge/language-Kotlin%20%7C%20Rust-orange)](https://kotlinlang.org/)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue)](LICENSE)
[![Website](https://img.shields.io/badge/website-securelegion.org-blue)](https://securelegion.org)

> "No servers. Metadata resistance. No compromises."

[Provisional Patent](https://securelegion.org/patent) | [Download Beta APK](https://securelegion.org/download) | [Documentation](https://securelegion.org/architecture) | [Roadmap](https://securelegion.org/roadmap)

</div>

---

## Overview

**Secure** is a revolutionary Android messaging application that combines truly serverless peer-to-peer communication, **post-quantum cryptography**, and integrated cryptocurrency payments. Unlike Signal, Session, or any traditional messenger, Secure eliminates ALL central infrastructure—no servers exist to log your metadata, no company can hand over data that was never collected.

**Core Architecture:**
- **Post-Quantum Cryptography** - Hybrid X25519 + ML-KEM-1024 (NIST FIPS 203) provides quantum-resistant encryption
- **Metadata Resistant** - No central servers track who communicates with whom, when, or how often
- **Truly Serverless P2P** - Messages route directly peer-to-peer at the application layer; no Secure-owned servers exist to collect metadata or relay messages. Uses Tor network for anonymous transport.
- **No Exit Nodes** - All communication stays within Tor network via hidden services; traffic never exits to clearnet
- **No Push Notification Servers** - No FCM, no APNs, no third-party notification infrastructure
- **Multi-Layered Access Control Hierarchy** - Hardware-backed keystores (StrongBox/TEE) with biometric authentication, Argon2id password hashing, domain-separated key derivation, memory zeroization, and duress PIN protection
- **Advanced ACH State Machine** - Sophisticated message tracking system managing ping/pong protocol states, delivery confirmations, exponential backoff retry logic, and persistent queue management for guaranteed offline message delivery
- **TAP Heartbeat Protocol** - When Tor connects, broadcasts encrypted "I'm online" signal to all contacts on port 9151; recipients immediately retry pending messages and check for available downloads, with TAP_ACK confirmation
- **Triple .onion Architecture** - Three separate deterministic Tor hidden services: friend discovery, friend requests, and encrypted messaging
- **Offline-First Design** - Send messages anytime; they queue locally and deliver automatically when recipient comes online
- **Ping-Pong Wake Protocol** - Recipient must authenticate via biometrics before message delivery
- **Hardware-Backed Security** - Private keys stored in Android StrongBox (Pixel, Samsung Knox) or Trusted Execution Environment, never accessible to software
- **Secure Pay** - Built-in multi-chain cryptocurrency wallet (Zcash + Solana) with in-chat payment protocol
- **Three-Phase Friend Protocol** - PIN-based initial request, post-quantum hybrid (X25519 + Kyber-1024) encrypted acceptance, and mutual acknowledgment for bidirectional contact addition, all over Tor

## What Makes Secure Unique

**The first of its kind messaging app combining:**

1. **True Serverless Architecture** - No central servers or notification servers. Messages go directly peer-to-peer using a hidden client service over Tor with no exit nodes.

2. **Post-Quantum Cryptography** - Hybrid encryption combining classical X25519 and quantum-resistant ML-KEM-1024, protecting your messages from future quantum computers.

3. **Complete Offline Support** - Both sender and recipient can be offline. Messages queue locally, sync automatically, no server required.

4. **Hardware-Backed Keys** - All cryptographic keys stored in dedicated security hardware (StrongBox/TEE), never exposed to Android OS or apps.

5. **Integrated Private Payments** - Send Zcash (shielded) and Solana payments directly in conversations via Secure Pay protocol.

6. **Tor VPN Mode** - System-wide Tor routing for ALL apps on your device, not just Secure.

7. **Per-Message Forward Secrecy** - Every message uses a unique ephemeral key that's immediately destroyed after use.

8. **Voice Calls Over Tor** - End-to-end encrypted voice calling routed exclusively through Tor network (experimental).

9. **Triple Hidden Service Design** - Separate .onion addresses for friend discovery, requests, and messaging provide layered anonymity.

10. **Biometric Message Delivery** - Recipient must authenticate via fingerprint/face before messages are delivered (Ping-Pong protocol).

**Competitive Analysis:**

| Feature | Secure | Signal | Session | Briar | SimpleX |
|---------|---------|--------|---------|-------|---------|
| **Serverless P2P** | Direct Tor | Central servers | SNODE relays | Limited | Relays |
| **Metadata Resistant** | Impossible to collect | Logged | Partial | Yes | Minimal |
| **Post-Quantum Crypto** | ML-KEM-1024 | PQXDH (X3DH + Kyber) | No | No | Partial |
| **Offline Messaging** | Full queue system | Requires servers | Requires SNODEs | Limited | No |
| **Integrated Wallet** | ZEC + SOL | MobileCoin only | No | No | No |
| **In-Chat Payments** | Secure Pay | No | No | No | No |
| **Tor VPN Mode** | System-wide | No | No | No | No |
| **Voice Calls** | Over Tor | VoIP | No | No | WebRTC |
| **Hardware Keys** | StrongBox/TEE | Software only | Software only | Software only | Software only |
| **Friend Requests** | 2-phase Tor | Phone number | Session ID | Bloom filter | QR code |

## Features

### Messaging

**Text & Media:**
- End-to-end encrypted text messaging with post-quantum hybrid encryption
- Image sharing with automatic compression and EXIF metadata stripping
- Voice messages with hold-to-record interface
- Self-destruct timers for sensitive messages (1 min to 7 days)
- Read receipts (optional, recipient-controlled)
- Secure message deletion with cryptographic wiping

**Voice Calling:**
- Voice calls over Tor using Opus codec (high-quality audio)
- End-to-end encrypted with XChaCha20-Poly1305 AEAD
- Real-time audio streaming via Tor hidden services
- Call quality indicators and connection statistics
- No phone number or VoIP service required

**Offline-First Design:**
- Send messages whether recipient is online or offline
- Messages queue locally in encrypted database
- Automatic delivery when recipient comes online
- Ping-Pong wake protocol notifies recipient
- No message loss, guaranteed delivery

**Coming Soon:**
- File attachments (documents, videos, arbitrary files)
- Group messaging with multi-party encryption
- Message reactions and replies

### Security & Privacy

**Post-Quantum Cryptography:**
- **Hybrid Key Exchange**: X25519 + ML-KEM-1024 (NIST FIPS 203)
  - Combines classical elliptic curve (X25519) with post-quantum key encapsulation mechanism
  - Secure if EITHER X25519 OR ML-KEM-1024 remains unbroken
  - 64-byte combined shared secret via HKDF-SHA256
  - Protects against "harvest now, decrypt later" quantum attacks

**Message Encryption:**
- **AEAD Encryption**: XChaCha20-Poly1305 (authenticated encryption with associated data)
- **Digital Signatures**: Ed25519 (message authentication and sender verification)
- **Forward Secrecy**: Per-message forward secrecy with bidirectional key chains
  - Every message uses unique ephemeral key derived from ratcheting chain
  - Separate send/receive ratchets prevent key reuse
  - Keys zeroized from memory immediately after use
  - HMAC-based key derivation (HKDF-SHA256)

**Hardware Security:**
- Private keys stored in Android StrongBox (Pixel 3+, Samsung Galaxy S9+ with Knox)
- Fallback to Trusted Execution Environment (TEE) on devices without StrongBox
- Keys never accessible to Android OS, apps, or even Secure itself
- Hardware-backed key attestation prevents extraction
- Secure element tamper detection

**Access Protection:**
- Biometric authentication (fingerprint/face) required on every app launch
- Duress PIN triggers instant cryptographic data wipe and network revocation
- Automatic screen lock after inactivity
- Screenshot prevention for sensitive screens
- Secure deletion with cryptographic key destruction (DOD 5220.22-M standard)

**Network Privacy:**
- All traffic routed exclusively through Tor network
- Triple .onion architecture:
  - **Friend Discovery .onion** - Shareable via QR code for contact exchange
  - **Friend Request .onion** - Receives PIN-encrypted friend requests (port 9151)
  - **Messaging .onion** - Receives end-to-end encrypted messages (port 9150)
- No IP address leakage (Tor provides anonymity)
- No DNS queries (Tor handles resolution)
- Deterministic .onion generation from seed phrase

**Tor VPN Mode (System-Wide):**
- Routes ALL device traffic through Tor (powered by OnionMasq + Arti)
- Protects all apps, not just Secure
- Supports bridges for censorship circumvention:
  - obfs4 (obfuscated Tor traffic)
  - Snowflake (domain fronting)
  - webtunnel (WebSocket-based)
- Automatic bridge selection in restrictive networks
- Battery-optimized Rust implementation (Arti)

### Payments - Secure Pay

**Multi-Chain Cryptocurrency Wallet:**
- **Zcash (ZEC)**: Privacy-focused payments with shielded transactions (z-addresses)
- **Solana (SOL)**: Fast, low-fee payments
- **SPL Tokens**: USDC and USDT stablecoin support
- Hardware wallet-grade security (keys in StrongBox/TEE)
- Transaction history with block explorer links
- Testnet mode for safe development and testing

**Secure Pay Protocol:**
*Built on NLx402 payment protocol core logic*

- **In-Chat Payment Quotes**: Send payment requests directly in conversations
  - Specify amount, cryptocurrency (ZEC/SOL/USDC/USDT), expiry time
  - Real-time SOL and ZEC price fetching for USD conversion
  - Quote expiry options: 15 min, 1 hour, 6 hours, 24 hours (default), 48 hours, 7 days
- **One-Tap Payment**: Recipient accepts quote with single tap
- **Cryptographic Verification**: Transaction signatures prevent double-spend and replay attacks
- **Payment Status Tracking**: Pending, paid, expired, cancelled states
- **Secure Memo Encryption**: Payment notes encrypted end-to-end
- **Audit Trail**: Transaction signatures stored for accounting/auditing

**Payment Features:**
- Request money from contacts with custom amounts
- Send money to contacts with optional encrypted memos
- Accept/decline payment quotes
- View transaction history

### Network Architecture

**Tor Integration:**
- Powered by Guardian Project's tor-android (maintained C implementation)
- Triple Tor v3 hidden services architecture:
  1. **Friend Discovery .onion** - Public, shareable via QR for contact exchange
  2. **Friend Request .onion** (port 9151) - Receives PIN-encrypted friend requests
  3. **Messaging .onion** (port 9150) - Receives end-to-end encrypted messages
- Deterministic .onion address generation from seed phrase (BIP39-derived)
- Control port management via jtorctl
- Pluggable transports: obfs4, Snowflake, meek, webtunnel
- Bridge support for censorship circumvention

**Ping-Pong Wake TAP Protocol:**
```
SENDER                          RECIPIENT
  |                                 |
  |- Create encrypted message       |
  |- Store in local queue           |
  |- Send PING token --------------->|
  |   (via Tor hidden service)      |- Receive wake notification
  |                                 |- Authenticate (biometric)
  |<--------------- PONG -----------|
  |   (confirms online + authed)    |
  |- Send encrypted message -------->|
  |   (via Tor)                     |- Decrypt & display
  |<---------------- ACK ------------|
  |- Delete from queue              |
```

**Key Properties:**
- No central servers—completely peer-to-peer
- Recipient must authenticate before receiving messages (biometric required)
- Messages queued locally until recipient comes online
- Offline-first design with automatic retry and exponential backoff
- End-to-end encrypted at every step (including PING tokens)

**TAP Heartbeat Protocol:**
```
DEVICE A                        DEVICE B
  |                                 |
  |- Tor connects                   |
  |- Send TAP to all contacts ----->|
  |   (port 9151, encrypted)        |- Decrypt TAP
  |<------------- TAP_ACK -----------|- Confirm receipt
  |                                 |
  |                                 |- ACH State Machine Checks:
  |                                 |  • Pending Pings FROM A? → Notify user (download available)
  |                                 |  • Pending messages TO A:
  |                                 |    - PHASE 4: MESSAGE_ACK received? → Skip (delivered)
  |                                 |    - PHASE 3: PONG_ACK received? → Skip (downloading)
  |                                 |    - PHASE 2: PING_ACK received? → Poll for PONG
  |                                 |    - PHASE 1: No PING_ACK? → Retry Ping immediately
  |                                 |
  |                                 |- Tor connects
  |<---------- TAP ------------------|
  |- Decrypt TAP                    |- Send TAP to all contacts
  |- TAP_ACK ----------------------->|
  |                                 |
  |- ACH State Machine Checks:      |
  |  • Pending Pings FROM B?        |
  |  • Pending messages TO B:       |
  |    - Check all 4 ACK phases     |
  |    - Take appropriate action    |
```

**TAP System Benefits:**
- Bidirectional "I'm online" notification without central servers
- Triggers full ACH state machine check for intelligent message retry
- Checks inbox for pending Pings (available downloads)
- Checks outbox at all 4 ACK phases (PING_ACK, PONG_ACK, MESSAGE_ACK)
- Polls for PONGs when PING_ACK confirmed
- Separate listener on port 9151 (doesn't interfere with message delivery)
- Encrypted with recipient's X25519 public key
- Broadcasts to all contacts on Tor connection (150ms delay between sends)

### Contact Discovery

**Local Contact Storage:**
- All contacts stored locally in encrypted SQLCipher database on your device
- Contact information never leaves your device (except during friend request exchange)
- No central contact directory, no phone number requirement, no email
- Complete privacy—only you know who your contacts are

**Three-Phase Friend Request Protocol:**

**Phase 1 - Initial Request (PIN-encrypted, 0x07):**
1. You receive friend's friend discovery .onion address and 10-digit PIN via QR code
2. You send initial contact information to their friend-request.onion:
   - Your username
   - Your friend-request.onion address
   - Your X25519 public key
3. Encrypted with shared secret derived from PIN (XSalsa20-Poly1305)
4. Sent directly via Tor hidden service to friend-request.onion
5. PIN prevents spam and unauthorized friend requests
6. Recipient receives notification and reviews request

**Phase 2 - Acceptance (Post-Quantum Hybrid Encrypted, 0x08):**
1. Recipient decrypts Phase 1 request using their PIN
2. Recipient reviews your username and decides to accept/reject
3. If accepted, recipient sends FULL contact card to your friend-request.onion:
   - Their username, messaging.onion, voice.onion addresses
   - Their Ed25519 signing public key
   - Their X25519 key exchange public key
   - Their Kyber-1024 post-quantum public key
   - Hybrid shared secret (X25519 + Kyber-1024 KEM) for quantum-resistant key chain initialization
4. Encrypted with hybrid post-quantum cryptography (X25519 + Kyber-1024)
5. You decrypt and save their contact to local database

**Phase 3 - Mutual Acknowledgment (Post-Quantum Hybrid Encrypted, 0x08):**
1. Original sender receives Phase 2 acceptance
2. Sender sends their FULL contact card back to recipient's friend-request.onion
3. Encrypted with post-quantum hybrid cryptography (X25519 + Kyber-1024)
4. Recipient saves sender's complete contact to database
5. Both parties now have each other's complete contact information
6. Bidirectional messaging enabled with post-quantum resistant key chains via messaging.onion addresses

**Privacy Design:**
- All communication via Tor hidden services (zero servers, zero IPFS)
- Friend discovery .onion shared via QR code (offline, no network)
- Friend-request.onion and messaging.onion exchanged during protocol
- All .onion addresses deterministically generated from seed phrase
- PIN-based initial encryption prevents spam (Phase 1)
- X25519-encrypted acceptance prevents man-in-the-middle attacks (Phase 2 & 3)
- Three-phase bidirectional exchange ensures both parties successfully add each other
- No phone numbers, no email addresses, no personally identifiable information

### User Experience

**Modern Material Design 3 UI:**
- Dark theme optimized for OLED displays and battery life
- Responsive layouts for all screen sizes (phones, tablets, foldables)
- Swipe gestures for quick actions (timestamps, deletion, forward)
- Pull-to-refresh for message synchronization
- Long-press context menus for advanced options
- Smooth animations and transitions

**Background Operation:**
- Foreground service keeps Tor running reliably
- Message queue persistence across app restarts
- Battery-optimized wake locks (2026 Play Store compliant)
- Lifecycle-aware components prevent memory leaks
- Efficient coroutine-based async operations

**Data Management:**
- Encrypted Room database with SQLCipher (AES-256-GCM)
- Automatic database migrations for seamless updates
- Secure deletion with cryptographic key destruction (DOD 5220.22-M standard)
- Database backup and restore (manual, coming soon)
- Export/import account data (encrypted, planned)

## Architecture

### Technology Stack

```
┌─────────────────────────────────────┐
│       Android App (Kotlin)          │
│  Material 3 • Room DB • Biometrics  │
├─────────────────────────────────────┤
│         JNI Bridge (FFI)            │
├─────────────────────────────────────┤
│      Rust Core Library              │
│  ┌──────────┬──────────┬──────────┐│
│  │  Crypto  │   Tor    │Blockchain││
│  │XChaCha20 │ Hidden   │ Solana   ││
│  │ Ed25519  │ Services │  Zcash   ││
│  │ ML-KEM   │SecurePay │   SPL    ││
│  └──────────┴──────────┴──────────┘│
├─────────────────────────────────────┤
│   Hardware Security (StrongBox/TEE)│
└─────────────────────────────────────┘
```

**Android Layer (Kotlin):**
- Material Design 3 UI components
- Room Database with SQLCipher encryption
- CameraX for QR code scanning
- Biometric authentication (fingerprint/face)
- WorkManager for background tasks
- Lifecycle components for state management
- Coroutines for async operations

**Rust Core Library:**
- Cryptographic operations (XChaCha20-Poly1305, Ed25519, X25519, ML-KEM-1024, Argon2id)
- Tor hidden service management (control port, ephemeral services)
- Ping-Pong protocol implementation
- Secure Pay payment quote creation and verification
- Message serialization/deserialization
- JNI bindings for Android integration
- Memory-safe implementations with zero-copy optimizations

**External Infrastructure:**
- **Tor Network**: Anonymous routing for all communications (no Secure-owned nodes)
- **Solana Blockchain**: Public blockchain for SOL/USDC/USDT payments
- **Zcash Blockchain**: Privacy-focused blockchain for shielded ZEC payments

**Security Hardware:**
- Android StrongBox (Titan M on Pixel, Knox on Samsung)
- Trusted Execution Environment (TEE) fallback for non-StrongBox devices
- Hardware-backed key attestation and tamper detection

### Cryptographic Primitives

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| **Post-Quantum KEM** | Hybrid X25519 + ML-KEM-1024 | 32-byte + 32-byte = 64-byte combined | Quantum-resistant key encapsulation (NIST FIPS 203) |
| **Message Encryption** | XChaCha20-Poly1305 | 256-bit | AEAD encryption for message content |
| **Digital Signatures** | Ed25519 | 256-bit | Message authentication and sender verification |
| **Key Exchange** | X25519 ECDH | 256-bit | Classical ephemeral session keys |
| **Key Derivation** | HKDF-SHA256 | 256-bit | Per-message key ratcheting from shared secret |
| **Forward Secrecy** | HMAC-based ratchet | 256-bit | Bidirectional key chains, unique key per message |
| **Voice Encryption** | XChaCha20-Poly1305 | 256-bit | Real-time audio stream encryption |
| **Voice Codec** | Opus | Variable | High-quality audio encoding/decoding |
| **Password Hashing** | Argon2id | Variable | PIN/password derivation (memory-hard) |
| **Database Encryption** | AES-256-GCM | 256-bit | SQLCipher local storage encryption |
| **Friend Request Phase 1** | XSalsa20-Poly1305 | 256-bit | PIN-based encryption for initial key exchange |

**Implementation Details:**
- All crypto operations delegated to Rust core (memory-safe, side-channel resistant)
- **Per-message forward secrecy**: Every message uses unique ephemeral key derived from ratcheting chain
- **Bidirectional key chains**: Separate ratchets for sending and receiving
- **Immediate key destruction**: Ephemeral keys zeroized from memory after use (Rust zeroize crate)
- **Post-quantum cryptography**: Hybrid X25519 + ML-KEM-1024 provides quantum resistance
  - Uses NIST-standardized ML-KEM (formerly Kyber-1024) from FIPS 203
  - Combines 32-byte X25519 + 32-byte ML-KEM secrets into 64-byte hybrid secret via HKDF
  - Secure if EITHER classical OR post-quantum algorithm remains unbroken
  - Protects against "harvest now, decrypt later" attacks by quantum adversaries
- Nonces never reused (random for XChaCha20, deterministic counter for signatures)
- Constant-time comparisons prevent timing attacks
- Secure memory wiping after use (DOD 5220.22-M 3-pass standard)
- Hardware-backed keys used where available (StrongBox/TEE)

### Threat Model

**Protected Against:**
- Passive network surveillance (Tor encryption + onion routing)
- Active man-in-the-middle attacks (Ed25519 signatures + Tor end-to-end encryption)
- Server compromise (no servers exist to compromise)
- Metadata analysis (no centralized logs, no "who talks to whom" data)
- Device seizure with duress (PIN triggers instant cryptographic wipe)
- Traffic correlation attacks (Tor + three separate .onion addresses)
- Traffic analysis (Tor hidden services obscure patterns)
- Future quantum computer attacks (ML-KEM-1024 post-quantum crypto)
- Key extraction attacks (hardware-backed keys in StrongBox/TEE)

**Not Protected Against:**
- Hardware implants in the device itself (physical supply chain attacks)
- Endpoint security failures (keyloggers, screen recorders, clipboard sniffers)
- Social engineering attacks (phishing, impersonation)
- Physical coercion ($5 wrench attack - duress PIN provides limited defense)

**Assumptions:**
- Android secure boot chain is intact and not compromised
- Hardware security module (StrongBox/TEE) is not backdoored
- User maintains physical security of device (screen lock, safe storage)
- Cryptographic algorithms (XChaCha20, Ed25519, X25519, ML-KEM-1024) are secure

See [Security Model](https://securelegion.org/security-model) for complete threat analysis and security guarantees.

## Quick Start

### Prerequisites

**Development Environment:**
- Android Studio Hedgehog 2023.1.1 or newer
- Rust toolchain 1.70+ (install via `rustup`)
- Android NDK 26.1.10909125 or newer
- `cargo-ndk` for cross-compilation: `cargo install cargo-ndk`

**Runtime Requirements:**
- Android 8.1 (API 27) or higher
- ARMv8-A 64-bit processor (arm64-v8a)
- Biometric hardware (fingerprint or face unlock)
- 200 MB free storage minimum
- Internet connection for Tor (optional for offline messaging)

### Installation

```bash
# 1. Clone repository
git clone https://github.com/Secure-Legion/secure-legion-android.git
cd secure-legion-android

# 2. Install Rust targets for Android
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android

# 3. Install cargo-ndk
cargo install cargo-ndk

# 4. Build Rust core library
cd secure-legion-core
./build_android.sh  # Linux/Mac
# or
build_android.bat   # Windows

# 5. Verify .so files were created
ls -lh ../app/src/main/jniLibs/arm64-v8a/libsecurelegion.so

# 6. Open project in Android Studio
cd ..
# File > Open > select secure-legion-android folder

# 7. Create keystore.properties (optional, for release builds)
echo "storeFile=release.keystore" > keystore.properties
echo "storePassword=YOUR_PASSWORD" >> keystore.properties
echo "keyAlias=secure" >> keystore.properties
echo "keyPassword=YOUR_PASSWORD" >> keystore.properties

# 8. Build and run
# Click Run in Android Studio (Shift+F10)
# Or via command line:
./gradlew installDebug
```

### First Run

1. **Create Account**: Generate new identity with hardware-backed keys (30 seconds)
2. **Set Biometric Lock**: Configure fingerprint or face unlock
3. **Set Duress PIN**: Emergency wipe trigger (optional but highly recommended)
4. **Add Contacts**: Share your friend discovery .onion address via QR code
5. **Fund Wallet** (optional): Send SOL/ZEC to your wallet addresses to enable Secure Pay

## Project Structure

```
secure-legion-android/
├── app/                              # Android application
│   ├── src/main/
│   │   ├── java/com/securelegion/
│   │   │   ├── ChatActivity.kt       # Main conversation UI
│   │   │   ├── CreateAccountActivity.kt
│   │   │   ├── AddFriendActivity.kt  # Contact management
│   │   │   ├── WalletActivity.kt     # Secure Pay wallet
│   │   │   ├── SendMoneyActivity.kt  # Payment sending
│   │   │   ├── crypto/
│   │   │   │   ├── RustBridge.kt     # JNI interface to Rust
│   │   │   │   ├── KeyManager.kt     # Hardware key management
│   │   │   │   ├── SecurePayManager.kt # Payment protocol
│   │   │   │   └── TorManager.kt     # Tor lifecycle
│   │   │   ├── services/
│   │   │   │   ├── TorService.kt     # Background Tor daemon
│   │   │   │   ├── MessageService.kt # Message queue
│   │   │   │   ├── FriendRequestService.kt # Friend request handling
│   │   │   │   ├── ZcashService.kt   # Zcash wallet
│   │   │   │   └── SolanaService.kt  # Solana wallet
│   │   │   ├── database/
│   │   │   │   ├── SecureLegionDatabase.kt # Room DB
│   │   │   │   ├── entities/
│   │   │   │   │   ├── Message.kt    # Message entity
│   │   │   │   │   ├── Contact.kt    # Contact entity
│   │   │   │   │   └── Wallet.kt     # Wallet entity
│   │   │   │   └── dao/              # Database access
│   │   │   └── models/               # Data models
│   │   ├── jniLibs/                  # Rust .so files (built)
│   │   │   ├── arm64-v8a/
│   │   │   │   └── libsecurelegion.so
│   │   │   └── armeabi-v7a/
│   │   │       └── libsecurelegion.so
│   │   └── res/                      # UI resources
│   └── build.gradle.kts
│
├── secure-legion-core/                # Rust core library
│   ├── src/
│   │   ├── lib.rs                    # Library entry point
│   │   ├── crypto/
│   │   │   ├── mod.rs                # XChaCha20, Ed25519, X25519, ML-KEM
│   │   │   └── password.rs           # Argon2id
│   │   ├── network/
│   │   │   ├── mod.rs                # Ping-Pong protocol
│   │   │   ├── ping_pong.rs          # Token management
│   │   │   ├── tor.rs                # Triple hidden service management
│   │   │   ├── friend_request_server.rs # Friend request listener
│   │   │   └── socks5_client.rs      # SOCKS5 Tor client
│   │   ├── protocol/
│   │   │   ├── message.rs            # Message serialization
│   │   │   └── contact_card.rs       # Contact format
│   │   ├── blockchain/
│   │   │   └── solana.rs             # Solana wallet operations
│   │   ├── securepay/
│   │   │   ├── mod.rs                # Secure Pay protocol
│   │   │   └── quote.rs              # Quote verification
│   │   └── ffi/
│   │       └── android.rs            # JNI bindings
│   ├── Cargo.toml
│   ├── build_android.sh
│   └── .cargo/config.toml
│
├── CHANGELOG.md
└── README.md
```

## Roadmap

### Completed

- [x] Rust cryptography core library with memory safety
- [x] Android app architecture with Material Design 3
- [x] Hardware security module integration (StrongBox/TEE)
- [x] Encrypted Room database with SQLCipher
- [x] Tor integration via Guardian Project libraries
- [x] Ping-Pong wake protocol implementation
- [x] Text messaging with post-quantum hybrid encryption
- [x] Image sharing with compression and EXIF stripping
- [x] Voice messages with hold-to-record interface
- [x] Biometric authentication (fingerprint/face)
- [x] Duress PIN with instant cryptographic wipe
- [x] Solana wallet integration (SOL, USDC, USDT)
- [x] Zcash wallet integration (shielded transactions)
- [x] Secure Pay payment protocol (based on NLx402 core logic)
- [x] Two-phase friend request protocol (PIN + ephemeral key)
- [x] Self-destruct timers for messages
- [x] Read receipts (optional, recipient-controlled)
- [x] Testnet mode for safe development
- [x] Background service architecture with battery optimization
- [x] Message queue persistence and offline support
- [x] Triple .onion architecture (discovery, requests, messaging)
- [x] Deterministic hidden service generation from seed phrase
- [x] Voice calling over Tor (Opus codec, real-time streaming)
- [x] Tor VPN mode (OnionMasq system-wide routing with Arti)
- [x] Per-message forward secrecy with bidirectional key ratcheting
- [x] Post-quantum cryptography (Hybrid X25519 + ML-KEM-1024)

### In Development

- [ ] Post-quantum Double Ratchet (PQC-enhanced Signal Protocol)
- [ ] File attachments (documents, videos, arbitrary files)
- [ ] Group messaging (multi-party encrypted conversations with forward secrecy)
- [ ] Reproducible builds for security audits
- [ ] F-Droid release (fully open source distribution)
- [ ] Google Play Store release

### Planned Features

- [ ] Device-to-device contact backup mesh via encrypted IPFS
- [ ] Desktop client (Linux/Windows/macOS with Qt/Rust)
- [ ] iOS app (Swift + Rust core)
- [ ] Disappearing messages (auto-delete after configurable time)
- [ ] Incognito keyboard (disable autocorrect/suggestions/clipboard)
- [ ] Contact verification via safety numbers (Signal-style)
- [ ] Message reactions and threaded replies
- [ ] Animated stickers and GIFs

### Future Exploration

- [ ] Monero (XMR) wallet integration for maximum payment privacy
- [ ] Lightning Network payments (instant, low-fee Bitcoin)
- [ ] Mesh networking (local P2P without internet using WiFi Direct)

See detailed [Roadmap](https://securelegion.org/roadmap) on website.

## Testing

### Rust Tests

```bash
cd secure-legion-core
cargo test                    # All tests
cargo test --release          # Optimized tests
cargo test crypto::           # Crypto module only
cargo test securepay::        # Secure Pay module only
cargo test --verbose          # Detailed output
```

### Android Unit Tests

```bash
./gradlew test                # All unit tests
./gradlew testDebugUnitTest   # Debug variant only
./gradlew testReleaseUnitTest # Release variant
```

### Android Instrumentation Tests

```bash
# Connect Android device or start emulator
./gradlew connectedAndroidTest
./gradlew connectedDebugAndroidTest
```

### Manual Testing Checklist

1. **Account Creation**: Create account, verify keys stored in StrongBox/TEE
2. **Biometric Lock**: Test fingerprint/face unlock on app launch
3. **Duress PIN**: Verify cryptographic data wipe on duress PIN entry
4. **Contact Sharing**: Share friend discovery .onion address via QR code
5. **Add Contact**: Scan friend's QR code, complete 2-phase friend request
6. **Text Messaging**: Send/receive text messages, verify encryption
7. **Image Sharing**: Send/receive images, verify EXIF stripping
8. **Voice Messages**: Record/send/receive voice messages
9. **Voice Calling**: Initiate voice call over Tor, verify audio quality
10. **Secure Pay**: Create payment quote, send ZEC/SOL, verify receipt on blockchain
11. **Self-Destruct**: Set timer on message, verify automatic deletion
12. **Offline Messaging**: Send message while recipient offline, verify queue and delivery
13. **Background Service**: Kill app, verify Tor service continues and messages queue
14. **Tor VPN Mode**: Enable system-wide Tor, verify all apps route through Tor

## Contributing

Contributions are welcome! **Secure** is open source (noncommercial license) and community-driven.

### How to Contribute

1. **Fork** the repository on GitHub
2. **Clone** your fork locally: `git clone https://github.com/YOUR_USERNAME/secure-legion-android.git`
3. **Create** a feature branch: `git checkout -b feature/your-feature-name`
4. **Commit** your changes with clear, descriptive messages
5. **Test** thoroughly (unit tests + manual testing on device)
6. **Push** to your fork: `git push origin feature/your-feature-name`
7. **Open** a Pull Request with detailed description of changes

### Areas to Contribute

**Security:**
- Cryptographic code review and auditing
- Threat modeling and attack surface analysis
- Penetration testing and vulnerability research
- Security documentation and best practices

**Development:**
- Bug fixes (see GitHub Issues for open bugs)
- Feature implementation (check roadmap for ideas)
- Performance optimization (battery life, message delivery speed)
- Code refactoring and cleanup

**Documentation:**
- Technical documentation and architecture diagrams
- User guides and tutorials
- API documentation for Rust core
- Translation and internationalization

**Design:**
- UI/UX improvements and modernization
- Icon design and app branding
- Screenshot creation for app stores
- Marketing materials and website design

**Testing:**
- Automated test coverage expansion
- Integration tests for Rust-Kotlin bridge
- Beta testing on diverse devices (manufacturers, Android versions)
- Bug reporting with reproduction steps

**Localization:**
- Translation to other languages (Spanish, French, German, Chinese, etc.)
- RTL language support (Arabic, Hebrew)
- Locale-specific formatting (dates, times, currency)

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines (coming soon).

### Code Style

**Kotlin:**
- Follow official [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)
- Use meaningful, descriptive variable names
- Add KDoc comments for public APIs
- Prefer immutable data structures (`val`, `List`, `data class`)
- Use Coroutines for async operations

**Rust:**
- Follow official [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/)
- Run `cargo fmt` before committing (automatic formatting)
- Run `cargo clippy` to catch common mistakes and anti-patterns
- Add doc comments (`///`) for all public functions
- Use `#![forbid(unsafe_code)]` unless absolutely necessary

### Pull Request Guidelines

- Keep PRs focused on a single feature or bug fix
- Update tests for any code changes
- Update documentation for user-facing changes
- Add entry to CHANGELOG.md with semantic versioning
- Rebase on latest `main` before submitting
- Respond to code review feedback promptly

## Documentation

**Official Documentation:**
- [Website](https://securelegion.org) - Project overview and feature showcase
- [Architecture](https://securelegion.org/architecture) - System design and technical components
- [Security Model](https://securelegion.org/security-model) - Threat analysis and security guarantees
- [Ping-Pong Protocol](https://securelegion.org/ping-pong-protocol) - P2P messaging protocol specification
- [Feasibility Audit](https://securelegion.org/feasibility-audit) - Technical validation and proof-of-concept

**Repository Documentation:**
- [CHANGELOG.md](CHANGELOG.md) - Version history and release notes

**Rust Core Documentation:**
- [secure-legion-core/README.md](secure-legion-core/README.md) - Rust library overview
- API documentation: Run `cargo doc --open` in `secure-legion-core/` directory

## Frequently Asked Questions

### General

**Q: How is Secure different from Signal?**

A: Signal uses centralized servers for message relay and metadata logging. Even though messages are encrypted, Signal's servers can see who messages whom, when, and how often. **Secure has zero servers**—messages route directly peer-to-peer over Tor. It's architecturally impossible for Secure to log metadata because no central infrastructure exists.

**Q: Why not just use Signal with Tor or a VPN?**

A: VPNs and Tor hide your IP from Signal's servers, but Signal still logs metadata (who talks to whom, timestamp, message count). **Secure prevents metadata collection entirely** through serverless P2P architecture. Additionally, Secure includes post-quantum cryptography, hardware-backed keys, and integrated cryptocurrency payments.

**Q: Does Secure use blockchain for messaging?**

A: No. Messages are P2P over Tor, never touching blockchain. Blockchain is only used for Secure Pay cryptocurrency payments. Your conversations are completely off-chain and private.

**Q: Can I use Secure without cryptocurrency?**

A: Yes! Cryptocurrency is completely optional. You can use text/image/voice messaging and calls without ever touching the wallet. Secure Pay is an extra feature for those who want it.

### Security

**Q: Has Secure been security audited?**

A: Not yet. A professional security audit is planned before 1.0 release. Current version is beta—use at your own risk. Do not use for life-critical communications until audit is complete.

**Q: What happens if Tor is compromised?**

A: If the Tor network is globally deanonymized (extremely difficult), attackers could potentially correlate traffic patterns. However, message content remains encrypted with post-quantum hybrid encryption (X25519 + ML-KEM-1024). End-to-end encryption is independent of Tor anonymity.

**Q: Can governments force you to hand over user data?**

A: No data to hand over. Secure has no servers, no databases, no logs. We cannot hand over what we don't possess. All messages are stored locally on user devices in encrypted databases.

**Q: What about the $5 wrench attack (physical coercion)?**

A: The duress PIN provides limited defense—entering it triggers instant cryptographic data wipe and network revocation broadcast. However, physical security is ultimately your responsibility. Use full-disk encryption, secure screen lock, and maintain physical control of your device.

**Q: Is Secure vulnerable to quantum computers?**

A: Secure uses hybrid post-quantum cryptography (X25519 + ML-KEM-1024). This protects against future quantum computers using Shor's algorithm. The encryption remains secure if EITHER classical OR post-quantum algorithm is unbroken.

### Technical

**Q: Why Android only?**

A: Initial development focused on Android for faster iteration. iOS app is planned after Android stabilizes. Desktop clients (Linux/Windows/macOS) are also on the roadmap.

**Q: Does Secure drain battery?**

A: Tor background service uses power, but is optimized for battery efficiency. Typical usage: 5-10% battery per day with moderate messaging. Tor VPN mode uses more power when routing all device traffic.

**Q: How large is the app?**

A: APK size is approximately 45-50 MB (includes Tor libraries, Rust core, Zcash SDK). Larger than Signal but necessary for serverless P2P architecture and integrated wallet.

**Q: What Android devices are supported?**

A: Android 8.1 (API 27) or higher. ARMv8-A 64-bit processor (arm64-v8a) required. Most devices from 2018+ are supported. StrongBox available on Pixel 3+, Samsung Galaxy S9+ (Knox), and other flagship devices.

**Q: Can messages be sent when both users are offline?**

A: Yes! Messages queue locally in encrypted database. When sender comes online, Ping-Pong protocol attempts delivery. When recipient comes online, they receive queued messages. Fully offline-first design.

### Privacy

**Q: Do I need to provide a phone number or email?**

A: No. Secure has no phone number verification, no email requirement, no identity checks. Completely anonymous by default. Your .onion address is your identity.

**Q: How do contacts find me?**

A: Share your friend discovery .onion address via QR code (offline, secure channel). Your .onion address is deterministically generated from your seed phrase.

**Q: Can contacts see if I'm online?**

A: Only during active messaging sessions. Ping-Pong protocol requires recipient to be online to receive messages, but no persistent "online status" is broadcast. Maximum privacy.

**Q: Does Secure collect analytics or telemetry?**

A: Zero analytics, zero telemetry, zero tracking. No data leaves your device except encrypted messages to recipients. No crash reports, no usage statistics, nothing.

## Beta Notice

**This software is in beta and not production-ready.**

**Known Limitations:**
- Security audit pending (scheduled for Q2 2026)
- No reproducible builds yet (work in progress)
- Limited testing on diverse devices and Android versions
- Breaking changes may occur in major updates
- Documentation still evolving

**Recommendations:**
- Do not use for life-critical communications
- Test thoroughly before relying on Secure for sensitive conversations
- Keep backups of important data (manual export coming soon)
- Report bugs immediately via GitHub Issues
- Use testnet mode for Secure Pay testing (mainnet transactions are real money)

**Security Vulnerabilities:**

If you discover a security vulnerability, **DO NOT** open a public GitHub issue. Email **dev@securelegion.org** with:
- Detailed description of the vulnerability
- Steps to reproduce with proof-of-concept (if applicable)
- Potential impact assessment
- Suggested fix (if any)
- Your preferred contact method

We will respond within 48 hours and work with you on responsible disclosure. Security researchers may be eligible for bug bounties (coming soon).

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

**Permissions:**
- Use for noncommercial purposes (personal use, education, research)
- Modify and create derivative works
- Distribute original or modified versions (noncommercial only)

**Limitations:**
- **No commercial use** without separate commercial license agreement
- Cannot sell the software or use it to provide paid services
- Cannot use in commercial products without permission

**Commercial Licensing:**

If you want to use Secure commercially (SaaS, embedded in products, enterprise deployment), contact **licensing@securelegion.org** for a commercial license agreement.

See [LICENSE](LICENSE) file for full legal terms or visit [polyformproject.org](https://polyformproject.org/licenses/noncommercial/1.0.0/).

## Cryptography Notice

This distribution includes cryptographic software. The country in which you currently reside may have restrictions on the import, possession, use, and/or re-export to another country, of encryption software. BEFORE using any encryption software, please check your country's laws, regulations and policies concerning the import, possession, or use, and re-export of encryption software, to see if this is permitted. See http://www.wassenaar.org/ for more information.

The U.S. Government Department of Commerce, Bureau of Industry and Security (BIS), has classified this software as Export Commodity Control Number (ECCN) 5D002.C.1, which includes information security software using or performing cryptographic functions with asymmetric algorithms. The form and manner of this PolyForm Noncommercial license distribution makes it eligible for export under the License Exception ENC Technology Software Unrestricted (TSU) exception (see the BIS Export Administration Regulations, Section 740.13) for both object code and source code.

## Acknowledgments

**Secure** is built on the shoulders of giants. Thank you to these open source projects:

**Cryptography:**
- [RustCrypto AEADs](https://github.com/RustCrypto/AEADs) - ChaCha20-Poly1305 and XChaCha20-Poly1305 implementations
- [Dalek Cryptography](https://github.com/dalek-cryptography) - Ed25519 and X25519 primitives
- [pqc_kyber](https://github.com/Argyle-Software/kyber) - ML-KEM-1024 post-quantum KEM (NIST FIPS 203)
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Password hashing (Password Hashing Competition winner)
- [Lazysodium](https://github.com/terl/lazysodium-android) - Android libsodium bindings

**Networking:**
- [Tor Project](https://www.torproject.org/) - Anonymous routing network
- [Guardian Project tor-android](https://guardianproject.info/) - Tor binaries for Android
- [OnionMasq](https://github.com/guardianproject/onionmasq) - Tor VPN using Arti (Rust Tor implementation)
- [jtorctl](https://github.com/guardianproject/jtorctl) - Tor control protocol library
- [IPtProxy](https://github.com/tladesignz/IPtProxy) - Pluggable transports (obfs4, snowflake, webtunnel)
- [Opus Codec](https://opus-codec.org/) - High-quality audio encoding for voice calls

**Blockchain:**
- [Zcash](https://z.cash/) - Privacy-focused cryptocurrency with shielded transactions
- [Solana](https://solana.com/) - High-performance blockchain for fast payments
- [Zcash Android SDK](https://github.com/Electric-Coin-Company/zcash-android-wallet-sdk) - Mobile Zcash wallet implementation
- [web3j](https://github.com/web3j/web3j) - BIP39/BIP44 implementation for wallet derivation

**Payment Protocol:**
- [PCEF (Perkins Coie Entrepreneur Fund)](https://perkinsfund.org/) - 501(c)(3) nonprofit supporting open source crypto projects; NLx402 payment protocol core logic

**Android:**
- [Android Jetpack](https://developer.android.com/jetpack) - Modern Android development libraries
- [Room](https://developer.android.com/training/data-storage/room) - SQLite database abstraction
- [SQLCipher](https://www.zetetic.net/sqlcipher/) - Database encryption for Android
- [CameraX](https://developer.android.com/training/camerax) - Modern camera API
- [ML Kit](https://developers.google.com/ml-kit) - Barcode and QR code scanning

## Support

**Get Help:**
- **GitHub Issues**: [Bug reports and feature requests](https://github.com/Secure-Legion/secure-legion-android/issues)
- **GitHub Discussions**: [Questions and community chat](https://github.com/Secure-Legion/secure-legion-android/discussions)
- **Website**: [securelegion.org](https://securelegion.org)
- **Twitter/X**: [@SecureLegion](https://x.com/SecureLegion)
- **Email**: contact@securelegion.org

**Security Issues:**
- **Email**: dev@securelegion.org
- **Response Time**: 48 hours for critical vulnerabilities

**Commercial Licensing:**
- **Email**: contact@securelegion.org

---

<div align="center">

**Built with privacy in mind. Powered by post-quantum cryptography.**

**No servers. Metadata resistance. No compromises.**

[Download Beta](https://securelegion.org/download) • [Website](https://securelegion.org) • [GitHub](https://github.com/Secure-Legion)

</div>
