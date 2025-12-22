<div align="center">

# Secure Legion

**Privacy-first Android messaging with zero metadata, serverless P2P, and hardware-backed encryption**

[![Platform](https://img.shields.io/badge/platform-Android-green)](https://www.android.com/)
[![Language](https://img.shields.io/badge/language-Kotlin%20%7C%20Rust-orange)](https://kotlinlang.org/)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue)](LICENSE)
[![Website](https://img.shields.io/badge/website-securelegion.com-blue)](https://securelegion.org)

> "No servers. No metadata. No compromises."

[Download Beta APK](https://securelegion.org/download) | [Documentation](https://securelegion.org/architecture) | [Roadmap](https://securelegion.org/roadmap)

</div>

---

## Overview

Secure Legion is a native Android messaging application that combines truly private P2P communication with cryptocurrency payments. Unlike Signal, Session, or traditional messengers, Secure Legion eliminates ALL central infrastructure - no servers can log your metadata, no company can hand over data that doesn't exist.

**Core Architecture:**
- **Zero Metadata** - No central servers track who communicates with whom
- **Direct P2P via Tor** - Messages route directly between peers over Tor hidden services
- **Dual .onion System** - Separate hidden services for friend requests and messaging (deterministic, ephemeral)
- **Ping-Pong Wake Protocol** - Recipient authentication required before message delivery
- **Hardware Security** - Keys stored in Android StrongBox (Android 9+) or Trusted Execution Environment
- **Integrated Payments** - Send Zcash and Solana payments directly in conversations via NLx402 protocol
- **Two-Phase Friend Requests** - PIN-encrypted Phase 1, X25519-encrypted Phase 2, all via Tor hidden services

## What Makes Secure Legion Unique

**The only messaging app combining:**
1. Serverless P2P architecture (no metadata collection possible)
2. Multi-chain cryptocurrency payments (Zcash + Solana)
3. NLx402 protocol integration (payment quotes embedded in messages)
4. Tor-exclusive routing (all traffic anonymous by default)
5. Hardware-backed encryption (keys never leave secure element)
6. Two-phase friend request protocol (PIN + X25519 cryptography)

**Competitive Analysis:**

| Feature | Secure Legion | Signal | Session | Briar | Orbot |
|---------|--------------|--------|---------|-------|-------|
| **P2P Messaging** | Yes (Tor) | No (servers) | No (SNODE relays) | Yes | No |
| **Zero Metadata** | Yes | No | Partial | Yes | N/A |
| **Integrated Wallet** | Yes (Zcash + Solana) | No (MobileCoin limited) | No | No | No |
| **Payment Protocol** | Yes (NLx402) | No | No | No | No |
| **2-Phase Friend Requests** | Yes | No | No | No | No |
| **VPN Mode** | Planned | No | No | No | Yes |
| **Image Messaging** | Yes | Yes | Yes | No | N/A |
| **Voice Messages** | Yes | Yes | Yes | No | N/A |

## Features

### Messaging

**Text & Media:**
- Encrypted text messaging with XChaCha20-Poly1305
- Image sharing with automatic compression and EXIF stripping
- Voice messages with hold-to-record interface
- Self-destruct timers for sensitive messages
- Read receipts (optional)
- Message deletion with secure wipe

**Coming Soon:**
- File attachments (general files)
- Group messaging
- Voice/video calling over Tor

### Security & Privacy

**Cryptography:**
- **Encryption**: XChaCha20-Poly1305 (authenticated encryption)
- **Signatures**: Ed25519 (message authentication)
- **Key Exchange**: X25519 (ephemeral session keys)
- **Hashing**: Argon2id (password derivation)
- **Database**: SQLCipher AES-256-GCM (local storage encryption)

**Hardware Security:**
- Private keys stored in Android StrongBox or Trusted Execution Environment
- Keys never leave secure hardware
- Hardware-backed attestation prevents key extraction

**Access Protection:**
- Biometric authentication required on every app launch
- Duress PIN triggers instant data wipe and network revocation
- Secure wipe for deleted messages and voice files
- Lock screen with PIN/fingerprint/face unlock

**Network Privacy:**
- All traffic routed exclusively through Tor network
- No IP address leakage
- Dual Tor v3 hidden services (.onion addresses):
  - **Friend Request .onion**: Receives new friend requests (port 9151)
  - **Messaging .onion**: Receives encrypted messages from contacts (port 9150→8080)
- Deterministic .onion generation from seed phrase (ephemeral services)
- No DNS queries (Tor handles resolution)

### Payments

**Multi-Chain Wallet:**
- **Zcash (ZEC)**: Privacy-focused payments with shielded transactions
- **Solana (SOL)**: Fast payments with low transaction fees
- **SPL Tokens**: USDC and USDT support
- Transaction history with block explorer links
- Testnet mode for development and testing

**NLx402 Payment Protocol:**
- Send payment quotes directly in chat (amount, token, expiry)
- Recipient accepts or declines quote
- Payment verification with replay protection
- Quote expiry options: 15 min, 1 hour, 6 hours, 24 hours (default), 48 hours, 7 days
- Transaction signatures stored for auditing
- Real-time SOL and ZEC price fetching

**Payment Features:**
- Request money from contacts with custom amounts
- Accept payments with single tap
- Track payment status (pending, paid, expired, cancelled)
- Secure payment memo encryption

### Network Architecture

**Tor Integration:**
- Powered by Guardian Project's tor-android (actively maintained C implementation)
- Dual Tor v3 hidden services: friend requests (port 9151) and messaging (port 9150→8080)
- Deterministic .onion address generation from seed phrase
- Control port management via jtorctl
- Pluggable transports (obfs4, snowflake, meek) for censorship circumvention
- Bridge support for restrictive networks

**Ping-Pong Wake Protocol:**
```
SENDER                          RECIPIENT
  |                                 |
  |- Create encrypted message       |
  |- Store in local queue           |
  |- Send PING token --------------->|
  |   (via Tor hidden service)      |- Receive wake notification
  |                                 |- Authenticate (biometric)
  |<--------------- PONG -----------|
  |   (confirms online)             |
  |- Send encrypted message -------->|
  |   (via Tor)                     |- Decrypt & display
  |<---------------- ACK ------------|
  |- Delete from queue              |
```

**Key Properties:**
- No central servers - completely peer-to-peer
- Recipient must authenticate before receiving messages
- Messages queued locally until recipient comes online
- Offline-first design with automatic retry
- End-to-end encrypted at every step

### Contact Discovery

**Local Contact Storage:**
- All contacts stored locally in encrypted SQLCipher database on your device
- Contact information never leaves your device (except during friend request exchange)
- No central contact directory or server

**Two-Phase Friend Request System:**

**Phase 1 - Initial Key Exchange (PIN-encrypted):**
- You receive friend's `.onion` address and 10-digit PIN via QR code
- You send minimal info to friend's friend-request.onion address:
  - Your username
  - Your friend-request.onion address
  - Your X25519 public key
- Encrypted with PIN using XSalsa20-Poly1305
- Sent directly via Tor hidden service (port 9151)

**Phase 2 - Acceptance & Full Exchange (X25519-encrypted):**
- Friend decrypts Phase 1 with PIN
- Friend sends FULL contact card back to you:
  - Username, public keys, both .onion addresses
- Encrypted with YOUR X25519 public key (from Phase 1)
- Sent to your friend-request.onion address
- Both sides now have complete contact information
- Contact saved to local encrypted database

**Privacy Design:**
- All communication via Tor hidden services (no IPFS, no servers)
- Friend-request.onion address shared via QR code
- Messaging.onion address exchanged during Phase 2
- Both .onion addresses deterministically generated from seed phrase
- PIN only used for Phase 1 initial contact
- X25519 encryption for Phase 2 prevents MITM attacks

### User Experience

**Modern UI:**
- Material Design 3 with dark theme
- Responsive layouts for all screen sizes
- Swipe gestures for timestamps and deletion
- Pull-to-refresh for message sync
- Long-press context menus

**Background Operation:**
- Foreground service keeps Tor running
- Message queue persistence across app restarts
- Battery-optimized wake locks (2026 Play Store compliant)
- Lifecycle-aware components prevent memory leaks

**Data Management:**
- Encrypted Room database (SQLCipher)
- Automatic database migrations
- Secure deletion with cryptographic wiping
- Export/import (planned)

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
│  │          │ NLx402   │   SPL    ││
│  └──────────┴──────────┴──────────┘│
├─────────────────────────────────────┤
│   Hardware Security (StrongBox)     │
└─────────────────────────────────────┘
```

**Android Layer (Kotlin):**
- Material Design 3 UI components
- Room Database with SQLCipher encryption
- CameraX for QR code scanning
- Biometric authentication (fingerprint/face)
- WorkManager for background tasks
- Lifecycle components for state management

**Rust Core Library:**
- Cryptographic operations (XChaCha20-Poly1305, Ed25519, X25519, Argon2id)
- Tor hidden service management
- Ping-Pong protocol implementation
- NLx402 payment quote creation and verification
- Message serialization/deserialization
- JNI bindings for Android integration

**External Infrastructure:**
- **Tor Network**: Anonymous routing for all communications
- **Solana Blockchain**: SOL payments
- **Zcash Blockchain**: Private shielded payments

**Security Hardware:**
- Android StrongBox (Titan M on Pixel, Knox on Samsung)
- Trusted Execution Environment (TEE) fallback
- Hardware-backed key attestation

### Cryptographic Primitives

| Component | Algorithm | Key Size | Purpose |
|-----------|-----------|----------|---------|
| **Message Encryption** | XChaCha20-Poly1305 | 256-bit | AEAD encryption for message content |
| **Digital Signatures** | Ed25519 | 256-bit | Message authentication and sender verification |
| **Key Exchange** | X25519 | 256-bit | Ephemeral session keys for forward secrecy |
| **Password Hashing** | Argon2id | Variable | PIN/password derivation (interactive params) |
| **Database Encryption** | AES-256-GCM | 256-bit | SQLCipher local storage encryption |
| **Friend Request Encryption** | XSalsa20-Poly1305 | 256-bit | PIN-based Phase 1 encryption |

**Implementation Details:**
- All crypto operations delegated to Rust core (memory-safe)
- Nonces never reused (random for XChaCha20, deterministic for signatures)
- Constant-time comparisons prevent timing attacks
- Secure memory wiping after use (zeroize crate in Rust)
- Hardware-backed keys used where available

### Threat Model

**Protected Against:**
- Passive network surveillance (Tor encryption)
- Active man-in-the-middle attacks (Ed25519 signatures + Tor)
- Server compromise (no servers exist)
- Metadata analysis (no centralized logs)
- Device seizure (duress PIN triggers wipe)
- Supply chain attacks (reproducible builds planned)
- Correlation attacks (Tor + no metadata)
- Traffic analysis (Tor hidden services)

**Not Protected Against:**
- Device compromise with root/admin access
- Hardware implants in the device
- Endpoint security failures (malware, keyloggers)
- Social engineering attacks
- $5 wrench attack (duress PIN helps)

**Assumptions:**
- Android secure boot chain not compromised
- Hardware security module (StrongBox/TEE) not backdoored
- Tor network not globally compromised
- User maintains physical security of device
- User follows operational security best practices

See [Security Model](https://securelegion.org/security-model) for complete threat analysis.

## Quick Start

### Prerequisites

- **Development Environment:**
  - Android Studio Hedgehog 2023.1.1 or newer
  - Rust toolchain (install via `rustup`)
  - Android NDK 26.1.10909125 or newer
  - `cargo-ndk` for cross-compilation

- **Runtime Requirements:**
  - Android 8.1 (API 27) or higher
  - ARMv8-A 64-bit processor (arm64-v8a)
  - Biometric hardware (fingerprint or face unlock)
  - 200 MB free storage minimum

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
echo "keyAlias=securelegion" >> keystore.properties
echo "keyPassword=YOUR_PASSWORD" >> keystore.properties

# 8. Build and run
# Click Run in Android Studio (Shift+F10)
# Or via command line:
./gradlew installDebug
```

### First Run

1. **Create Account**: Generate new identity with hardware-backed keys
2. **Set Biometric Lock**: Configure fingerprint or face unlock
3. **Set Duress PIN**: Emergency wipe trigger (optional but recommended)
4. **Add Contacts**: Share your friend request .onion address via QR code

## Project Structure

```
secure-legion-android/
├── app/                              # Android application
│   ├── src/main/
│   │   ├── java/com/securelegion/
│   │   │   ├── ChatActivity.kt      # Main conversation UI
│   │   │   ├── CreateAccountActivity.kt
│   │   │   ├── AddFriendActivity.kt # Contact management
│   │   │   ├── SendMoneyActivity.kt # Payment sending
│   │   │   ├── crypto/
│   │   │   │   ├── RustBridge.kt    # JNI interface to Rust
│   │   │   │   ├── KeyManager.kt    # Hardware key management
│   │   │   │   ├── NLx402Manager.kt # Payment protocol
│   │   │   │   └── TorManager.kt    # Tor lifecycle
│   │   │   ├── services/
│   │   │   │   ├── TorService.kt    # Background Tor daemon
│   │   │   │   ├── MessageService.kt # Message queue
│   │   │   │   ├── FriendRequestService.kt # Friend request handling
│   │   │   │   ├── ZcashService.kt  # Zcash wallet
│   │   │   │   └── SolanaService.kt # Solana wallet
│   │   │   ├── database/
│   │   │   │   ├── SecureLegionDatabase.kt # Room DB
│   │   │   │   ├── entities/
│   │   │   │   │   ├── Message.kt   # Message entity
│   │   │   │   │   ├── Contact.kt   # Contact entity
│   │   │   │   │   └── Wallet.kt    # Wallet entity
│   │   │   │   └── dao/             # Database access
│   │   │   └── models/              # Data models
│   │   ├── jniLibs/                 # Rust .so files (built)
│   │   │   ├── arm64-v8a/
│   │   │   │   └── libsecurelegion.so
│   │   │   └── armeabi-v7a/
│   │   │       └── libsecurelegion.so
│   │   └── res/                     # UI resources
│   └── build.gradle.kts
│
├── secure-legion-core/               # Rust core library
│   ├── src/
│   │   ├── lib.rs                   # Library entry point
│   │   ├── crypto/
│   │   │   ├── mod.rs               # XChaCha20, Ed25519, X25519
│   │   │   └── password.rs          # Argon2id
│   │   ├── network/
│   │   │   ├── mod.rs               # Ping-Pong protocol
│   │   │   ├── ping_pong.rs         # Token management
│   │   │   ├── tor.rs               # Dual hidden service management
│   │   │   ├── friend_request_server.rs # Friend request listener
│   │   │   └── socks5_client.rs     # SOCKS5 Tor client
│   │   ├── protocol/
│   │   │   ├── message.rs           # Message serialization
│   │   │   └── contact_card.rs      # Contact format
│   │   ├── blockchain/
│   │   │   └── solana.rs            # Solana wallet operations
│   │   ├── nlx402/
│   │   │   ├── mod.rs               # Payment protocol
│   │   │   └── quote.rs             # Quote verification
│   │   └── ffi/
│   │       └── android.rs           # JNI bindings
│   ├── Cargo.toml
│   ├── build_android.sh
│   └── .cargo/config.toml
│
├── CHANGELOG.md
└── README.md
```

## Roadmap

### Completed

- [x] Rust cryptography core library
- [x] Android app architecture with Material Design 3
- [x] Hardware security module integration (StrongBox/TEE)
- [x] Encrypted Room database with SQLCipher
- [x] Tor integration via Guardian Project libraries
- [x] Ping-Pong wake protocol implementation
- [x] Text messaging with XChaCha20-Poly1305 encryption
- [x] Image sharing with compression and EXIF stripping
- [x] Voice messages with hold-to-record interface
- [x] Biometric authentication (fingerprint/face)
- [x] Duress PIN with instant wipe
- [x] Solana wallet integration
- [x] Zcash wallet integration
- [x] NLx402 payment protocol (quotes, verification, replay protection)
- [x] Two-phase friend request system (PIN + X25519)
- [x] Self-destruct timers for messages
- [x] Read receipts
- [x] Testnet mode for development
- [x] Background service architecture
- [x] Message queue persistence
- [x] Dual .onion architecture (separate friend request and messaging addresses)
- [x] Deterministic hidden service generation from seed phrase

### In Development

- [ ] File attachments (general file sharing)
- [ ] Group messaging (multi-party encrypted conversations)
- [ ] Voice/video calling over Tor
- [ ] VpnService mode (system-wide Tor routing)
- [x] Export/import account data
- [ ] Reproducible builds
- [ ] F-Droid release
- [ ] Google Play Store release

### Planned Features

- [ ] Multi-device sync (via encrypted IPFS)
- [ ] Desktop client (Linux/Windows/macOS)
- [ ] iOS app
- [ ] Disappearing messages (auto-delete after time)
- [x] Screen security (prevent screenshots)
- [ ] Incognito keyboard (disable autocorrect/suggestions)
- [x] Contact verification (safety numbers like Signal)
- [ ] Message reactions
- [x] Push notifications (without FCM)

### Future Exploration

- [ ] Monero wallet integration
- [ ] Lightning Network payments
- [ ] P2P file backup system
- [ ] Mesh networking (local P2P without internet)

See detailed [Roadmap](https://securelegion.org/roadmap) on website.

## Testing

### Rust Tests

```bash
cd secure-legion-core
cargo test                    # All tests
cargo test --release          # Optimized tests
cargo test crypto::           # Crypto module only
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

1. **Account Creation**: Create account, verify keys stored in StrongBox
2. **Biometric Lock**: Test fingerprint/face unlock
3. **Duress PIN**: Verify data wipe on duress PIN entry
4. **Contact Sharing**: Share friend request .onion address via QR code
5. **Add Contact**: Scan friend's QR code and send friend request
6. **Text Messaging**: Send/receive text messages
7. **Image Sharing**: Send/receive images, verify EXIF stripped
8. **Voice Messages**: Record/send/receive voice messages
9. **Payments**: Create payment quote, send ZEC/SOL, verify receipt
10. **Self-Destruct**: Set timer, verify message deleted
11. **Background Service**: Kill app, verify messages still queue
12. **Offline Mode**: Disable network, send messages, verify queue

## Contributing

Contributions welcome! Security Legion is open source (noncommercial license) and community-driven.

### How to Contribute

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create** a feature branch (`git checkout -b feature/your-feature`)
4. **Commit** your changes with clear messages
5. **Test** thoroughly (unit tests + manual testing)
6. **Push** to your fork (`git push origin feature/your-feature`)
7. **Open** a Pull Request with detailed description

### Areas to Contribute

**Security:**
- Cryptographic code review
- Threat modeling
- Penetration testing
- Security documentation

**Development:**
- Bug fixes
- Feature implementation (see roadmap)
- Performance optimization
- Code refactoring

**Documentation:**
- Technical documentation
- User guides
- API documentation
- Architecture diagrams

**Design:**
- UI/UX improvements
- Icon design
- Screenshot creation
- Marketing materials

**Testing:**
- Automated test coverage
- Integration tests
- Beta testing on various devices
- Bug reporting

**Localization:**
- Translation to other languages
- RTL language support
- Locale-specific formatting

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines (coming soon).

### Code Style

**Kotlin:**
- Follow official [Kotlin Coding Conventions](https://kotlinlang.org/docs/coding-conventions.html)
- Use meaningful variable names
- Add KDoc comments for public APIs
- Prefer immutable data structures

**Rust:**
- Follow official [Rust Style Guide](https://doc.rust-lang.org/stable/style-guide/)
- Use `cargo fmt` before committing
- Use `cargo clippy` to catch common mistakes
- Add doc comments (`///`) for public functions

### Pull Request Guidelines

- Keep PRs focused on single feature/fix
- Update tests for code changes
- Update documentation for user-facing changes
- Add entry to CHANGELOG.md
- Rebase on latest main before submitting
- Respond to code review feedback promptly

## Documentation

**Official Documentation:**
- [Website](https://securelegion.org) - Project overview and features
- [Architecture](https://securelegion.org/architecture) - System design and components
- [Security Model](https://securelegion.org/security-model) - Threat analysis and defenses
- [Ping-Pong Protocol](https://securelegion.org/ping-pong-protocol) - P2P messaging protocol
- [Feasibility Audit](https://securelegion.org/feasibility-audit) - Technical validation

**Repository Documentation:**
- [CHANGELOG.md](CHANGELOG.md) - Version history and changes

**Rust Core Documentation:**
- [secure-legion-core/README.md](secure-legion-core/README.md) - Rust library overview
- API documentation: `cargo doc --open` in `secure-legion-core/`

## Frequently Asked Questions

### General

**Q: How is Secure Legion different from Signal?**

A: Signal uses centralized servers for message relay and metadata logging. Secure Legion has zero servers - messages route directly peer-to-peer over Tor. Signal's servers can see who messages whom and when. Secure Legion cannot, because no servers exist.

**Q: Why not just use Signal + VPN?**

A: VPNs hide your IP from Signal's servers, but Signal still logs metadata (who talks to whom, when, message count). Secure Legion prevents metadata collection entirely through serverless P2P architecture.

**Q: Does Secure Legion use blockchain for messaging?**

A: No. Messages are P2P over Tor. Blockchain is only used for cryptocurrency payments. Your conversations never touch a blockchain.

### Security

**Q: Has Secure Legion been audited?**

A: Not yet. Security audit is planned before 1.0 release. Current version is beta - do not use for critical communications.

**Q: What happens if Tor is compromised?**

A: If Tor network is globally deanonymized (extremely difficult), attackers could potentially correlate traffic. However, message content remains encrypted with XChaCha20-Poly1305. End-to-end encryption is independent of Tor.

**Q: Can governments force you to hand over user data?**

A: No data to hand over. Secure Legion has no servers, no databases, no logs. We cannot hand over what we don't have.

**Q: What about the $5 wrench attack?**

A: Duress PIN provides defense - entering it triggers instant data wipe and network revocation. However, physical security is ultimately your responsibility.

### Technical

**Q: Why Android only?**

A: Initial focus on Android for faster development. iOS app planned after Android is stable. Desktop clients (Linux/Windows/macOS) also planned.

**Q: Does Secure Legion drain battery?**

A: Tor background service uses power, but optimized for battery efficiency. Typical usage: 5-10% battery per day with moderate messaging. VpnService mode (planned) will be more efficient than current wake lock approach.

**Q: How large are the app binaries?**

A: APK size is approximately 45-50 MB (Tor libraries, Rust core, Zcash SDK). Larger than Signal but necessary for serverless P2P architecture.

**Q: What Android devices are supported?**

A: Android 8.1 (API 27) or higher. ARM64 required (arm64-v8a). Most devices from 2018+ are supported. StrongBox available on Pixel 3+, Samsung Galaxy S9+ (Knox), and other flagship devices.

**Q: Can I use Secure Legion without cryptocurrency?**

A: Yes! Cryptocurrency is optional. You can use text/image/voice messaging without ever touching the wallet. Payments are an extra feature, not a requirement.

### Privacy

**Q: Do I need to provide phone number or email?**

A: No. Secure Legion has no phone number verification, email requirement, or identity checks. Completely anonymous by default.

**Q: How do contacts find me?**

A: Share your friend request .onion address via QR code or secure channel. Your .onion address is deterministically generated from your seed phrase.

**Q: Can contacts see if I'm online?**

A: Only during active messaging. Ping-Pong protocol requires recipient to be online to receive messages, but no persistent "online status" is broadcast.

**Q: Does Secure Legion collect analytics?**

A: Zero analytics, zero telemetry, zero tracking. No data leaves your device except encrypted messages to recipients.

## Beta Notice

**This software is in beta and not production-ready.**

**Known Limitations:**
- Security audit pending
- No reproducible builds yet
- Limited testing on diverse devices
- Breaking changes may occur in updates
- Documentation still evolving

**Recommendations:**
- Do not use for life-critical communications
- Test thoroughly before relying on it
- Keep backups of important data (export feature coming soon)
- Report bugs immediately via GitHub Issues
- Use testnet mode for payment testing

**Security Vulnerabilities:**

If you discover a security vulnerability, **DO NOT** open a public GitHub issue. Email **security@securelegion.com** with:
- Detailed description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We will respond within 48 hours and work with you on responsible disclosure.

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

**Permissions:**
- Use for noncommercial purposes
- Modify and create derivatives
- Distribute original or modified versions

**Limitations:**
- **No commercial use** without separate agreement
- Cannot sell the software or use it to provide paid services
- Cannot use in commercial products

**Commercial Licensing:**

If you want to use Secure Legion commercially, contact **licensing@securelegion.com** for a commercial license agreement.

See [LICENSE](LICENSE) file for full legal terms or visit [polyformproject.org](https://polyformproject.org/licenses/noncommercial/1.0.0/).

## Acknowledgments

Secure Legion is built on the shoulders of giants. Thank you to these projects:

**Cryptography:**
- [RustCrypto AEADs](https://github.com/RustCrypto/AEADs) - ChaCha20-Poly1305 implementation
- [Dalek Cryptography](https://github.com/dalek-cryptography) - Ed25519 and X25519 primitives
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Password hashing (PHC winner)
- [Lazysodium](https://github.com/terl/lazysodium-android) - Android libsodium bindings

**Networking:**
- [Tor Project](https://www.torproject.org/) - Anonymous routing network
- [Guardian Project tor-android](https://guardianproject.info/) - Tor binaries for Android
- [jtorctl](https://github.com/guardianproject/jtorctl) - Tor control protocol library
- [IPtProxy](https://github.com/tladesignz/IPtProxy) - Pluggable transports (obfs4, snowflake)

**Blockchain:**
- [Zcash](https://z.cash/) - Privacy-focused cryptocurrency
- [Solana](https://solana.com/) - High-performance blockchain for payments
- [Zcash Android SDK](https://github.com/Electric-Coin-Company/zcash-android-wallet-sdk) - Mobile Zcash wallet
- [web3j](https://github.com/web3j/web3j) - BIP39/BIP44 implementation

**Android:**
- [Android Jetpack](https://developer.android.com/jetpack) - Modern Android development
- [Room](https://developer.android.com/training/data-storage/room) - SQLite database abstraction
- [SQLCipher](https://www.zetetic.net/sqlcipher/) - Database encryption
- [CameraX](https://developer.android.com/training/camerax) - Camera API
- [ML Kit](https://developers.google.com/ml-kit) - Barcode scanning

**Storage:**
- [IPFS](https://ipfs.io/) - Decentralized file storage

## Support

**Get Help:**
- **GitHub Issues**: [Bug reports and feature requests](https://github.com/Secure-Legion/secure-legion-android/issues)
- **GitHub Discussions**: [Questions and community chat](https://github.com/Secure-Legion/secure-legion-android/discussions)
- **Website**: [securelegion.org](https://securelegion.org)
- **Twitter**: [@SecureLegion](https://x.com/SecureLegion)
- **Email**: support@securelegion.com

**Security Issues:**
- **Email**: security@securelegion.com (PGP key available on website)
- **Response Time**: 48 hours for critical vulnerabilities

**Commercial Licensing:**
- **Email**: licensing@securelegion.com

---

<div align="center">

**Built with privacy in mind.**

**No servers. No metadata. No compromises.**

[Download Beta](https://securelegion.org/download) • [Website](https://securelegion.org) • [GitHub](https://github.com/Secure-Legion)

</div>
