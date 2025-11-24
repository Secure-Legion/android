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

Secure Legion is a native Android messaging application that provides truly private communication through:

- **Zero Metadata Architecture** - No central servers track who communicates with whom
- **Ping-Pong Wake Protocol** - Direct peer-to-peer message delivery requiring recipient authentication
- **Tor Integration** - Anonymous routing via Tor network for all communications
- **Hardware-Level Security** - Keys stored in StrongBox (Android 9+) or TEE
- **Blockchain Identity** - Solana-based contact discovery without exposing real identities
- **Duress PIN Protection** - Emergency wipe triggers instant key destruction and network revocation
- **Text-Only Messaging** - Security-first approach (no media attachments)

## Features

### Security & Privacy

- **Hardware Security Module (HSM)**: Private keys never leave StrongBox/TEE
- **Modern Cryptography**: XChaCha20-Poly1305, Ed25519, X25519, Argon2id
- **Biometric Authentication**: Required on every app launch
- **Duress PIN**: Emergency data wipe with network revocation
- **No Metadata Leaks**: Communication patterns invisible to observers

### Network

- **Tor Integration**: All traffic routed through Tor for anonymity
- **Ping-Pong Protocol**: Direct P2P messaging without central servers
- **Serverless Architecture**: No company can hand over your data
- **Offline-First**: Messages queued locally until recipient comes online

### Built-in Wallet

- **Solana Integration**: Send/receive SOL for contact discovery
- **Transaction History**: View all blockchain transactions
- **Hardware-Backed Keys**: Wallet keys stored in secure hardware

### User Experience

- **Material Design 3**: Modern, dark-themed UI
- **Room Database**: Fast local storage with encryption
- **Background Services**: Reliable message delivery
- **Lock Screen**: PIN/biometric protection

## Screenshots

<div align="center">

| Lock Screen | Chat List | Conversation | Wallet |
|------------|-----------|--------------|--------|
| Coming Soon | Coming Soon | Coming Soon | Coming Soon |

</div>

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
│  │XChaCha20 │  Arti    │ Solana   ││
│  │ Ed25519  │   P2P    │  SPL     ││
│  └──────────┴──────────┴──────────┘│
├─────────────────────────────────────┤
│   Hardware Security (StrongBox)     │
└─────────────────────────────────────┘
```

**Android (Kotlin)**
- Material Design 3 UI
- Room Database (SQLite)
- Jetpack Compose + XML layouts
- Biometric authentication
- Background services

**Rust Core**
- XChaCha20-Poly1305 encryption
- Ed25519 signatures
- X25519 key exchange
- Argon2id password hashing
- Tor integration (Arti client)
- JNI bindings

**Infrastructure**
- Tor network (anonymous routing)
- Solana blockchain (identity)
- IPFS (contact cards - planned)

## Quick Start

### Prerequisites

- Android Studio (Hedgehog 2023.1.1+)
- Rust toolchain (`rustup`)
- Android NDK
- `cargo-ndk` for cross-compilation

### Installation

```bash
# 1. Clone repository
git clone https://github.com/Secure-Legion/secure-legion-android.git
cd secure-legion-android

# 2. Install Rust targets
rustup target add aarch64-linux-android armv7-linux-androideabi

# 3. Install cargo-ndk
cargo install cargo-ndk

# 4. Build Rust core library
cd secure-legion-core
./build_android.sh  # or build_android.bat on Windows

# 5. Open in Android Studio
cd ..
# Open project in Android Studio

# 6. Run on device
# Click Run in Android Studio
```

See [QUICKSTART.md](QUICKSTART.md) for detailed instructions.

## Project Structure

```
secure-legion-android/
├── app/                          # Android application
│   ├── src/main/
│   │   ├── java/com/securelegion/
│   │   │   ├── ui/              # Activities & UI
│   │   │   ├── crypto/          # RustBridge, KeyManager
│   │   │   ├── data/            # Room database, models
│   │   │   ├── wallet/          # Solana wallet
│   │   │   └── services/        # Background services
│   │   ├── jniLibs/             # Rust .so files (built)
│   │   └── res/                 # Resources
│   └── build.gradle
│
├── secure-legion-core/           # Rust core library
│   ├── src/
│   │   ├── crypto/              # Cryptographic operations
│   │   ├── network/             # Tor, Ping-Pong protocol
│   │   ├── protocol/            # Message formats
│   │   └── ffi/                 # JNI bindings
│   ├── Cargo.toml
│   └── build_android.sh
│
├── .gitignore
├── README.md
├── QUICKSTART.md
├── TODO.md
└── PING_PONG_IMPLEMENTATION.md
```

## Security Model

### Cryptography

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Encryption** | XChaCha20-Poly1305 | Message content encryption |
| **Signatures** | Ed25519 | Message authentication |
| **Key Exchange** | X25519 | Ephemeral session keys |
| **Hashing** | Argon2id | Password derivation |
| **Storage** | AES-256-GCM | Local database encryption |

### Threat Model

- Protects against passive network observers
- Protects against active MITM attacks
- Protects against server compromise (no servers!)
- Protects against device seizure (duress PIN)
- Protects against metadata analysis
- Protects against supply chain attacks (reproducible builds)

See [Security Model](https://securelegion.com/security-model) for complete details.

## Ping-Pong Protocol

The Ping-Pong Wake Protocol enables serverless P2P messaging:

```
SENDER                          RECIPIENT
  │                                 │
  ├─ Create encrypted message       │
  ├─ Store in local queue           │
  ├─ Send PING token ──────────────>│
  │   (via Tor)                     ├─ Receive wake notification
  │                                 ├─ Authenticate (biometric)
  │<────────────────── PONG ────────┤
  │   (confirms online)             │
  ├─ Send encrypted message ───────>│
  │   (via Tor)                     ├─ Decrypt & display
  │<──────────── ACK ───────────────┤
  ├─ Delete from queue              │
```

**Key Features:**
- No central servers - direct peer-to-peer
- Recipient must authenticate before message delivery
- End-to-end encrypted via Tor
- Offline-first with local queue

See [Ping-Pong Protocol](https://securelegion.com/ping-pong-protocol) for technical details.

## Roadmap

### Phase 1-7: Foundation (Complete)
- [x] Project architecture
- [x] Rust cryptography library
- [x] Hardware security integration
- [x] Database layer
- [x] Tor integration
- [x] Ping-Pong protocol implementation
- [x] Basic UI

### Phase 8: Mobile Applications (In Progress)
- [x] Android app structure
- [x] Wallet integration
- [x] Complete messaging flow
- [x] Contact management
- [x] Background services
- [x] Beta testing

### Phase 9-11: Launch (Planned)
- [x] Security audit
- [ ] F-Droid release
- [ ] Google Play release
- [x] Public beta launch

See full [Roadmap](https://securelegion.com/roadmap) on website.

## Testing

```bash
# Rust tests
cd secure-legion-core
cargo test

# Android unit tests
./gradlew test

# Android instrumentation tests
./gradlew connectedAndroidTest
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Areas to Contribute

- UI/UX improvements
- Bug fixes
- Documentation
- Tests
- Translations
- Security review

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Documentation

- [Website](https://securelegion.org) - Project overview and features
- [Architecture](https://securelegion.org/architecture) - System design
- [Security Model](https://securelegion.org/security-model) - Threat model and defenses
- [Ping-Pong Protocol](https://securelegion.org/ping-pong-protocol) - P2P messaging protocol
- [Feasibility Audit](https://securelegion.org/feasibility-audit) - Technical validation
- [Quickstart Guide](QUICKSTART.md) - Build instructions
- [TODO.md](TODO.md) - Development tasks

## Beta Notice

**This software is in beta and not production-ready.**

- Do not use for critical communications
- Security audit pending
- Breaking changes may occur
- Report issues on GitHub

For security vulnerabilities, email: **security@securelegion.com**

## License

This project is licensed under the **PolyForm Noncommercial License 1.0.0**.

**You can use, modify, and distribute this software for noncommercial purposes only.** Commercial use requires separate permission.

See [LICENSE](LICENSE) file for full terms or visit [polyformproject.org](https://polyformproject.org/licenses/noncommercial/1.0.0/).

## Acknowledgments

**Cryptography:**
- [ChaCha20-Poly1305](https://github.com/RustCrypto/AEADs) - AEAD encryption
- [Ed25519-Dalek](https://github.com/dalek-cryptography/ed25519-dalek) - Signatures
- [X25519-Dalek](https://github.com/dalek-cryptography/x25519-dalek) - Key exchange
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) - Password hashing

**Networking:**
- [Arti](https://gitlab.torproject.org/tpo/core/arti) - Tor client
- [Tor Project](https://www.torproject.org/) - Anonymous routing

**Blockchain:**
- [Solana](https://solana.com/) - Fast blockchain for identity

## Support

- **Issues**: [GitHub Issues](https://github.com/Secure-Legion/secure-legion-android/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Secure-Legion/secure-legion-android/discussions)
- **Website**: [securelegion.com](https://securelegion.com)
- **Twitter**: [@SecureLegion](https://x.com/SecureLegion)

---

<div align="center">

**Built with privacy in mind.**

**No servers. No metadata. No compromises.**

[Download Beta](https://securelegion.org/download) • [Website](https://securelegion.org) • [GitHub](https://github.com/Secure-Legion)

</div>
