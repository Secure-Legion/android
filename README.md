<div align="center">

# Secure Legion - Crypto Library

**Privacy-focused cryptography, CRDT consensus, audio codec, Tor integration, and wallet primitives for the Secure messaging platform**

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-B7410E?style=flat-square&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/target-Android%20%7C%20Linux-34A853?style=flat-square" alt="Android | Linux" />
  <img src="https://img.shields.io/badge/license-MIT%20%2F%20Apache--2.0-blue?style=flat-square" alt="License" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Post--Quantum-ML--KEM--1024-FF6F00?style=flat-square" alt="Post-Quantum" />
  <img src="https://img.shields.io/badge/Encryption-XChaCha20--Poly1305-4A90D9?style=flat-square" alt="XChaCha20" />
  <img src="https://img.shields.io/badge/Signatures-Ed25519-2E7D32?style=flat-square" alt="Ed25519" />
  <img src="https://img.shields.io/badge/Tor-Arti%20v0.40-7D4698?style=flat-square&logo=torproject&logoColor=white" alt="Arti Tor" />
  <img src="https://img.shields.io/badge/ZK%20Proofs-Bulletproofs-9C27B0?style=flat-square" alt="Bulletproofs" />
</p>

> Open-source cryptographic foundation of [Secure](https://securelegion.org) — the serverless, post-quantum private messenger.

[Website](https://securelegion.org) | [Documentation](https://securelegion.org/architecture) | [Android App](https://github.com/Secure-Legion/android)

</div>

---

## Overview

`securelegion-crypto` is the open-source Rust library powering the cryptographic, networking, and consensus layers of the Secure messaging app. It provides:

- **Post-quantum hybrid key encapsulation** (X25519 + ML-KEM-1024)
- **Ed25519 signing and verification** for message authentication
- **In-process Tor integration** via Arti for anonymous P2P connectivity
- **Conflict-free replicated data types** (CRDTs) for decentralized group consensus
- **Opus voice codec** integration for encrypted voice calling over Tor
- **Zero-knowledge range proofs** (Bulletproofs) for private payments

This crate is a pure library (`crate-type = ["lib"]`) designed to be consumed by higher-level application crates that provide FFI bindings, protocol logic, and platform-specific integration.

## Architecture

```
securelegion-crypto/
|
|-- crypto/              Cryptographic primitives
|   |-- signing.rs       Ed25519 keypair generation, signing, verification
|   |-- key_exchange.rs  X25519 ECDH key agreement
|   |-- hashing.rs       Argon2id password hashing, handle hashing
|   |-- replay_cache.rs  LRU PING deduplication (Blake3, 10K capacity)
|   |-- zkproofs.rs      Bulletproof range proofs for private transfers
|   +-- pqc/
|       |-- hybrid_kem.rs  Hybrid X25519 + ML-KEM-1024 encapsulation
|       +-- types.rs       KEM keypair and ciphertext structures
|
|-- network/             Tor integration and P2P connectivity
|   |-- arti.rs          In-process Arti Tor client (bootstrap, circuits, onion services)
|   |-- tor.rs           .onion address derivation, TorManager, bootstrap polling
|   |-- socks5_client.rs SOCKS5 proxy for legacy Tor connections
|   +-- friend_request_server.rs  Contact exchange endpoint
|
|-- crdt/                Conflict-free replicated data types for groups
|   |-- ops.rs           OpEnvelope (bincode outer, CBOR inner), 10 op types
|   |-- ids.rs           DeviceID, GroupID, OpID (lamport + sequence)
|   |-- limits.rs        Guardrails (250K soft / 500K hard cap, rate limiting)
|   |-- membership.rs    OR-Set membership with role-based authorization
|   |-- messages.rs      LWW message store with edit/delete/reactions
|   |-- metadata.rs      LWW registers for group name, topic, avatar
|   +-- apply.rs         Deterministic apply engine + state hash (Blake3)
|
|-- audio/               Voice calling codec and streaming
|   |-- opus.rs          Opus encoder/decoder via C FFI (48kHz, 32kbps CBR)
|   |-- opus_ctl.rs      Encoder tuning (bitrate, FEC, DTX)
|   |-- voice_streaming.rs  Bidirectional voice over Tor with redundant framing
|   +-- loss_adaptive_fec.rs  Forward error correction for packet loss
|
|-- nlx402/              Payment protocol (Secure Pay)
|   |-- quote.rs         Payment quote generation with SHA3-256 replay protection
|   +-- verify.rs        Quote verification against on-chain transactions
|
+-- util/                Shared utilities
    +-- lock.rs          Panic-recovering mutex wrapper
```

## Modules

### Cryptography

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Signatures** | Ed25519 | Message authentication, CRDT op signing |
| **Key Exchange** | X25519 ECDH | Classical ephemeral key agreement |
| **Post-Quantum KEM** | Hybrid X25519 + ML-KEM-1024 | Quantum-resistant key encapsulation (NIST FIPS 203) |
| **Password Hashing** | Argon2id | PIN/password derivation (memory-hard) |
| **Replay Protection** | Blake3 LRU cache | PING deduplication (10,000 entry capacity) |
| **ZK Proofs** | Bulletproofs (Ristretto) | Range proofs for private payment amounts |
| **Constant-Time** | subtle crate | Timing-safe comparisons for all secret material |

**Post-Quantum Hybrid KEM:**
- Deterministic keypair generation from 32-byte seed (domain-separated SHA-256)
- Encapsulation produces 64-byte combined secret via HKDF-SHA256
- Secure if EITHER X25519 OR ML-KEM-1024 remains unbroken

### Tor / Arti Integration

The `network/` module provides in-process Tor connectivity via [Arti](https://gitlab.torproject.org/tpo/core/arti) (the Tor Project's Rust implementation):

- **Arti Client** - Full in-process Tor client with bootstrap, circuit management, and onion service hosting
- **Onion Address Derivation** - v3 .onion address from Ed25519 seed (SHA3-256 checksum per rend-spec-v3)
- **Hidden Service Hosting** - Create and manage onion services for P2P message reception
- **SOCKS5 Client** - Legacy proxy support for outbound Tor connections

### CRDT Groups

Conflict-free replicated data types for decentralized group messaging without servers:

**Operation Types:**
- `GroupCreate` - Initialize group with creator
- `MemberInvite` / `MemberAccept` / `MemberRemove` - OR-Set membership
- `RoleSet` - LWW role assignment (Creator, Admin, Member)
- `MsgAdd` / `MsgEdit` / `MsgDelete` - LWW message store with tombstones
- `ReactionSet` - Per-(device, emoji) boolean toggle
- `MetadataSet` - LWW registers for name, topic, avatar

**Design Properties:**
- **Deterministic** - `rebuild_from_ops()` produces identical `state_hash` regardless of receive order
- **Signed** - Every `OpEnvelope` carries Ed25519 signature over Blake3 hash
- **Guarded** - 250K soft cap, 500K hard cap, 100 ops/peer/min rate limit, 64KB max payload

### Audio

Opus codec integration for voice calling over Tor:

- **Opus Encoder/Decoder** - Direct C FFI to libopus (48kHz, 40ms frames, mono, 32kbps CBR)
- **Voice Streaming** - Bidirectional audio via Tor with `VoicePacket` framing
- **Redundant Framing** - Uses free Tor cell padding (342 bytes per 514-byte cell)
- **Loss-Adaptive FEC** - Forward error correction tuned for Tor packet loss patterns

### Payments (NLx402)

Payment quote protocol for in-chat cryptocurrency transfers:

- **Quote Generation** - SHA3-256 hash over deterministic fields for replay protection
- **Memo Format** - `NLx402:{hash_hex}` prefix for on-chain memo brevity
- **Verification** - Transaction memo matching against stored quote hash
- **Expiry** - Default 24-hour quote lifetime

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
securelegion-crypto = { path = "../securelegion-crypto" }
# Or from git:
# securelegion-crypto = { git = "https://github.com/Secure-Legion/securelegion-crypto.git" }
```

### Example: Ed25519 Signing

```rust
use securelegion_crypto::crypto::{generate_keypair, sign_data, verify_signature};

let (public_key, secret_key) = generate_keypair();
let message = b"Hello, post-quantum world!";
let signature = sign_data(message, &secret_key);
assert!(verify_signature(message, &signature, &public_key));
```

### Example: Hybrid Post-Quantum KEM

```rust
use securelegion_crypto::crypto::pqc::{generate_hybrid_keypair_from_seed, hybrid_encapsulate, hybrid_decapsulate};

let seed = [0u8; 32]; // Use a real random seed
let keypair = generate_hybrid_keypair_from_seed(&seed);
let (ciphertext, shared_secret_enc) = hybrid_encapsulate(&keypair.public_key);
let shared_secret_dec = hybrid_decapsulate(&ciphertext, &keypair.secret_key);
assert_eq!(shared_secret_enc, shared_secret_dec);
```

## Building

### Prerequisites

- Rust 1.70+
- Android NDK r27c (for Android targets)
- `cargo-ndk`: `cargo install cargo-ndk`
- libopus (for audio module)

### Host (Linux/macOS/Windows)

```bash
cargo check    # Verify compilation
cargo test     # Run tests
```

### Android Cross-Compilation

```bash
# Install targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# Set environment
export ANDROID_NDK_HOME="/path/to/android-ndk-r27c"
export LIBOPUS_STATIC=1
export LIBOPUS_NO_PKG=1
export OPUS_INCLUDE_DIR="/path/to/opus/include"

# Build for ARM64
export OPUS_LIB_DIR="/path/to/opus/build/arm64-v8a"
cargo ndk --target aarch64-linux-android --platform 26 build --release

# Build for ARMv7
export OPUS_LIB_DIR="/path/to/opus/build/armeabi-v7a"
cargo ndk --target armv7-linux-androideabi --platform 26 build --release

# Build for x86_64 (emulator)
export OPUS_LIB_DIR="/path/to/opus/build/x86_64"
cargo ndk --target x86_64-linux-android --platform 26 build --release
```

## Dependencies

### Cryptography
- `ed25519-dalek` - Ed25519 signatures
- `x25519-dalek` - X25519 key exchange
- `pqc_kyber` - ML-KEM-1024 (NIST FIPS 203)
- `chacha20poly1305` - XChaCha20-Poly1305 AEAD
- `argon2` - Argon2id password hashing
- `blake3` - Fast hashing (replay cache, CRDT state hash)
- `bulletproofs` + `curve25519-dalek` + `merlin` - Zero-knowledge range proofs
- `sha3` / `sha2` / `hkdf` / `hmac` - Hash functions and key derivation
- `zeroize` - Secure memory wiping
- `subtle` - Constant-time operations

### Tor
- `arti-client` v0.40 - In-process Tor client (Rust)
- `tor-hsservice` / `tor-proto` / `tor-cell` - Onion service hosting
- `tor-llcrypto` / `tor-hscrypto` - Tor cryptographic primitives

### Serialization
- `serde` + `bincode` - Binary serialization (CRDT outer frame)
- `ciborium` - CBOR encoding (CRDT op payloads)
- `serde_json` - JSON interop
- `bs58` / `base64` / `hex` / `base32` - Encoding formats

### Async Runtime
- `tokio` - Async runtime (Tor bootstrap, voice streaming)
- `tokio-util` + `bytes` - Codec framing

### Audio
- `opus` - Opus audio codec (C FFI)

## Security

- All cryptographic keys are zeroized on drop via the `zeroize` crate
- Constant-time comparisons used for all secret material via `subtle`
- No unsafe crypto — all primitives from audited RustCrypto and Dalek libraries
- Post-quantum hybrid KEM provides defense-in-depth against quantum adversaries

**Reporting Vulnerabilities:** Please report security issues to security@securelegion.org

## Related Repositories

| Repository | Description | Visibility |
|------------|-------------|------------|
| [android](https://github.com/Secure-Legion/android) | Kotlin/Java Android application | Public |
| **securelegion-crypto** (this repo) | Rust cryptographic library | Public |
| rust-core | Protocol logic, FFI bridge, wire protocol | Private |

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

---

<div align="center">

**Secure Legion - Crypto Library**

Part of the [Secure Legion](https://github.com/Secure-Legion) project

</div>
