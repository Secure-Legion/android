<div align="center">

# Secure - Rust Core

**The cryptographic engine powering Secure's post-quantum encrypted messaging, CRDT group consensus, and voice calling**

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-B7410E?style=flat-square&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/target-Android%20JNI-34A853?style=flat-square&logo=android&logoColor=white" alt="Android JNI" />
  <img src="https://img.shields.io/badge/license-Proprietary-red?style=flat-square" alt="License" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Post--Quantum-ML--KEM--1024-FF6F00?style=flat-square" alt="Post-Quantum" />
  <img src="https://img.shields.io/badge/Encryption-XChaCha20--Poly1305-4A90D9?style=flat-square" alt="XChaCha20" />
  <img src="https://img.shields.io/badge/Signatures-Ed25519-2E7D32?style=flat-square" alt="Ed25519" />
  <img src="https://img.shields.io/badge/ZK%20Proofs-Bulletproofs-9C27B0?style=flat-square" alt="Bulletproofs" />
</p>

> Private repository. This library is closed source and proprietary to Secure Legion.

</div>

---

## Overview

`secure-legion-core` is the Rust native library that handles all cryptographic operations, protocol logic, CRDT-based group consensus, voice codec integration, and payment quote generation for the Secure messaging app. It compiles to a shared library (`libsecurelegion.so`) consumed by the Android app via JNI.

**Key properties:**
- **Memory-safe cryptography** - All crypto runs in Rust with zeroize-on-drop for sensitive material
- **Post-quantum hybrid KEM** - X25519 + ML-KEM-1024 (NIST FIPS 203) key encapsulation
- **Signal-like forward secrecy** - Per-message chain key ratchet with two-phase deferred commit
- **Deterministic CRDT engine** - Same ops in any order produce identical state hash
- **Zero unsafe crypto** - All primitives from audited RustCrypto and Dalek libraries

## Architecture

```
secure-legion-core/
|
|-- crypto/              Cryptographic primitives and ratchet protocol
|   |-- encryption.rs    XChaCha20-Poly1305 AEAD + chain key ratchet
|   |-- signing.rs       Ed25519 keypair generation, signing, verification
|   |-- key_exchange.rs  X25519 ECDH key agreement
|   |-- hashing.rs       Argon2id password hashing, handle hashing
|   |-- replay_cache.rs  LRU PING deduplication (Blake3, 10K capacity)
|   |-- ack_state.rs     ACK type tracking (PING/PONG/MESSAGE) with idempotency
|   |-- zkproofs.rs      Bulletproof range proofs for private transfers
|   +-- pqc/
|       |-- hybrid_kem.rs  Hybrid X25519 + ML-KEM-1024 encapsulation
|       +-- types.rs       KEM keypair and ciphertext structures
|
|-- protocol/            Wire protocol types and serialization
|   |-- message.rs       PingToken, PongToken, ACK structures
|   |-- contact.rs       ContactCard with pubkeys, .onion, Solana address
|   +-- security_mode.rs Connection mode enums (Direct, Relay, Auto)
|
|-- network/             Tor integration and P2P handshake
|   |-- tor.rs           .onion address generation, bootstrap polling, wire constants
|   |-- pingpong.rs      Ping-Pong-ACK wake protocol (async, tokio)
|   |-- socks5_client.rs SOCKS5 proxy for Tor connections
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
+-- ffi/                 Foreign function interface
    |-- android.rs       JNI entry points, catch_panic! macro, wire normalization
    |-- crdt.rs          CRDT group operations (5 core + 4 sync entry points)
    +-- keystore.rs      Android KeyStore access (hardware-backed key retrieval)
```

## Modules

### Cryptography

The `crypto/` module provides the complete cryptographic stack:

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Encryption** | XChaCha20-Poly1305 | AEAD message encryption with 24-byte nonce |
| **Signatures** | Ed25519 | Message authentication, CRDT op signing |
| **Key Exchange** | X25519 ECDH | Classical ephemeral key agreement |
| **Post-Quantum KEM** | Hybrid X25519 + ML-KEM-1024 | Quantum-resistant key encapsulation (NIST FIPS 203) |
| **Password Hashing** | Argon2id | PIN/password derivation (memory-hard) |
| **Key Derivation** | HKDF-SHA256 | Root key, chain key, per-message key derivation |
| **Forward Secrecy** | HMAC-SHA256 ratchet | One-way chain evolution, bidirectional send/receive |
| **Replay Protection** | Blake3 LRU cache | PING deduplication (10,000 entry capacity) |
| **ZK Proofs** | Bulletproofs (Ristretto) | Range proofs for private payment amounts |
| **Constant-Time** | subtle crate | Timing-safe comparisons for all secret material |

**Chain Key Ratchet:**
- Signal-like bidirectional ratchet with per-message forward secrecy
- Two-phase deferred commit: ratchet advancement held until PING_ACK received
- Out-of-order tolerance: 100-message sequence window for Tor delivery variance
- Immediate key zeroization after use via `zeroize` crate

**Post-Quantum Hybrid KEM:**
- Deterministic keypair generation from 32-byte seed (domain-separated SHA-256)
- Encapsulation produces 64-byte combined secret via HKDF-SHA256
- Secure if EITHER X25519 OR ML-KEM-1024 remains unbroken

### CRDT Groups

The `crdt/` module implements conflict-free replicated data types for decentralized group messaging:

**Operation Types:**
- `GroupCreate` - Initialize group with creator
- `MemberInvite` / `MemberAccept` / `MemberRemove` - OR-Set membership
- `RoleSet` - LWW role assignment (Creator, Admin, Member)
- `MsgAdd` / `MsgEdit` / `MsgDelete` - LWW message store with tombstones
- `ReactionSet` - Per-(device, emoji) boolean toggle
- `MetadataSet` - LWW registers for name, topic, avatar

**Design Properties:**
- **Deterministic**: `rebuild_from_ops()` sorts by (lamport, op_id), replays in order, produces identical `state_hash` regardless of receive order
- **Signed**: Every `OpEnvelope` carries Ed25519 signature over Blake3 hash
- **Serialized**: Bincode outer frame (deterministic), CBOR inner payloads (flexible)
- **Guarded**: 250K soft cap (UI warning), 500K hard cap (blocks message ops, membership always allowed), 100 ops/peer/min rate limit, 64KB max payload

### Network

The `network/` module handles Tor integration and the P2P wake protocol:

- **Tor Manager** - v3 .onion address derivation from Ed25519 seed (SHA3-256 checksum per rend-spec-v3), bootstrap status polling via control port Unix socket
- **Ping-Pong-ACK Protocol** - Async handshake (tokio) with global session storage, 5-minute session TTL, oneshot channels for pong waiters
- **ACK State Machine** - Tracks PING_ACK, PONG_ACK, MESSAGE_ACK with idempotency and forward progress (tolerates out-of-order from Tor circuit churn)

**Wire Protocol Types:**
```
0x01  PING          0x07  FRIEND_REQ      0x30  CRDT_OPS
0x02  PONG          0x08  IMAGE           0x31  SYNC_REQUEST
0x03  TEXT          0x09  PAYMENT         0x32  SYNC_CHUNK
0x04  VOICE         0x0A  CALL_OFFER      0x33  SYNC_HELLO
0x05  TAP           0x0B  CALL_ANSWER     0x34  SYNC_ACK
0x06  ACK           0x0D  VOICE_CALL
```

### Audio

The `audio/` module provides Opus codec integration for voice calling over Tor:

- **Opus Encoder/Decoder** - Direct C FFI to libopus (48kHz sample rate, 40ms frames, mono, 32kbps CBR optimized for Tor bandwidth)
- **Voice Streaming** - Bidirectional audio via Tor hidden services with `VoicePacket` framing (sequence, timestamp, circuit index for multi-circuit multiplexing)
- **Redundant Framing** - Uses free Tor cell padding (342 bytes per 514-byte cell) for redundant audio data
- **Handshake** - VOICE_HELLO/VOICE_OK with 10-second timeout

### Payments (NLx402)

The `nlx402/` module implements the Secure Pay payment quote protocol:

- **Quote Generation** - SHA3-256 hash over deterministic fields (quote_id, recipient, amount, token, timestamps) for replay protection
- **Memo Format** - `NLx402:{hash_hex}` prefix (first 16 bytes as hex) for on-chain memo brevity
- **Verification** - Transaction memo matching against stored quote hash
- **Expiry** - Default 24-hour quote lifetime with configurable duration

### FFI Bridge

The `ffi/` module provides the JNI interface consumed by Android's `RustBridge.kt`:

- **android.rs** - Core JNI entry points with `catch_panic!` macro (catches Rust panics, throws Java RuntimeException), wire byte normalization for legacy packet migration, stress test metrics (SOCKS timeout, channel init race, listener thrashing diagnostics)
- **crdt.rs** - 5 core CRDT operations (`crdtLoadGroup`, `crdtUnloadGroup`, `crdtApplyOps`, `crdtCreateOp`, `crdtQuery`) + 4 sync stubs, JSON return values for Kotlin interop
- **keystore.rs** - Hardware-backed key retrieval via JNI callback to Android KeyStore (keys never stored in Rust heap)

**Port Assignments:**
```
8080  Main listener (ping, pong, message, ack)
9150  Ping-Pong handshake
9151  TAP heartbeat + friend requests
9152  Voice streaming
```

## Building

### Prerequisites

- Rust toolchain 1.70+
- Android NDK 26.1+
- `cargo-ndk`: `cargo install cargo-ndk`

### Android Targets

```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android
rustup target add i686-linux-android
```

### Build Commands

```bash
# ARM64 (primary target)
cargo ndk --target aarch64-linux-android --platform 26 build --release

# All architectures
./build_android.sh    # Linux/macOS
build_android.bat     # Windows
```

### Output

Copy the built `.so` to the Android project:

```bash
cp target/aarch64-linux-android/release/libsecurelegion.so \
   ../app/src/main/jniLibs/arm64-v8a/
```

### Release Profile

```toml
[profile.release]
opt-level = 3       # Maximum optimization
lto = true          # Link-time optimization
codegen-units = 1   # Single codegen unit for best optimization
strip = true        # Strip debug symbols
panic = "abort"     # Abort on panic (smaller binary)
```

## Testing

```bash
cargo test                       # All tests
cargo test crypto::              # Crypto module
cargo test crdt::                # CRDT module
cargo test -- --nocapture        # With stdout
```

## Dependencies

### Cryptography
- `chacha20poly1305` - XChaCha20-Poly1305 AEAD
- `ed25519-dalek` - Ed25519 signatures
- `x25519-dalek` - X25519 key exchange
- `pqc_kyber` - ML-KEM-1024 (NIST FIPS 203)
- `argon2` - Argon2id password hashing
- `blake3` - Fast hashing (replay cache, CRDT state hash)
- `bulletproofs` + `curve25519-dalek` + `merlin` - Zero-knowledge range proofs
- `sha3` / `sha2` / `hkdf` / `hmac` - Hash functions and key derivation
- `zeroize` - Secure memory wiping
- `subtle` - Constant-time operations

### Serialization
- `serde` + `bincode` - Binary serialization (CRDT outer frame, protocol messages)
- `ciborium` - CBOR encoding (CRDT op payloads)
- `serde_json` - JSON (FFI return values)
- `bs58` / `base64` / `hex` / `base32` - Encoding formats

### Async Runtime
- `tokio` - Async runtime (Ping-Pong protocol, Tor control port, voice streaming)
- `tokio-util` + `bytes` - Codec framing

### Audio
- `opus` - Opus audio codec for voice calling

### Platform
- `jni` - Java Native Interface for Android
- `android_logger` - Android logcat integration

## Project Structure

```
secure-legion-core/
+-- src/
|   +-- lib.rs                         Library entry point
|   +-- crypto/
|   |   +-- mod.rs
|   |   +-- encryption.rs              XChaCha20-Poly1305 + chain key ratchet
|   |   +-- signing.rs                 Ed25519
|   |   +-- key_exchange.rs            X25519 ECDH
|   |   +-- hashing.rs                 Argon2id
|   |   +-- replay_cache.rs            Blake3 LRU PING dedup
|   |   +-- ack_state.rs               ACK type tracking
|   |   +-- zkproofs.rs                Bulletproof range proofs
|   |   +-- pqc/
|   |       +-- hybrid_kem.rs          X25519 + ML-KEM-1024
|   |       +-- types.rs               KEM structures
|   +-- protocol/
|   |   +-- message.rs                 Ping/Pong/ACK tokens
|   |   +-- contact.rs                 Contact card format
|   |   +-- security_mode.rs           Connection mode enums
|   +-- network/
|   |   +-- tor.rs                     Onion address gen, bootstrap, wire types
|   |   +-- pingpong.rs                Ping-Pong-ACK handshake
|   |   +-- socks5_client.rs           SOCKS5 Tor proxy
|   |   +-- friend_request_server.rs   Contact exchange endpoint
|   +-- crdt/
|   |   +-- ops.rs                     OpEnvelope, op types, payloads
|   |   +-- ids.rs                     DeviceID, GroupID, OpID
|   |   +-- limits.rs                  Op caps and rate limits
|   |   +-- membership.rs             OR-Set membership CRDT
|   |   +-- messages.rs                LWW message CRDT
|   |   +-- metadata.rs               LWW metadata registers
|   |   +-- apply.rs                   Deterministic apply engine
|   +-- audio/
|   |   +-- opus.rs                    Opus encoder/decoder (C FFI)
|   |   +-- opus_ctl.rs                Encoder tuning controls
|   |   +-- voice_streaming.rs         Voice packet framing
|   |   +-- loss_adaptive_fec.rs       Forward error correction
|   +-- nlx402/
|   |   +-- quote.rs                   Payment quote generation
|   |   +-- verify.rs                  Quote verification
|   +-- ffi/
|       +-- android.rs                 JNI bridge + metrics
|       +-- crdt.rs                    CRDT JNI entry points
|       +-- keystore.rs                Android KeyStore access
+-- .cargo/
|   +-- config.toml                    Android NDK linker config
+-- Cargo.toml
+-- build.rs
+-- build_android.sh
```

## Debugging

```bash
# View Rust logs on Android
adb logcat | grep securelegion

# View panics
adb logcat | grep RustPanic
```

**Common Issues:**

1. **Library not found** - Verify `.so` is in the correct `jniLibs/{abi}/` directory
2. **JNI signature mismatch** - Function names must match exactly between Rust `#[no_mangle]` exports and Kotlin `external fun` declarations
3. **Rust panic on Android** - Check logcat; the `catch_panic!` macro converts panics to Java RuntimeException

## License

This library is proprietary and confidential. All rights reserved by Secure Legion.

Unauthorized copying, distribution, or use of this software is strictly prohibited.

---

<div align="center">

**Secure - Rust Core**

Private repository of [Secure Legion](https://github.com/Secure-Legion)

</div>
