<div align="center">

# Secure - Rust Core

**Patent-pending protocol logic, encryption ratchet, and JNI bridge for the Secure messaging platform**

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-B7410E?style=flat-square&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/target-Android%20JNI-34A853?style=flat-square&logo=android&logoColor=white" alt="Android JNI" />
  <img src="https://img.shields.io/badge/license-Proprietary-red?style=flat-square" alt="License" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Encryption-XChaCha20--Poly1305-4A90D9?style=flat-square" alt="XChaCha20" />
  <img src="https://img.shields.io/badge/Protocol-Ping--Pong--ACK-E91E63?style=flat-square" alt="Ping-Pong-ACK" />
  <img src="https://img.shields.io/badge/Ratchet-Chain%20Key-FF6F00?style=flat-square" alt="Chain Key Ratchet" />
</p>

> Private repository. This library contains patent-pending protocol code and is proprietary to Secure Legion.

</div>

---

## Overview

`secure-legion-core` is the private Rust crate that contains Secure's patent-pending protocol logic, encryption ratchet, and Android JNI bridge. It depends on the open-source [`securelegion-crypto`](https://github.com/Secure-Legion/securelegion-crypto) crate for cryptographic primitives, CRDT engine, audio codec, Tor/Arti integration, wallet, and utilities.

This crate compiles to a shared library (`libsecurelegion.so`) consumed by the Android app via JNI.

**What lives here (private / patent-pending):**
- **Chain key ratchet** - Signal-like bidirectional ratchet with two-phase deferred commit
- **Ping-Pong-ACK protocol** - Async wake handshake requiring biometric authentication before message delivery
- **ACK state machine** - Delivery confirmation with idempotency and forward progress tracking
- **Wire protocol** - Message types, contact cards, security modes
- **FFI bridge** - JNI entry points for Android, CRDT bindings, KeyStore access

**What lives in securelegion-crypto (public):**
- Cryptographic primitives (Ed25519, X25519, ML-KEM-1024, Argon2id, Bulletproofs)
- CRDT group consensus engine
- Opus voice codec and streaming
- Arti Tor integration
- Payment quote protocol (NLx402)
- Utility modules

## Architecture

```
secure-legion-core/
|
|-- crypto/              Private cryptographic protocol
|   |-- encryption.rs    XChaCha20-Poly1305 AEAD + chain key ratchet
|   +-- ack_state.rs     ACK type tracking (PING/PONG/MESSAGE) with idempotency
|
|-- protocol/            Wire protocol types and serialization
|   |-- message.rs       PingToken, PongToken, ACK structures
|   |-- contact.rs       ContactCard with pubkeys, .onion, Solana address
|   +-- security_mode.rs Connection mode enums (Direct, Relay, Auto)
|
|-- network/             P2P handshake protocol
|   +-- pingpong.rs      Ping-Pong-ACK wake protocol (async, tokio)
|
+-- ffi/                 Foreign function interface
    |-- android.rs       JNI entry points, catch_panic! macro, wire normalization
    |-- crdt.rs          CRDT group operations (5 core + 4 sync entry points)
    +-- keystore.rs      Android KeyStore access (hardware-backed key retrieval)
```

All other modules (crypto primitives, CRDT, audio, network/tor, nlx402, util) are re-exported from `securelegion-crypto`.

## Modules

### Encryption & Ratchet (Patent-Pending)

The `crypto/` module contains the proprietary encryption protocol:

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Encryption** | XChaCha20-Poly1305 | AEAD message encryption with 24-byte nonce |
| **Key Derivation** | HKDF-SHA256 | Root key, chain key, per-message key derivation |
| **Forward Secrecy** | HMAC-SHA256 ratchet | One-way chain evolution, bidirectional send/receive |

**Chain Key Ratchet:**
- Signal-like bidirectional ratchet with per-message forward secrecy
- Two-phase deferred commit: ratchet advancement held until PING_ACK received
- Out-of-order tolerance: 100-message sequence window for Tor delivery variance
- Immediate key zeroization after use via `zeroize` crate

### Ping-Pong-ACK Protocol (Patent-Pending)

The `network/pingpong.rs` module implements the wake protocol:

- **Async handshake** (tokio) with global session storage
- **5-minute session TTL** with oneshot channels for pong waiters
- **ACK State Machine** - Tracks PING_ACK, PONG_ACK, MESSAGE_ACK with idempotency and forward progress

**Wire Protocol Types:**
```
0x01  PING          0x07  FRIEND_REQ      0x30  CRDT_OPS
0x02  PONG          0x08  IMAGE           0x31  SYNC_REQUEST
0x03  TEXT          0x09  PAYMENT         0x32  SYNC_CHUNK
0x04  VOICE         0x0A  CALL_OFFER      0x33  SYNC_HELLO
0x05  TAP           0x0B  CALL_ANSWER     0x34  SYNC_ACK
0x06  ACK           0x0D  VOICE_CALL
```

### FFI Bridge

The `ffi/` module provides the JNI interface consumed by Android's `RustBridge.kt`:

- **android.rs** - Core JNI entry points with `catch_panic!` macro, wire byte normalization
- **crdt.rs** - 5 core CRDT operations + 4 sync stubs, JSON return values for Kotlin interop
- **keystore.rs** - Hardware-backed key retrieval via JNI callback to Android KeyStore

**Port Assignments:**
```
8080  Main listener (ping, pong, message, ack)
9150  Ping-Pong handshake
9151  TAP heartbeat + friend requests
9152  Voice streaming
```

## Dependencies

```toml
[dependencies]
securelegion-crypto = { path = "../securelegion-crypto" }
```

All cryptographic, networking, CRDT, audio, and wallet dependencies come transitively through `securelegion-crypto`. This crate adds only:

- `jni` - Java Native Interface for Android
- `android_logger` - Android logcat integration
- Protocol-specific async runtime features

## Building

### Prerequisites

- Rust 1.70+
- Android NDK r27c
- `cargo-ndk`: `cargo install cargo-ndk`
- libopus (for audio — see `securelegion-crypto` build docs)

### Android Cross-Compilation

```bash
export ANDROID_NDK_HOME="/path/to/android-ndk-r27c"
export LIBOPUS_STATIC=1 LIBOPUS_NO_PKG=1
export OPUS_INCLUDE_DIR="/path/to/opus/include"

# ARM64
export OPUS_LIB_DIR="/path/to/opus/build/arm64-v8a"
cargo ndk --target aarch64-linux-android --platform 26 build --release

# ARMv7
export OPUS_LIB_DIR="/path/to/opus/build/armeabi-v7a"
cargo ndk --target armv7-linux-androideabi --platform 26 build --release

# x86_64 (emulator)
export OPUS_LIB_DIR="/path/to/opus/build/x86_64"
cargo ndk --target x86_64-linux-android --platform 26 build --release
```

### Output

```bash
cp target/aarch64-linux-android/release/libsecurelegion.so \
   ../app/src/main/jniLibs/arm64-v8a/
```

## Related Repositories

| Repository | Description | Visibility |
|------------|-------------|------------|
| [android](https://github.com/Secure-Legion/android) | Kotlin/Java Android application | Public |
| [securelegion-crypto](https://github.com/Secure-Legion/securelegion-crypto) | Rust cryptographic library | Public |
| **rust-core** (this repo) | Protocol logic, FFI bridge | Private |

## License

This library is proprietary and confidential. All rights reserved by Secure Legion.

Contains patent-pending technology. Unauthorized copying, distribution, or use is strictly prohibited.

---

<div align="center">

**Secure - Rust Core**

Private repository of [Secure Legion](https://github.com/Secure-Legion)

</div>
