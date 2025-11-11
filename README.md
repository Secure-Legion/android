# Secure Legion Core Library (Rust)

**Privacy-focused cryptography and messaging core for Secure Legion**

This is the Rust core library that powers Secure Legion's cryptographic operations, networking, and blockchain integration. It provides native JNI bindings for Android.

## 🏗️ Architecture

### Modules

1. **crypto/** - Cryptographic operations
   - `encryption.rs` - XChaCha20-Poly1305 encryption
   - `signing.rs` - Ed25519 signatures
   - `key_exchange.rs` - X25519 Diffie-Hellman
   - `hashing.rs` - Argon2id password hashing

2. **protocol/** - Data structures
   - `message.rs` - Message format and Ping-Pong tokens
   - `contact.rs` - Contact card format
   - `security_mode.rs` - Security modes and tiers

3. **ffi/** - Foreign Function Interface
   - `android.rs` - JNI bindings for Android

## 🚀 Building for Android

### Prerequisites

1. **Rust toolchain**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

2. **Android targets**
```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android
```

3. **cargo-ndk** (for easy Android cross-compilation)
```bash
cargo install cargo-ndk
```

4. **Android NDK**
   - Download from: https://developer.android.com/ndk
   - Or install via Android Studio: Tools → SDK Manager → SDK Tools → NDK
   - Set environment variable:
     ```bash
     export ANDROID_NDK_HOME=/path/to/ndk
     ```
     On Windows:
     ```cmd
     set ANDROID_NDK_HOME=C:\Users\YourName\AppData\Local\Android\Sdk\ndk\26.1.10909125
     ```

### Build Commands

#### Build for all Android architectures:

```bash
# ARM64 (most modern devices)
cargo ndk --target aarch64-linux-android --platform 26 build --release

# ARMv7 (older devices)
cargo ndk --target armv7-linux-androideabi --platform 26 build --release

# x86_64 (emulators)
cargo ndk --target x86_64-linux-android --platform 26 build --release

# x86 (older emulators)
cargo ndk --target i686-linux-android --platform 26 build --release
```

#### Or build all at once:

```bash
# On Unix/Linux/macOS
./build_android.sh

# On Windows
build_android.bat
```

### Copy to Android Project

After building, copy the libraries to your Android project:

```bash
# ARM64
cp target/aarch64-linux-android/release/libsecurelegion.so \
   ../secure-legion-android/app/src/main/jniLibs/arm64-v8a/

# ARMv7
cp target/armv7-linux-androideabi/release/libsecurelegion.so \
   ../secure-legion-android/app/src/main/jniLibs/armeabi-v7a/
```

On Windows:
```cmd
copy target\aarch64-linux-android\release\libsecurelegion.so ^
     ..\secure-legion-android\app\src\main\jniLibs\arm64-v8a\

copy target\armv7-linux-androideabi\release\libsecurelegion.so ^
     ..\secure-legion-android\app\src\main\jniLibs\armeabi-v7a\
```

## 🧪 Testing

### Run unit tests:

```bash
cargo test
```

### Run specific test:

```bash
cargo test test_encrypt_decrypt
```

### Run tests with output:

```bash
cargo test -- --nocapture
```

## 📦 Dependencies

### Core Cryptography
- **chacha20poly1305** - XChaCha20-Poly1305 AEAD encryption
- **ed25519-dalek** - Ed25519 signatures
- **x25519-dalek** - Curve25519 key exchange
- **argon2** - Argon2id password hashing

### Serialization
- **serde** - Serialization framework
- **serde_json** - JSON support
- **bincode** - Binary encoding

### Platform
- **jni** - Java Native Interface for Android

## 🔐 Cryptographic Operations

### Encryption (XChaCha20-Poly1305)

```rust
use securelegion::crypto::encrypt_message;

let key = [0u8; 32]; // 32-byte key
let plaintext = b"Hello, Secure Legion!";

let encrypted = encrypt_message(plaintext, &key)?;
// Returns: [24-byte nonce][ciphertext][16-byte tag]
```

### Signing (Ed25519)

```rust
use securelegion::crypto::{generate_keypair, sign_data, verify_signature};

let (public_key, private_key) = generate_keypair();
let data = b"Message to sign";

let signature = sign_data(data, &private_key)?;
let valid = verify_signature(data, &signature, &public_key)?;
```

### Key Exchange (X25519)

```rust
use securelegion::crypto::derive_shared_secret;

// User1's keypair
let user1_private = [/* 32 bytes */];
let user1_public = [/* 32 bytes */];

// User2's public key
let user2_public = [/* 32 bytes */];

// Derive shared secret
let shared_secret = derive_shared_secret(&user1_private, &user2_public)?;
```

### Password Hashing (Argon2id)

```rust
use securelegion::crypto::hash_password;

let password = "my_secure_password";
let hash = hash_password(password)?;

// Verify
let valid = verify_password(password, &hash)?;
```

## 🌐 JNI Interface

The library exposes functions to Android via JNI. All functions are prefixed with:
```
Java_com_securelegion_crypto_RustBridge_
```

### Implemented Functions

#### Cryptography
- ✅ `encryptMessage` - Encrypt plaintext
- ✅ `decryptMessage` - Decrypt ciphertext
- ✅ `signData` - Create Ed25519 signature
- ✅ `verifySignature` - Verify Ed25519 signature
- ✅ `generateKeypair` - Generate Ed25519 keypair
- ✅ `hashPassword` - Hash password with Argon2id

#### Network (Stubs)
- 🚧 `initializeTor` - Initialize Tor daemon
- 🚧 `sendPing` - Send Ping token
- 🚧 `waitForPong` - Wait for Pong response
- 🚧 `respondToPing` - Respond with Pong
- 🚧 `sendDirectMessage` - Send direct message

#### Relay (Stubs)
- 🚧 `uploadToRelay` - Upload to relay network
- 🚧 `checkRelay` - Check for messages
- 🚧 `downloadFromRelay` - Download from relay
- 🚧 `deleteFromRelay` - Delete from relay

#### Blockchain (Stubs)
- 🚧 `initializeSolanaWallet` - Initialize Solana wallet
- 🚧 `getSolanaBalance` - Get SOL balance
- 🚧 `sendSolanaTransaction` - Send SOL
- 🚧 `publishContactCard` - Publish to blockchain
- 🚧 `fetchContactCard` - Fetch from blockchain

#### IPFS (Stubs)
- 🚧 `uploadToIPFS` - Upload to IPFS
- 🚧 `downloadFromIPFS` - Download from IPFS

#### Utility
- ✅ `getVersion` - Get library version

## 🔧 Development

### Project Structure

```
secure-legion-core/
├── src/
│   ├── lib.rs                    # Main library entry
│   ├── crypto/
│   │   ├── mod.rs
│   │   ├── encryption.rs         # XChaCha20-Poly1305
│   │   ├── signing.rs            # Ed25519
│   │   ├── key_exchange.rs       # X25519
│   │   └── hashing.rs            # Argon2id
│   ├── protocol/
│   │   ├── mod.rs
│   │   ├── message.rs            # Message structures
│   │   ├── contact.rs            # Contact card
│   │   └── security_mode.rs      # Security enums
│   └── ffi/
│       ├── mod.rs
│       └── android.rs            # JNI bindings
├── .cargo/
│   └── config.toml               # Android NDK config
├── Cargo.toml                    # Dependencies
├── build.rs                      # Build script
└── README.md                     # This file
```

### Adding New JNI Functions

1. Define the function in `src/ffi/android.rs`:
```rust
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_myFunction(
    mut env: JNIEnv,
    _class: JClass,
    param: JString,
) -> jstring {
    // Implementation
}
```

2. Add corresponding method in Kotlin `RustBridge.kt`:
```kotlin
external fun myFunction(param: String): String
```

3. Rebuild library and test

## 📊 Performance

### Benchmarks (Release build on ARM64)

- **Encryption**: ~50ms per message
- **Decryption**: ~50ms per message
- **Signing**: ~20ms per signature
- **Verification**: ~25ms per signature
- **Key Generation**: ~10ms per keypair

## 🐛 Debugging

### Enable logging:

```rust
env_logger::init();
log::debug!("Debug message");
```

### View logs on Android:

```bash
adb logcat | grep RustPanic
```

### Common issues:

1. **Library not found**
   - Ensure `.so` files are in correct `jniLibs/` folders
   - Check ABI matches device architecture

2. **JNI signature mismatch**
   - Verify function names match exactly
   - Check parameter types (JString, JByteArray, etc.)

3. **Rust panic**
   - Check logcat for panic messages
   - Use `catch_panic!` macro in JNI functions

## 🚧 Future Implementation

### Network Layer
- [ ] Tor client integration (using `arti` crate)
- [ ] Ping-Pong protocol implementation
- [ ] Relay network client
- [ ] NAT traversal for P2P

### Blockchain Layer
- [ ] Solana wallet integration
- [ ] IPFS client for contact cards
- [ ] Transaction signing
- [ ] Contact discovery

## 📄 License

TBD - See main project for license information.

## 🤝 Contributing

This is part of the Secure Legion project. See main repository for contribution guidelines.

---

**Security Notice**: This library handles cryptographic operations. Always audit code before production use.
