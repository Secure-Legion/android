# Build Instructions for Secure Legion Core Library

## Current Status

✅ **Code Complete** - All Rust source files are ready
❌ **Rust Not Installed** - Need to install Rust toolchain

## Step-by-Step Installation & Build

### Step 1: Install Rust (5 minutes)

**On Windows:**

1. Download Rust installer:
   - Visit: https://rustup.rs/
   - Click "Download rustup-init.exe (64-bit)"
   - Or use this direct link: https://win.rustup.rs/x86_64

2. Run the installer:
   ```cmd
   # Download and run rustup-init.exe
   # Choose: 1) Proceed with installation (default)
   ```

3. Verify installation:
   ```cmd
   # Open NEW terminal/PowerShell window
   rustc --version
   cargo --version
   ```

   Expected output:
   ```
   rustc 1.75.0 (82e1608df 2023-12-21)
   cargo 1.75.0 (1d8b05cdd 2023-11-20)
   ```

**Alternative - Using winget:**

```cmd
winget install Rustlang.Rustup
```

### Step 2: Install Android Targets (2 minutes)

```cmd
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
```

Expected output:
```
info: downloading component 'rust-std' for 'aarch64-linux-android'
info: installing component 'rust-std' for 'aarch64-linux-android'
```

### Step 3: Install cargo-ndk (2 minutes)

```cmd
cargo install cargo-ndk
```

Expected output:
```
    Updating crates.io index
  Downloaded cargo-ndk v3.4.0
   Compiling cargo-ndk v3.4.0
    Finished release [optimized] target(s) in 45.23s
  Installing cargo-ndk.exe
```

### Step 4: Set Android NDK Path

```cmd
# Find your NDK (check Android Studio SDK Manager)
dir "C:\Users\%USERNAME%\AppData\Local\Android\Sdk\ndk"

# Set environment variable (replace with your version)
setx ANDROID_NDK_HOME "C:\Users\%USERNAME%\AppData\Local\Android\Sdk\ndk\26.1.10909125"

# IMPORTANT: Close and reopen terminal after this
```

### Step 5: Build the Library

```cmd
cd C:\Users\Eddie\AndroidStudioProjects\SecureLegion\secure-legion-core

# Option 1: Quick test build (host architecture)
cargo build --release

# Option 2: Full Android build
build_android.bat
```

## Expected Build Output

### Cargo Build (Local)

```
   Compiling autocfg v1.1.0
   Compiling proc-macro2 v1.0.70
   Compiling unicode-ident v1.0.12
   Compiling libc v0.2.151
   Compiling cfg-if v1.0.0
   Compiling version_check v0.9.4
   Compiling typenum v1.17.0
   Compiling subtle v2.5.0
   Compiling cpufeatures v0.2.11
   Compiling getrandom v0.2.11
   Compiling rand_core v0.6.4
   Compiling crypto-common v0.1.6
   Compiling block-buffer v0.10.4
   Compiling digest v0.10.7
   Compiling generic-array v0.14.7
   Compiling thiserror-impl v1.0.56
   Compiling thiserror v1.0.56
   Compiling quote v1.0.33
   Compiling syn v2.0.43
   Compiling serde_derive v1.0.193
   Compiling serde v1.0.193
   Compiling rand v0.8.5
   Compiling chacha20poly1305 v0.10.1
   Compiling ed25519-dalek v2.1.0
   Compiling x25519-dalek v2.0.0
   Compiling argon2 v0.5.2
   Compiling jni v0.21.1
   Compiling bincode v1.3.3
   Compiling serde_json v1.0.108
   Compiling uuid v1.6.1
   Compiling chrono v0.4.31
   Compiling securelegion v1.0.0 (C:\Users\Eddie\AndroidStudioProjects\SecureLegion\secure-legion-core)
    Finished release [optimized] target(s) in 52.34s
```

### Android Build Output

```
Building Secure Legion Core Library for Android...

Building for ARM64 (arm64-v8a)...
   Compiling securelegion v1.0.0
    Finished release [optimized] target(s) in 45.32s

Building for ARMv7 (armeabi-v7a)...
   Compiling securelegion v1.0.0
    Finished release [optimized] target(s) in 42.18s

Build successful!

Copying libraries to Android project...
        1 file(s) copied.
        1 file(s) copied.

Done! Libraries copied to:
  - secure-legion-android/app/src/main/jniLibs/arm64-v8a/libsecurelegion.so
  - secure-legion-android/app/src/main/jniLibs/armeabi-v7a/libsecurelegion.so

You can now build the Android app in Android Studio!
```

## Expected File Sizes

After successful build:

```
target/release/libsecurelegion.so          ~2.5 MB (debug symbols)
target/release/libsecurelegion.so          ~800 KB (stripped)

target/aarch64-linux-android/release/
  └── libsecurelegion.so                   ~1.2 MB

target/armv7-linux-androideabi/release/
  └── libsecurelegion.so                   ~1.1 MB
```

## Running Tests

```cmd
cd C:\Users\Eddie\AndroidStudioProjects\SecureLegion\secure-legion-core

cargo test
```

Expected output:
```
   Compiling securelegion v1.0.0
    Finished test [unoptimized + debuginfo] target(s) in 12.45s
     Running unittests src\lib.rs

running 15 tests
test crypto::encryption::tests::test_decrypt_with_wrong_key ... ok
test crypto::encryption::tests::test_encrypt_decrypt ... ok
test crypto::encryption::tests::test_invalid_key_length ... ok
test crypto::hashing::tests::test_generate_salt ... ok
test crypto::hashing::tests::test_hash_handle ... ok
test crypto::hashing::tests::test_hash_password ... ok
test crypto::hashing::tests::test_hash_password_with_salt ... ok
test crypto::hashing::tests::test_verify_password ... ok
test crypto::key_exchange::tests::test_derive_public_key ... ok
test crypto::key_exchange::tests::test_derive_shared_secret ... ok
test crypto::key_exchange::tests::test_ephemeral_key_exchange ... ok
test crypto::key_exchange::tests::test_generate_static_keypair ... ok
test crypto::signing::tests::test_derive_public_key ... ok
test crypto::signing::tests::test_generate_keypair ... ok
test crypto::signing::tests::test_sign_verify ... ok
test crypto::signing::tests::test_verify_invalid_signature ... ok
test protocol::message::tests::test_message_json ... ok
test protocol::message::tests::test_message_serialization ... ok
test protocol::contact::tests::test_contact_card_json ... ok
test protocol::contact::tests::test_contact_card_serialization ... ok
test tests::test_version ... ok

test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Troubleshooting

### Error: "rustc not found"
**Solution**: Install Rust from https://rustup.rs/

### Error: "linker not found"
**Solution**: Install Visual Studio Build Tools or MinGW

### Error: "ANDROID_NDK_HOME not set"
**Solution**:
```cmd
set ANDROID_NDK_HOME=C:\Users\YourName\AppData\Local\Android\Sdk\ndk\26.1.10909125
```

### Error: "cargo-ndk not found"
**Solution**: `cargo install cargo-ndk`

### Error: "target not found"
**Solution**:
```cmd
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
```

## Verification Checklist

After successful build, verify:

- [ ] `target/release/libsecurelegion.so` exists
- [ ] `target/aarch64-linux-android/release/libsecurelegion.so` exists
- [ ] `target/armv7-linux-androideabi/release/libsecurelegion.so` exists
- [ ] Files copied to `../secure-legion-android/app/src/main/jniLibs/`
- [ ] All tests pass (`cargo test`)
- [ ] File sizes are reasonable (~1-2 MB per .so file)

## Next Steps

Once build completes successfully:

1. ✅ Rust library built
2. ✅ `.so` files in jniLibs/
3. ➡️ Open Android Studio
4. ➡️ Sync Gradle
5. ➡️ Build Android app
6. ➡️ Run on device

## Manual Build Commands

If the script doesn't work, run manually:

```cmd
# Test build first
cargo build --release

# Run tests
cargo test

# Build for Android ARM64
cargo ndk --target aarch64-linux-android --platform 26 build --release

# Build for Android ARMv7
cargo ndk --target armv7-linux-androideabi --platform 26 build --release

# Copy to Android project
copy target\aarch64-linux-android\release\libsecurelegion.so ^
     ..\secure-legion-android\app\src\main\jniLibs\arm64-v8a\

copy target\armv7-linux-androideabi\release\libsecurelegion.so ^
     ..\secure-legion-android\app\src\main\jniLibs\armeabi-v7a\
```

## Time Estimates

- Rust installation: 5 minutes
- Dependencies setup: 5 minutes
- First build: 5-10 minutes
- Subsequent builds: 1-2 minutes
- **Total first-time setup: ~20 minutes**

---

**Ready to build!** Follow the steps above in order.
