# Secure Legion - Quick Start Guide

Complete guide to building and running the Secure Legion Android app.

## 📋 Project Structure

```
SecureLegion/
├── secure-legion-core/          # Rust core library
│   ├── src/
│   │   ├── crypto/              # Cryptography (XChaCha20, Ed25519, Argon2)
│   │   ├── protocol/            # Message and contact formats
│   │   └── ffi/                 # JNI bindings for Android
│   ├── Cargo.toml
│   ├── build_android.bat        # Windows build script
│   ├── build_android.sh         # Unix build script
│   └── README.md
│
└── secure-legion-android/       # Android application
    ├── app/
    │   ├── src/main/
    │   │   ├── java/com/securelegion/
    │   │   ├── jniLibs/         # Native libraries (.so files)
    │   │   └── res/
    │   └── build.gradle
    ├── build.gradle
    └── README.md
```

## 🚀 Setup Instructions (Windows)

### Step 1: Install Prerequisites

1. **Android Studio** (Hedgehog 2023.1.1+)
   - Download: https://developer.android.com/studio
   - Install with default settings

2. **Rust**
   ```cmd
   # Download and run rustup-init.exe from:
   # https://rustup.rs/

   # Or use winget:
   winget install Rustlang.Rustup
   ```

3. **Android NDK** (via Android Studio)
   - Open Android Studio
   - Tools → SDK Manager
   - SDK Tools tab
   - Check "NDK (Side by side)"
   - Check "CMake"
   - Click Apply

4. **Add Android targets to Rust**
   ```cmd
   rustup target add aarch64-linux-android
   rustup target add armv7-linux-androideabi
   ```

5. **Install cargo-ndk**
   ```cmd
   cargo install cargo-ndk
   ```

6. **Set ANDROID_NDK_HOME**
   ```cmd
   # Find your NDK path (usually):
   # C:\Users\YourName\AppData\Local\Android\Sdk\ndk\26.1.10909125

   setx ANDROID_NDK_HOME "C:\Users\YourName\AppData\Local\Android\Sdk\ndk\26.1.10909125"

   # Restart your terminal/PowerShell after this
   ```

### Step 2: Build Rust Core Library

```cmd
cd C:\Users\Eddie\AndroidStudioProjects\SecureLegion\secure-legion-core

# Run the build script
build_android.bat
```

This will:
- Build for ARM64 and ARMv7
- Copy `.so` files to `secure-legion-android/app/src/main/jniLibs/`

Expected output:
```
Building for ARM64 (arm64-v8a)...
   Compiling securelegion v1.0.0
    Finished release [optimized] target(s) in 45.32s

Building for ARMv7 (armeabi-v7a)...
   Compiling securelegion v1.0.0
    Finished release [optimized] target(s) in 42.18s

Libraries copied successfully!
```

### Step 3: Open Android Project

```cmd
cd C:\Users\Eddie\AndroidStudioProjects\SecureLegion

# Open Android Studio and select:
# File → Open → Select "secure-legion-android" folder
```

### Step 4: Sync and Build

1. Android Studio will prompt "Gradle Sync" - Click **Sync Now**
2. Wait for sync to complete (may take 5-10 minutes first time)
3. Build → Make Project (Ctrl+F9)

### Step 5: Run the App

1. **Connect a physical device** (recommended)
   - Enable Developer Options
   - Enable USB Debugging
   - Connect via USB
   - Accept RSA key prompt

2. **Or create an emulator**
   - Tools → Device Manager
   - Create Device
   - Select "Pixel 6" or newer
   - API 26+ (Android 8.0+)
   - ARM64 or x86_64 system image

3. **Run the app**
   - Select device from dropdown
   - Click Run (▶️) or Shift+F10

## 🔧 Troubleshooting

### Error: "Library not found"

**Problem**: App crashes with `UnsatisfiedLinkError`

**Solution**:
1. Check that `.so` files exist:
   ```cmd
   dir secure-legion-android\app\src\main\jniLibs\arm64-v8a\libsecurelegion.so
   dir secure-legion-android\app\src\main\jniLibs\armeabi-v7a\libsecurelegion.so
   ```

2. If missing, rebuild Rust library:
   ```cmd
   cd secure-legion-core
   build_android.bat
   ```

### Error: "ANDROID_NDK_HOME not set"

**Solution**:
```cmd
# Find NDK location
dir "C:\Users\%USERNAME%\AppData\Local\Android\Sdk\ndk"

# Set environment variable
setx ANDROID_NDK_HOME "C:\Users\%USERNAME%\AppData\Local\Android\Sdk\ndk\26.1.10909125"

# Restart terminal
```

### Error: "Gradle sync failed"

**Solutions**:
1. File → Invalidate Caches / Restart
2. Check internet connection (Gradle downloads dependencies)
3. Tools → SDK Manager → Check "Android SDK" installed
4. Build → Clean Project → Rebuild Project

### Error: "StrongBox not available"

**Note**: StrongBox requires:
- Android 9+ (API 28+)
- Hardware support (Pixel 3+, Galaxy S9+)
- Physical device (not emulator)

**Fallback**: App will use TEE (Trusted Execution Environment) automatically

### Error: "Biometric not available"

**Solutions**:
- Use physical device with fingerprint/face unlock
- Emulator: Use "Set Lock Screen PIN" in settings
- Enable biometric in emulator settings

## 📱 Testing Checklist

- [ ] App launches and shows lock screen
- [ ] Biometric authentication works
- [ ] Chat list screen loads (empty state)
- [ ] No crashes in logcat
- [ ] StrongBox detected (on supported devices)
- [ ] Rust library loaded successfully

Check logs:
```cmd
adb logcat | findstr SecureLegion
```

## 🏗️ Development Workflow

### Making Changes to Rust Code

1. Edit files in `secure-legion-core/src/`
2. Run `build_android.bat` to rebuild
3. In Android Studio: Build → Rebuild Project
4. Run app

### Making Changes to Android Code

1. Edit Kotlin files in `secure-legion-android/app/src/main/java/`
2. Android Studio auto-syncs changes
3. Run app

### Adding New JNI Functions

1. **Rust side** (`secure-legion-core/src/ffi/android.rs`):
```rust
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_myNewFunction(
    mut env: JNIEnv,
    _class: JClass,
    param: JString,
) -> jstring {
    // Implementation
}
```

2. **Kotlin side** (`secure-legion-android/.../RustBridge.kt`):
```kotlin
external fun myNewFunction(param: String): String
```

3. Rebuild Rust library and test

## 📊 Performance Expectations

### First Build Times
- Rust library: 2-5 minutes
- Android app: 3-5 minutes
- Total: ~10 minutes

### Subsequent Builds
- Rust library: 30 seconds (if changed)
- Android app: 1-2 minutes
- Incremental: 10-30 seconds

## 🎯 Next Steps

### Implement Missing Features

1. **Complete UI**
   - Chat activity
   - Contacts management
   - Wallet interface
   - Settings screens

2. **Network Layer** (Rust)
   - Tor integration
   - Ping-Pong protocol
   - Relay network client

3. **Blockchain** (Rust)
   - Solana wallet
   - IPFS contact cards
   - Transaction signing

4. **Services** (Android)
   - MessageService (foreground)
   - Background message polling
   - Notification handling

### Testing

```cmd
# Rust tests
cd secure-legion-core
cargo test

# Android tests
cd secure-legion-android
gradlew test
gradlew connectedAndroidTest
```

## 📚 Resources

### Documentation
- **Architecture**: `C:\Users\Eddie\Desktop\Secure Legion\Secure Legion - Complete Architec.txt`
- **Protocol**: `C:\Users\Eddie\Desktop\Secure Legion\Secure_Legion_Ping_Pong_Protocol.md`
- **Security Model**: `C:\Users\Eddie\Desktop\Secure Legion\Secure_Legion_Security_Model.md`

### Rust Library
- README: `secure-legion-core/README.md`
- Crypto docs: `secure-legion-core/src/crypto/`

### Android App
- README: `secure-legion-android/README.md`
- Architecture: `secure-legion-android/app/src/main/java/com/securelegion/`

## 🆘 Getting Help

### View Logs

```cmd
# Android logs
adb logcat | findstr "SecureLegion"

# Rust panics
adb logcat | findstr "RustPanic"

# System logs
adb logcat *:E
```

### Clean Build

```cmd
# Rust
cd secure-legion-core
cargo clean
build_android.bat

# Android
cd secure-legion-android
gradlew clean
gradlew assembleDebug
```

### Reset Everything

```cmd
# Delete build artifacts
rmdir /s /q secure-legion-core\target
rmdir /s /q secure-legion-android\app\build
rmdir /s /q secure-legion-android\.gradle

# Rebuild
cd secure-legion-core
build_android.bat

cd ..\secure-legion-android
# Open in Android Studio → Sync → Build
```

## ✅ Success Criteria

You've successfully set up Secure Legion when:

1. ✅ Rust library builds without errors
2. ✅ `.so` files copied to `jniLibs/`
3. ✅ Android Studio syncs successfully
4. ✅ App builds and installs
5. ✅ Lock screen shows and biometric works
6. ✅ Chat list screen loads
7. ✅ No crashes or native library errors
8. ✅ Logs show "Secure Legion initialized successfully"

---

**Ready to build!** Follow the steps above and you'll have Secure Legion running in ~30 minutes.
