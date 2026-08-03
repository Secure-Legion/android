
# Building SecureLegion with Opus Dependency Issues

## Current verified fast path (August 2, 2026)

**CMake is not required for a normal Android Rust build.** The repository already contains
`libopus.a` for `arm64-v8a`, `armeabi-v7a`, and `x86_64`. Set the four Opus environment variables
below and `audiopus_sys` links the prebuilt archive instead of invoking CMake.

The CMake sections later in this document are only for regenerating those Opus archives. CMake is
not currently installed on the verified Windows workstation, and both `cargo check` and all three
release Android native builds succeed without it. Do not patch files inside Cargo's registry for a
normal build.

Verified toolchain: Rust 1.93.0, cargo-ndk 4.1.2, Android NDK r27c, Arti 0.44.0.

```powershell
$env:ANDROID_NDK_HOME = 'C:\\Users\\Eddie\\AppData\\Local\\Android\\Sdk\\ndk\\android-ndk-r27c'
$env:LIBOPUS_STATIC = '1'
$env:LIBOPUS_NO_PKG = '1'
$env:OPUS_LIB_DIR = 'C:\\Users\\Eddie\\Desktop\\SecureLegion\\opus-official\\build\\arm64-v8a'
$env:OPUS_INCLUDE_DIR = 'C:\\Users\\Eddie\\Desktop\\SecureLegion\\opus-official\\include'

Set-Location C:\\Users\\Eddie\\Desktop\\SecureLegion\\secure-legion-core
cargo ndk --target aarch64-linux-android --platform 26 build --release --locked
```

Change only `OPUS_LIB_DIR` and `--target` for the other ABIs:

- `opus-official\\build\\armeabi-v7a` / `armv7-linux-androideabi`
- `opus-official\\build\\x86_64` / `x86_64-linux-android`

The checked-in prebuilt inputs are:

- `opus-official/build/arm64-v8a/libopus.a`
- `opus-official/build/armeabi-v7a/libopus.a`
- `opus-official/build/x86_64/libopus.a`
- `opus-official/include/opus.h`

## Problem Summary

The `opus = "0.3"` dependency in `secure-legion-core/Cargo.toml` causes build failures due to the `audiopus_sys` crate attempting to build Opus via CMake during cargo compilation. The issue: **cmake-rs cannot properly invoke make for Android NDK** because it doesn't set up the correct build environment.

## Root Causes

1. **CMake Version Incompatibility**: audiopus_sys bundles Opus with `cmake_minimum_required(VERSION 3.1)`, but CMake 4.2+ removed support for versions < 3.5
2. **cmake-rs Android NDK Issues**: The cmake-rs crate doesn't properly configure CMAKE_MAKE_PROGRAM and toolchain settings for Android NDK cross-compilation
3. **Missing Environment Variables**: audiopus_sys build script needs environment variables to use pre-built Opus libraries instead of building from source

## Solution: Use Pre-Built Opus Libraries

Instead of letting audiopus_sys build Opus during cargo compilation, we:
1. Patch the bundled Opus CMakeLists.txt for CMake 4.2 compatibility
2. Build Opus separately for each Android architecture
3. Tell audiopus_sys to use the pre-built libraries via environment variables

---

## Step 1: Patch audiopus_sys CMakeLists.txt

**File**: `C:\Users\Eddie\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\audiopus_sys-0.2.2\opus\CMakeLists.txt`

**Change Line 1**:
```cmake
# OLD:
cmake_minimum_required(VERSION 3.1)

# NEW:
cmake_minimum_required(VERSION 3.5)
```

**Why**: CMake 4.2 removed support for versions < 3.5

---

## Step 2: Build Opus for Android (All Architectures)

### Prerequisites
- Android NDK: `C:\Users\Eddie\AppData\Local\Android\Sdk\ndk\android-ndk-r27c`
- CMake: `C:\Program Files\CMake\bin\cmake.exe`
- Opus source: `opus-official` directory in project root

### Build Script

Run these commands in **Git Bash** (NOT PowerShell - make requires Unix environment):

#### arm64-v8a (Most Important - Primary Physical Devices)
```bash
cd C:/Users/Eddie/Desktop/SecureLegion/opus-official
mkdir -p build/arm64-v8a && cd build/arm64-v8a

PATH="C:\Users\Eddie\AppData\Local\Android\Sdk\ndk\android-ndk-r27c\prebuilt\windows-x86_64\bin:$PATH"

"C:\Program Files\CMake\bin\cmake.exe" -G "Unix Makefiles" \
  -DCMAKE_TOOLCHAIN_FILE="C:\Users\Eddie\AppData\Local\Android\Sdk\ndk\android-ndk-r27c\build\cmake\android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  ../..

make -j4
```

#### armeabi-v7a
```bash
cd C:/Users/Eddie/Desktop/SecureLegion/opus-official
mkdir -p build/armeabi-v7a && cd build/armeabi-v7a

PATH="C:\Users\Eddie\AppData\Local\Android\Sdk\ndk\android-ndk-r27c\prebuilt\windows-x86_64\bin:$PATH"

"C:\Program Files\CMake\bin\cmake.exe" -G "Unix Makefiles" \
  -DCMAKE_TOOLCHAIN_FILE="C:\Users\Eddie\AppData\Local\Android\Sdk\ndk\android-ndk-r27c\build\cmake\android.toolchain.cmake" \
  -DANDROID_ABI=armeabi-v7a \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  ../..

make -j4
```

#### x86_64 (Emulator)
```bash
cd C:/Users/Eddie/Desktop/SecureLegion/opus-official
mkdir -p build/x86_64 && cd build/x86_64

PATH="C:\Users\Eddie\AppData\Local\Android\Sdk\ndk\android-ndk-r27c\prebuilt\windows-x86_64\bin:$PATH"

"C:\Program Files\CMake\bin\cmake.exe" -G "Unix Makefiles" \
  -DCMAKE_TOOLCHAIN_FILE="C:\Users\Eddie\AppData\Local\Android\Sdk\ndk\android-ndk-r27c\build\cmake\android.toolchain.cmake" \
  -DANDROID_ABI=x86_64 \
  -DANDROID_PLATFORM=android-26 \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  ../..

make -j4
```

### Expected Output
- `opus-official/build/arm64-v8a/libopus.a` (static library, ~3.4M)
- `opus-official/build/armeabi-v7a/libopus.a` (~2.2M)
- `opus-official/build/x86_64/libopus.a` (~3.5M)

**Note**: The builds will create static libraries (.a) instead of shared libraries (.so) despite `-DBUILD_SHARED_LIBS=ON`. This is an Android NDK CMake limitation, but it's fine - we'll link the static Opus into our final libsecurelegion.so.

---

## Step 3: Build Rust Libraries with Environment Variables

Now that Opus is pre-built, tell audiopus_sys to use it instead of building from source.

**Important**: You must set `ANDROID_NDK_HOME` and have `cargo` in PATH. When running from Git Bash:
```bash
export PATH="/c/Users/Eddie/.cargo/bin:$PATH"
export ANDROID_NDK_HOME="C:/Users/Eddie/AppData/Local/Android/Sdk/ndk/android-ndk-r27c"
```

### arm64-v8a
```bash
cd C:/Users/Eddie/Desktop/SecureLegion/secure-legion-core

export LIBOPUS_STATIC=1
export LIBOPUS_NO_PKG=1
export OPUS_LIB_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/build/arm64-v8a"
export OPUS_INCLUDE_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/include"

cargo ndk --target aarch64-linux-android --platform 26 build --release
```

### armeabi-v7a
```bash
cd C:/Users/Eddie/Desktop/SecureLegion/secure-legion-core

export LIBOPUS_STATIC=1
export LIBOPUS_NO_PKG=1
export OPUS_LIB_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/build/armeabi-v7a"
export OPUS_INCLUDE_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/include"

cargo ndk --target armv7-linux-androideabi --platform 26 build --release
```

### x86_64
```bash
cd C:/Users/Eddie/Desktop/SecureLegion/secure-legion-core

export LIBOPUS_STATIC=1
export LIBOPUS_NO_PKG=1
export OPUS_LIB_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/build/x86_64"
export OPUS_INCLUDE_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/include"

cargo ndk --target x86_64-linux-android --platform 26 build --release
```

### Environment Variables Explained
- `LIBOPUS_STATIC=1`: Tell audiopus_sys to link against static Opus library
- `LIBOPUS_NO_PKG=1`: Disable pkg-config (doesn't work for Android cross-compilation)
- `OPUS_LIB_DIR`: Directory containing libopus.a
- `OPUS_INCLUDE_DIR`: Directory containing Opus headers
- `ANDROID_NDK_HOME`: Root directory of Android NDK (required by cargo-ndk)

### Expected Build Time
- arm64-v8a: ~25 seconds
- armeabi-v7a: ~31 seconds
- x86_64: ~33 seconds

### Expected Output
Fresh libraries with timestamps from TODAY:
- `secure-legion-core/target/aarch64-linux-android/release/libsecurelegion.so` (2.3M)
- `secure-legion-core/target/armv7-linux-androideabi/release/libsecurelegion.so` (1.8M)
- `secure-legion-core/target/x86_64-linux-android/release/libsecurelegion.so` (2.8M)

---

## Step 4: Copy Libraries to jniLibs

```bash
cd C:/Users/Eddie/Desktop/SecureLegion/secure-legion-core

cp target/aarch64-linux-android/release/libsecurelegion.so ../app/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libsecurelegion.so ../app/src/main/jniLibs/armeabi-v7a/
cp target/x86_64-linux-android/release/libsecurelegion.so ../app/src/main/jniLibs/x86_64/

# Verify fresh timestamps
ls -lh ../app/src/main/jniLibs/*/libsecurelegion.so
```

**Critical**: Verify the timestamps are TODAY, not from days ago!

---

## Step 5: Build and Deploy APK

**Important**: You must set `JAVA_HOME` to Android Studio's bundled JDK:
```bash
export JAVA_HOME="C:/Program Files/Android/Android Studio/jbr"
```

### Build all flavors (one by one):
```bash
cd C:/Users/Eddie/Desktop/SecureLegion

./gradlew assembleMasterDebug --no-daemon
./gradlew assembleSolanadappDebug --no-daemon
./gradlew assembleSolanahackathonDebug --no-daemon
./gradlew assembleStarnethackathonDebug --no-daemon
./gradlew assembleGoogleplayDebug --no-daemon
./gradlew assembleGoogleplaydemoDebug --no-daemon
./gradlew assembleFdroidDebug --no-daemon
```

**Note**: The `release` product flavor conflicts with the `Release` build type and cannot be built separately. Use `assembleRelease` to build all flavors in release mode.

### Install on devices
```bash
# Physical device (Pixel 9a)
adb -s 59041JEBF02616 install -r app/build/outputs/apk/solanahackathon/debug/app-solanahackathon-debug.apk

# Emulator
adb -s emulator-5554 install -r app/build/outputs/apk/solanahackathon/debug/app-solanahackathon-debug.apk
```

### Available Product Flavors
| Flavor | Application ID | Features |
|--------|---------------|----------|
| master | com.securelegion.master | All features enabled |
| solanadapp | com.securelegion.solana | Tor + Voice + Solana |
| solanahackathon | com.securelegion.solana.hackathon | Tor + Voice + Solana + Demo |
| starnethackathon | com.securelegion.starnet.hackathon | Tor + Voice + Starnet features |
| googleplay | com.securelegion | Tor + Voice (store-ready) |
| googleplaydemo | com.securelegion.demo | Tor + Voice + Demo login |
| fdroid | com.securelegion.fdroid | Tor + Voice (F-Droid) |

---

## Verification

### Verify pollVoiceMessage() is Present
```bash
strings app/src/main/jniLibs/arm64-v8a/libsecurelegion.so | grep -i pollVoiceMessage
```

**Expected Output**:
```
Java_com_securelegion_crypto_RustBridge_pollVoiceMessage
```

If this function is missing, VOICE channel will NOT work on physical devices!

---

## What NOT To Do

### DO NOT:
1. Remove `opus = "0.3"` from Cargo.toml (voice calling requires it)
2. Try to use environment variables like `CMAKE_ARGS` or `CMAKE_MAKE_PROGRAM` (cmake-rs ignores them)
3. Use PowerShell for Opus builds (make requires Unix environment - use Git Bash)
4. Skip verifying library timestamps (old libraries = missing VOICE code)
5. Trust "BUILD SUCCESSFUL" messages without checking if files were actually created
6. Forget to set `JAVA_HOME` and `ANDROID_NDK_HOME` environment variables

---

## Common Issues

### Issue: "no such file or directory" for libopus.so
**Cause**: CMake created static library (.a) instead of shared library (.so)
**Solution**: This is expected! Use the static library (.a) - it works fine.

### Issue: "cargo build succeeded but no library created"
**Cause**: Build actually failed, but cp command copied old cached files
**Solution**: Check the actual cargo output, don't trust the final success message

### Issue: "CMAKE_MAKE_PROGRAM is not set"
**Cause**: cmake-rs doesn't configure Android NDK environment properly
**Solution**: That's why we build Opus separately (Step 2) instead of letting cargo build it

### Issue: Libraries dated from weeks ago instead of today
**Cause**: Cargo cached old build, didn't actually rebuild
**Solution**: Run `cargo clean` and rebuild with fresh environment variables

### Issue: "JAVA_HOME is not set"
**Cause**: Git Bash doesn't inherit Windows JAVA_HOME
**Solution**: `export JAVA_HOME="C:/Program Files/Android/Android Studio/jbr"`

### Issue: "Could not find any NDK"
**Cause**: cargo-ndk can't find Android NDK
**Solution**: `export ANDROID_NDK_HOME="C:/Users/Eddie/AppData/Local/Android/Sdk/ndk/android-ndk-r27c"`

### Issue: "cargo: command not found" in Git Bash
**Cause**: Git Bash doesn't have cargo in PATH
**Solution**: `export PATH="/c/Users/Eddie/.cargo/bin:$PATH"`

---

## Quick Reference Commands

### Full rebuild from scratch:
```bash
# 0. Set up environment (Git Bash)
export PATH="/c/Users/Eddie/.cargo/bin:$PATH"
export ANDROID_NDK_HOME="C:/Users/Eddie/AppData/Local/Android/Sdk/ndk/android-ndk-r27c"
export JAVA_HOME="C:/Program Files/Android/Android Studio/jbr"

# 1. Patch CMakeLists.txt (one-time, manual edit)

# 2. Build Opus for all architectures
cd C:/Users/Eddie/Desktop/SecureLegion/opus-official
# Run arm64-v8a build commands from Step 2
# Run armeabi-v7a build commands from Step 2
# Run x86_64 build commands from Step 2

# 3. Build Rust with environment variables
cd C:/Users/Eddie/Desktop/SecureLegion/secure-legion-core

# Build arm64-v8a
export LIBOPUS_STATIC=1 LIBOPUS_NO_PKG=1 \
  OPUS_LIB_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/build/arm64-v8a" \
  OPUS_INCLUDE_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/include"
cargo ndk --target aarch64-linux-android --platform 26 build --release

# Build armeabi-v7a
export OPUS_LIB_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/build/armeabi-v7a"
cargo ndk --target armv7-linux-androideabi --platform 26 build --release

# Build x86_64
export OPUS_LIB_DIR="C:/Users/Eddie/Desktop/SecureLegion/opus-official/build/x86_64"
cargo ndk --target x86_64-linux-android --platform 26 build --release

# 4. Copy libraries
cp target/aarch64-linux-android/release/libsecurelegion.so ../app/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/libsecurelegion.so ../app/src/main/jniLibs/armeabi-v7a/
cp target/x86_64-linux-android/release/libsecurelegion.so ../app/src/main/jniLibs/x86_64/

# 5. Build and deploy
cd ..
./gradlew assembleSolanahackathonDebug --no-daemon
adb -s <DEVICE_ID> install -r app/build/outputs/apk/solanahackathon/debug/app-solanahackathon-debug.apk
```

---

## Success Criteria

- CMakeLists.txt patched to VERSION 3.5
- libopus.a exists for all 3 architectures
- Rust builds complete in ~25-33 seconds each
- libsecurelegion.so has TODAY's timestamp in jniLibs
- `strings` shows `Java_com_securelegion_crypto_RustBridge_pollVoiceMessage`
- APK builds successfully for all 7 flavors
- Physical devices can receive VOICE messages (test with voice call)

---

**Last Updated**: August 2, 2026
**Tested On**: Windows 11, Android NDK r27c, Rust 1.93.0, cargo-ndk 4.1.2, Arti 0.44.0
**Project Path**: `C:\Users\Eddie\Desktop\SecureLegion`
**Java**: Android Studio bundled JBR (`C:\Program Files\Android\Android Studio\jbr`)
