#!/bin/bash

echo "Building Secure Legion Core Library for Android..."
echo ""

# Check if cargo-ndk is installed
if ! command -v cargo-ndk &> /dev/null; then
    echo "ERROR: cargo-ndk not found!"
    echo "Please install it with: cargo install cargo-ndk"
    exit 1
fi

# Check if ANDROID_NDK_HOME is set
if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "ERROR: ANDROID_NDK_HOME environment variable not set!"
    echo "Please set it to your NDK path, for example:"
    echo "export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/26.1.10909125"
    exit 1
fi

echo "Building for ARM64 (arm64-v8a)..."
cargo ndk --target aarch64-linux-android --platform 26 build --release
if [ $? -ne 0 ]; then
    echo "ERROR: ARM64 build failed!"
    exit 1
fi

echo ""
echo "Building for ARMv7 (armeabi-v7a)..."
cargo ndk --target armv7-linux-androideabi --platform 26 build --release
if [ $? -ne 0 ]; then
    echo "ERROR: ARMv7 build failed!"
    exit 1
fi

echo ""
echo "Build successful!"
echo ""
echo "Copying libraries to Android project..."

# Create jniLibs directories if they don't exist
mkdir -p ../secure-legion-android/app/src/main/jniLibs/arm64-v8a
mkdir -p ../secure-legion-android/app/src/main/jniLibs/armeabi-v7a

# Copy libraries
cp target/aarch64-linux-android/release/libsecurelegion.so \
   ../secure-legion-android/app/src/main/jniLibs/arm64-v8a/

cp target/armv7-linux-androideabi/release/libsecurelegion.so \
   ../secure-legion-android/app/src/main/jniLibs/armeabi-v7a/

echo ""
echo "Done! Libraries copied to:"
echo "  - secure-legion-android/app/src/main/jniLibs/arm64-v8a/libsecurelegion.so"
echo "  - secure-legion-android/app/src/main/jniLibs/armeabi-v7a/libsecurelegion.so"
echo ""
echo "You can now build the Android app in Android Studio!"
