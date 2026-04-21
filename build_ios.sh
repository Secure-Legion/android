#!/bin/bash
set -e

echo "Building Secure Legion Core Library for iOS (arm64)..."
echo ""

# Match Xcode project minimum deployment target so the library works on older devices.
export IPHONEOS_DEPLOYMENT_TARGET=17.0

# Build staticlib only — skip cdylib (requires JNI/linking that fails on iOS)
cargo rustc --release --target aarch64-apple-ios --crate-type staticlib

echo ""
echo "Build successful!"
echo ""

LIB_PATH="target/aarch64-apple-ios/release/libsecurelegion.a"
DEST="../build/Debug-iphoneos/libsecurelegion.a"

if [ ! -f "$LIB_PATH" ]; then
    echo "ERROR: $LIB_PATH not found!"
    exit 1
fi

# Copy to project build dir
mkdir -p "$(dirname "$DEST")"
cp "$LIB_PATH" "$DEST"
echo "Copied to: $DEST"
ls -lh "$DEST"

# Update xcframework (this is what Xcode actually links)
XCFW="target/SecureLegion.xcframework/ios-arm64/libsecurelegion.a"
if [ -d "$(dirname "$XCFW")" ]; then
    cp "$LIB_PATH" "$XCFW"
    echo "Updated xcframework: $XCFW"
fi

# Replace all copies in Xcode DerivedData to prevent stale linking
REPLACED=0
for dd in $(find ~/Library/Developer/Xcode/DerivedData -name "libsecurelegion.a" 2>/dev/null); do
    cp "$LIB_PATH" "$dd"
    REPLACED=$((REPLACED + 1))
done
if [ $REPLACED -gt 0 ]; then
    echo "Replaced $REPLACED copies in Xcode DerivedData"
fi

echo ""
echo "Done! Rebuild the Xcode project to pick up the new library."
