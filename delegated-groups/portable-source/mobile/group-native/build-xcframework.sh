#!/usr/bin/env bash
set -euo pipefail
task_native_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
task_target_root="$task_native_root/target"
task_output="${1:-$task_native_root/dist/SecureGroupNative.xcframework}"
if [[ -e "$task_output" ]]; then
  printf '%s\n' "Output already exists; choose a new output path: $task_output" >&2
  exit 1
fi
for task_triple in aarch64-apple-ios aarch64-apple-ios-sim; do
  CARGO_TARGET_DIR="$task_target_root" cargo build --manifest-path "$task_native_root/Cargo.toml" \
    --locked --release --target "$task_triple"
done
mkdir -p -- "$(dirname -- "$task_output")"
xcodebuild -create-xcframework \
  -library "$task_target_root/aarch64-apple-ios/release/libsecure_group_mobile.a" -headers "$task_native_root/include" \
  -library "$task_target_root/aarch64-apple-ios-sim/release/libsecure_group_mobile.a" -headers "$task_native_root/include" \
  -output "$task_output"
