# Android Arti Current State — August 2, 2026

## Build truth

- Rust: 1.93.0
- cargo-ndk: 4.1.2
- Android NDK: r27c
- Arti and direct `tor-*` dependencies: 0.44.0
- Android release version: 1.0.0 (code 33)
- Packaged ABIs: `arm64-v8a`, `armeabi-v7a`, and `x86_64` only. Gradle excludes the stale,
  unsupported 32-bit x86 artifact that predates the unified JNI receiver.

The Android-target reverse dependency tree contains one `arti-client v0.44.0`, shared by
`securelegion` and `securelegion-crypto`. The prior 0.40/0.41 lines are no longer in the active core
graph.

## Outbound ownership

`arti_connect_to_onion()` performs one `TorClient.connect()` attempt. It does not sleep, retry, or
send peer-triggered NEWNYM. Friend-request retry timing belongs to the Room-backed Android
dispatcher.

Each JNI friend-request operation has:

- one connection/write attempt;
- a 45-second outer deadline;
- a typed result (`SUCCESS`, `TRANSIENT_NETWORK`, `TOR_NOT_READY`, `CANCELLED`, or
  `PERMANENT_INPUT`);
- a cancellation token keyed by operation ID;
- a short in-flight guard that prevents overlapping sends to the same onion/type.

## Inbound ownership

Android uses one native event queue and one blocking JNI poll for PING, MESSAGE, VOICE, TAP,
friend request, PONG, and ACK. The call wakes immediately when an event arrives and has a shutdown
sentinel. Live messaging therefore does not wait for WorkManager or periodic health checks.

## Circuit and battery policy

- Exit-port prediction is cleared for the onion-only Android messaging client so Arti does not
  prebuild unused clearnet exit circuits.
- TorService health checks run every 2 seconds only while starting/recovering, then every 30
  seconds when stable.
- Message and Tor-health WorkManager jobs are 15-minute safety nets and no-op while the foreground
  service is healthy.
- The download recovery watchdog runs every 2 minutes; it is not part of normal live delivery.
- The direct-mode pending-message safety scan runs every 90 seconds (30 seconds with bridges),
  while successful sends and inbound delivery still trigger immediate event-driven work.
- Contact-list backup/recovery polls every 5 seconds instead of every 500 ms; it is separate from
  instant-message and friend-request delivery.
- Session cleanup runs every 15 minutes, and bandwidth/notification polling is parked whenever the
  app UI is in the background.

## Live battery and transport verification

- The pre-fix Android Battery screen attributed 40.6% of the selected period's consumed battery to
  Secure and flagged high CPU usage. This is an app share, not 40.6 percentage points of charge.
- After the fixes, the same device reported an 8% Secure share. That is an observed 80% reduction
  in share, but it is not a controlled battery benchmark because Android's window and workload can
  change.
- A 30-second `/proc` measurement with the app backgrounded averaged 2.32% process CPU. Android
  reported zero active wake locks, no active camera/audio use, and no pending or active Secure jobs.
- On the clean 1.0.0 (33) install, Arti bootstrapped to 100%, both the messaging and friend-request
  publishers reached `Running`, the transport gate opened after two healthy samples, and a real
  peer connection captured a current three-hop route without restarting the process.

## Verified commands

From `secure-legion-core`, with the prebuilt Opus environment documented in `BUILD_FIX_OPUS.md`:

```text
cargo check --locked --target aarch64-linux-android
cargo ndk --target aarch64-linux-android --platform 26 build --release --locked
cargo ndk --target armv7-linux-androideabi --platform 26 build --release --locked
cargo ndk --target x86_64-linux-android --platform 26 build --release --locked
cargo tree --locked --target aarch64-linux-android -i arti-client@0.44.0
```

All commands passed on August 2, 2026. The three ELF outputs were checked for their target
architecture and for the unified-poller/typed-friend-request JNI symbols before being copied to
`app/src/main/jniLibs`.
