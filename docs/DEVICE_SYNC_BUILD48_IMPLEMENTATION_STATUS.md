# Android build-48 device sync implementation status

This branch is an implementation work branch. It must not advertise linked-device
or sync capabilities, and its debug APK is not an end-to-end feature build.

## Implemented and source-checked

- Exact portable device authorization and forward-secret Noise crates, with JNI.
- Independent protected per-installation keys and signed roster validation.
- Transactional roster replacement, removed-device queue purge, and pending
  notification/grant storage.
- Unlocked primary profile bootstraps its independent identity and signed roster.
- Isolated device-onion A4/A5 listener, roster notification retry, and exact
  signed receipt verification. Enrollment and Noise frames are still closed.
- Bounded verified history chunk assembly and exact durable settlement parsing.
- Tor UI reports connected from verified transport state instead of a fresh
  own-onion self-test.
- Devices screen lists the current signed roster and lets the primary revoke
  all other devices through an account-signed successor roster.
- A3 canonical transcript/proof encoding and an in-memory owner authentication
  session for signed offers, candidate ML-KEM proof, and both approvals. It does
  not yet issue a grant or activate a candidate.
- Protected sync tables and exact history identity/outbox/settlement storage.
- No fake settlement of Tor-skipped history; Tor ACKs cannot clear Nearby-only rows.
- Signed group-operation type validator. Group-link relay remains disabled.
- No raw B0-B5 Tor fallback. Tor host rejects PULL_REQUEST and history PUSH.
- Exact iOS build-48 Nearby offer transcript parser and fixture test.
- Release JNI libraries built for arm64-v8a, armeabi-v7a, and x86_64; debug APK builds.

## Required before device-sync acceptance

1. Complete A3 owner/candidate enrollment and recovery, both user approvals,
   full ML-KEM key proof, exact grant retry, and committed receipt recovery.
2. Extend A4/A5 operation to linked profiles after candidate activation works.
3. Support linked-candidate startup with an independent local DB key and public
   account binding, without copying the account seed or contact ratchets.
4. Connect the Noise host to a bounded device-onion sender/receiver worker with
   lock, profile-switch, revocation, and process-lifecycle cleanup.
5. Implement exact metadata payload import/export, cursors, deferral, chunks,
   authenticated settlements, capability exchange, and bounded retries.
6. Keep group-link Tor work disabled until every signed operation is validated
   before both import and re-export, including indirect pull paths.
7. Implement Android Nearby receiver and sender roles as supported by the
   cross-platform role matrix, with pinned TLS 1.3 and transactional history apply.
8. Complete Devices enrollment and per-device status paths; gate all
   advertising until interoperability passes.

The separate Arti 0.48 branch still requires real-device Tor runtime gates and
must not be merged into this branch before those gates pass.
