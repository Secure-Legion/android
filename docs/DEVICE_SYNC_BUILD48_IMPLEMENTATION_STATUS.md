# Android build-48 device sync implementation status

This branch is an implementation work branch. It must not advertise linked-device
or sync capabilities, and its debug APK is not an end-to-end feature build.

The 2026-11-18 live-message handoff supersedes the older blanket Tor message
block. Source: `Secure-Live-Message-Fix-2026-11-18-All-In-One.zip`, SHA-256
`884D357B5ACEA03CD0F735729B7F632679F14AAB069B190EAE174D6F3C394640`.
Its direct `live_message_sync_v1` lane applies only after mutual negotiation;
bulk history and full groups remain Nearby-only.

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
  session for signed offers, candidate ML-KEM proof, both approvals, and an
  encrypted grant committed with the successor roster. The owner retries exact
  grant bytes and verifies a signed candidate receipt after process restart.
- The Android primary Devices screen scans a candidate QR, shows the matching
  comparison code, requires local approval, and routes A3 responses through
  the isolated onion listener. The in-memory session is cleared on listener
  stop; the signed grant remains in the durable retry outbox.
- Candidate A3 session creates a bounded QR, authenticates the owner's signed
  offer and approvals, verifies the encrypted grant against the account identity,
  device certificate, and signed roster, and can sign a post-commit receipt.
- Candidate onboarding now displays the QR/comparison code, starts a separate
  device-onion Tor listener, and stores the in-flight exchange in Keystore-backed
  preferences so an exact grant retry can survive a process restart. The
  candidate commits a public-account linked profile without the account seed.
  A linked-profile main screen and direct messaging runtime are still missing.
- Candidate profile commit stages an independent protected SQLCipher key and a
  receipt before roster acceptance, then promotes only after the signed roster
  authorizes the local device. A restart can verify and finish that promotion.
  App startup and the linked-profile onion worker are not connected yet.
- Build-49 Tor policy parser permits only negotiated `sync_mode=live_v1`
  message/receipt PUSH frames. Existing metadata-only behavior remains active
  until capability exchange is implemented. SQLCipher v62 records `is_live`
  on outbox and deferred rows, defaulting preexisting work to false; Tor ACKs
  still cannot clear Wi-Fi-only revisions. The live outbox enforces 256 revision
  and 16 MiB serialized delta caps without deleting the source change. Live
  enqueue cannot replace an outstanding Wi-Fi archive row for the same object.
- SQLCipher message triggers capture inserts, body edits, status/read changes,
  and deletes in the same transaction as the local write. The sequence-based
  capture reader loads at most 25 IDs, and a transaction-scoped import guard is
  available for the future importer. Per-peer state selects at most 50 initial
  IDs once, then discovers later changes by durable sequence in bounded work
  queues with independent retry. No live dispatcher consumes this work yet.
- Direct receipt deltas have an exact-key parser, small export query, and
  transactional import that preserves monotonic delivery/read state and
  suppresses outbound recapture. Missing messages remain a dependency rather
  than receiving a successful commit response.
- Complete receipt chunks can now be applied under the authenticated roster
  check with exact version/cursor storage; missing-message receipts are kept
  in an encrypted pending row with `is_live=1` and receive no settlement. A
  bounded replay method rechecks authorization and the event identity after
  message import; its network worker and settlement dispatch are not wired yet.
- Protected sync tables and exact history identity/outbox/settlement storage.
- No fake settlement of Tor-skipped history; Tor ACKs cannot clear Nearby-only rows.
- Signed group-operation type validator. Group-link relay remains disabled.
- No raw B0-B5 Tor fallback. Tor host rejects PULL_REQUEST and history PUSH.
- Exact iOS build-48 Nearby offer transcript parser and fixture test.
- Release JNI libraries built for arm64-v8a, armeabi-v7a, and x86_64; debug APK builds.
- Pixel 9a Android 17 instrumented JNI smoke test passed on 2026-11-18:
  deterministic native history identity and Noise engine create/free, one
  test with zero failures. The fresh F-Droid debug app also installs and opens.
  No authenticated device-sync or Tor status UI run has been performed yet.

## Required before device-sync acceptance

1. Physically verify both A3 enrollment roles against iOS, including process
   death, delayed grant, local cancellation and expired checkpoint. Add the
   separate recovery-v2 flow. The current grant path supports enrollment only.
2. Extend A4/A5 operation to linked profiles after candidate activation works.
3. Support linked-candidate startup with an independent local DB key and public
   account binding, without copying the account seed or contact ratchets.
4. Connect the Noise host to a bounded device-onion sender/receiver worker with
   lock, profile-switch, revocation, and process-lifecycle cleanup.
5. Implement exact metadata payload import/export, cursors, deferral, chunks,
   authenticated settlements, capability exchange, and bounded retries.
   Include the new live direct-message payload preparation, full import
   suppression, end-to-end receipt dispatch, and no timestamp-based delivery
   cutoff. Do not
   advertise `live_message_sync_v1` until both sender and receiver pass.
6. Keep group-link Tor work disabled until every signed operation is validated
   before both import and re-export, including indirect pull paths.
7. Implement Android Nearby receiver and sender roles as supported by the
   cross-platform role matrix, with pinned TLS 1.3 and transactional history apply.
8. Complete Devices enrollment and per-device status paths; gate all
   advertising until interoperability passes.

The separate Arti 0.48 branch passed a Pixel 9a bootstrap/shutdown test, but
onion-service operation and the 24-hour soak remain unverified. It has not been
merged into this branch.
