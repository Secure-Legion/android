# Independent group messaging: mobile native link target

This crate makes the existing canonical Desktop group protocol linkable as a
separate iOS static library. It reuses `rust/src/group_ffi.rs` verbatim, including
its FFI boundary tests, and `rust/group-protocol`. It does not introduce a second
cryptographic protocol or copy an account signing seed to a linked installation.

**Status:** the host library and protocol tests run on Windows. The Apple target,
Swift adapter, Swift database/transport host and real-device interoperability
still require Mac integration and verification. Linking this library alone does
not implement independent group messaging in the iOS app. Do not advertise
`delegated_groups_v1` until the complete host described below is active.

## Build on Mac

Preserve this source layout: `mobile/group-native`, `rust/group-protocol`,
`rust/device-protocol`, `rust/src/group_ffi.rs`, `shared-rust/rust-core` and
`shared-rust/securelegion-crypto`. The all-in-one handoff includes these sources.

With Rust, Xcode and the `aarch64-apple-ios` / `aarch64-apple-ios-sim` Rust targets
installed, from the portable-source directory:

```sh
cargo test --manifest-path mobile/group-native/Cargo.toml --locked
bash mobile/group-native/build-xcframework.sh
```

The script creates `mobile/group-native/dist/SecureGroupNative.xcframework` for
arm64 devices and Apple Silicon simulators. An Intel simulator needs a separate
`x86_64-apple-ios` slice; do not use the arm64 simulator slice there. The script
refuses to overwrite an existing output. No framework binary or Apple build is
included in the Windows package.

Link the static XCFramework to the app and any extension target that executes
group validation. Include its module map/header and the Swift adapter in
`Swift/DeviceGroupProtocolBridge.swift`. The iOS patch provides scoped access to
the independent installation seed in `LocalDeviceIdentity`; it never exposes
the account root through this adapter. Primary-only exact-operation ratification
requires a separate local approval path; the Swift adapter deliberately refuses
generic `ratify` requests.

## Required iOS host implementation — still outstanding

Use the supplied Desktop implementation as the executable specification, with
the two protocol documents and tests. Port these components together:

| Desktop source | iOS responsibility |
| --- | --- |
| `lib/services/device_group_store.dart` | SQLCipher committed mixed history, acceptance receipts, state projection, key epochs, local mutation origins and atomic transactions |
| `lib/services/device_group_wire.dart` | Strict C2 framing, signatures, hybrid encryption and signed ACK modes |
| `lib/services/device_group_bundle.dart` | Canonical bounded private bundle codec |
| `lib/services/device_group_chunk_store.dart` | Restart-safe bounded staging; conflicts/expiry; no premature application ACK |
| `lib/services/device_group_receiver.dart` | Current source/recipient authorization; native preview; atomic state + ACK + staging cleanup |
| `lib/services/device_group_delivery_store.dart` | Frozen per-device/account obligations, causal selection, exact ACK matching, retries and key distribution |
| `lib/services/device_group_transport.dart` | Bounded C2 workers, dependency/proof repair, revocation checks |
| `lib/services/device_group_sync_store.dart` | Own-account `group_history_v:1` snapshots, SLGH receipts, exact recovery responsibility |
| `lib/services/device_group_roster_trust.dart` | Scoped trusted account pins, highest roster continuity and revocation |
| `lib/services/device_group_proof_request.dart` | Bound exact proof requests, no arbitrary signing oracle |
| `lib/database/database_schema_migrator.dart` | Group schema references; adapt projections to iOS names instead of creating conflicting existing groups tables |

1. Persist new protocol tables in SQLCipher. Map Desktop projection columns to
   iOS `groups`/`group_peers`/`group_ops`; preserve IDs, secrets, roles, history and
   current linked identities. Do not wipe/relink or recreate groups.
2. First adoption loads the already committed legacy root-signed operations into
   the native mixed-history state, verifies them and creates the next operation
   with the device certificate/leaf signer. The new group engine supports this;
   a Desktop regression covers this exact transition with the phone offline.
3. Route **all reads and mutations** of an adopted group through the mixed
   engine, including message queries, membership, metadata, edits, reactions,
   deletes, invitations, leave/rejoin and moderation. The old mutable CRDT
   registry cannot parse SLGO01/SLGE01 and must not overwrite or project an
   adopted group from an incomplete legacy-only log.
4. Add C2 routing to the app and Network Extension inbox. Handle all defined
   delivery/ACK/proof kinds with strict bounds and fresh current roster checks.
   Reuse existing hybrid crypto primitives; do not substitute a plaintext,
   classical-only, account-root or phone-relay transport.
5. Wire native state validation and exact SQLCipher publication in one
   transaction. Do not sign a storage ACK before acceptance, retries and any
   promised account catch-up responsibility are durable. Socket writes do not
   prove delivery/application. Revocation cannot revive via a stale certificate.
6. Export/import adopted groups using `group_history_v:1`, SLGH receipts and
   exact ratifications/roster proofs. Legacy `group_snapshots_v1` remains for
   untouched groups only. Never send mixed logs into the old legacy reader.
7. Advertise `delegated_groups_v1` only after steps 1–6 and their tests pass.
   Desktop already gates adoption on the currently trusted primary phone's
   authenticated capability. A capability string is not a replacement for
   receive/store/delivery implementation.
8. Other group members' receiving apps need the matching protocol too. A legacy
   recipient cannot verify a new device-signed operation. Keep incompatible
   recipients visibly pending or require an update; do not fake a successful
   send or quietly depend on the sender's primary phone again.

The direct-message/history iOS patch in the surrounding handoff does not complete
this outstanding host port. Keep its legacy relay fallback available for old
clients while independent group support remains unadvertised.

## Protocol and acceptance references

Read `docs/DELEGATED-GROUP-PROTOCOL.md` and `docs/DEVICE-GROUP-TRANSPORT.md`.
Portable native tests include mixed legacy/device histories, logical account
membership, independent signers, role checks, exact receipts, revocation,
history after revocation, invitations, key epochs, causal dependencies and
bounded framing. Run the supplied Dart security/store/transport tests when
porting; these describe behavior rather than merely codec shapes.

Required real-device acceptance:

- Existing phone group, unchanged ID/history/members: phone off, Desktop sends
  text to a real other member and receives its reply directly.
- Reverse roles: Desktop off, phone sends and receives through its own device
  transport. Reopen both and reconcile without duplicates or missing history.
- Restart sender/receiver during delivery, lose ACKs, reorder dependencies and
  repeat exact frames. Preserve queue responsibility and commit once.
- Revoke a sender, remove/demote a member and rotate keys. No stale authorization
  or old group secret may deliver new content; history remains readable as
  allowed by previously accepted receipts or exact root proofs.
- No group-specific workflow requires keeping the account's primary phone open
  for ordinary sending/receiving after authorization and protocol setup.
- Group images/voice require typed group-media payload support in addition to
  this existing text-group protocol. Do not assume the direct-chat image/voice
  patch implements group media or encode media as ordinary chat text silently.

Until the Mac host port and these checks pass, independent groups are unfinished.
