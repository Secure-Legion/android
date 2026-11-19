# Android delegated groups integration

The canonical Rust protocol from the 2026-11-19 Android handoff is preserved
under `portable-source`. It is isolated from the app's existing Arti and direct
message native crate. `build-android.ps1` builds all three Android ABIs and copies
only `libsecure_group_mobile.so` into the app. Cargo NDK also emits dependency
libraries, which must not replace the app's existing `libsecurelegion.so`.

The Kotlin/JNI boundary accepts bounded UTF-8 JSON and optional 32-byte device
seed/group key copies. It refuses ordinary-device `ratify` calls. The SQLCipher
migration creates group protocol tables without changing existing group IDs,
operations, secrets, or account identities.

The C2 frame and private bundle codecs now enforce the Desktop wire bounds.
Hybrid encrypted chunks can be sealed/opened; SQLCipher staging detects exact
conflicts, bounds active transfers, and assembles only a complete matching hash.
The native device onion accepts C2, while the legacy contact listener rejects it.
`build-core-c2.ps1` rebuilds that listener for each ABI and copies only the core
library, preserving the isolated group protocol library.
The legacy group snapshot reader and CRDT manager reject groups after they acquire
a delegated state marker, preventing mixed logs from entering the old engine.
The local Pending text store checks current device and native group authority and
enforces the 256-message/8 MiB/30 KiB limits. It is not yet connected to the
group composer or exactly-once native operation conversion.

This is an integration checkpoint, not a working independent group host. The
Android C2 application receiver/sender, authorized state publication, roster
continuity, delivery workers, own-account mixed history, pending intent
conversion, and UI adoption remain to be implemented and tested. Do not advertise
`delegated_groups_v1` or claim Desktop Pending messages are deliverable yet.

The current `DeviceRosterRuntime` requires SYNC authority to start. The eventual
group host must also run for a GROUPS-only certificate; group delivery must not
depend on a currently connected primary phone or a C0 session.
