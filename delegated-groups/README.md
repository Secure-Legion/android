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
a delegated state marker. Legacy mutation, broadcast, sync and local cleanup
entry points check this before touching their old Rust state or database rows.
The SQLCipher host now verifies group-scoped Root rosters, stages C2 chunks,
previews live/invitation/re-invitation/proof-response bundles in the canonical
native engine, and commits the validated log, state projection, exact ACK receipt,
and staging removal together. The sender persists encrypted C2 packets before
retrying and settles exact device ACKs. Pending text converts to a signed native
operation in one transaction. The chat screen reads native messages and routes
adopted-group text and member invitations through that host. The group profile,
member list, and permission screen read validated native state; group names and
member permissions publish signed native metadata operations. Member removal and
the required fresh epoch commit together; removed members receive a terminal
delivery selection. Promotion, demotion and admin-rights edits publish native
role operations. Group photos publish Avatar metadata and project into the
local group cache after native validation. Invitation acceptance uses the native
engine, and the legacy swipe-to-leave cleanup is blocked for adopted groups.
GROUPS-only devices
run the device onion loop. Nearby can carry receipt-bound mixed group history
between mutually capable own-account devices.
An accepted inbound bundle marks own-account history dirty in the same commit.
Single-installation accounts sign an account storage ACK; other accounts send a
device storage ACK until catch-up responsibility is durable. The receiver now
promotes a stored device ACK only after every currently authorized installation
has authenticated the same later `group_history_v:1` event over own-account
SYNC. The account ACK is persisted before transmission and retried after a
send failure. Outgoing bubbles
remain Pending until exact account ACKs cover their recipient obligations, and
an ACK commit refreshes an open group chat.
Owner group deletion and self-leave now publish native terminal operations.
The local accepted log remains available for recipient retries and historical
reads; the composer reports the resulting read-only state.
The C2 proof exchange requests missing exact historical authority in bounded
batches and serves only already committed proofs for this account's accepted
operations. The current primary may approve missing, already accepted own
operation hashes using its local Root seed inside an atomic proof transaction.
Network requests do not invoke Root signing.

This remains an integration checkpoint. Android-created group activation and
mixed-platform end-to-end tests remain.
Android Nearby now advertises `delegated_groups_v1` to eligible own-account
devices; iOS still needs the receiver before mixed-platform catch-up can finish.
The current APK should not replace a user's
account installation until those paths are complete and verified on a test
profile. The iOS receiver is also required for group delivery to iOS members.
