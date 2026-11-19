# Delegated group protocol implementation checkpoint

The portable `rust/group-protocol` crate implements the new cryptographic
envelope, authorization checks, a pinned-core state adapter, stateless native
API, Flutter binding and durable storage. The developer independent-device host
now activates C2 ingress/background delivery and own-device history recovery.
Existing group UI actions now use the developer path; live Tor acceptance is
still pending. Production
group behavior remains on the existing root-signed protocol. This is not a
final mobile implementation handoff.

The crate depends on the existing pinned shared Rust core and
`secure-device-protocol`. No shared-core source was changed. New operations use
an independent installation signing key, while `author_pubkey` remains the
account root public identity for group membership, roles and permissions.
OpID authors use the existing group's 16-byte BLAKE3 identity of the **leaf**
signing key, so independent devices have distinct operation namespaces.
Device authorization still uses its separate 32-byte Ed25519/X25519 device ID.
Do not interchange these identity formats or add leaves as separate group users.

The signed frame is:

```
SLGO01 | rootSignedDeviceCertificate[274] | innerLength:u32 big endian
       | canonicalInnerOp | deviceSignature[64]
```

Signature domain: `secure-legion-group-device-operation-v1\0`. The inner operation
uses the pinned core's bincode layout and CBOR payload. Its root-signature field
is all zero; it is never independently treated as a legacy signed operation.
The account author, certificate and leaf OpID author must agree. Leaf signing
identity must differ from the account root identity; copying a root signer into
this protocol is rejected. Lamport and
OpID Lamport agree, clocks fit safe integers, parent heads are sorted/unique,
bounded to64 and causally earlier, and payload/complete encoding are bounded.
Canonical reserialization rejects ambiguous encodings and trailing bytes.
Timestamps also fit the platform's DateTime range. Both delegated and legacy
records require matching positive OpID/envelope counters within safe integers.
An operation cannot advance more than4096 beyond available history; a far-ahead
peer must supply the missing range before a new operation can be accepted.

Parsing a certificate/signature is not current authorization. Live operations
must use the latest durably pinned root roster, continuity checks and active
groups capability. A copied old certificate or roster cannot revive a removed
device. Renewing the same device's certificate preserves its existing signed
operations when the current roster still authorizes that signing identity.

Historical revocation must not rely on an operation's wall-clock timestamp.
Known, already accepted local operation hashes may preserve local history.
Newly imported historical authority needs current device authorization or a
permanent account-root ratification of the **exact operation hash**:

```
SLGR01 | SHA256(exactSLGO01Frame)[32] | accountRootPublicKey[32]
       | accountRootSignature[64]
```

Ratification domain: `secure-legion-group-operation-ratification-v1\0`. This
endorses exactly one operation, equivalent in account authority to an existing
legacy root-signed operation. It does not change the operation identity or grant
group roles by itself. The pinned membership state machine still decides whether
that account may perform the operation. A root host must ratify only previously
approved local operations, never blindly endorse incoming packets. Linked
devices never receive an account private key.

The state adapter calls the pinned core's membership, message and metadata
subsystems with the logical account author. It keeps separate exact operation
hashes for legacy and delegated operations, atomically publishes a batch only
after every operation succeeds, preserves duplicate/fork/DAG bookkeeping, and
rebuilds mixed history in the same order as the core. Already accepted local
history may remain after revocation; newly imported backdated operations require
current authority or exact root approval. The host must supply existing history
from committed local storage, never substitute incoming snapshot fields for it.

The API `sl_desktop_group_protocol` accepts strict tagged JSON and separate
32-byte signing-seed/group-key pointers. It performs no I/O, changes no native
registry, and publishes no state before the host's database commit. Calls are
bounded (72 MiB request, 40 MiB response, 24 MiB per packed history) with fixed
error codes. Buffers are erased on release. JSON contains membership key
material and encrypted content and must never enter diagnostic logs. A
read-only request rejects signing seeds. The native function is available as
an offline primitive in all builds; developer runtime activation remains gated
and is enabled only in the developer host. Normal legacy group functions retain
their existing API.

The request operations are `inspect`, `read_state`, `create_operation`, `preview_live`,
`preview_history`, `preview_invite`, `preview_reinvite`, `read_messages`, `select_delivery`, `compact_delivery_acknowledgements`, `attest_history` and
`attest_invitation` and `ratify`. `state.existing_local` must be loaded exclusively from previously
validated committed database rows. `state.rosters` contains explicit pinned
account roots and signed rosters, never a convenient roster copied from an
operation. Equal-epoch forks are rejected. Ratifications must bind exact
operations present in that history. Read queries are cursor-paginated, at most
256 messages. Creation derives Lamport from all committed operations, uses a
random operation nonce and signs only with the authorized installation seed.
Message IDs use the installation namespace while message authors remain accounts.

`preview_live` first applies a foreign packet in its supplied order against
current committed permissions. It then also requires a successful deterministic
rebuild of the accepted union. It never sorts an unseen operation into an older
role to grant permission, and does not accept a log that cannot survive restart.
`preview_invite` is restricted to first import, verifies a signed delivery receipt
from a currently authorized active group participant and requires our pending
membership and matching group secret. Every foreign historical operation still
needs current authority or exact root ratification. Re-invitation into existing
local history uses the separate explicit lifecycle below.

Own-account history replication uses a receipt over the **exact packed bytes**:

```
SLGH01 | rootSignedDeviceCertificate[274] | groupId[32]
       | SHA256(packedHistory)[32] | installationSignature[64]
```

Domain: `secure-legion-group-history-receipt-v1\0`. Only a device in our current
pinned roster with both `groups` and `sync` capability may attest already
committed history for `preview_history`. This permits our authenticated device
to replicate previously accepted operations after their original signer was
revoked; group roles/signatures and the secret are still rebuilt and checked by
Rust. A receipt from another account is never accepted as our own history. A
foreign receipt authenticates an invitation's source, and grants no historical
authorization bypass. The caller must use `attest_history` only for exact
database history; root ratification additionally requires a fresh primary role
and an exact locally approved stored hash. No network signing endpoint exists.

New delegated payloads require canonical typed CBOR with no ignored/trailing
fields. Membership IDs must derive from the invited account key. Invitations
start as Member/ReadOnly; promotion is a separate role operation after acceptance.
Only an Owner can grant ownership or change group-wide permission toggles.
These additional new-frame guards are in this Rust wrapper, with no changes to
the pinned legacy core. Ordinary role/rights validation still uses that core.
The kick safeguard remains: content sending fails while group key rotation is
required. The explicit epoch primitive and transactional keyring below are
implemented and the developer worker performs required authorized rotations.

`attest_invitation` permits a groups-only device to sign a foreign delivery
receipt; it additionally requires active local group membership and current
invitation permission. Initial invitation preview checks that permission too. This receipt
cannot bypass the separate groups+sync check on own-account history import.

Schema33 adds `DeviceGroupStore` and the `device_group_states`,
`device_group_acceptance`, `device_group_ratifications`, `device_group_origins`
and `device_group_targets` tables. Native preview precedes the transaction's
publication of the exact log bytes/hashes, state hash/count, account membership,
group projection and local-action retry origins. There is no mutable native
registry to leave ahead of SQL after a failed commit. Stored delegated rows
without their exact acceptance receipt are rejected as untrusted, and state
hash/count mismatches fail closed. The complete union is bounded before commit.
Old root-signed rows remain unchanged by migration; no acceptance or retry
ownership is invented for them.

Only `mutate` originates group delivery work. Foreign updates and own history
imports never create origins. Target accounts are stored separately from local
installation ownership; first invites and live updates are distinguished for
the developer transport integration. Queue capacity failure rolls back the visible
action as well. Restore/local revocation clears origins and targets while
retaining validated history and root proofs. The normal C0 contact purge does
not erase group membership or group history.

The store can create/edit local group operations offline, import an authenticated
first invitation, apply live updates idempotently, export/import exact own history,
query state/paginated messages, and ratify stored own-account operations. Ratifying
requires primary role, the currently pinned primary installation, all current
capabilities and exact accepted local history; linked/restored hosts cannot do it.
All writes recheck developer-profile and key-session generation before commit.
Key material supplied to native calls is erased from scratch buffers; requests
and responses are not diagnostic data. The developer app activates this store.

The wrapper permits an active or pending non-owner member (including ReadOnly) to leave
only its own account membership. It uses the pinned membership dispatcher for
the leave, preserving owner immutability and protection from removing an owner.
Any successful removal, including a voluntary leave, retains a key-rotation
requirement across replay until an eligible explicit epoch covers that exposure.
A removed recipient accepts no new live group state; an exact already accepted
duplicate can still be acknowledged without reactivating its group. Member
acceptance and terminal delivery dependencies must be retained by the transport.

Committed histories can contain concurrent writes accepted on a device before
it learned of a leave, demotion or deletion. Canonical rebuild retains their
exact signed records and clock identities, but marks superseded effects without
reapplying them. The native summary reports these IDs/hashes. Storage cancels
only those retry origins/targets and retains the log/acceptance receipts for
own-device convergence. It preserves pending membership dependencies. New wire
operations and Root ratifications alone do not receive this historical replay
privilege. A receipt-bound first invitation can retain deterministically
invalidated records as no-effects after **every** historical leaf has current
authorization or exact Root ratification. It still requires actual pending
membership and a currently permitted inviter; it cannot bootstrap an archive.
Signatures, identities, conflicting creators, Owner immutability and
owner-only grants remain hard validation failures.

Two installations accepting the same invitation, or independently leaving their
same logical membership, produce distinct signed operations with one membership
effect. Current device authority is still required; neither event reactivates a
removed member. Valid pre-leave messages remain readable from the validated
message map after the author leaves, including on a linked device importing its
own account history. Superseded concurrent content does not enter that map.
The developer message view retains superseded own-account message additions
with a visible not-delivered status. They remain outside accepted CRDT message
state and never acquire retry ownership. Read requests opt into
`include_local_dispositions`; default native reads retain their previous output.
The projection is paginated by the signed creation operation, uses its recorded
epoch for decryption and respects retained delete records. Other accounts'
superseded additions are not included in the host's local-account view.

Accept/Leave creation is idempotent once the logical action is already settled.
It returns an unchanged summary without signing, publication or retry ownership.
Unseen terminal no-effects are bounded to one action per installation and exact
invitation lifecycle. Distinct installations can repair their own dependencies;
one removed leaf cannot fill the log with unlimited alternate nonces.

A concurrent leave cannot discard a later authorized ban. The wrapper retains
that ban over the already-removed target without changing the shared core or
inventing membership. Unban clears it while leaving the account removed.
Concurrent last-slot invitations deterministically retain at most20 pending or
active principals; an already-accepted excess invitation is retained as a
superseded private archive/key exposure. It cannot deadlock history replay.

## Explicit key epochs and storage (schema36)

`group_rekey` creates a new OS-random32-byte group key using a current groups
leaf whose logical account is Owner, or Admin with `can_remove`. It is a
separate operation, never a fake metadata payload or a new account member:

```
SLGE01 | certificate[274] | groupId[32] | operationId[32]
       | timestamp:u64 | parentCount:u8 | parents[32 each]
       | exposureCount:u8 | exposureOperationIds[32 each]
       | previousEpochHash[32] | sourceMembershipDigest[32]
       | freshGroupKey[32] | installationSignature[64]
```

Integers are big endian. An operation ID is leaf BLAKE3 identity[16], Lamport:u64,
nonce:u64. The signature domain is `secure-legion-group-key-epoch-v1\0`.
Parents are sorted/unique, at most64. Exposure references are sorted/unique,
at most128 and at most one per affected account. All references are earlier
than the epoch. The previous epoch must exist and keys cannot be reused. The
genesis epoch ID is SHA256 of the exact GroupCreate frame. Later epoch IDs are
SHA256 of the exact SLGE01 frame. SLGR01 ratification also supports exact epochs.

Coverage inherits from the signed predecessor and adds the explicit exposure
delta. The state retains each account's latest actual removal or invalidated
invitation exposure. Only an eligible version covering all current requirements
permits new content. Larger merged frontiers can require several bounded
rotations; each retains earlier coverage. A rotation which predates an unseen
removal cannot clear that removal. A signed membership digest describes the
source snapshot; independent concurrent membership views need not match it.
Current group role, current leaf authority and explicit exposure coverage decide
eligibility. A previously accepted epoch invalidated by later control history is
retained for historical decryption and marked ineligible; it cannot become the
active send key. Canonical state hashes bind version IDs, resolved coverage,
eligibility, current epoch and exposure requirements once an epoch exists.

New delegated message additions/edits frame the encrypted ciphertext as
`SLGM01 | epochId[32] | ciphertext`. Existing raw history uses genesis; legacy
raw ciphertext is never guessed to be a framed value merely because of a prefix.
Native message queries strip the frame and return `cipher_epoch`. Unknown epochs
defer; stale/ineligible keys cannot authorize a fresh message. Older accepted
messages remain associated with their original key, including after restart
and edits under a later key. Missing effects of a superseded message do not
deadlock already accepted dependent edits/deletions/reactions. New wire actions
do not gain that recovery privilege.

Schema36 adds `device_group_keys(groupId,epoch,secret,eligible)` in SQLCipher.
Native mutating preview returns the derived current key and keyring only to the
storage adapter. It commits these together with exact operation bytes,
acceptance receipts, projection, state hash/count and retry ownership. A failed
commit rolls back all of them. A stored epoch's key cannot silently change.
Existing schema35 history and ACKs survive migration; no keys or acceptance
receipts are invented. Epoch rows require matching committed acceptance just
like SLGO01. Scratch key buffers are erased and public summaries omit keys.
`read_state` does not export a keyring. Diagnostic logging must exclude all
of these private native request/response bodies.

Own-history preview validates the local committed key and the receipt-bound
source branch's proposed key independently before deterministic merging. Two
devices can therefore converge after independent rotations without requiring
their pre-merge keys to match. Foreign live preview validates the old local key
before applying an epoch; storage adopts the newly derived key atomically.
New messages are limited to30 KiB ciphertext plus authentication overhead before
the pinned canonical-CBOR bounds; the developer UI still needs this limit.

Distribution must never send a full current history or new epoch key to a
removed account. Terminal delivery needs a bounded dependency closure ending
at the leave/kick/delete operation. Re-invitation and terminal snapshots need
explicit lifecycles. These sender/runtime integrations remain unfinished.

## Explicit re-invitation lifecycle

`preview_reinvite` is separate from ordinary first-invite and live updates.
With local history, unseen invitation history requires our locally committed
membership to be Removed/privately archived, or a proof of the prior lifecycle's
departure validated against the current local state. The group must not be
deleted. Native verifies the local key and the receipt-bound source branch's
proposed key independently. Each unseen historical leaf needs current groups
authority or its exact Root proof; exact locally accepted bytes retain their
existing history authority. The source branch must establish a genuinely new
pending invitation and a current active permitted inviter. The merged history
must preserve that same new pending invitation and permitted source. Local
history is retained, and receiving does not accept on the user's behalf.

An active local lifecycle cannot be silently replaced: native first applies the
exact closing operation's bounded causal closure to a clone of the current
state, using current leaf/group authority and preserving the previous invitation
identity. A missing/revoked/invalid departure proof rejects the new invitation.
This lets an offline sibling receive a real leave followed by a new pending
invitation without weakening current role checks. Deleted groups cannot be
revived. Replaying an already known
invitation snapshot preserves current membership and can recover a lost ACK,
including after the exact ACK cache is evicted. An uninitialized recipient still
needs genuine pending native membership, as for first invitation. Durable source
preparation, developer network workers and existing group UI actions are
implemented. Live Tor acceptance remains pending.

If a concurrent control invalidates an invitation which was already committed
locally, native rebuild can retain private archive access using that exact
superseded invitation's key. The summary reports Removed/archived with no invented
membership entry. This is restricted to trusted committed/own-account histories;
a first foreign invitation must still establish real native membership. Archived
recipients reject new live state and cannot issue invitations.

Delegated operations require every signed parent to exist in the accepted log;
MemberAccept also requires its exact invitation operation. Missing dependencies
return the fixed Dependency result without partial application or ACK. Inspection
exposes parent IDs, invitation dependency and message target IDs for bounded
repair tooling, without exposing content. Creation retains the installation's
exact predecessor within its bounded64-parent window even with many concurrent
heads. Edits, deletions and reactions also retain the target's creation/latest
edit dependencies. Delegated actions with missing message targets defer rather
than letting the core silently discard an early reaction. This is a causal
check, not a claim that an observed maximum counter means
all earlier operations from that author have arrived. Legacy-only parent behavior
is unchanged.

`select_delivery` is a structural preparation primitive, not transport or target
authorization. It requires current groups authority and an origin belonging to
that exact local installation/account. A bounded iterative walk retains signed
parents, exact invitation references, epoch predecessor/exposure references and
founding state. It selects at most1000 operations in causal order, excluding
exact hashes supplied from the host's verified per-recipient storage ACK
records and their exact causal ancestors. A committed operation proves its
required parents, acceptance invitation, epoch predecessor/removal frontier and
founding state were stored too. This does not infer an author-counter prefix or
cover unrelated concurrent branches. Missing dependencies, conflicting identities/groups and invalid ACK
hashes reject selection. Batches can advance after each committed complete ACK;
an observed maximum counter never substitutes for hashes. The selection stops
at the origin's dependency closure, so a removal cannot acquire later key epochs
from current history. Creation also retains the target's current invitation,
acceptance, role, removal and ban provenance within its bounded parent window.
Tests repair a target administrator across more than64 concurrent heads and
verify terminal batches exclude later keys/content.

`compact_delivery_acknowledgements` retains only exact causal checkpoints not
covered by another verified checkpoint. It accepts at most8192 input hashes
(a prior4096-checkpoint frontier plus a4096-checkpoint invitation), returns at most4096
sorted hashes, and rejects unknown/duplicate hashes and signing seeds. Its
current groups certificate and group-key checks are the same as sender
selection. A1201-operation chain advances in two batches while retaining one
checkpoint; a concurrent lower-clock branch is still selected separately.

The SQLCipher store exposes transaction-bound selection and compaction helpers.
Selection additionally requires this installation's durable local origin row;
history imports cannot select another installation's retry ownership. These
helpers preserve the committed state hash and do not themselves settle origins.

`prepare_invitation` additionally requires the current local leaf signing seed,
current group key, an exact locally owned MemberInvite and the intended Root.
The current target must retain that exact invitation, remain unbanned/unremoved,
and the source must still have invitation permission. For a still-pending target,
the snapshot contains current committed history and its matching key. If that
logical account accepted on another device, the snapshot stops before its first
non-superseded acceptance of this invitation. This gives a blank installation a
genuine pending invitation and excludes later accepted-state keys/history.
The source membership lifecycle must agree with the current authoritative view.
The operation returns a signed SLGH receipt, matching private key, explicit
re-invitation classification, required unratified leaf roster accounts, and a
bounded `acknowledged_on_commit` causal frontier. This frontier is only proposed
coverage: it becomes delivery evidence after the recipient's exact complete
storage ACK. The private result must never enter diagnostic logs or general UI.

The sender must still authorize the destination/lifecycle, persist the exact
encrypted packet and its selected hashes, verify the corresponding ACK, and
handle obsolete/cancelled actions explicitly. This primitive is not connected
to networking or the normal group UI, and does not make historical live actions
bypass the recipient's current role/key checks.

Role/identity checks also apply to legacy records in mixed-history validation,
so a root signature cannot bypass owner-only grants or alias another account's
membership ID. Unsafe legacy histories are rejected without publishing changes;
their prior SQL rows remain available for recovery. Normal beta group functions
are unchanged. The new C2 codecs are described in [the transport checkpoint](DEVICE-GROUP-TRANSPORT.md).

The developer SYNC host negotiates `delegated_groups_v1` only for enrolled v3
devices when the portable native adapter is available. Group exports/imports,
queued retries and settled ACKs require current GROUPS|SYNC authorization on both
installations. Old PAIR_V2 and default-build group snapshots retain their existing
format. A peer without the new capability cannot receive a delegated snapshot
through the legacy group validator.

The encrypted group delta contains exactly `group_history_v` (integer1),
`group_snapshot_id`, `group_id`, `packed_ops`, `group_secret`, `receipt`,
`ratifications`, and `rosters`. The snapshot ID is
`<group>:dg1:<SHA256(packed_ops)>`; ordinary durable-history metadata also binds
the entire canonical delta. Its private key and contents never enter diagnostic
logs. Export validates the committed hash/count and current leaf authority,
signs an SLGH receipt over exact committed bytes, and obeys the existing32MiB
group-delta bound. Oversized histories fail explicitly rather than truncating.

Trusted public roster advances commit independently before business acceptance.
Unknown observations remain provisional until native admission of their group
principals, without creating contacts/DM trust. The same roster-observation rules
serve C2 and own-account history. Native history union, keys, accepted hashes,
projection and SYNC replay metadata commit together; a disk failure cannot emit
a settled ACK. A blank phone can recover the companion's accepted history after
the original sender goes offline. Imports never acquire ratchets or retry jobs.

An old local group-deletion marker cannot suppress this native-validated history
or cause a false settled ACK. A successfully validated non-deleted native group
clears that legacy marker. A signed native GroupDelete remains authoritative in
the accepted union. Legacy deletion deltas cannot erase delegated accepted state.

`freezeResponsibilityInTransaction` prepares a frozen signed history event for
every other authorized own GROUPS|SYNC device within the application's SQL
transaction. Event clock allocation and durable SYNC outbox insertion therefore
cannot commit separately from accepted group data. Current peer authority is
checked while queueing; an offline connection does not discard that work. A
savepoint restores the old outbox/clock on expected capacity or capability
failure. Actual storage errors propagate and abort the application transaction.
The frozen payload survives restart and subsequent group growth. The developer
C2 receiver invokes it in the application transaction before producing ACK4;
the source commits exact account causal coverage before transferring delivery
responsibility. Capacity failure retains device-only acknowledgment; actual
storage failure emits no acknowledgment.

Remaining work includes automated permanent Root-proof distribution for revoked
leaf history, disposition for other superseded local controls, public group
vectors and live acceptance. Existing accepted history must be retained during
recovery. Authenticated restored-device authorization, new developer MSI and
final mobile handoff remain separate Desktop completion work.

Portable tests cover independent signatures, canonical framing/tampering,
revocation/rollback, renewal, exact root ratification, invalid heads/clocks/
capabilities, unchanged legacy state hashes, shared account membership and edits,
atomic rejection, last-owner protection, duplicate/fork behavior, deletion and
the accepted-history trust boundary, strict API/secret modes, history receipts,
invitation source/membership checks, live-role backdating rejection, leaf-only
creation/editing/pagination, key mismatch, rekey blocking and privilege checks.
Native FFI tests cover buffer rejection, fixed errors and capacity retry without
partial output. Storage tests cover crash rollback, restart, idempotence,
invitations/acceptance, ownership isolation, missing receipts, key/receipt
substitution, primary-only ratification, post-revocation invitation recovery and
restore cleanup. Developer transport and normal group-control tests additionally
cover both phones offline, exact retry/restart, per-chunk gates and membership
closure/key rotation. Production group behavior is unchanged.
