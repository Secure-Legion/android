# Developer group transport implementation checkpoint

The developer-only independent-device host now connects C2 application ingress,
the native receiver, frozen own-device recovery and durable background sends.
The developer build's existing group screens now use this path. Live Tor
acceptance of the new group implementation is still pending.
Production builds keep their existing group path; beta distribution is unchanged.
This document is not the final mobile implementation handoff.

Each receiving installation gets its own X25519/ML-KEM encrypted chunks, signed
by the sending installation. Account roots identify group members; installations
are delivery endpoints, not extra group members. No account private key is used.
The encryption uses long-term recipient device keys and does not provide forward
secrecy against later compromise of those private keys.

## C2 frame

All integers are unsigned, big endian. The 253-byte header has these fields:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | `0xC2` |
| 1 | 4 | Remaining frame length after the first 5 bytes |
| 5 | 1 | Version `1` |
| 6 | 1 | Kind: data `1`, device storage ACK `2`, explicit re-invitation data `3`, account storage ACK `4`, history-proof request `5`, history-proof response `6` |
| 7 | 32 | Sender account root public key |
| 39 | 32 | Recipient account root public key |
| 71 | 32 | Sender authorization device ID |
| 103 | 32 | Recipient authorization device ID |
| 135 | 32 | Group ID |
| 167 | 32 | Random nonzero bundle ID |
| 199 | 32 | SHA-256 of the complete plaintext bundle |
| 231 | 8 | UTC creation time in milliseconds |
| 239 | 2 | Zero-based chunk index; zero for ACK |
| 241 | 2 | Complete bundle chunk count |
| 243 | 4 | Complete plaintext bundle length |
| 247 | 2 | Sender's signed roster length |
| 249 | 4 | Encrypted payload length |

The header is followed by the signed public roster, payload, and 64-byte device
signature. Signature input is `Secure-GROUP-TRANSPORT-v1/signature\0` followed by
the entire preceding frame. Existing Tor `sendOnly` supplies its normal outer
transport framing; the C2 frame is its application payload.

Data uses 64 KiB plaintext chunks, up to 32 MiB per complete bundle (512 chunks).
Every chunk has its own 1600-byte hybrid ciphertext, followed by the native
XChaCha20-Poly1305 output: 24-byte nonce plus encrypted plaintext/tag (40 bytes
overhead). The canonical chunk count and each chunk's exact expected length are
checked before decryption. A packet is at most 100261 bytes with the maximum
32768-byte public roster. ACKs have no payload and repeat the complete bundle's
hash, length and count with the account/device directions reversed.

The 32-byte wrap key uses HKDF-SHA256 expressed as HMAC extract/expand:

```
domain  = UTF8("Secure-GROUP-TRANSPORT-v1/wrap\0")
context = exactHeader || SHA256(senderRoster) || SHA256(hybridCiphertext)
salt    = SHA256(domain || context)
prk     = HMAC-SHA256(salt, hybridSharedSecret)
key     = HMAC-SHA256(prk, domain || context || 0x01)
```

Binding routing, group, chunk index, complete hash, roster and KEM ciphertext
through both the signature and derived AEAD key prevents transplanting a valid
ciphertext to another group, chunk or installation. Temporary shared/wrap keys
and native crypto scratch buffers are cleared after use.

## Private bundle

The encrypted body uses this bounded binary layout:

```
SLGB01 | mode:u8 | keyLength:u8 | groupKey
       | receiptLength:u16 | historyReceipt
       | packedOperationsLength:u32 | packedOperations
       | ratificationCount:u32 | ratifications[134 each]
       | rosterCount:u16 | (accountRoot[32] | length:u16 | signedRoster)*
```

Mode `1` is a live update with no group-key or receipt field. Mode `2` is an
initial invitation with a 32-byte group key and 408-byte SLGH01 history receipt.
Mode `3` carries the same bounded fields for an explicit re-invitation and must
use outer C2 kind `3`. A mode/kind mismatch rejects application acceptance.
Mode `4` is a proof-only response and must use C2 kind `6`: empty operations,
no key, no receipt, no roster observations, and 1–16 exact Root ratifications.
The outer kind is bound by both the signature and chunk encryption context.
Packed operations are limited to 24 MiB. Ratifications are strictly ordered by
their exact operation hash and cannot repeat. Up to128 public roster observations
are strictly ordered by account root and cannot repeat. Canonical framing checks
lengths, modes, counts and trailing bytes. Native group validation still owns
operation signatures, roles, key agreement and application authority.

The body contains private membership/history material. Do not put its JSON,
operation bytes, group key, plaintext chunks, or contents into logs or diagnostic
manifests. `clear()` erases the bundle's owned backing buffer; callers separately
erase decrypted chunk buffers. Database exceptions from the new group store use
a fixed error so SQLite bound values are not exposed by ordinary error logging.

## Bounded staging implementation

Schema34 adds `device_group_inbox` and `device_group_inbox_chunks`.
`DeviceGroupChunkStore` stages decrypted chunks in SQLCipher and grants no
account or group authority. It bounds active transfers to8 overall,2 per sender
account and64 MiB of staged bytes including saved first frames. Transfers expire
one hour after first receipt; duplicate chunks cannot extend that lifetime.
Ordinary and re-invitation chunks cannot mix under a single bundle identity.
The transfer key binds the local account/device, sender account/device, group
and random bundle ID. Conflicting metadata or chunk bytes cannot replace an
existing partial transfer.

Complete assembly checks every index/length, stored chunk hash and full bundle
hash. A complete hash failure discards staging with no app acceptance or ACK.
Otherwise staging remains until the host validates and commits the complete
application result with its ACK receipt, then calls `finishInTransaction` in
that same transaction. A failed application transaction leaves the previous
partial transfer intact for exact retry after restart.

Ready single-chunk bundles can be returned without consuming staging slots,
so small dependency replies are not blocked behind incomplete large transfers.
If native validation still needs a dependency, the host explicitly requests
`retainSingleChunk` to persist that deferred body. The owned assembly and input
scratch copies can be cleared without changing caller buffers.

Restore/local revocation clears private staging. Revoking a foreign device
purges only that sender's staged transfers. Chunk storage tests use real hybrid
encryption plus SQLCipher restart/rollback and do not claim application-level
group acceptance. The developer transport now uses this staging component.

## Receiver acceptance implementation

Schema35 adds a bounded exact committed-ACK cache. `DeviceGroupReceiver` checks
the developer profile, connection gate, local device and current sender before
decrypting or returning a cached ACK. The developer host activates this adapter.
It accepts foreign-account C2 data; own-account history uses the
separate authenticated SYNC path.

Valid public updates for already-trusted foreign Root identities commit before
business validation. A malformed bundle, application storage failure, or revoked
packet signer cannot roll back a valid Root revocation. Older attached rosters
are signature checked but never replace a higher durable pin. Own-account roster
advances still require the A4 path, including its peer installation callbacks.

Previously unknown roster identities are provisional in the application transaction.
Only Root principals in the native-validated group summary gain group routing
scope. A roster used solely to authenticate deterministically invalidated
historical records is discarded if newly staged; a pre-existing global pin is
retained for other groups. Arbitrary unrelated observations still reject the
application transaction. Native signatures and current authority/exact Root
proofs are checked before historical no-effect reconstruction.
Group-scoped identity checks require a committed native group marker and matching
Root membership record. Historical members retain this identity scope for terminal
ACKs; native checks still enforce current role authority. None of this creates a
DM contact or changes the default contact-only authorization path.

Full native application, exact signed ACK receipt and chunk staging removal share
one transaction. ACK bytes are exposed only after commit. Missing dependencies
retain staging without ACK; a one-chunk repair can bypass large blocked transfers.
The cache holds at most8192 receipts overall and1024 per sender account, evicting
oldest receipts. Exact invitation replay after eviction revalidates the current
source and bound receipt in native code, checks all operations are already
committed, and preserves current membership; unseen invitation history requires
an explicit lifecycle. Duplicate application does not allocate a new sync revision.

SQLCipher tests cover out-of-order encrypted history, restart, commit failure,
small dependency repair, revocation followed by malformed data, scoped roster
admission, closed gates and exact invitation replay. Local revocation/restore
clears cached ACKs; foreign revocation clears that sender's cached ACKs.

After local departure, ordinary new bodies are rejected before decryption;
exact cached committed ACKs remain available. The explicit kind `3` permits
bounded decryption/staging for native `preview_reinvite` validation of a genuinely
new pending invitation; parsing alone cannot restore group membership. Deleted
groups reject all new bodies. Committing departure purges
unaccepted partial chunks while retaining committed receipts. Obsolete initial
invitation targets are cancelled for removed recipients, without discarding
other recipients or MemberAccept/Leave dependencies. Key epochs are described
in [the native protocol checkpoint](DELEGATED-GROUP-PROTOCOL.md).

## Persistent live batch storage checkpoint

Schema38 adds `DeviceGroupDeliveryStore` for ordinary live batches between
currently accepted, active group accounts. The developer runtime now activates
it. Its live preparer rejects invitation targets, deleted groups and departed or
pending recipients; separate native-scoped invitation and terminal preparers
handle those exact operation lifecycles.

Preparation requires the current local GROUPS certificate, this installation's
durable origin/target row and the native-validated committed state. Native
selection supplies at most64 operations per batch. The store builds the private
bundle itself, adds the selected exact Root proofs/public roster observations,
and encrypts each chunk for the current recipient. Ciphertext, selected hashes,
origin and target context commit together before any transmission.

A domain-separated local-device signature binds the stored plan to its exact
first wire, selected hashes, final-batch flag and context. Altered cache metadata
cannot manufacture ACK progress. Retries return the exact saved ciphertext only
after rechecking profile/session/connection, current device authorization and
active live-target scope. This storage class has no socket or capture tooling;
the eventual sender must recheck those gates again before every socket write.

Only a complete signed ACK matching the exact saved bundle context can advance
that device's native-compacted causal frontier. Progress and partial-batch
deletion share a transaction. A partial batch does not mark its origin delivered.
A final kind2 ACK settles only that device, retaining other current GROUPS
devices' obligations and the exact final ciphertext for a possible kind4 upgrade.
Kind2 does not transfer account catch-up responsibility.
The host must first apply newer authenticated public roster observations through
the separate trusted-roster path; this store refuses an ACK advertising an
unapplied higher roster. Imports never acquire source origin ownership.

The wire cache is bounded to128 batches, two unacknowledged batches per target
device and256MiB of saved
wire bytes; progress is bounded to4096 scopes and16MiB. Capacity errors leave
origins and existing exact retries intact. Revocation/restore and existing
origin/target cancellation erase dependent caches. Public replay floors for C0
remain independent. Schema37 migration adds empty batch/progress tables while
preserving group origins, accepted history and C0 generation pins.

Native encrypted SQLCipher tests cover lost ACK/both restarts, exact retry,
receiver deduplication, device-only settlement, staged-write/ACK rollback,
validly signed wrong-body ACK rejection, altered local-plan rejection,
multi-batch progress, quota rollback, gates and revocation. The complete Desktop
suite passes465 tests with a clean analyzer at this checkpoint. This is not a
live app/Tor acceptance run or a completed group runtime.

The same outbox also prepares first invitations and explicit
re-invitations using native `prepare_invitation`. The native result selects the
exact lifecycle, genuine pending snapshot, key and signed history receipt.
Preparation cannot manufacture a pending invitation from a later accepted
snapshot. A re-invitation uses SLGB mode3 and C2 kind3; first invitation uses
SLGB mode2 and C2 kind1. Native selection supplies the required public rosters;
stored exact Root proofs accompany their selected records. Large snapshots use
the existing encrypted restartable chunk transport. The signed local plan binds
at most4096 proposed causal checkpoints instead of recording every snapshot hash.
Only a matching complete ACK commits those checkpoints. Native selection then
confirms that the committed frontier covers the invitation origin before final
device settlement. The increased wire-cache quota permits separate large
snapshots for an offline primary and its reachable companion.

Retries preserve exact saved ciphertext and revalidate current invitation
authority and lifecycle. A removed, banned, deleted or replaced invitation
cancels its obsolete invitation target/cache atomically with projection changes.
Successful delivery leaves membership pending; only the recipient's explicit
acceptance changes it. Invitation delivery does not acquire imported retry
ownership or transfer responsibility to the recipient's other devices.

## Account storage acknowledgment

Kind4 has the same exact bundle binding and empty payload as kind2, but its
current signer must hold GROUPS|SYNC. Changing a kind byte invalidates the device
signature. A current GROUPS-only certificate cannot validate an old kind4 ACK.
The receiving application enables this path only with a matching
`DeviceGroupSyncStore`. Native accepted data, frozen signed own-device recovery
work, its logical clock, the kind4 receipt and staging cleanup commit together.
A socket write or generic acceptance callback cannot promise this responsibility.
Expected catch-up capacity/capability failure retains kind2; a storage-write
failure aborts application publication and emits no ACK.

Schema39 adds a separate account causal frontier, scoped to group, originating
installation and recipient Root. A verified kind4 commits only its exact selected
coverage and required causal ancestors. Native selection must prove the origin
covered before its Root target and other devices' ciphertext are removed. Later
origins already covered by this frontier can settle without retransmission;
unrelated concurrent branches remain pending. Device/account frontiers share
the4096-scope/16MiB bound. Migration retains schema38 exact batches, signatures,
chunks and device progress while creating empty account progress.

A final kind2 retry remains exact until all current devices store it or an
account promise covers it. Replaying it lets the receiver upgrade its cached
receipt after catch-up capacity becomes available. Such committed retry caches
count toward total128-batch/256MiB limits, while freeing the device's active
two-batch slot. Cached signatures are authenticated at issuance, then today's
authority governs replies. Loss of SYNC downgrades a cached kind4 to kind2;
revocation still prevents all replies. An already verified account frontier
survives witness-device revocation as a fact of previously accepted Root storage,
and grants no new device authority. Restore/local revocation erase it.

## Runtime authority requirements

Parsing or opening a chunk never installs account trust. Before decryption or
ACK acceptance, the host must authorize its local device and the sender against
the highest durably pinned rosters. Attached older rosters cannot replace a newer
pin or revive a revoked device. A renewed certificate for the same active device
may still authenticate an exact older retry packet using its current signing key.
Creation times are bounded and reject clocks more than five minutes ahead; old
packets remain retryable while current device authorization permits them.

Group-member routing trust must be scoped to native-validated group principals;
it must not create a normal direct-message friendship. Public roster observations
inside an invitation remain candidates until signature/antirollback checks and
native group admission succeed in the same transaction. Unknown roots must never
be trusted merely because they supplied a certificate or appeared in a packet.

The sender must durably retain exact encrypted packets and target obligations
until a valid complete-bundle storage ACK. A socket write or individual chunk
cannot settle delivery. The receiver must persist bounded restartable assembly,
check the complete hash, run native role/history validation, and atomically save
the complete application result with its signed ACK receipt. Transmit that ACK
only after the transaction commits. Dependencies,
terminal leave/delete notifications and re-invitation require explicit lifecycle
handling; a pending acceptance needed by a later leave must not be discarded.

All sends, including retries and cached ACKs, need the existing developer-profile,
session, lab health and Tor connection gates. The host must use the configured
Tor hostname-forwarding path and fail closed on a disconnected lab connection.
No capture collection, Proxmox credential, Thor private key or direct/public
fallback belongs in this transport.

## Developer background host

`DeviceGroupTransport` is connected to `IndependentDeviceService` and reserved
C2 ingress in `MessageService`, behind the existing developer profile and live
lab gates. It supplies `DeviceGroupSyncStore` to the receiver, so an account ACK4
is available only after the frozen own-device recovery work commits. Public
trusted roster advances commit independently before source ACK matching.

Outgoing and reply queues are separate, each bounded to128 work items with four
concurrent workers. One outgoing worker serves a recipient installation at a
time. Preparation scans16 origin/account targets with a rotating cursor; an
invalid target cannot permanently hide later targets. An unanswered socket does
not hold a database transaction or block another installation's receiver.

Retries reserve persisted backoff before sending: 2,5,10,30,60,120 seconds,
capped at120 seconds thereafter. Attempts do not expire an accepted origin.
Each attempt loads and validates exact signed ciphertext once. Before **every**
chunk write, the sender checks the session/profile/connection, continued origin
and target ownership, unchanged signed plan/native state hash, and current local
and recipient GROUPS authorization. A native state change aborts the snapshot;
the next attempt fully validates it again. Roster authorization always resolves
the current certified onion endpoint. A cancelled batch cannot send remaining
chunks. Cached replies separately require current GROUPS and, for ACK4, SYNC.

Encrypted worker tests cover invitation/acceptance and bidirectional messages
with both phones offline, durable lost-ACK restart/backoff, an unanswered phone
socket alongside successful companion delivery, and disconnection, native-state
change or authenticated revocation between chunks. These are automated local
transport tests; live Tor/MSI/capture acceptance is still outstanding.

## Existing developer group controls

`GroupsService` selects this path only for the developer build, with the same
isolated-profile gates as other delegated traffic. Its existing screens support
create/invite/explicit accept or decline, text/edit/delete/reactions, metadata,
permission and role changes, removal/ban/unban and group deletion. Native group
authorization decides permissions; linked installations use their own leaf
signer and never obtain an account private key. Legacy incoming group packets
and legacy retries cannot select a fallback within this mode.

Text encryption and operation creation share one SQL transaction, so a rotation
cannot bind ciphertext encrypted under an earlier key to a newer epoch. Text is
bounded to30KiB. History pages decrypt with each message's recorded epoch key;
old accepted messages remain readable after rotation. UI metadata comes from
the validated native registers, and the group list excludes private key fields.

Actions created after a frozen invitation retain deferred live targets while
that account is pending. Preparation requires acceptance, then delivers the
pending-period history. Decline/removal/deletion cancels no-longer-deliverable
data targets and their ciphertext without inventing an ACK or erasing signed
history. Terminal dependencies addressed to an active account remain retained.
The worker attempts required rotations using only a currently eligible native
Owner/Admin; a failed rotation never enables old-key sending.

Local UI integration tests use real delegated companion vaults and encrypted
workers with both phones offline. They cover the controls above, current-role
and closed-profile failures, pending-period catch-up, decline cancellation and
readable old/new epochs after automatic rotation. They do not substitute for
live Tor, mobile hardware or installer acceptance.

Superseded own-account message additions stay visible with a not-delivered
status and their original text. They do not return to active group state or
resume retries. Their menu permits copying but disables edits, reactions and
pinning. Known deletion still hides their text. Native tests check default-read
compatibility, local-account scope, pagination and deletion; SQLCipher tests
decrypt the failed text and retain the same disposition through own-device
history recovery.

## Historical device revocation and proof repair

Revoking a leaf stops new operations and sockets from that installation. An
invitation to a new account still needs verifiable authority for the historical
operations it contains. Previously accepted local history does not by itself
authorize a new recipient to accept a now-revoked author's signature.

A current primary with all capabilities signs permanent Root ratifications only
for exact own-account operations already committed with matching acceptance
hashes. The worker processes one group and at most128 records per pump, with a
rotating cursor. Linked, restored and non-primary installations cannot perform
this signing. Received requests never supply approval candidates to the signer.
New invitations wait for the primary's bounded proof batches to finish.

The native read-only `missing_history_authority` operation returns at most128
sorted `(account_public, hash)` pairs and `has_more`. It checks the stored history
and current group key, and identifies records lacking both current leaf
authorization and an exact Root proof. The worker requests at most16 at a time.
C2 kind5 uses the same signature, KEM and encryption context as other C2 data,
with exactly one chunk and this plaintext:

```
SLPQ01 | count:u8 (1..16) | SHA256(operationBytes)[32] * count
```

Hashes are strictly increasing with no duplicates or trailing bytes. Its full
plaintext digest must match the signed header. Requests require a currently
authorized GROUPS device of an already trusted contact/group principal. Responses
serve only existing Root signatures for exact accepted records of the serving
account. A request cannot cause a new endorsement or fetch message contents or
group keys. Kind6 has one chunk, at most2164 plaintext bytes, and carries only the
mode4 bundle. The recipient verifies every Root proof against its own exact
committed record through the native validator before storing any proof.

Proof work has a separate64-item queue with two workers. Requests retry after10
seconds; the bounded in-memory timer is safe to reset because the original
durable group origin recreates the missing-proof scan after restart. Proof repair
does not create application retry ownership. An unavailable authority leaves the
original operation pending and does not weaken validation.

Newly verified proofs refresh only frozen invitations whose snapshot frontier
can include the affected historical record. Their source origin and acknowledged
causal progress remain; rebuilding uses a new bundle identity and recipient KEM,
with the same signed operation identities. Ordinary unchanged retries retain
their exact ciphertext. Every chunk also checks an ordered global roster epoch
revision, so a third account's author revocation aborts an in-flight snapshot
even when the native group state hash did not change.

Regression coverage includes a revoked own author with130 earlier operations,
three accounts with a revoked foreign author, an invitation queued before that
revocation, explicit pending acceptance, signature rejection, bounded canonical
proof codecs, and unchanged application state/retry ownership after proof repair.
