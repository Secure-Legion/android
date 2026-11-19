# Desktop 28: metadata-only own-device sync

Historical build-28 policy. Desktop 29 corrects its blanket block on new direct
messages and receipts; see [live-message sync](LIVE-MESSAGE-SYNC-2026-11-18.md).
Use that newer policy when implementing current clients.

Desktop advertises `tor_metadata_only_v1` and `group_links_v1` in HELLO and
HELLO_ACK. The policy is enforced locally even when an older peer ignores it.
This supersedes earlier handoffs describing full own-device history over Tor.

| Own-account data | Tor | Authenticated local Wi-Fi |
|---|---|---|
| Contacts, contact photos, settings, account profile | Yes | Yes |
| Signed group connections | `group_links` | Supported importer |
| Messages, attachments, voice, receipts, complete group history | No | Yes |
| Old phone group-message action relay | Disabled | Not implemented |

Ordinary encrypted direct peer messaging is a separate protocol and retains its
existing delivery, retry, authentication and encryption behavior. This change
does not make the phone forward newly received messages to Desktop over sync.
Independent delivery still requires compatible peers and authorized device data.

## Routing and durable commits

Tor topic selection applies to replay, live pushes, retry selection, pending
imports, and the final guard before Noise encryption. Rejected inbound history
is stopped before chunk buffering or database application. Valid revision
headers receive `kind: transport_skipped`, containing only history-v2 metadata.
It does not increment imported/saved counts or advance a cursor.

`transport_skipped` is never passed to the history ACK path. The durable store
also accepts only `kind: settled`. Existing full-history outbox and deferred rows
are retained across restart; they are neither transmitted nor removed because
Tor is unsuitable. Tor replay does not read all message/media rows or regenerate
full group history. New history remains in the normal local encrypted database.

The current iOS reference, commit
`ad145fddea5b7b0a3884e5e2b90a5836b24a2e4c` (project build 47), incorrectly returns
`settled` from `ignoredTorPushSettlement` without importing the history. Desktop
28 ignores ALL Tor settlements for messages/receipts/groups, protecting its queue
even against this older response. iOS should change that response to
`transport_skipped`, stop incrementing settled counts for it, and exclude it from
outbox deletion, ACK caches, cursors, history-pass saved counts and commit state.
No iOS source was modified or compiled as part of this Desktop change.

## Group connections

`group_links` retains `group_snapshot_id`, `group_id`, `packed_ops`, and
`group_secret`. Both installations must hold current GROUPS|SYNC authorization.
Allowed signed operations are GroupCreate, GroupDelete, MemberInvite,
MemberAccept, MemberRemove, MemberUnban, MetadataSet and RoleSet. Messages,
edits, message deletion, reactions, pins, unknown operations and delegated full
group history cannot be relabeled as connections.

Export selects connection operations, then native canonical/signature/membership
validation verifies their actual signed types. Import validates actual operation
types before any writes, including stale/duplicate revisions. The existing native
validator and encryption protocols are unchanged. A group-link ACK is separate
from a full-group-history ACK and cannot delete that full history.

The old phone message-action relay is unavailable, including already queued
requests. Independent native group messaging retains its existing protocol.
Delegated group history is excluded from the legacy connection exporter because
it requires its own native proof format; no compatibility fallback is invented.

## Wi-Fi and release checks

The existing explicit, pinned-TLS iPhone-to-Desktop nearby transfer continues to
import complete supported messages/media/receipts/groups and return exact
post-commit acknowledgements. Transfer text no longer promises history over Tor.
Desktop-to-phone nearby history export is not implemented in this receiver;
retained Desktop outbox rows must not be described as already transferred.
Resume interrupted/deferred history through another authenticated nearby session.

Only an active nearby session can report full-history progress. Old persisted Tor
progress does not produce a completed-history banner. Tor activity counts include
only metadata work, so preserved Wi-Fi-only rows do not imply an active Tor copy.

Before the beta release, test with physical iPhone/Windows devices: link and lock/
unlock, contacts/profile/group connections over Tor, no history over Tor, Wi-Fi
full copy and interruption/resume, new direct messages independently, group
permissions, and no queue loss after transport-skipped responses. Windows tests
and builds do not replace a Mac compile or real-device interoperability testing.
