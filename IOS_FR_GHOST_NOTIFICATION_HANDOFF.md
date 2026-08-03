# iOS Friend-Request Ghost Notification Handoff

Scope: iOS follow-up only. Android code 33 contains the Android fix; no iOS source was changed in
this pass.

## Why iOS may have shown a ghost alert

The iOS log showed otherwise healthy operation near an alert that could have been triggered by an
Android Phase 1 retry. Android code 32 could retry at multiple layers and could forget its in-memory
nonce history after process death. That makes an Android-originated replay a stronger working
hypothesis than an iOS Tor failure. Confirm with matching hashed nonce/sender telemetry; do not log
raw contact cards, tokens, PINs, onion addresses, or nonce values.

## Required iOS invariants

1. Generate one nonce when a logical Phase 1 request is created and reuse that nonce for every
   transport retry. A retry must refresh only allowed time metadata, not request identity.
2. Persist the authenticated nonce before posting a local notification. Enforce uniqueness in the
   database, not only in an actor/dictionary/cache.
3. Also dedupe while an incoming request from the same stable sender identity is pending. This
   protects against older senders that incorrectly generate a new nonce per retry.
4. Treat a duplicate as protocol convergence: refresh the pending record if needed, but do not post
   another notification or increment the badge twice.
5. Keep replay validation and notification dedupe separate. Invalid authentication must not poison
   a nonce that a later valid envelope uses.
6. Apply the same timestamp window as Android (`±24 hours`) and reject overflow/extreme values
   safely.

## Suggested durable record

```text
FriendRequestReceipt
  nonceDigest       UNIQUE
  senderIdentityDigest
  firstReceivedAt
  notificationPosted
  pendingRequestId
```

Persist only digests where practical. The transaction should insert/claim the receipt and upsert the
pending request. Post the notification only for a newly claimed receipt; then record that it was
posted. If the app dies between persistence and notification, the request must still be visible in
the in-app inbox.

## Cross-platform test matrix

- Android code 33 → iOS: repeat the same Phase 1 before and after killing iOS; one alert.
- Android code 32 → iOS: repeated Phase 1 with same nonce; one alert.
- Compatibility sender that changes nonce but keeps sender identity while pending; one alert.
- Reject/dismiss, then create a genuinely new request with a new nonce; one new alert.
- iOS → Android code 33 across Android process death; one Android alert and one pending row.
- Mutual friend requests and already-confirmed contacts; no ghost alert and no duplicate contact.
