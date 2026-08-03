# Android Tor, Battery, and Friend-Request Stability Plan

Status: implemented for 1.0.1 (code 33); device soak testing remains.

## Findings

The code-32 failure was state- and time-dependent, which explains why devices could work for two
months before failing. The old system multiplied retries across Kotlin, WorkManager, JNI, and Arti.
Network changes, stale onion descriptors/guards, or one slow peer could therefore accumulate
overlapping circuit work. A service retry branch also continued without delaying, allowing a tight
CPU loop during failure. Multiple native pollers and frequent duplicate health workers added idle
wakeups.

This is an inference from the logs plus the audited execution paths; it is not evidence of a Tor
network-wide outage. iOS continuing to work is consistent with an Android lifecycle/scheduler
failure.

The friend-request ghost had a separate persistence gap: authenticated nonces were remembered only
in memory. Android process death cleared that cache, so a sender retry could post the same system
notification again.

## Implemented changes

### Friend-request delivery

- One unique WorkManager dispatcher owns all pending rows.
- Room atomically leases one due row for 90 seconds and persists retry time/backoff.
- Backoff is 1, 2, 5, 15, 30, then 60 minutes with bounded jitter.
- Phase 1/2 continue until the protocol advances or the user cancels; a native write alone is not
  treated as final protocol success.
- Native sends perform one attempt with a 45-second deadline and coroutine-driven cancellation.
- Code-32 work names are cancelled once without deleting pending requests.

### Battery and live messaging

- Seven native inbound polling paths converge into one blocking event queue.
- Incoming traffic triggers the service-local debounced flush immediately; it does not enqueue a
  new WorkManager job.
- Stable health polling is 30 seconds; bootstrap/recovery remains 2 seconds.
- Download recovery is every 2 minutes.
- Message retry and Tor health are unique 15-minute fallback workers that no-op while TorService is
  healthy.
- Bandwidth callbacks run only in the foreground and are explicitly removed before restart/destroy.
- The fast-retry loop now delays on every branch, eliminating the observed spin path.
- Arti does not prebuild unused exit-port circuits.

These changes preserve instant messaging: inbound native events wake immediately, outgoing sends
start immediately, and PING/PONG/ACK traffic kicks the live service path. Only recovery scans were
slowed.

### Ghost notification protection

- Authenticated Phase 1 nonces are persisted in Room as namespaced `FR1:` received IDs.
- Friend-request dedupe rows are excluded from normal message-ID cleanup.
- A pending request is synchronously persisted before notification.
- A request notifies only when its durable nonce and semantic sender-pending record are both new.
- Invalid envelopes no longer consume a nonce in the in-memory replay cache.
- Database marker failures fail closed for notifications while keeping the request visible in the
  in-app pending inbox.

## Expected battery impact

The responsible estimate is a 25–45% reduction in Secure's background battery use during a healthy
idle day, with a much larger reduction during the former tight-loop failure condition. This is not
a claim about total phone battery percentage. Measure before/after on the same device and network;
Tor radio conditions can dominate any single run.

## Acceptance test

1. Upgrade code 32 to code 33 and confirm the Room 55→56 migration preserves queued friend
   requests.
2. Send and receive messages in foreground and background; delivery must not wait for a periodic
   worker.
3. Switch Wi-Fi to cellular, toggle airplane mode, and let Tor recover without duplicate workers or
   sustained CPU.
4. Kill/restart Android between receipt and a repeated Phase 1; exactly one system notification and
   one pending sender record may exist.
5. Leave a Phase 1 offline through multiple retries; verify one persisted retry row and the
   documented backoff.
6. Run an 8-hour idle A/B battery test using `adb shell dumpsys batterystats` and Android Battery
   Historian. Record CPU time, wakeups, mobile/Wi-Fi radio time, and Secure's consumed percentage.

## Build/install note

The connected Pixel 9a currently has Google Play code 32 signed by Google's app-signing key. Local
debug and upload-key APKs cannot update it with `adb install -r`. Do not uninstall it to bypass the
check, because that deletes its app data. Use a Google Play internal-test rollout for an in-place
upgrade, or install a different application ID side-by-side for isolated testing.
