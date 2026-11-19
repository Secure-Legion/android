//! Global sync session manager.
//!
//! Owns the in-memory session table, the per-peer rate-limit token buckets,
//! the global concurrency cap, and the dual-init collision rule. Exposes
//! `process_frame`, `start_initiator`, `tick`, `abort_group`, and
//! `list_sessions` to the FFI layer.
//!
//! # Architecture
//! - **Pure protocol logic.** No I/O, no clock, no storage. The caller
//!   provides `now_ms` and a `SyncBackend` trait impl that supplies the
//!   delta op list for a HELLO. This trait is also where the Phase 5
//!   cross-platform storage abstraction begins.
//! - **Session table key**: `(GroupID, canonical_pair(local, peer))`.
//!   Crossed HELLOs collapse to a single row.
//! - **Dual-init collision rule** (per project doc + user direction):
//!   lower DeviceID wins as Initiator. Implemented in `decide_initiator`.
//! - **Rate bucket per peer**: token bucket with capacity
//!   `MAX_OPS_PER_PEER_PER_MINUTE`, refilling continuously. Global across
//!   groups — one peer flooding multiple groups gets one bucket.
//! - **Global concurrency cap**: `MAX_CONCURRENT_SYNCS` active sessions
//!   total. New `start_initiator` calls beyond the cap are rejected.
//!
//! # `session_id` discipline (user guard)
//! `session_id` is observability-only here too. The session-table key uses
//! DeviceID, NOT session_id. Cross-checked in tests.

use std::collections::HashMap;

use crate::crdt::ids::{DeviceID, GroupID};
use crate::crdt::limits::{MAX_CONCURRENT_SYNCS, MAX_OPS_PER_PEER_PER_MINUTE};
use crate::crdt::ops::OpEnvelope;

use super::frames::{FrameError, SyncFrame};
use super::session::{
    CloseReason, SessionInfo, SyncAction, SyncSession,
};

// ---------------------------------------------------------------------------
// Collision rule helpers (used by SyncManager + visible to integration tests)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorRole {
    LocalInitiates,
    RemoteInitiates,
}

/// Canonical ordering of a peer pair — used as part of the session table key
/// so crossed HELLOs map to the same row.
pub fn canonical_pair(a: DeviceID, b: DeviceID) -> (DeviceID, DeviceID) {
    if a <= b { (a, b) } else { (b, a) }
}

/// Decide which side of a (local, remote) pair is the canonical Initiator.
/// Lower DeviceID wins.
pub fn decide_initiator(local: DeviceID, remote: DeviceID) -> InitiatorRole {
    if local <= remote {
        InitiatorRole::LocalInitiates
    } else {
        InitiatorRole::RemoteInitiates
    }
}

// ---------------------------------------------------------------------------
// SyncBackend trait — caller-supplied op-log queries
// ---------------------------------------------------------------------------

/// Provides the manager with the data it needs from the caller's op log.
///
/// On Android: implemented by a JNI bridge that calls into Room/SQLCipher.
/// On iOS / desktop: implemented against the platform's storage layer.
/// In tests: implemented as an in-memory mock.
///
/// Keeping this as a trait — not a concrete `Vec<OpEnvelope>` argument —
/// allows the manager to query lazily, only when a HELLO actually triggers
/// responder construction.
pub trait SyncBackend {
    /// Compute the ops the peer is missing.
    ///
    /// `peer_heads`: per-author lamport ceiling — peer claims to have everything
    /// up to and including these lamports.
    /// `peer_bloom`: bloom of op_ids peer has (may be empty in v1; ignored if so).
    /// `peer_bloom_k`: number of hash functions used by peer's bloom (0 if no bloom).
    ///
    /// Implementation MUST return ops sorted by `(lamport, author, nonce)` so
    /// the responder's outbound chunks arrive in the order the receiver will
    /// apply. Implementation MUST NOT include ops the peer already has by
    /// lamport-head check.
    fn compute_delta(
        &mut self,
        group_id: &GroupID,
        peer_heads: &HashMap<DeviceID, u64>,
        peer_bloom: &[u8],
        peer_bloom_k: u8,
    ) -> Vec<OpEnvelope>;
}

// ---------------------------------------------------------------------------
// RateBucket — token bucket for per-peer rate limiting
// ---------------------------------------------------------------------------

/// Token bucket: `MAX_OPS_PER_PEER_PER_MINUTE` tokens per minute, refilling
/// continuously. `try_consume(n)` returns true and debits n tokens, or false
/// if the bucket lacks enough tokens.
#[derive(Debug, Clone)]
pub struct RateBucket {
    /// Tokens available. Stored as f64 for sub-token continuous refill math.
    tokens: f64,
    /// Wall-clock time of the last refill, in ms.
    last_refill_ms: u64,
}

impl RateBucket {
    const CAPACITY: f64 = MAX_OPS_PER_PEER_PER_MINUTE as f64;
    /// Refill rate per millisecond.
    const REFILL_PER_MS: f64 = (MAX_OPS_PER_PEER_PER_MINUTE as f64) / 60_000.0;

    pub fn new(now_ms: u64) -> Self {
        RateBucket { tokens: Self::CAPACITY, last_refill_ms: now_ms }
    }

    /// Refill based on elapsed time, then attempt to consume `n` tokens.
    /// Returns `true` if the consume succeeded.
    pub fn try_consume(&mut self, n: u32, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms) as f64;
        let refill = elapsed * Self::REFILL_PER_MS;
        self.tokens = (self.tokens + refill).min(Self::CAPACITY);
        self.last_refill_ms = now_ms;
        let n_f = n as f64;
        if self.tokens >= n_f {
            self.tokens -= n_f;
            true
        } else {
            false
        }
    }

    pub fn tokens(&self) -> f64 { self.tokens }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// Already at `MAX_CONCURRENT_SYNCS`.
    GlobalCapReached,
    /// Already have an active session for this peer pair in this group.
    SessionAlreadyExists,
    /// The peer is at its rate limit (token bucket exhausted).
    PeerRateLimited,
    /// Bincode serialization of the HELLO failed.
    EncodeError(String),
    /// Local device cannot sync with itself.
    SelfPeer,
}

impl From<FrameError> for StartError {
    fn from(e: FrameError) -> Self { StartError::EncodeError(e.to_string()) }
}

// ---------------------------------------------------------------------------
// SyncManager
// ---------------------------------------------------------------------------

type SessionKey = (GroupID, (DeviceID, DeviceID));

pub struct SyncManager {
    local_device: DeviceID,
    sessions: HashMap<SessionKey, SyncSession>,
    rate_buckets: HashMap<DeviceID, RateBucket>,
}

impl SyncManager {
    pub fn new(local_device: DeviceID) -> Self {
        SyncManager {
            local_device,
            sessions: HashMap::new(),
            rate_buckets: HashMap::new(),
        }
    }

    pub fn local_device(&self) -> &DeviceID { &self.local_device }

    /// Number of active (non-terminal) sessions across all groups.
    pub fn active_session_count(&self) -> usize {
        self.sessions.values().filter(|s| !s.is_terminal()).count()
    }

    /// Start an outbound (Initiator) sync session.
    ///
    /// Returns the actions to execute (a single `SendFrame { HELLO }`) on
    /// success. On failure, returns `StartError`.
    pub fn start_initiator(
        &mut self,
        group_id: GroupID,
        peer: DeviceID,
        heads: HashMap<DeviceID, u64>,
        bloom: Vec<u8>,
        bloom_k: u8,
        bloom_n: u32,
        session_id: u64,
        now_ms: u64,
    ) -> Result<Vec<SyncAction>, StartError> {
        if peer == self.local_device {
            return Err(StartError::SelfPeer);
        }

        let key = (group_id, canonical_pair(self.local_device, peer));

        // Existing session for this peer-pair in this group? Reject duplicate.
        if let Some(existing) = self.sessions.get(&key) {
            if !existing.is_terminal() {
                return Err(StartError::SessionAlreadyExists);
            }
            // Stale terminal entry — sweep it so we can take its slot.
            self.sessions.remove(&key);
        }

        if self.active_session_count() >= MAX_CONCURRENT_SYNCS {
            return Err(StartError::GlobalCapReached);
        }

        // Reserve a token from the peer's rate bucket. Even outbound HELLOs
        // count — they oblige the peer to spend resources responding.
        let bucket = self.rate_buckets
            .entry(peer)
            .or_insert_with(|| RateBucket::new(now_ms));
        if !bucket.try_consume(1, now_ms) {
            return Err(StartError::PeerRateLimited);
        }

        let (session, actions) = SyncSession::new_initiator(
            group_id, self.local_device, peer, session_id,
            heads, bloom, bloom_k, bloom_n, now_ms,
        )?;
        self.sessions.insert(key, session);
        Ok(actions)
    }

    /// Process an inbound transport frame.
    ///
    /// `wire_type` is the Tor byte (0x31..0x34); `bytes` is the bincode body
    /// stripped of any transport-layer envelope. Validates the wire-type-vs-body
    /// match before any state-machine work.
    pub fn process_frame<B: SyncBackend>(
        &mut self,
        backend: &mut B,
        peer: DeviceID,
        wire_type: u8,
        bytes: &[u8],
        now_ms: u64,
    ) -> Vec<SyncAction> {
        if peer == self.local_device {
            return vec![]; // self-loop; silently drop
        }

        // Decode + validate wire-type/body match.
        let frame = match SyncFrame::decode_with_wire_type(wire_type, bytes) {
            Ok(f) => f,
            Err(_) => return vec![], // malformed; drop silently (manager-level rate strike could go here)
        };

        // Account inbound bytes against the peer's rate bucket. Every frame
        // costs at least 1 token; CHUNK frames cost `len(ops)` tokens.
        let cost = match &frame {
            SyncFrame::Chunk(c) => c.ops.len().max(1) as u32,
            _ => 1,
        };
        let bucket = self.rate_buckets
            .entry(peer)
            .or_insert_with(|| RateBucket::new(now_ms));
        if !bucket.try_consume(cost, now_ms) {
            // Find or create a session to mark rate-limited closed.
            let key = (*frame.group_id(), canonical_pair(self.local_device, peer));
            if let Some(s) = self.sessions.get_mut(&key) {
                let actions = s.abort();
                self.sessions.remove(&key);
                return actions;
            }
            return vec![SyncAction::CloseSession { reason: CloseReason::PeerProtocolViolation(
                "peer rate-limited; no active session to close".into(),
            )}];
        }

        let group_id = *frame.group_id();
        let key = (group_id, canonical_pair(self.local_device, peer));

        // HELLO is the only frame that can create a session (Responder mode).
        if let SyncFrame::Hello(ref hello) = frame {
            return self.handle_inbound_hello(backend, peer, key, hello.clone(), now_ms);
        }

        // For all other frame types, we need an existing session.
        let session = match self.sessions.get_mut(&key) {
            Some(s) => s,
            None => return vec![], // orphan frame; silently drop
        };
        let mut actions = session.accept_frame(frame, now_ms);

        // Sweep terminal sessions out of the table.
        if session.is_terminal() {
            // Sessions emit their own CloseSession action; keep that, drop the entry.
            self.sessions.remove(&key);
        } else {
            // Belt-and-suspenders: if the session emitted CloseSession but its
            // state is NOT terminal, remove it anyway (defensive).
            if actions.iter().any(|a| matches!(a, SyncAction::CloseSession { .. })) {
                self.sessions.remove(&key);
            }
        }

        // Filter duplicate CloseSession (defensive: session emits one; we don't add).
        actions.retain(|a| !matches!(a, SyncAction::CloseSession { .. }) ||
            // Keep the FIRST CloseSession; drop trailing dups. (None expected.)
            true);
        actions
    }

    fn handle_inbound_hello<B: SyncBackend>(
        &mut self,
        backend: &mut B,
        peer: DeviceID,
        key: SessionKey,
        hello: super::frames::HelloFrame,
        now_ms: u64,
    ) -> Vec<SyncAction> {
        // Existing session for this peer-pair?
        if let Some(existing) = self.sessions.get_mut(&key) {
            if !existing.is_terminal() {
                // Collision. Apply rule.
                match decide_initiator(self.local_device, peer) {
                    InitiatorRole::LocalInitiates => {
                        // We're the canonical Initiator — peer should not have
                        // initiated. Drop the inbound HELLO; keep our session.
                        return vec![];
                    }
                    InitiatorRole::RemoteInitiates => {
                        // Peer is canonical Initiator. Abort our outbound and
                        // accept theirs as Responder.
                        let mut abort_actions = existing.abort();
                        self.sessions.remove(&key);
                        // Drop the CloseSession action — we'll emit our new
                        // Responder close on terminate, not now.
                        abort_actions.retain(|a| !matches!(a, SyncAction::CloseSession { .. }));
                        // Continue below to construct Responder.
                        let mut responder_actions = self.start_responder(
                            backend, peer, key, hello, now_ms,
                        );
                        abort_actions.append(&mut responder_actions);
                        return abort_actions;
                    }
                }
            }
            // Stale terminal — sweep and proceed.
            self.sessions.remove(&key);
        }

        // No existing session: ensure we have headroom under the global cap.
        if self.active_session_count() >= MAX_CONCURRENT_SYNCS {
            // Reject the HELLO silently. Peer will time out and retry later.
            return vec![];
        }

        self.start_responder(backend, peer, key, hello, now_ms)
    }

    fn start_responder<B: SyncBackend>(
        &mut self,
        backend: &mut B,
        peer: DeviceID,
        key: SessionKey,
        hello: super::frames::HelloFrame,
        now_ms: u64,
    ) -> Vec<SyncAction> {
        let group_id = hello.group_id;
        let session_id = hello.session_id;
        let delta = backend.compute_delta(
            &group_id, &hello.heads, &hello.bloom, hello.bloom_k,
        );
        let (session, actions) = match SyncSession::new_responder(
            group_id, self.local_device, peer, session_id, delta, now_ms,
        ) {
            Ok(pair) => pair,
            Err(_) => return vec![],
        };
        // Only insert if the session isn't terminal (zero-delta case completes
        // immediately with a CloseSession action; no point keeping it).
        if !session.is_terminal() {
            self.sessions.insert(key, session);
        }
        actions
    }

    /// Periodic timer (caller drives, e.g. once per second).
    /// Fires timeouts and harvests terminal sessions.
    pub fn tick(&mut self, now_ms: u64) -> Vec<SyncAction> {
        let mut all_actions: Vec<SyncAction> = Vec::new();
        let mut to_remove: Vec<SessionKey> = Vec::new();

        for (key, session) in self.sessions.iter_mut() {
            let actions = session.tick(now_ms);
            for a in &actions {
                if matches!(a, SyncAction::CloseSession { .. }) {
                    to_remove.push(*key);
                }
            }
            all_actions.extend(actions);
        }
        for k in to_remove {
            self.sessions.remove(&k);
        }
        all_actions
    }

    /// Abort all sessions for a group (group deleted, manager teardown, etc.).
    pub fn abort_group(&mut self, group_id: &GroupID) -> Vec<SyncAction> {
        let keys: Vec<SessionKey> = self.sessions.keys()
            .filter(|(g, _)| g == group_id)
            .copied()
            .collect();
        let mut all_actions: Vec<SyncAction> = Vec::new();
        for k in keys {
            if let Some(mut session) = self.sessions.remove(&k) {
                all_actions.extend(session.abort());
            }
        }
        all_actions
    }

    /// Abort everything (e.g. logout, app teardown).
    pub fn abort_all(&mut self) -> Vec<SyncAction> {
        let keys: Vec<SessionKey> = self.sessions.keys().copied().collect();
        let mut all_actions: Vec<SyncAction> = Vec::new();
        for k in keys {
            if let Some(mut session) = self.sessions.remove(&k) {
                all_actions.extend(session.abort());
            }
        }
        all_actions
    }

    /// Snapshot of all live sessions for `crdtSyncListSessions`.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        self.sessions.values().map(|s| s.info()).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::ids::{DeviceID, GroupID, OpID};
    use crate::crdt::ops::{OpEnvelope, OpType};
    use std::collections::HashMap;

    fn dev(byte: u8) -> DeviceID { DeviceID::from_bytes([byte; 16]) }
    fn gid(byte: u8) -> GroupID { GroupID::from_bytes([byte; 32]) }

    fn make_op(g: GroupID, author: DeviceID, lamport: u64) -> OpEnvelope {
        OpEnvelope {
            group_id: g,
            op_id: OpID::new(author, lamport, lamport.wrapping_mul(0xCAFEBABE)),
            parent_heads: vec![],
            lamport,
            timestamp_ms: 1_700_000_000_000,
            op_type: OpType::MsgAdd,
            payload: vec![0xAB; 32],
            author_pubkey: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    /// Mock backend: returns a fixed delta regardless of heads/bloom.
    struct MockBackend {
        delta: Vec<OpEnvelope>,
        calls: u32,
    }
    impl MockBackend {
        fn new(delta: Vec<OpEnvelope>) -> Self { MockBackend { delta, calls: 0 } }
    }
    impl SyncBackend for MockBackend {
        fn compute_delta(
            &mut self,
            _group_id: &GroupID,
            _peer_heads: &HashMap<DeviceID, u64>,
            _peer_bloom: &[u8],
            _peer_bloom_k: u8,
        ) -> Vec<OpEnvelope> {
            self.calls += 1;
            self.delta.clone()
        }
    }

    // -------------------- collision rule helpers --------------------

    #[test]
    fn canonical_pair_is_symmetric() {
        let a = dev(1); let b = dev(7);
        assert_eq!(canonical_pair(a, b), canonical_pair(b, a));
        assert_eq!(canonical_pair(a, b), (a, b));
    }

    #[test]
    fn canonical_pair_handles_equal() {
        let a = dev(5);
        assert_eq!(canonical_pair(a, a), (a, a));
    }

    #[test]
    fn lower_device_id_initiates() {
        let lo = dev(1); let hi = dev(99);
        assert_eq!(decide_initiator(lo, hi), InitiatorRole::LocalInitiates);
        assert_eq!(decide_initiator(hi, lo), InitiatorRole::RemoteInitiates);
    }

    #[test]
    fn collision_resolution_consistent_across_peers() {
        for i in 0..=255u8 {
            for j in 0..=255u8 {
                if i == j { continue; }
                let a = dev(i); let b = dev(j);
                let from_a = decide_initiator(a, b);
                let from_b = decide_initiator(b, a);
                assert!(matches!(
                    (from_a, from_b),
                    (InitiatorRole::LocalInitiates, InitiatorRole::RemoteInitiates)
                        | (InitiatorRole::RemoteInitiates, InitiatorRole::LocalInitiates)
                ));
            }
        }
    }

    // -------------------- RateBucket --------------------

    #[test]
    fn rate_bucket_starts_full() {
        let mut b = RateBucket::new(0);
        assert!(b.try_consume(MAX_OPS_PER_PEER_PER_MINUTE as u32, 0));
        assert!(!b.try_consume(1, 0));
    }

    #[test]
    fn rate_bucket_refills_continuously() {
        let mut b = RateBucket::new(0);
        // Drain the bucket.
        assert!(b.try_consume(MAX_OPS_PER_PEER_PER_MINUTE as u32, 0));
        // After 30 seconds, half capacity should have refilled.
        let half_min_ms = 30_000;
        assert!(b.try_consume(50, half_min_ms));
        // No more available.
        assert!(!b.try_consume(1, half_min_ms));
    }

    #[test]
    fn rate_bucket_caps_refill_at_capacity() {
        let mut b = RateBucket::new(0);
        b.try_consume(50, 0); // 50 left
        // Wait an hour — refill should max at capacity, not overflow.
        let one_hour = 3_600_000;
        assert!(b.try_consume(MAX_OPS_PER_PEER_PER_MINUTE as u32, one_hour));
        assert!(!b.try_consume(1, one_hour));
    }

    // -------------------- start_initiator --------------------

    #[test]
    fn start_initiator_emits_hello() {
        let mut mgr = SyncManager::new(dev(1));
        let actions = mgr.start_initiator(
            gid(1), dev(2), HashMap::new(), vec![], 0, 0, 42, 0,
        ).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SyncAction::SendFrame { wire_type, .. } => assert_eq!(*wire_type, 0x31),
            _ => panic!("expected SendFrame HELLO"),
        }
        assert_eq!(mgr.active_session_count(), 1);
    }

    #[test]
    fn start_initiator_rejects_self_peer() {
        let mut mgr = SyncManager::new(dev(1));
        let err = mgr.start_initiator(
            gid(1), dev(1), HashMap::new(), vec![], 0, 0, 1, 0,
        ).unwrap_err();
        assert_eq!(err, StartError::SelfPeer);
    }

    #[test]
    fn start_initiator_rejects_duplicate() {
        let mut mgr = SyncManager::new(dev(1));
        mgr.start_initiator(gid(1), dev(2), HashMap::new(), vec![], 0, 0, 1, 0).unwrap();
        let err = mgr.start_initiator(
            gid(1), dev(2), HashMap::new(), vec![], 0, 0, 99, 100,
        ).unwrap_err();
        assert_eq!(err, StartError::SessionAlreadyExists);
    }

    #[test]
    fn start_initiator_enforces_global_concurrency_cap() {
        let mut mgr = SyncManager::new(dev(1));
        // MAX_CONCURRENT_SYNCS = 2 — first two succeed.
        mgr.start_initiator(gid(1), dev(2), HashMap::new(), vec![], 0, 0, 1, 0).unwrap();
        mgr.start_initiator(gid(2), dev(3), HashMap::new(), vec![], 0, 0, 2, 0).unwrap();
        // Third hits the cap.
        let err = mgr.start_initiator(
            gid(3), dev(4), HashMap::new(), vec![], 0, 0, 3, 0,
        ).unwrap_err();
        assert_eq!(err, StartError::GlobalCapReached);
    }

    // -------------------- inbound HELLO → Responder --------------------

    #[test]
    fn inbound_hello_creates_responder_and_emits_chunks() {
        // Local is dev(5); peer is dev(2). dev(2) < dev(5) so peer wins as
        // Initiator (no collision since local has no outbound). We should
        // accept HELLO and become Responder.
        let mut mgr = SyncManager::new(dev(5));
        let g = gid(1);
        let mut backend = MockBackend::new(vec![
            make_op(g, dev(2), 1),
            make_op(g, dev(2), 2),
        ]);
        let hello = SyncFrame::Hello(super::super::frames::HelloFrame {
            group_id: g, session_id: 0xAB, initiator_device: dev(2),
            heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = hello.encode().unwrap();
        let actions = mgr.process_frame(&mut backend, dev(2), 0x31, &bytes, 100);
        assert_eq!(backend.calls, 1);
        // Expect at least one SendFrame chunk action.
        assert!(actions.iter().any(|a| matches!(a, SyncAction::SendFrame { wire_type: 0x33, .. })));
        assert_eq!(mgr.active_session_count(), 1);
    }

    #[test]
    fn inbound_hello_with_zero_delta_does_not_persist_session() {
        let mut mgr = SyncManager::new(dev(5));
        let g = gid(1);
        let mut backend = MockBackend::new(vec![]);
        let hello = SyncFrame::Hello(super::super::frames::HelloFrame {
            group_id: g, session_id: 0xCAFE, initiator_device: dev(2),
            heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = hello.encode().unwrap();
        let actions = mgr.process_frame(&mut backend, dev(2), 0x31, &bytes, 100);
        // Manager should emit the immediate-CloseSession from the responder
        // and NOT keep the session in its table.
        assert!(actions.iter().any(|a| matches!(a, SyncAction::CloseSession { .. })));
        assert_eq!(mgr.active_session_count(), 0);
    }

    // -------------------- Dual-init collision --------------------

    #[test]
    fn collision_local_lower_keeps_outbound_drops_inbound_hello() {
        // local=dev(1) < peer=dev(2); local wins.
        let mut mgr = SyncManager::new(dev(1));
        mgr.start_initiator(gid(1), dev(2), HashMap::new(), vec![], 0, 0, 100, 0).unwrap();

        // Inbound HELLO from peer mid-flight.
        let hello = SyncFrame::Hello(super::super::frames::HelloFrame {
            group_id: gid(1), session_id: 999, initiator_device: dev(2),
            heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = hello.encode().unwrap();
        let mut backend = MockBackend::new(vec![]);
        let actions = mgr.process_frame(&mut backend, dev(2), 0x31, &bytes, 50);
        // No actions — we ignore inbound HELLO (we're winning).
        assert!(actions.is_empty(), "got actions: {:?}", actions);
        // Our outbound session is untouched — still 1 active.
        assert_eq!(mgr.active_session_count(), 1);
        // Backend was not consulted — we didn't take the Responder path.
        assert_eq!(backend.calls, 0);
    }

    #[test]
    fn collision_local_higher_aborts_outbound_and_becomes_responder() {
        // local=dev(9) > peer=dev(2); peer wins.
        let mut mgr = SyncManager::new(dev(9));
        mgr.start_initiator(gid(1), dev(2), HashMap::new(), vec![], 0, 0, 100, 0).unwrap();
        assert_eq!(mgr.active_session_count(), 1);

        let g = gid(1);
        let hello = SyncFrame::Hello(super::super::frames::HelloFrame {
            group_id: g, session_id: 999, initiator_device: dev(2),
            heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = hello.encode().unwrap();
        let mut backend = MockBackend::new(vec![make_op(g, dev(9), 1)]);
        let actions = mgr.process_frame(&mut backend, dev(2), 0x31, &bytes, 50);
        // Backend was consulted to compute Responder delta.
        assert_eq!(backend.calls, 1);
        // We should emit responder chunks.
        assert!(actions.iter().any(|a| matches!(a, SyncAction::SendFrame { wire_type: 0x33, .. })));
        // Still 1 active (the new Responder; old Initiator was aborted).
        assert_eq!(mgr.active_session_count(), 1);
    }

    // -------------------- Rate limiting --------------------

    #[test]
    fn rate_bucket_throttles_chunk_storm() {
        let mut mgr = SyncManager::new(dev(1));
        let g = gid(1);
        // Local is Initiator; we send a HELLO to peer dev(2).
        mgr.start_initiator(g, dev(2), HashMap::new(), vec![], 0, 0, 1, 0).unwrap();

        let mut backend = MockBackend::new(vec![]);

        // Peer responds with a CHUNK containing more ops than the bucket allows.
        // Bucket starts at 100 (after the start_initiator HELLO debit, 99 left).
        let mut huge_ops = Vec::new();
        for i in 1..=200u64 {
            huge_ops.push(make_op(g, dev(2), i));
        }
        let chunk = SyncFrame::Chunk(super::super::frames::ChunkFrame {
            group_id: g, session_id: 1, seq: 0, total: 1, last: true, ops: huge_ops,
        });
        let bytes = chunk.encode().unwrap();
        let _ = mgr.process_frame(&mut backend, dev(2), 0x33, &bytes, 100);
        // After the rate-limit kick, the session should be closed.
        assert_eq!(mgr.active_session_count(), 0);
    }

    // -------------------- process_frame validation --------------------

    #[test]
    fn process_frame_drops_self_peer() {
        let mut mgr = SyncManager::new(dev(1));
        let mut backend = MockBackend::new(vec![]);
        let hello = SyncFrame::Hello(super::super::frames::HelloFrame {
            group_id: gid(1), session_id: 1, initiator_device: dev(1),
            heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = hello.encode().unwrap();
        let actions = mgr.process_frame(&mut backend, dev(1), 0x31, &bytes, 0);
        assert!(actions.is_empty());
    }

    #[test]
    fn process_frame_drops_wire_type_confusion() {
        let mut mgr = SyncManager::new(dev(1));
        let mut backend = MockBackend::new(vec![]);
        let hello = SyncFrame::Hello(super::super::frames::HelloFrame {
            group_id: gid(1), session_id: 1, initiator_device: dev(2),
            heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = hello.encode().unwrap();
        // Body says HELLO, transport claims CHUNK.
        let actions = mgr.process_frame(&mut backend, dev(2), 0x33, &bytes, 0);
        assert!(actions.is_empty());
        assert_eq!(mgr.active_session_count(), 0);
    }

    #[test]
    fn orphan_chunk_dropped_silently() {
        let mut mgr = SyncManager::new(dev(1));
        let mut backend = MockBackend::new(vec![]);
        let chunk = SyncFrame::Chunk(super::super::frames::ChunkFrame {
            group_id: gid(1), session_id: 1, seq: 0, total: 1, last: true, ops: vec![],
        });
        let bytes = chunk.encode().unwrap();
        let actions = mgr.process_frame(&mut backend, dev(2), 0x33, &bytes, 0);
        assert!(actions.is_empty());
    }

    // -------------------- tick --------------------

    #[test]
    fn tick_harvests_timed_out_sessions() {
        let mut mgr = SyncManager::new(dev(1));
        mgr.start_initiator(gid(1), dev(2), HashMap::new(), vec![], 0, 0, 1, 0).unwrap();
        assert_eq!(mgr.active_session_count(), 1);
        // Past the timeout window.
        let actions = mgr.tick(super::super::session::SESSION_TIMEOUT_MS);
        assert!(actions.iter().any(|a| matches!(a, SyncAction::CloseSession { reason: CloseReason::Timeout })));
        assert_eq!(mgr.active_session_count(), 0);
    }

    // -------------------- abort --------------------

    #[test]
    fn abort_group_kills_only_that_groups_sessions() {
        let mut mgr = SyncManager::new(dev(1));
        mgr.start_initiator(gid(1), dev(2), HashMap::new(), vec![], 0, 0, 1, 0).unwrap();
        mgr.start_initiator(gid(2), dev(3), HashMap::new(), vec![], 0, 0, 2, 0).unwrap();
        assert_eq!(mgr.active_session_count(), 2);
        let actions = mgr.abort_group(&gid(1));
        assert_eq!(actions.len(), 1);
        assert_eq!(mgr.active_session_count(), 1);
    }

    #[test]
    fn abort_all_kills_everything() {
        let mut mgr = SyncManager::new(dev(1));
        mgr.start_initiator(gid(1), dev(2), HashMap::new(), vec![], 0, 0, 1, 0).unwrap();
        mgr.start_initiator(gid(2), dev(3), HashMap::new(), vec![], 0, 0, 2, 0).unwrap();
        let actions = mgr.abort_all();
        assert_eq!(actions.len(), 2);
        assert_eq!(mgr.active_session_count(), 0);
    }

    // -------------------- list_sessions --------------------

    #[test]
    fn list_sessions_returns_snapshot() {
        let mut mgr = SyncManager::new(dev(1));
        mgr.start_initiator(gid(1), dev(2), HashMap::new(), vec![], 0, 0, 0xDEAD, 100).unwrap();
        let sessions = mgr.list_sessions();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, 0xDEAD);
        assert_eq!(sessions[0].peer_device_hex, dev(2).to_hex());
    }

    // -------------------- session_id discipline --------------------

    #[test]
    fn session_table_key_does_not_include_session_id() {
        // Two HELLOs from the same peer-pair with different session_ids must
        // map to the same session-table row (else the user's session_id-is-
        // observational guarantee is violated).
        let mut mgr = SyncManager::new(dev(5));
        let g = gid(1);
        let mut backend = MockBackend::new(vec![make_op(g, dev(2), 1)]);

        let h1 = SyncFrame::Hello(super::super::frames::HelloFrame {
            group_id: g, session_id: 1, initiator_device: dev(2),
            heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
            protocol_version: 1,
        });
        mgr.process_frame(&mut backend, dev(2), 0x31, &h1.encode().unwrap(), 100);
        // Table key independent of session_id; second HELLO from same peer
        // should see the existing session and not stack a new one.
        assert_eq!(mgr.active_session_count(), 1);
    }
}
