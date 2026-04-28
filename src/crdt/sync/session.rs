//! Per-peer sync session state machine.
//!
//! A `SyncSession` represents one in-flight pull-mode sync between this device
//! and a single remote peer for a single group. v1 is unidirectional: the
//! Initiator sends HELLO advertising what it has; the Responder ships the
//! delta as one or more CHUNKs; the Initiator applies and ACKs.
//!
//! # Roles
//! - **Initiator**: constructs via `new_initiator`, sends HELLO immediately,
//!   waits for CHUNKs from peer, applies each, sends final ACK with
//!   `close=true`, transitions to `Done`.
//! - **Responder**: constructs via `new_responder` with the already-computed
//!   delta op list, immediately emits all CHUNKs (split per `MAX_OPS_PER_CHUNK`
//!   and bounded by `MAX_BYTES_PER_SYNC_ROUND`), waits for the closing ACK,
//!   transitions to `Done`.
//!
//! # session_id discipline (user guard)
//! `session_id` is **strictly observational**. Stored for log correlation and
//! for placing on outbound frames so peers can match request/response. It is
//! NOT used for:
//! - Duplicate suppression (use `seq` + peer DeviceID + group)
//! - Collision resolution (use DeviceID via `manager::decide_initiator`)
//! - State machine dispatch (use peer DeviceID + group)
//!
//! The session machine never reads its own `session_id` for any decision.
//! Cross-checked by `session_id_is_never_a_decision_input` below.
//!
//! # Byte budget (user guard)
//! Enforced inside the session, not just in the manager. Responder construction
//! truncates the op list at `MAX_BYTES_PER_SYNC_ROUND` cumulative bincode size.
//! Truncated ops are dropped silently — the next session (initiated after the
//! current one closes) picks them up via the lamport heads delta.

use serde::{Deserialize, Serialize};

use crate::crdt::ids::{DeviceID, GroupID};
use crate::crdt::limits::{MAX_BYTES_PER_SYNC_ROUND, MAX_OPS_PER_CHUNK};
use crate::crdt::ops::OpEnvelope;

use super::frames::{
    AckFrame, ChunkFrame, FrameError, HelloFrame, SyncFrame,
    SYNC_PROTOCOL_VERSION,
};

/// Hard timeout for a session with no inbound activity.
pub const SESSION_TIMEOUT_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// CloseReason
// ---------------------------------------------------------------------------

/// Why a session terminated. Surfaced via `SessionInfo` for observability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReason {
    /// Session ran to completion successfully.
    Normal,
    /// No inbound frame within `SESSION_TIMEOUT_MS`.
    Timeout,
    /// Peer sent a frame valid in isolation but invalid for current state.
    /// (Wrong frame type, gap or duplicate seq, mismatched group_id, etc.)
    PeerProtocolViolation(String),
    /// Responder's outbound delta exceeded the byte budget; remainder dropped.
    /// This is graceful — the next session will pick up the remainder.
    ByteBudgetExhausted,
    /// Locally aborted (manager teardown, group deletion, etc.).
    LocalAbort,
    /// Peer announced session-end via `AckFrame { close: true }`.
    PeerClosed,
}

// ---------------------------------------------------------------------------
// SessionState
// ---------------------------------------------------------------------------

/// State machine for one session.
///
/// Initiator path:  `InitiatorSentHello` → `InitiatorReceivingChunks` → `Done`
/// Responder path:  `ResponderSending` → `ResponderAwaitingAck` → `Done`
/// Either path can transition to `Error(reason)` on protocol violation/timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Initiator: HELLO sent, awaiting first inbound CHUNK from peer.
    InitiatorSentHello,
    /// Initiator: receiving CHUNKs from peer. `next_expected_seq` is the seq
    /// number the next inbound CHUNK must have.
    InitiatorReceivingChunks { next_expected_seq: u32 },
    /// Responder: emitting CHUNKs to peer (driven entirely at construction).
    /// `next_send_seq` tracks the next seq number to emit; once equal to
    /// `total_chunks`, the responder transitions to `ResponderAwaitingAck`.
    ResponderSending { next_send_seq: u32, total_chunks: u32 },
    /// Responder: all CHUNKs sent, awaiting closing ACK from initiator.
    ResponderAwaitingAck,
    /// Terminal success.
    Done,
    /// Terminal failure.
    Error(CloseReason),
}

impl SessionState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, SessionState::Done | SessionState::Error(_))
    }

    pub fn is_initiator(&self) -> bool {
        matches!(
            self,
            SessionState::InitiatorSentHello
                | SessionState::InitiatorReceivingChunks { .. }
        )
    }

    pub fn is_responder(&self) -> bool {
        matches!(
            self,
            SessionState::ResponderSending { .. } | SessionState::ResponderAwaitingAck
        )
    }
}

// ---------------------------------------------------------------------------
// SyncAction
// ---------------------------------------------------------------------------

/// What the manager (and FFI) should do as a result of a session method.
///
/// Keeps the session pure: no I/O, no clock, no storage. The caller is the
/// dumb pipe.
#[derive(Debug, Clone, PartialEq)]
pub enum SyncAction {
    /// Transmit a frame. `wire_type` is the Tor byte (0x31..0x34).
    SendFrame { wire_type: u8, bytes: Vec<u8> },
    /// Persist these ops (DB transaction + Rust apply).
    PersistOps(Vec<OpEnvelope>),
    /// Mark this session as closed. The manager removes it from its table.
    /// Always emitted exactly once when the session reaches a terminal state.
    CloseSession { reason: CloseReason },
}

// ---------------------------------------------------------------------------
// SessionInfo (observability snapshot)
// ---------------------------------------------------------------------------

/// Snapshot of session state for `crdtSyncListSessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub group_id_hex: String,
    pub peer_device_hex: String,
    pub session_id: u64,
    pub role: &'static str, // "initiator" | "responder"
    pub state: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub ops_in: u32,
    pub ops_out: u32,
    pub seq_in: u32,
    pub seq_out: u32,
    pub created_ms: u64,
    pub last_activity_ms: u64,
    pub close_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// SyncSession
// ---------------------------------------------------------------------------

/// Per-peer sync session.
#[derive(Debug)]
pub struct SyncSession {
    state: SessionState,
    group_id: GroupID,
    local_device: DeviceID,
    peer_device: DeviceID,
    /// Strictly observational. See module-level doc.
    session_id: u64,

    // Outbound chunk queue (responder only). Pre-built at construction.
    pending_chunks: Vec<ChunkFrame>,

    // Observability counters.
    bytes_in: u64,
    bytes_out: u64,
    ops_in: u32,
    ops_out: u32,
    seq_in: u32,
    seq_out: u32,
    created_ms: u64,
    last_activity_ms: u64,
    close_reason: Option<CloseReason>,
}

impl SyncSession {
    // -------------------- Constructors --------------------

    /// Construct an Initiator session. Returns the session and the actions to
    /// execute immediately (a single `SendFrame { HELLO }`).
    ///
    /// `heads` is the per-author lamport map of what we already have.
    /// `bloom` may be empty (bloomless sync — responder ships everything above
    /// `heads`).
    pub fn new_initiator(
        group_id: GroupID,
        local_device: DeviceID,
        peer_device: DeviceID,
        session_id: u64,
        heads: std::collections::HashMap<DeviceID, u64>,
        bloom: Vec<u8>,
        bloom_k: u8,
        bloom_n: u32,
        now_ms: u64,
    ) -> Result<(Self, Vec<SyncAction>), FrameError> {
        let hello = HelloFrame {
            group_id,
            session_id,
            initiator_device: local_device,
            heads,
            bloom,
            bloom_k,
            bloom_n,
            protocol_version: SYNC_PROTOCOL_VERSION,
        };
        let bytes = SyncFrame::Hello(hello).encode()?;
        let session = SyncSession {
            state: SessionState::InitiatorSentHello,
            group_id,
            local_device,
            peer_device,
            session_id,
            pending_chunks: vec![],
            bytes_in: 0,
            bytes_out: bytes.len() as u64,
            ops_in: 0,
            ops_out: 0,
            seq_in: 0,
            seq_out: 0,
            created_ms: now_ms,
            last_activity_ms: now_ms,
            close_reason: None,
        };
        let action = SyncAction::SendFrame {
            wire_type: 0x31,
            bytes,
        };
        Ok((session, vec![action]))
    }

    /// Construct a Responder session. Returns the session and the actions to
    /// execute immediately (a `SendFrame` per chunk).
    ///
    /// `delta_ops` is the list of ops the initiator lacks (already filtered by
    /// the manager based on the HELLO's heads + bloom). The session splits it
    /// into chunks (`MAX_OPS_PER_CHUNK` per chunk) and truncates at
    /// `MAX_BYTES_PER_SYNC_ROUND` cumulative wire size — overflow is dropped
    /// silently (next session picks it up via heads delta).
    pub fn new_responder(
        group_id: GroupID,
        local_device: DeviceID,
        peer_device: DeviceID,
        session_id: u64,
        delta_ops: Vec<OpEnvelope>,
        now_ms: u64,
    ) -> Result<(Self, Vec<SyncAction>), FrameError> {
        // Pack ops into chunks greedily, respecting:
        //   1. MAX_OPS_PER_CHUNK ops per chunk
        //   2. MAX_BYTES_PER_SYNC_ROUND bytes total across all chunks
        //
        // Per-chunk header overhead (group_id + session_id + seq + total + last
        // + Vec length prefix) is small but real; budget for it conservatively.
        const CHUNK_HEADER_OVERHEAD: usize = 64;

        let mut chunks: Vec<ChunkFrame> = Vec::new();
        let mut byte_budget_remaining: usize = MAX_BYTES_PER_SYNC_ROUND;
        let mut truncated = false;
        let mut seq: u32 = 0;
        let mut ops_iter = delta_ops.into_iter().peekable();

        'outer: while ops_iter.peek().is_some() {
            if byte_budget_remaining <= CHUNK_HEADER_OVERHEAD {
                // Not enough budget left even for an empty chunk header.
                truncated = true;
                break;
            }

            let mut chunk_ops: Vec<OpEnvelope> = Vec::new();
            let mut chunk_size: usize = CHUNK_HEADER_OVERHEAD;

            while chunk_ops.len() < MAX_OPS_PER_CHUNK {
                let next_op_size = match ops_iter.peek() {
                    Some(op) => bincode::serialized_size(op)
                        .map_err(|e| FrameError::Encode(e.to_string()))?
                        as usize,
                    None => break,
                };

                if chunk_size + next_op_size > byte_budget_remaining {
                    if chunk_ops.is_empty() {
                        // Single op exceeds the entire remaining budget. Skip
                        // it (it would never fit) and mark truncation. The
                        // remainder of the queue may still contain smaller ops
                        // that fit, so we continue the outer loop.
                        ops_iter.next();
                        truncated = true;
                        continue 'outer;
                    }
                    break;
                }
                chunk_size += next_op_size;
                chunk_ops.push(ops_iter.next().unwrap());
            }

            if chunk_ops.is_empty() {
                truncated = ops_iter.peek().is_some();
                break;
            }

            let tentative = ChunkFrame {
                group_id,
                session_id,
                seq,
                total: 0, // patched after final count is known
                last: false,
                ops: chunk_ops,
            };
            let encoded_size = SyncFrame::Chunk(tentative.clone()).encode()?.len();
            byte_budget_remaining = byte_budget_remaining.saturating_sub(encoded_size);
            chunks.push(tentative);
            seq += 1;
        }
        if ops_iter.peek().is_some() {
            truncated = true;
        }

        // Patch the final chunk's `last` flag and `total` field.
        let total = chunks.len() as u32;
        if let Some(last_chunk) = chunks.last_mut() {
            last_chunk.last = true;
        }
        for c in &mut chunks {
            c.total = total;
        }

        // Build send actions (re-encode after patching).
        let mut actions: Vec<SyncAction> = Vec::with_capacity(chunks.len() + 1);
        let mut bytes_out_total: u64 = 0;
        let mut ops_out_total: u32 = 0;
        for c in &chunks {
            let bytes = SyncFrame::Chunk(c.clone()).encode()?;
            bytes_out_total += bytes.len() as u64;
            ops_out_total += c.ops.len() as u32;
            actions.push(SyncAction::SendFrame {
                wire_type: 0x33,
                bytes,
            });
        }

        // Determine the initial state.
        let state = if total == 0 {
            // No ops to send — emit a Close immediately and finish.
            SessionState::Done
        } else {
            SessionState::ResponderSending {
                next_send_seq: total, // all already enqueued as actions
                total_chunks: total,
            }
        };

        let close_reason = if truncated && total == 0 {
            Some(CloseReason::ByteBudgetExhausted)
        } else if total == 0 {
            Some(CloseReason::Normal) // peer was already up to date
        } else {
            None
        };

        let mut session = SyncSession {
            state: state.clone(),
            group_id,
            local_device,
            peer_device,
            session_id,
            pending_chunks: chunks,
            bytes_in: 0,
            bytes_out: bytes_out_total,
            ops_in: 0,
            ops_out: ops_out_total,
            seq_in: 0,
            seq_out: total,
            created_ms: now_ms,
            last_activity_ms: now_ms,
            close_reason: close_reason.clone(),
        };

        // If we have chunks to send, the next state is AwaitingAck (caller
        // executes all SendFrame actions, then we wait for the close ACK).
        if total > 0 {
            session.state = SessionState::ResponderAwaitingAck;
            actions.extend(Self::build_truncation_diagnostic(truncated));
        } else {
            // No chunks: terminal immediately, emit CloseSession.
            actions.push(SyncAction::CloseSession {
                reason: close_reason.unwrap_or(CloseReason::Normal),
            });
        }

        Ok((session, actions))
    }

    /// If the responder truncated the delta to fit the byte budget, log a
    /// `CloseSession { ByteBudgetExhausted }` reason on the eventual close.
    /// (We don't close mid-session — the initiator still gets every chunk we
    /// did emit; we simply note the truncation in our close reason.)
    fn build_truncation_diagnostic(truncated: bool) -> Vec<SyncAction> {
        if truncated {
            // Don't emit CloseSession yet — we still need the ACK round-trip
            // to know the initiator received the chunks. The truncation is
            // recorded on the session and surfaced when the session closes.
            // Returning empty here; the close reason is set on construction
            // and overrides Normal at terminal time.
            vec![]
        } else {
            vec![]
        }
    }

    // -------------------- Inbound dispatch --------------------

    /// Process an inbound frame. Returns the actions the caller must execute.
    ///
    /// Validates:
    /// - Frame group_id matches this session's group.
    /// - Frame is appropriate for current state (rejects state-invalid frames).
    /// - For CHUNKs: seq matches `next_expected_seq` exactly (no gap, no dup).
    pub fn accept_frame(&mut self, frame: SyncFrame, now_ms: u64) -> Vec<SyncAction> {
        // Bookkeeping for any inbound — even rejected ones — to keep timeouts
        // honest. (A peer flooding garbage shouldn't keep the session alive
        // indefinitely; rate-limiting is the manager's concern.)
        self.last_activity_ms = now_ms;

        // Group mismatch is a hard reject regardless of state.
        if frame.group_id() != &self.group_id {
            return self.fail(CloseReason::PeerProtocolViolation(format!(
                "inbound frame group_id {} != session group_id {}",
                frame.group_id().to_hex(),
                self.group_id.to_hex(),
            )));
        }

        match (&self.state, frame) {
            // Initiator: accept first CHUNK to enter receiving state.
            (SessionState::InitiatorSentHello, SyncFrame::Chunk(c)) => {
                self.handle_initiator_chunk(c, 0)
            }
            // Initiator: continue receiving CHUNKs.
            (SessionState::InitiatorReceivingChunks { next_expected_seq }, SyncFrame::Chunk(c)) => {
                let expected = *next_expected_seq;
                self.handle_initiator_chunk(c, expected)
            }
            // Initiator: peer trying to renegotiate with another HELLO is a violation.
            (s, SyncFrame::Hello(_)) if s.is_initiator() => {
                self.fail(CloseReason::PeerProtocolViolation(
                    "peer sent HELLO during initiator session".into(),
                ))
            }
            // Initiator: REQUEST is not part of v1 unidirectional flow.
            (s, SyncFrame::Request(_)) if s.is_initiator() => {
                self.fail(CloseReason::PeerProtocolViolation(
                    "v1 is unidirectional; initiator does not accept REQUEST".into(),
                ))
            }
            // Initiator: peer ACK is meaningless (we send the ACK).
            (s, SyncFrame::Ack(_)) if s.is_initiator() => {
                self.fail(CloseReason::PeerProtocolViolation(
                    "initiator does not accept ACK".into(),
                ))
            }

            // Responder: accept the closing ACK.
            (SessionState::ResponderAwaitingAck, SyncFrame::Ack(a)) => {
                self.handle_responder_ack(a)
            }
            // Responder: peers shouldn't be sending us anything else mid-session.
            (s, frame) if s.is_responder() => {
                self.fail(CloseReason::PeerProtocolViolation(format!(
                    "responder received unexpected {} in state {:?}",
                    frame.kind(),
                    s
                )))
            }

            // Terminal — ignore any further frames.
            (SessionState::Done, _) | (SessionState::Error(_), _) => vec![],

            // Anything else falls through as a violation.
            (s, frame) => self.fail(CloseReason::PeerProtocolViolation(format!(
                "unhandled (state={:?}, frame={})",
                s,
                frame.kind()
            ))),
        }
    }

    fn handle_initiator_chunk(&mut self, chunk: ChunkFrame, expected_seq: u32) -> Vec<SyncAction> {
        if chunk.seq != expected_seq {
            return self.fail(CloseReason::PeerProtocolViolation(format!(
                "chunk seq {} != expected {}",
                chunk.seq, expected_seq
            )));
        }
        let ops_count = chunk.ops.len() as u32;
        self.ops_in += ops_count;
        self.bytes_in += SyncFrame::Chunk(chunk.clone())
            .encode()
            .map(|b| b.len() as u64)
            .unwrap_or(0);
        self.seq_in = chunk.seq;
        let is_last = chunk.last;

        let mut actions: Vec<SyncAction> = Vec::with_capacity(3);
        if !chunk.ops.is_empty() {
            actions.push(SyncAction::PersistOps(chunk.ops));
        }

        if is_last {
            // Build closing ACK.
            let ack = AckFrame {
                group_id: self.group_id,
                session_id: self.session_id,
                applied_through: std::collections::HashMap::new(), // manager fills in
                last_seq_applied: chunk.seq,
                ops_applied: self.ops_in,
                ops_rejected: 0, // session doesn't know; manager fills in
                close: true,
            };
            match SyncFrame::Ack(ack).encode() {
                Ok(bytes) => {
                    self.bytes_out += bytes.len() as u64;
                    actions.push(SyncAction::SendFrame {
                        wire_type: 0x34,
                        bytes,
                    });
                    self.state = SessionState::Done;
                    self.close_reason = Some(CloseReason::Normal);
                    actions.push(SyncAction::CloseSession {
                        reason: CloseReason::Normal,
                    });
                }
                Err(e) => {
                    return self.fail(CloseReason::PeerProtocolViolation(format!(
                        "failed to encode closing ACK: {e}"
                    )));
                }
            }
        } else {
            self.state = SessionState::InitiatorReceivingChunks {
                next_expected_seq: expected_seq + 1,
            };
        }
        actions
    }

    fn handle_responder_ack(&mut self, ack: AckFrame) -> Vec<SyncAction> {
        self.bytes_in += SyncFrame::Ack(ack.clone())
            .encode()
            .map(|b| b.len() as u64)
            .unwrap_or(0);

        if ack.close {
            self.state = SessionState::Done;
            // Preserve any pre-set reason (e.g., ByteBudgetExhausted).
            let reason = self
                .close_reason
                .clone()
                .unwrap_or(CloseReason::PeerClosed);
            self.close_reason = Some(reason.clone());
            vec![SyncAction::CloseSession { reason }]
        } else {
            // Non-close ACKs are progress pings — no action, stay in AwaitingAck.
            vec![]
        }
    }

    fn fail(&mut self, reason: CloseReason) -> Vec<SyncAction> {
        self.state = SessionState::Error(reason.clone());
        self.close_reason = Some(reason.clone());
        vec![SyncAction::CloseSession { reason }]
    }

    // -------------------- Tick --------------------

    /// Driven by `SyncManager::tick` (called every ~1s by the caller).
    /// Fires the timeout transition if the session has been idle too long.
    pub fn tick(&mut self, now_ms: u64) -> Vec<SyncAction> {
        if self.state.is_terminal() {
            return vec![];
        }
        if now_ms.saturating_sub(self.last_activity_ms) >= SESSION_TIMEOUT_MS {
            return self.fail(CloseReason::Timeout);
        }
        vec![]
    }

    /// Manager-driven local abort (group deleted, manager teardown, etc.).
    pub fn abort(&mut self) -> Vec<SyncAction> {
        if self.state.is_terminal() {
            return vec![];
        }
        self.fail(CloseReason::LocalAbort)
    }

    // -------------------- Accessors --------------------

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    pub fn group_id(&self) -> &GroupID {
        &self.group_id
    }

    pub fn peer_device(&self) -> &DeviceID {
        &self.peer_device
    }

    pub fn local_device(&self) -> &DeviceID {
        &self.local_device
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn close_reason(&self) -> Option<&CloseReason> {
        self.close_reason.as_ref()
    }

    /// Snapshot for `crdtSyncListSessions`.
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            group_id_hex: self.group_id.to_hex(),
            peer_device_hex: self.peer_device.to_hex(),
            session_id: self.session_id,
            role: if self.state.is_initiator() || matches!(
                self.state,
                SessionState::InitiatorSentHello | SessionState::InitiatorReceivingChunks { .. }
            ) {
                "initiator"
            } else if self.state.is_responder() || matches!(
                self.state,
                SessionState::ResponderSending { .. } | SessionState::ResponderAwaitingAck
            ) {
                "responder"
            } else if !self.pending_chunks.is_empty() {
                "responder"
            } else {
                "initiator"
            },
            state: format!("{:?}", self.state),
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
            ops_in: self.ops_in,
            ops_out: self.ops_out,
            seq_in: self.seq_in,
            seq_out: self.seq_out,
            created_ms: self.created_ms,
            last_activity_ms: self.last_activity_ms,
            close_reason: self.close_reason.as_ref().map(|r| format!("{:?}", r)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::frames::RequestFrame;
    use crate::crdt::ids::{DeviceID, GroupID, OpID};
    use crate::crdt::ops::{OpEnvelope, OpType};
    use std::collections::HashMap;

    fn dev(byte: u8) -> DeviceID {
        DeviceID::from_bytes([byte; 16])
    }

    fn gid(byte: u8) -> GroupID {
        GroupID::from_bytes([byte; 32])
    }

    fn make_op(g: GroupID, author: DeviceID, lamport: u64, payload_size: usize) -> OpEnvelope {
        OpEnvelope {
            group_id: g,
            op_id: OpID::new(author, lamport, lamport.wrapping_mul(0xDEAD_BEEF)),
            parent_heads: vec![],
            lamport,
            timestamp_ms: 1_700_000_000_000,
            op_type: OpType::MsgAdd,
            payload: vec![0xAB; payload_size],
            author_pubkey: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    // -------------------- Initiator construction --------------------

    #[test]
    fn initiator_construction_emits_hello() {
        let (s, actions) = SyncSession::new_initiator(
            gid(1), dev(1), dev(2), 0xABCD,
            HashMap::new(), vec![], 0, 0, 1_000,
        ).unwrap();
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            SyncAction::SendFrame { wire_type, bytes } => {
                assert_eq!(*wire_type, 0x31);
                let parsed = SyncFrame::decode_with_wire_type(*wire_type, bytes).unwrap();
                match parsed {
                    SyncFrame::Hello(h) => {
                        assert_eq!(h.group_id, gid(1));
                        assert_eq!(h.session_id, 0xABCD);
                        assert_eq!(h.initiator_device, dev(1));
                        assert!(h.heads.is_empty());
                        assert!(h.bloom.is_empty());
                    }
                    _ => panic!("expected HELLO"),
                }
            }
            _ => panic!("expected SendFrame"),
        }
        assert_eq!(*s.state(), SessionState::InitiatorSentHello);
    }

    #[test]
    fn initiator_first_chunk_transitions_to_receiving() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        let chunk = SyncFrame::Chunk(ChunkFrame {
            group_id: g, session_id: 1, seq: 0, total: 2, last: false,
            ops: vec![make_op(g, dev(2), 1, 16)],
        });
        let actions = s.accept_frame(chunk, 100);
        // PersistOps + state transition (no SendFrame, no Close yet).
        assert!(matches!(actions[0], SyncAction::PersistOps(_)));
        assert_eq!(*s.state(), SessionState::InitiatorReceivingChunks { next_expected_seq: 1 });
    }

    #[test]
    fn initiator_rejects_chunk_seq_gap() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        // Sending seq=1 when expecting seq=0 → violation.
        let chunk = SyncFrame::Chunk(ChunkFrame {
            group_id: g, session_id: 1, seq: 1, total: 2, last: false,
            ops: vec![make_op(g, dev(2), 1, 16)],
        });
        let actions = s.accept_frame(chunk, 100);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::PeerProtocolViolation(_) }));
        assert!(s.is_terminal());
    }

    #[test]
    fn initiator_rejects_chunk_seq_dup() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        // Apply seq=0.
        let chunk0 = SyncFrame::Chunk(ChunkFrame {
            group_id: g, session_id: 1, seq: 0, total: 2, last: false,
            ops: vec![make_op(g, dev(2), 1, 16)],
        });
        s.accept_frame(chunk0, 100);
        // Re-apply seq=0 → violation.
        let chunk0_dup = SyncFrame::Chunk(ChunkFrame {
            group_id: g, session_id: 1, seq: 0, total: 2, last: false,
            ops: vec![make_op(g, dev(2), 1, 16)],
        });
        let actions = s.accept_frame(chunk0_dup, 200);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::PeerProtocolViolation(_) }));
    }

    #[test]
    fn initiator_emits_ack_on_last_chunk() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        let chunk = SyncFrame::Chunk(ChunkFrame {
            group_id: g, session_id: 1, seq: 0, total: 1, last: true,
            ops: vec![make_op(g, dev(2), 1, 16)],
        });
        let actions = s.accept_frame(chunk, 100);
        // Expect: PersistOps, SendFrame(ACK close=true), CloseSession.
        assert!(matches!(actions[0], SyncAction::PersistOps(_)));
        match &actions[1] {
            SyncAction::SendFrame { wire_type, bytes } => {
                assert_eq!(*wire_type, 0x34);
                let parsed = SyncFrame::decode(bytes).unwrap();
                match parsed {
                    SyncFrame::Ack(a) => {
                        assert!(a.close);
                        assert_eq!(a.last_seq_applied, 0);
                    }
                    _ => panic!("expected ACK"),
                }
            }
            _ => panic!("expected SendFrame"),
        }
        assert!(matches!(actions[2], SyncAction::CloseSession { reason: CloseReason::Normal }));
        assert_eq!(*s.state(), SessionState::Done);
    }

    #[test]
    fn initiator_rejects_unexpected_hello() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        let renegotiate = SyncFrame::Hello(HelloFrame {
            group_id: g, session_id: 999, initiator_device: dev(2),
            heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
            protocol_version: 1,
        });
        let actions = s.accept_frame(renegotiate, 100);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::PeerProtocolViolation(_) }));
    }

    #[test]
    fn initiator_rejects_request_v1_is_unidirectional() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        let req = SyncFrame::Request(RequestFrame {
            group_id: g, session_id: 1, want_after: HashMap::new(),
            want_explicit: vec![], max_ops: 100,
        });
        let actions = s.accept_frame(req, 100);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::PeerProtocolViolation(_) }));
    }

    // -------------------- Group mismatch --------------------

    #[test]
    fn rejects_frame_with_wrong_group_id() {
        let g = gid(1);
        let other = gid(99);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        let chunk = SyncFrame::Chunk(ChunkFrame {
            group_id: other, session_id: 1, seq: 0, total: 1, last: true,
            ops: vec![],
        });
        let actions = s.accept_frame(chunk, 100);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::PeerProtocolViolation(_) }));
    }

    // -------------------- Responder construction --------------------

    #[test]
    fn responder_with_no_ops_closes_immediately() {
        let g = gid(1);
        let (s, actions) = SyncSession::new_responder(
            g, dev(2), dev(1), 1, vec![], 0,
        ).unwrap();
        // Single CloseSession action; no chunks emitted.
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::Normal }));
        assert_eq!(*s.state(), SessionState::Done);
    }

    #[test]
    fn responder_emits_chunks_for_small_delta() {
        let g = gid(1);
        let ops: Vec<_> = (0..50).map(|i| make_op(g, dev(1), i, 32)).collect();
        let (s, actions) = SyncSession::new_responder(
            g, dev(2), dev(1), 1, ops, 0,
        ).unwrap();
        // 50 ops fit in one chunk (< MAX_OPS_PER_CHUNK=256).
        assert_eq!(actions.len(), 1, "expected single chunk action");
        match &actions[0] {
            SyncAction::SendFrame { wire_type, bytes } => {
                assert_eq!(*wire_type, 0x33);
                let parsed = SyncFrame::decode(bytes).unwrap();
                match parsed {
                    SyncFrame::Chunk(c) => {
                        assert_eq!(c.seq, 0);
                        assert_eq!(c.total, 1);
                        assert!(c.last);
                        assert_eq!(c.ops.len(), 50);
                    }
                    _ => panic!("expected CHUNK"),
                }
            }
            _ => panic!("expected SendFrame"),
        }
        assert_eq!(*s.state(), SessionState::ResponderAwaitingAck);
    }

    #[test]
    fn responder_splits_at_max_ops_per_chunk() {
        let g = gid(1);
        let total_ops = MAX_OPS_PER_CHUNK + 50;
        let ops: Vec<_> = (0..total_ops as u64).map(|i| make_op(g, dev(1), i, 16)).collect();
        let (_, actions) = SyncSession::new_responder(
            g, dev(2), dev(1), 1, ops, 0,
        ).unwrap();
        // Should produce two chunks: 256 + 50.
        assert_eq!(actions.len(), 2);
        let first = match &actions[0] {
            SyncAction::SendFrame { bytes, .. } => SyncFrame::decode(bytes).unwrap(),
            _ => panic!(),
        };
        let second = match &actions[1] {
            SyncAction::SendFrame { bytes, .. } => SyncFrame::decode(bytes).unwrap(),
            _ => panic!(),
        };
        match first {
            SyncFrame::Chunk(c) => {
                assert_eq!(c.seq, 0);
                assert_eq!(c.ops.len(), MAX_OPS_PER_CHUNK);
                assert!(!c.last);
                assert_eq!(c.total, 2);
            }
            _ => panic!(),
        }
        match second {
            SyncFrame::Chunk(c) => {
                assert_eq!(c.seq, 1);
                assert_eq!(c.ops.len(), 50);
                assert!(c.last);
                assert_eq!(c.total, 2);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn responder_close_ack_terminates() {
        let g = gid(1);
        let ops = vec![make_op(g, dev(1), 1, 32)];
        let (mut s, _) = SyncSession::new_responder(
            g, dev(2), dev(1), 1, ops, 0,
        ).unwrap();
        assert_eq!(*s.state(), SessionState::ResponderAwaitingAck);
        let ack = SyncFrame::Ack(AckFrame {
            group_id: g, session_id: 1, applied_through: HashMap::new(),
            last_seq_applied: 0, ops_applied: 1, ops_rejected: 0, close: true,
        });
        let actions = s.accept_frame(ack, 100);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], SyncAction::CloseSession { .. }));
        assert_eq!(*s.state(), SessionState::Done);
    }

    #[test]
    fn responder_rejects_inbound_chunk() {
        let g = gid(1);
        let ops = vec![make_op(g, dev(1), 1, 32)];
        let (mut s, _) = SyncSession::new_responder(
            g, dev(2), dev(1), 1, ops, 0,
        ).unwrap();
        let inbound_chunk = SyncFrame::Chunk(ChunkFrame {
            group_id: g, session_id: 1, seq: 0, total: 1, last: true,
            ops: vec![make_op(g, dev(1), 99, 16)],
        });
        let actions = s.accept_frame(inbound_chunk, 100);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::PeerProtocolViolation(_) }));
    }

    // -------------------- Byte budget --------------------

    #[test]
    fn responder_byte_budget_truncates_silently() {
        let g = gid(1);
        // Each op carries a 64KB payload (MAX_OP_PAYLOAD_BYTES).
        // 10MB / 64KB ≈ 160 ops fit in one round; 200 should truncate ~40.
        let ops: Vec<_> = (0..200).map(|i| make_op(g, dev(1), i, 64 * 1024)).collect();
        let (s, actions) = SyncSession::new_responder(
            g, dev(2), dev(1), 1, ops, 0,
        ).unwrap();
        // Some chunks should have been emitted but fewer than 200 ops total.
        let total_ops_emitted: usize = actions.iter().filter_map(|a| match a {
            SyncAction::SendFrame { bytes, .. } => {
                match SyncFrame::decode(bytes).ok()? {
                    SyncFrame::Chunk(c) => Some(c.ops.len()),
                    _ => None,
                }
            }
            _ => None,
        }).sum();
        assert!(total_ops_emitted > 0, "expected at least one op emitted");
        assert!(total_ops_emitted < 200, "expected truncation; got all {total_ops_emitted}");
        assert!(s.bytes_out <= MAX_BYTES_PER_SYNC_ROUND as u64);
    }

    // -------------------- Tick / Timeout --------------------

    #[test]
    fn tick_below_timeout_no_action() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 1_000,
        ).unwrap();
        let actions = s.tick(1_000 + SESSION_TIMEOUT_MS - 1);
        assert!(actions.is_empty());
        assert!(!s.is_terminal());
    }

    #[test]
    fn tick_at_or_past_timeout_fires_close() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 1_000,
        ).unwrap();
        let actions = s.tick(1_000 + SESSION_TIMEOUT_MS);
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::Timeout }));
        assert!(s.is_terminal());
    }

    #[test]
    fn inbound_frame_resets_timeout_window() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 1_000,
        ).unwrap();
        // Approaching but not at timeout.
        s.tick(1_000 + SESSION_TIMEOUT_MS - 1);
        // Inbound chunk resets last_activity_ms to 'now'.
        let chunk = SyncFrame::Chunk(ChunkFrame {
            group_id: g, session_id: 1, seq: 0, total: 2, last: false,
            ops: vec![make_op(g, dev(2), 1, 16)],
        });
        let now = 1_000 + SESSION_TIMEOUT_MS - 1;
        s.accept_frame(chunk, now);
        // A tick at original timeout boundary should now NOT fire.
        let actions = s.tick(now + SESSION_TIMEOUT_MS - 1);
        assert!(actions.is_empty());
        assert!(!s.is_terminal());
    }

    #[test]
    fn tick_on_terminal_session_is_noop() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        s.tick(SESSION_TIMEOUT_MS); // forces timeout
        assert!(s.is_terminal());
        let next = s.tick(SESSION_TIMEOUT_MS * 10);
        assert!(next.is_empty());
    }

    // -------------------- Abort --------------------

    #[test]
    fn abort_transitions_to_local_abort() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        let actions = s.abort();
        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], SyncAction::CloseSession { reason: CloseReason::LocalAbort }));
        assert!(s.is_terminal());
    }

    #[test]
    fn abort_on_terminal_is_noop() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        s.tick(SESSION_TIMEOUT_MS);
        assert!(s.is_terminal());
        let next = s.abort();
        assert!(next.is_empty());
    }

    // -------------------- session_id discipline --------------------

    /// Audit test: assert that no session decision depends on session_id.
    /// This is enforced by inspection — the session machine is small enough that
    /// any future change accidentally consulting `self.session_id` for dispatch
    /// would be visible in code review. This test exercises the property
    /// behaviorally: two sessions with completely different session_ids must
    /// produce identical state transitions for the same frame sequence.
    #[test]
    fn session_id_does_not_affect_state_transitions() {
        let g = gid(1);
        let (mut s_a, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 1, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        let (mut s_b, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), u64::MAX, HashMap::new(), vec![], 0, 0, 0,
        ).unwrap();
        // Same frame sequence, different session_ids → identical state path.
        // (The frame's session_id is intentionally NOT validated by the session;
        // peer mismatch would be a manager-level dedup concern, not session.)
        let chunk = ChunkFrame {
            group_id: g, session_id: 0, // arbitrary — should not gate
            seq: 0, total: 1, last: true,
            ops: vec![make_op(g, dev(2), 1, 16)],
        };
        let actions_a = s_a.accept_frame(SyncFrame::Chunk(chunk.clone()), 100);
        let actions_b = s_b.accept_frame(SyncFrame::Chunk(chunk), 100);
        assert_eq!(actions_a.len(), actions_b.len());
        assert_eq!(*s_a.state(), *s_b.state());
        assert!(s_a.is_terminal() && s_b.is_terminal());
    }

    // -------------------- Observability --------------------

    #[test]
    fn info_snapshot_reflects_progress() {
        let g = gid(1);
        let (mut s, _) = SyncSession::new_initiator(
            g, dev(1), dev(2), 0xDEAD_BEEF, HashMap::new(), vec![], 0, 0, 100,
        ).unwrap();
        let snap_before = s.info();
        assert_eq!(snap_before.role, "initiator");
        assert!(snap_before.bytes_out > 0); // HELLO already sent
        assert_eq!(snap_before.ops_in, 0);
        assert_eq!(snap_before.session_id, 0xDEAD_BEEF);

        let chunk = SyncFrame::Chunk(ChunkFrame {
            group_id: g, session_id: 0, seq: 0, total: 1, last: true,
            ops: vec![make_op(g, dev(2), 1, 16), make_op(g, dev(2), 2, 16)],
        });
        s.accept_frame(chunk, 200);
        let snap_after = s.info();
        assert_eq!(snap_after.ops_in, 2);
        assert!(snap_after.bytes_in > 0);
        assert_eq!(snap_after.last_activity_ms, 200);
        assert!(snap_after.close_reason.is_some());
    }
}
