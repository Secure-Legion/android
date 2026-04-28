/// Sync protocol wire frames.
///
/// All frames are bincode-serialized; the `SyncFrame` enum wraps the four
/// concrete types and provides the dispatch tag. Bincode encodes the variant
/// as a 4-byte u32 prefix — adequate for v1; can be tightened to a single
/// byte tag later without changing the public API.
///
/// # Wire mapping (Tor)
/// - `0x31` HELLO   → `SyncFrame::Hello(HelloFrame)`
/// - `0x32` REQUEST → `SyncFrame::Request(RequestFrame)`
/// - `0x33` CHUNK   → `SyncFrame::Chunk(ChunkFrame)`
/// - `0x34` ACK     → `SyncFrame::Ack(AckFrame)`
///
/// The Kotlin/Swift caller must NOT inspect frame bodies. It hands the raw
/// bytes to `SyncManager::process_frame(group_id, peer, bytes)` and receives
/// a `Vec<SyncAction>` back. Each action contains the wire type + bytes for
/// outbound frames.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use crate::crdt::ids::{DeviceID, GroupID, OpID};
use crate::crdt::ops::OpEnvelope;

/// Current sync protocol version. Bump only on wire-incompatible changes.
pub const SYNC_PROTOCOL_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum FrameError {
    #[error("Bincode serialization failed: {0}")]
    Encode(String),

    #[error("Bincode deserialization failed: {0}")]
    Decode(String),

    #[error("Frame size {size} exceeds limit {max}")]
    TooLarge { size: usize, max: usize },

    #[error("Unsupported sync protocol version: got {got}, expected <= {max}")]
    UnsupportedVersion { got: u8, max: u8 },

    #[error("Frame group_id mismatch: expected {expected}, got {got}")]
    GroupMismatch { expected: String, got: String },
}

// ---------------------------------------------------------------------------
// HelloFrame — initiator advertises heads + bloom of known op_ids
// ---------------------------------------------------------------------------

/// First frame of a sync session.
///
/// The initiator publishes:
/// - `heads`: per-author lamport floor — "I have everything <= heads[author]
///   from this author."
/// - `bloom`: a bloom filter over op_ids the initiator already has, for
///   detecting concurrent ops above the lamport floor without enumerating them.
///   Empty (`bloom.is_empty()`) when the group is small enough that lamport
///   heads are sufficient.
///
/// The responder uses heads + bloom to compute a delta and replies with a
/// REQUEST (asking for explicit ops it lacks) or directly with CHUNKs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelloFrame {
    pub group_id: GroupID,
    /// Random per-session identifier. Used by both peers to correlate frames
    /// and by the dual-init collision rule (lower DeviceID wins; session_id
    /// is observability-only, not a tiebreaker).
    pub session_id: u64,
    pub initiator_device: DeviceID,
    /// Per-author lamport heads from the initiator's perspective.
    /// `heads.get(author)` is the highest lamport this peer has applied
    /// from `author`. Missing key = 0 (peer has nothing from this author).
    pub heads: HashMap<DeviceID, u64>,
    /// Bloom filter bytes. Empty when no bloom is in use.
    pub bloom: Vec<u8>,
    /// Number of hash functions used for the bloom (0 if bloom is empty).
    pub bloom_k: u8,
    /// Estimated number of items in the bloom (for receiver to compute
    /// expected false-positive rate). 0 if bloom is empty.
    pub bloom_n: u32,
    pub protocol_version: u8,
}

// ---------------------------------------------------------------------------
// RequestFrame — explicit op pull
// ---------------------------------------------------------------------------

/// Sent by either peer in response to HELLO (or as a follow-up if the first
/// CHUNK round wasn't enough).
///
/// Two complementary cursor mechanisms:
/// - `want_after`: "give me ops with lamport > want_after[author] from author."
///   This is the bulk-delta path.
/// - `want_explicit`: a list of OpIDs the requester has identified as missing
///   (typically via the bloom on HELLO). Used to fetch concurrent ops above
///   the lamport floor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestFrame {
    pub group_id: GroupID,
    pub session_id: u64,
    pub want_after: HashMap<DeviceID, u64>,
    pub want_explicit: Vec<OpID>,
    /// Requester-side cap on how many ops to send back. Responder enforces
    /// `min(this, MAX_OPS_PER_SYNC_ROUND)`.
    pub max_ops: u32,
}

// ---------------------------------------------------------------------------
// ChunkFrame — a batch of ops in a sync stream
// ---------------------------------------------------------------------------

/// One batch of ops in a sync session.
///
/// `seq` is protocol-critical. Receivers MUST:
/// - Track `next_expected_seq` (starting at 0).
/// - Drop chunks where `seq < next_expected_seq` as duplicates.
/// - Treat `seq > next_expected_seq` as a gap and request retransmit.
/// - Honor `last == true` only when `seq == next_expected_seq`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChunkFrame {
    pub group_id: GroupID,
    pub session_id: u64,
    /// Monotonic sequence number within this session, starting at 0.
    pub seq: u32,
    /// Total chunks the sender expects to emit (0 if unknown — streaming mode).
    /// Receivers use this for progress estimation only; correctness relies on `last`.
    pub total: u32,
    /// True only for the final chunk of this transmission from this sender.
    pub last: bool,
    pub ops: Vec<OpEnvelope>,
}

// ---------------------------------------------------------------------------
// AckFrame — receiver confirms apply progress
// ---------------------------------------------------------------------------

/// Acknowledgment of applied chunks. Sent periodically by the receiver and
/// always once at session end.
///
/// `applied_through` is the receiver's heads AFTER applying the chunks in this
/// session. The sender uses this to (a) confirm convergence, (b) detect that
/// the receiver is behind on a specific author and re-prepare a follow-up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AckFrame {
    pub group_id: GroupID,
    pub session_id: u64,
    pub applied_through: HashMap<DeviceID, u64>,
    /// Highest contiguous chunk seq applied so far.
    pub last_seq_applied: u32,
    /// Number of ops actually applied in this session (excludes duplicates).
    pub ops_applied: u32,
    /// Number of ops rejected (sig fail, schema fail, membership gate).
    pub ops_rejected: u32,
    /// True = receiver is closing the session (final ACK).
    pub close: bool,
}

// ---------------------------------------------------------------------------
// SyncFrame wrapper enum — the on-wire dispatchable type
// ---------------------------------------------------------------------------

/// The unified sync wire type. All inbound bytes deserialize into this enum.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncFrame {
    Hello(HelloFrame),
    Request(RequestFrame),
    Chunk(ChunkFrame),
    Ack(AckFrame),
}

impl SyncFrame {
    /// Bincode-encode the frame.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        bincode::serialize(self).map_err(|e| FrameError::Encode(e.to_string()))
    }

    /// Bincode-decode the frame.
    ///
    /// Performs only structural validation (bincode parse). Semantic rejection
    /// (wrong group, stale session, state-machine mismatch) is the manager's job.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        bincode::deserialize(bytes).map_err(|e| FrameError::Decode(e.to_string()))
    }

    /// Bincode-decode AND verify the parsed variant matches the transport
    /// wire-type byte. This is the entrypoint the FFI/JNI layer must use.
    ///
    /// Protects against transport-byte confusion: a peer can't claim
    /// `wire_type = 0x31` (HELLO) and send bytes that bincode-parse as a
    /// `ChunkFrame`. The transport byte is authoritative for dispatch; if
    /// the body's variant tag disagrees, we reject.
    pub fn decode_with_wire_type(wire_type: u8, bytes: &[u8]) -> Result<Self, FrameError> {
        let frame = Self::decode(bytes)?;
        let parsed_wt = frame.wire_type();
        if parsed_wt != wire_type {
            return Err(FrameError::Decode(format!(
                "wire_type mismatch: transport said 0x{:02x}, body parsed as {} (0x{:02x})",
                wire_type, frame.kind(), parsed_wt,
            )));
        }
        Ok(frame)
    }

    /// Map to the Tor wire-type byte. Used by callers when constructing
    /// outbound transport frames.
    pub fn wire_type(&self) -> u8 {
        match self {
            SyncFrame::Hello(_) => 0x31,
            SyncFrame::Request(_) => 0x32,
            SyncFrame::Chunk(_) => 0x33,
            SyncFrame::Ack(_) => 0x34,
        }
    }

    /// The group this frame is targeted at.
    pub fn group_id(&self) -> &GroupID {
        match self {
            SyncFrame::Hello(f) => &f.group_id,
            SyncFrame::Request(f) => &f.group_id,
            SyncFrame::Chunk(f) => &f.group_id,
            SyncFrame::Ack(f) => &f.group_id,
        }
    }

    /// The session id this frame belongs to.
    pub fn session_id(&self) -> u64 {
        match self {
            SyncFrame::Hello(f) => f.session_id,
            SyncFrame::Request(f) => f.session_id,
            SyncFrame::Chunk(f) => f.session_id,
            SyncFrame::Ack(f) => f.session_id,
        }
    }

    /// Short label for logs/observability.
    pub fn kind(&self) -> &'static str {
        match self {
            SyncFrame::Hello(_) => "HELLO",
            SyncFrame::Request(_) => "REQUEST",
            SyncFrame::Chunk(_) => "CHUNK",
            SyncFrame::Ack(_) => "ACK",
        }
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

    fn dev(byte: u8) -> DeviceID {
        DeviceID::from_bytes([byte; 16])
    }

    fn gid(byte: u8) -> GroupID {
        GroupID::from_bytes([byte; 32])
    }

    fn make_envelope(group: GroupID, author: DeviceID, lamport: u64) -> OpEnvelope {
        OpEnvelope {
            group_id: group,
            op_id: OpID::new(author, lamport, 0xDEAD_BEEF),
            parent_heads: vec![],
            lamport,
            timestamp_ms: 1_700_000_000_000,
            op_type: OpType::MsgAdd,
            payload: vec![1, 2, 3, 4, 5],
            author_pubkey: [0u8; 32],
            signature: [0u8; 64],
        }
    }

    // ------- HelloFrame -------

    #[test]
    fn hello_roundtrip_minimal() {
        let frame = HelloFrame {
            group_id: gid(1),
            session_id: 0xABCD_EF00,
            initiator_device: dev(7),
            heads: HashMap::new(),
            bloom: vec![],
            bloom_k: 0,
            bloom_n: 0,
            protocol_version: SYNC_PROTOCOL_VERSION,
        };
        let wrapped = SyncFrame::Hello(frame.clone());
        let bytes = wrapped.encode().unwrap();
        let decoded = SyncFrame::decode(&bytes).unwrap();
        assert_eq!(wrapped, decoded);
        match decoded {
            SyncFrame::Hello(h) => assert_eq!(h, frame),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn hello_roundtrip_with_heads_and_bloom() {
        let mut heads = HashMap::new();
        heads.insert(dev(1), 100);
        heads.insert(dev(2), 250);
        heads.insert(dev(3), 0);

        let frame = HelloFrame {
            group_id: gid(99),
            session_id: u64::MAX,
            initiator_device: dev(1),
            heads,
            bloom: vec![0xFF; 512],
            bloom_k: 5,
            bloom_n: 2_500,
            protocol_version: SYNC_PROTOCOL_VERSION,
        };
        let bytes = SyncFrame::Hello(frame.clone()).encode().unwrap();
        let decoded = SyncFrame::decode(&bytes).unwrap();
        assert_eq!(SyncFrame::Hello(frame), decoded);
    }

    #[test]
    fn hello_wire_type_is_0x31() {
        let f = SyncFrame::Hello(HelloFrame {
            group_id: gid(0),
            session_id: 0,
            initiator_device: dev(0),
            heads: HashMap::new(),
            bloom: vec![],
            bloom_k: 0,
            bloom_n: 0,
            protocol_version: SYNC_PROTOCOL_VERSION,
        });
        assert_eq!(f.wire_type(), 0x31);
        assert_eq!(f.kind(), "HELLO");
    }

    // ------- RequestFrame -------

    #[test]
    fn request_roundtrip_want_after_only() {
        let mut want = HashMap::new();
        want.insert(dev(1), 50);
        want.insert(dev(2), 0);

        let frame = RequestFrame {
            group_id: gid(2),
            session_id: 0x1234,
            want_after: want,
            want_explicit: vec![],
            max_ops: 1000,
        };
        let bytes = SyncFrame::Request(frame.clone()).encode().unwrap();
        let decoded = SyncFrame::decode(&bytes).unwrap();
        assert_eq!(SyncFrame::Request(frame), decoded);
    }

    #[test]
    fn request_roundtrip_want_explicit() {
        let frame = RequestFrame {
            group_id: gid(3),
            session_id: 7,
            want_after: HashMap::new(),
            want_explicit: vec![
                OpID::new(dev(1), 10, 0xAA),
                OpID::new(dev(2), 11, 0xBB),
                OpID::new(dev(3), 12, 0xCC),
            ],
            max_ops: 256,
        };
        let bytes = SyncFrame::Request(frame.clone()).encode().unwrap();
        assert_eq!(SyncFrame::decode(&bytes).unwrap(), SyncFrame::Request(frame));
    }

    #[test]
    fn request_wire_type_is_0x32() {
        let f = SyncFrame::Request(RequestFrame {
            group_id: gid(0),
            session_id: 0,
            want_after: HashMap::new(),
            want_explicit: vec![],
            max_ops: 0,
        });
        assert_eq!(f.wire_type(), 0x32);
        assert_eq!(f.kind(), "REQUEST");
    }

    // ------- ChunkFrame -------

    #[test]
    fn chunk_roundtrip_empty() {
        let frame = ChunkFrame {
            group_id: gid(4),
            session_id: 42,
            seq: 0,
            total: 1,
            last: true,
            ops: vec![],
        };
        let bytes = SyncFrame::Chunk(frame.clone()).encode().unwrap();
        assert_eq!(SyncFrame::decode(&bytes).unwrap(), SyncFrame::Chunk(frame));
    }

    #[test]
    fn chunk_roundtrip_with_ops() {
        let g = gid(5);
        let frame = ChunkFrame {
            group_id: g,
            session_id: 100,
            seq: 3,
            total: 10,
            last: false,
            ops: vec![
                make_envelope(g, dev(1), 1),
                make_envelope(g, dev(1), 2),
                make_envelope(g, dev(2), 1),
            ],
        };
        let bytes = SyncFrame::Chunk(frame.clone()).encode().unwrap();
        let decoded = SyncFrame::decode(&bytes).unwrap();
        assert_eq!(SyncFrame::Chunk(frame), decoded);
    }

    #[test]
    fn chunk_wire_type_is_0x33() {
        let f = SyncFrame::Chunk(ChunkFrame {
            group_id: gid(0),
            session_id: 0,
            seq: 0,
            total: 0,
            last: false,
            ops: vec![],
        });
        assert_eq!(f.wire_type(), 0x33);
        assert_eq!(f.kind(), "CHUNK");
    }

    // ------- AckFrame -------

    #[test]
    fn ack_roundtrip_progress() {
        let mut applied = HashMap::new();
        applied.insert(dev(1), 200);
        applied.insert(dev(2), 175);

        let frame = AckFrame {
            group_id: gid(6),
            session_id: 1,
            applied_through: applied,
            last_seq_applied: 5,
            ops_applied: 1234,
            ops_rejected: 7,
            close: false,
        };
        let bytes = SyncFrame::Ack(frame.clone()).encode().unwrap();
        assert_eq!(SyncFrame::decode(&bytes).unwrap(), SyncFrame::Ack(frame));
    }

    #[test]
    fn ack_roundtrip_close() {
        let frame = AckFrame {
            group_id: gid(7),
            session_id: 99,
            applied_through: HashMap::new(),
            last_seq_applied: 0,
            ops_applied: 0,
            ops_rejected: 0,
            close: true,
        };
        let bytes = SyncFrame::Ack(frame.clone()).encode().unwrap();
        assert_eq!(SyncFrame::decode(&bytes).unwrap(), SyncFrame::Ack(frame));
    }

    #[test]
    fn ack_wire_type_is_0x34() {
        let f = SyncFrame::Ack(AckFrame {
            group_id: gid(0),
            session_id: 0,
            applied_through: HashMap::new(),
            last_seq_applied: 0,
            ops_applied: 0,
            ops_rejected: 0,
            close: false,
        });
        assert_eq!(f.wire_type(), 0x34);
        assert_eq!(f.kind(), "ACK");
    }

    // ------- Cross-frame invariants -------

    #[test]
    fn group_id_accessor_matches_payload() {
        let g = gid(123);
        let frames = vec![
            SyncFrame::Hello(HelloFrame {
                group_id: g,
                session_id: 0,
                initiator_device: dev(0),
                heads: HashMap::new(),
                bloom: vec![],
                bloom_k: 0,
                bloom_n: 0,
                protocol_version: 1,
            }),
            SyncFrame::Request(RequestFrame {
                group_id: g,
                session_id: 0,
                want_after: HashMap::new(),
                want_explicit: vec![],
                max_ops: 0,
            }),
            SyncFrame::Chunk(ChunkFrame {
                group_id: g,
                session_id: 0,
                seq: 0,
                total: 0,
                last: false,
                ops: vec![],
            }),
            SyncFrame::Ack(AckFrame {
                group_id: g,
                session_id: 0,
                applied_through: HashMap::new(),
                last_seq_applied: 0,
                ops_applied: 0,
                ops_rejected: 0,
                close: false,
            }),
        ];
        for f in frames {
            assert_eq!(f.group_id(), &g);
        }
    }

    #[test]
    fn session_id_accessor_matches_payload() {
        let sid = 0xCAFE_BABE;
        let chunk = SyncFrame::Chunk(ChunkFrame {
            group_id: gid(0),
            session_id: sid,
            seq: 0,
            total: 0,
            last: false,
            ops: vec![],
        });
        assert_eq!(chunk.session_id(), sid);
    }

    #[test]
    fn decode_corrupted_bytes_errors_cleanly() {
        let garbage = vec![0xFFu8; 64];
        let err = SyncFrame::decode(&garbage);
        assert!(err.is_err(), "garbage bytes must not silently parse");
    }

    #[test]
    fn decode_truncated_frame_errors_cleanly() {
        let f = SyncFrame::Hello(HelloFrame {
            group_id: gid(1),
            session_id: 1,
            initiator_device: dev(1),
            heads: HashMap::new(),
            bloom: vec![],
            bloom_k: 0,
            bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = f.encode().unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        assert!(SyncFrame::decode(truncated).is_err());
    }

    #[test]
    fn encoding_is_deterministic() {
        let mut heads = HashMap::new();
        for i in 0..16u8 {
            heads.insert(dev(i), i as u64 * 100);
        }
        let f = SyncFrame::Hello(HelloFrame {
            group_id: gid(0),
            session_id: 1,
            initiator_device: dev(0),
            heads,
            bloom: vec![],
            bloom_k: 0,
            bloom_n: 0,
            protocol_version: 1,
        });
        // Note: HashMap iteration order is NOT stable across encodes, so this
        // test verifies that *decoding* of either ordering yields the same
        // logical frame. Determinism on the wire requires BTreeMap; deferred
        // to a follow-up if/when state_hash needs to cover sync frames.
        let a = f.encode().unwrap();
        let b = f.encode().unwrap();
        let da = SyncFrame::decode(&a).unwrap();
        let db = SyncFrame::decode(&b).unwrap();
        assert_eq!(da, db);
    }

    #[test]
    fn empty_chunk_is_smaller_than_loaded_chunk() {
        let g = gid(0);
        let empty = SyncFrame::Chunk(ChunkFrame {
            group_id: g,
            session_id: 0,
            seq: 0,
            total: 0,
            last: true,
            ops: vec![],
        });
        let loaded = SyncFrame::Chunk(ChunkFrame {
            group_id: g,
            session_id: 0,
            seq: 0,
            total: 0,
            last: true,
            ops: (0..50).map(|i| make_envelope(g, dev(1), i)).collect(),
        });
        let empty_bytes = empty.encode().unwrap();
        let loaded_bytes = loaded.encode().unwrap();
        assert!(loaded_bytes.len() > empty_bytes.len());
    }

    #[test]
    fn protocol_version_constant_is_1() {
        assert_eq!(SYNC_PROTOCOL_VERSION, 1);
    }

    #[test]
    fn decode_with_wire_type_accepts_matching_byte() {
        let f = SyncFrame::Hello(HelloFrame {
            group_id: gid(0),
            session_id: 1,
            initiator_device: dev(0),
            heads: HashMap::new(),
            bloom: vec![],
            bloom_k: 0,
            bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = f.encode().unwrap();
        let decoded = SyncFrame::decode_with_wire_type(0x31, &bytes).unwrap();
        assert_eq!(decoded, f);
    }

    #[test]
    fn decode_with_wire_type_rejects_mismatched_byte() {
        // Body is HelloFrame (variant tag would say 0x31), transport claims CHUNK 0x33.
        let f = SyncFrame::Hello(HelloFrame {
            group_id: gid(0),
            session_id: 1,
            initiator_device: dev(0),
            heads: HashMap::new(),
            bloom: vec![],
            bloom_k: 0,
            bloom_n: 0,
            protocol_version: 1,
        });
        let bytes = f.encode().unwrap();
        let err = SyncFrame::decode_with_wire_type(0x33, &bytes);
        assert!(err.is_err(), "wire-type confusion must be rejected");
    }

    #[test]
    fn decode_with_wire_type_validates_all_four() {
        let cases = [
            (0x31u8, SyncFrame::Hello(HelloFrame {
                group_id: gid(0), session_id: 0, initiator_device: dev(0),
                heads: HashMap::new(), bloom: vec![], bloom_k: 0, bloom_n: 0,
                protocol_version: 1,
            })),
            (0x32u8, SyncFrame::Request(RequestFrame {
                group_id: gid(0), session_id: 0,
                want_after: HashMap::new(), want_explicit: vec![], max_ops: 0,
            })),
            (0x33u8, SyncFrame::Chunk(ChunkFrame {
                group_id: gid(0), session_id: 0, seq: 0, total: 0, last: false, ops: vec![],
            })),
            (0x34u8, SyncFrame::Ack(AckFrame {
                group_id: gid(0), session_id: 0, applied_through: HashMap::new(),
                last_seq_applied: 0, ops_applied: 0, ops_rejected: 0, close: false,
            })),
        ];
        for (wt, frame) in &cases {
            let bytes = frame.encode().unwrap();
            assert_eq!(
                SyncFrame::decode_with_wire_type(*wt, &bytes).unwrap(),
                *frame
            );
            // Any other wire_type rejects.
            for other in [0x31u8, 0x32, 0x33, 0x34] {
                if other == *wt { continue; }
                assert!(SyncFrame::decode_with_wire_type(other, &bytes).is_err());
            }
        }
    }
}
