/// CRDT group sync protocol — Phase 6.
///
/// Pure protocol logic (no I/O, no time, no Tor). The caller (Kotlin/Swift)
/// owns transport; this module owns the wire format, the per-session state
/// machine, the global session manager, and the digest filter.
///
/// # Action-based FFI
/// Inbound bytes go in via `SyncManager::process_frame`; the manager returns a
/// `Vec<SyncAction>` describing what the caller should do next (send a frame,
/// persist ops, close a session, drop on rate-limit). The caller never inspects
/// frame bytes.
///
/// # Module structure
/// - `frames` — HelloFrame, RequestFrame, ChunkFrame, AckFrame + the wrapping
///              `SyncFrame` enum. Bincode-serialized over the wire.
/// - `session` — `SyncSession`: per-peer state machine, byte budget, seq tracking.
/// - `manager` — `SyncManager`: global concurrency cap, per-peer rate bucket,
///               session table, dual-init collision rule.
/// - `digest` — bloom filter for HELLO: lets a fresh peer announce "I have these
///              op_ids" compactly so the responder doesn't ship the full set.

pub mod frames;
pub mod session;
pub mod manager;
pub mod digest;

pub use frames::{SyncFrame, HelloFrame, RequestFrame, ChunkFrame, AckFrame, FrameError};
