/// CRDT operation guardrails — enforced from day 1.
///
/// These constants bound op-log growth, sync bandwidth, and per-peer rates
/// to prevent unbounded resource consumption on mobile devices over Tor.

/// Max payload size per op (messages, metadata).
pub const MAX_OP_PAYLOAD_BYTES: usize = 64 * 1024; // 64 KB

/// Max payload size for attachment metadata ops (future use).
pub const MAX_ATTACHMENT_META_BYTES: usize = 256 * 1024; // 256 KB

/// Max ops per group before UI "needs compaction" warning.
pub const MAX_OPS_PER_GROUP: usize = 250_000;

/// Max ops per group hard cap — reject new message ops beyond this.
/// Membership ops are always allowed regardless of this cap.
pub const HARD_CAP_OPS_PER_GROUP: usize = 500_000;

/// Max ops accepted from a single peer per sync round.
pub const MAX_OPS_PER_SYNC_ROUND: usize = 1_000;

/// Max bytes per sync round (all chunks combined).
pub const MAX_BYTES_PER_SYNC_ROUND: usize = 10 * 1024 * 1024; // 10 MB

/// Max ops per peer per minute (rate limit).
pub const MAX_OPS_PER_PEER_PER_MINUTE: usize = 100;

/// Max concurrent sync sessions (global, not per-peer).
pub const MAX_CONCURRENT_SYNCS: usize = 2;

/// Max ops per sync chunk.
pub const MAX_OPS_PER_CHUNK: usize = 256;

/// Op limit status for a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpLimitStatus {
    /// Under soft cap, all operations allowed.
    Ok,
    /// Approaching limit — UI should warn, but ops still accepted.
    NeedsCompaction,
    /// Hard cap reached — reject new message ops (membership ops still allowed).
    HardCapReached,
}

/// Check if a group is approaching or has hit its op limit.
pub fn check_op_limits(op_count: usize) -> OpLimitStatus {
    if op_count >= HARD_CAP_OPS_PER_GROUP {
        OpLimitStatus::HardCapReached
    } else if op_count >= MAX_OPS_PER_GROUP {
        OpLimitStatus::NeedsCompaction
    } else {
        OpLimitStatus::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_limits_ok() {
        assert_eq!(check_op_limits(0), OpLimitStatus::Ok);
        assert_eq!(check_op_limits(100_000), OpLimitStatus::Ok);
        assert_eq!(check_op_limits(249_999), OpLimitStatus::Ok);
    }

    #[test]
    fn test_op_limits_needs_compaction() {
        assert_eq!(check_op_limits(250_000), OpLimitStatus::NeedsCompaction);
        assert_eq!(check_op_limits(300_000), OpLimitStatus::NeedsCompaction);
        assert_eq!(check_op_limits(499_999), OpLimitStatus::NeedsCompaction);
    }

    #[test]
    fn test_op_limits_hard_cap() {
        assert_eq!(check_op_limits(500_000), OpLimitStatus::HardCapReached);
        assert_eq!(check_op_limits(1_000_000), OpLimitStatus::HardCapReached);
    }
}
