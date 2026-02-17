/// Core identity types for the CRDT group system.
///
/// - `DeviceID`: 16-byte stable device identity derived from Ed25519 pubkey
/// - `GroupID`: 32-byte unique group identifier
/// - `OpID`: globally unique, sortable operation identifier

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// DeviceID
// ---------------------------------------------------------------------------

/// Stable device identity — BLAKE3(Ed25519 public key)[0..16].
///
/// 16 bytes is sufficient for collision resistance within a group context
/// while keeping OpIDs compact for storage and wire transfer.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceID(pub [u8; 16]);

impl DeviceID {
    /// Derive DeviceID from an Ed25519 public key.
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        let hash = blake3::hash(pubkey);
        let mut id = [0u8; 16];
        id.copy_from_slice(&hash.as_bytes()[..16]);
        DeviceID(id)
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        DeviceID(bytes)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Hex-encode for display/storage.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 16 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes);
        Ok(DeviceID(id))
    }
}

impl Ord for DeviceID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for DeviceID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for DeviceID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceID({})", &self.to_hex()[..8])
    }
}

impl fmt::Display for DeviceID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// GroupID
// ---------------------------------------------------------------------------

/// Unique group identifier — BLAKE3("SL-GROUP" || creator_device_id || random32).
///
/// 32 bytes provides strong collision resistance across the entire network.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupID(pub [u8; 32]);

impl GroupID {
    /// Create a new GroupID from creator identity and randomness.
    pub fn new(creator: &DeviceID, random: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"SL-GROUP");
        hasher.update(&creator.0);
        hasher.update(random);
        GroupID(*hasher.finalize().as_bytes())
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        GroupID(bytes)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex-encode for display/storage.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode from hex string.
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        Ok(GroupID(id))
    }
}

impl Ord for GroupID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for GroupID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for GroupID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GroupID({}..)", &self.to_hex()[..12])
    }
}

impl fmt::Display for GroupID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// OpID
// ---------------------------------------------------------------------------

/// Globally unique, sortable operation identifier.
///
/// Composed of:
/// - `author`: the device that created the op
/// - `lamport`: monotonically increasing per-author logical clock
/// - `nonce`: 64-bit random to avoid collision across app restarts
///
/// **Ordering**: `(lamport, author, nonce)` — lamport first for causal ordering,
/// author for deterministic tie-break, nonce as final disambiguator.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpID {
    pub author: DeviceID,
    pub lamport: u64,
    pub nonce: u64,
}

impl OpID {
    /// Create a new OpID.
    pub fn new(author: DeviceID, lamport: u64, nonce: u64) -> Self {
        OpID { author, lamport, nonce }
    }

    /// Hex-encode the full OpID for storage keys.
    /// Format: `{author_hex}:{lamport_hex}:{nonce_hex}`
    pub fn to_hex(&self) -> String {
        format!(
            "{}:{:016x}:{:016x}",
            self.author.to_hex(),
            self.lamport,
            self.nonce,
        )
    }
}

impl Ord for OpID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.lamport
            .cmp(&other.lamport)
            .then_with(|| self.author.cmp(&other.author))
            .then_with(|| self.nonce.cmp(&other.nonce))
    }
}

impl PartialOrd for OpID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for OpID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OpID({:?}, L={}, N={:04x})",
            self.author,
            self.lamport,
            self.nonce & 0xFFFF,
        )
    }
}

impl fmt::Display for OpID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_from_pubkey() {
        let pubkey = [42u8; 32];
        let id = DeviceID::from_pubkey(&pubkey);
        assert_eq!(id.as_bytes().len(), 16);

        // Same pubkey → same DeviceID
        let id2 = DeviceID::from_pubkey(&pubkey);
        assert_eq!(id, id2);

        // Different pubkey → different DeviceID
        let other = [43u8; 32];
        let id3 = DeviceID::from_pubkey(&other);
        assert_ne!(id, id3);
    }

    #[test]
    fn test_device_id_hex_roundtrip() {
        let id = DeviceID::from_pubkey(&[7u8; 32]);
        let hex_str = id.to_hex();
        let decoded = DeviceID::from_hex(&hex_str).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_group_id_deterministic() {
        let creator = DeviceID::from_pubkey(&[1u8; 32]);
        let random = [99u8; 32];
        let gid1 = GroupID::new(&creator, &random);
        let gid2 = GroupID::new(&creator, &random);
        assert_eq!(gid1, gid2);
    }

    #[test]
    fn test_group_id_unique_with_different_random() {
        let creator = DeviceID::from_pubkey(&[1u8; 32]);
        let r1 = [10u8; 32];
        let r2 = [11u8; 32];
        assert_ne!(GroupID::new(&creator, &r1), GroupID::new(&creator, &r2));
    }

    #[test]
    fn test_group_id_hex_roundtrip() {
        let creator = DeviceID::from_pubkey(&[5u8; 32]);
        let gid = GroupID::new(&creator, &[77u8; 32]);
        let hex_str = gid.to_hex();
        let decoded = GroupID::from_hex(&hex_str).unwrap();
        assert_eq!(gid, decoded);
    }

    #[test]
    fn test_op_id_ordering() {
        let author_a = DeviceID::from_bytes([0u8; 16]);
        let author_b = DeviceID::from_bytes([1u8; 16]);

        // Lower lamport < higher lamport, regardless of author
        let op1 = OpID::new(author_b, 1, 0);
        let op2 = OpID::new(author_a, 2, 0);
        assert!(op1 < op2);

        // Same lamport → tie-break by author
        let op3 = OpID::new(author_a, 5, 0);
        let op4 = OpID::new(author_b, 5, 0);
        assert!(op3 < op4);

        // Same lamport and author → tie-break by nonce
        let op5 = OpID::new(author_a, 5, 100);
        let op6 = OpID::new(author_a, 5, 200);
        assert!(op5 < op6);
    }

    #[test]
    fn test_op_id_hex_format() {
        let author = DeviceID::from_bytes([0xABu8; 16]);
        let op = OpID::new(author, 42, 99);
        let hex = op.to_hex();
        assert!(hex.contains("abababababababababababababababab")); // author hex
        assert!(hex.contains("000000000000002a")); // lamport 42
        assert!(hex.contains("0000000000000063")); // nonce 99
    }

    #[test]
    fn test_device_id_serde_roundtrip() {
        let id = DeviceID::from_pubkey(&[33u8; 32]);
        let bytes = bincode::serialize(&id).unwrap();
        let decoded: DeviceID = bincode::deserialize(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_op_id_serde_roundtrip() {
        let author = DeviceID::from_pubkey(&[50u8; 32]);
        let op = OpID::new(author, 1000, 0xDEAD);
        let bytes = bincode::serialize(&op).unwrap();
        let decoded: OpID = bincode::deserialize(&bytes).unwrap();
        assert_eq!(op, decoded);
    }
}
