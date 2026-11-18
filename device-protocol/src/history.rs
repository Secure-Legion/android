//! Stable build-48 history identity, independent of local SQLite row IDs.
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const MAX_ORDINARY_DELTA: usize = 8 * 1024 * 1024;
pub const MAX_GROUP_DELTA: usize = 32 * 1024 * 1024;
pub const MAX_SAFE_TIME: u64 = (1 << 53) - 1;

#[derive(Debug, PartialEq, Eq)]
pub enum HistoryError {
    InvalidInput,
    TooLarge,
}

pub struct HistoryIdentity {
    pub canonical_delta: Vec<u8>,
    pub digest: [u8; 32],
    pub event_id: [u8; 32],
}

pub fn identity(
    delta_json: &[u8],
    topic: &str,
    object_id: &str,
    event_ts: u64,
) -> Result<HistoryIdentity, HistoryError> {
    let limit = if topic == "groups" { MAX_GROUP_DELTA } else { MAX_ORDINARY_DELTA };
    if !matches!(topic, "messages" | "receipts" | "contacts" | "settings" | "groups" | "group_links")
        || object_id.is_empty()
        || object_id.len() > 512
        || event_ts == 0
        || event_ts > MAX_SAFE_TIME
        || delta_json.is_empty()
        || delta_json.len() > limit
    {
        return Err(HistoryError::InvalidInput);
    }
    let delta: Value = serde_json::from_slice(delta_json).map_err(|_| HistoryError::InvalidInput)?;
    if !delta.is_object() {
        return Err(HistoryError::InvalidInput);
    }
    let mut canonical_delta = Vec::with_capacity(delta_json.len());
    canonical(&delta, &mut canonical_delta)?;
    if canonical_delta.len() > limit {
        return Err(HistoryError::TooLarge);
    }
    let digest: [u8; 32] = Sha256::digest(&canonical_delta).into();
    let digest_hex = lower_hex(&digest);
    let key = serde_json::to_vec(&serde_json::json!([
        "secure-sync-history-v2", topic, object_id, event_ts, digest_hex
    ])).map_err(|_| HistoryError::InvalidInput)?;
    let event_id = Sha256::digest(key).into();
    Ok(HistoryIdentity { canonical_delta, digest, event_id })
}

fn canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), HistoryError> {
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 { out.push(b','); }
                out.extend_from_slice(serde_json::to_string(key)
                    .map_err(|_| HistoryError::InvalidInput)?.as_bytes());
                out.push(b':');
                canonical(&map[key], out)?;
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 { out.push(b','); }
                canonical(item, out)?;
            }
            out.push(b']');
        }
        _ => out.extend_from_slice(serde_json::to_string(value)
            .map_err(|_| HistoryError::InvalidInput)?.as_bytes()),
    }
    Ok(())
}

pub fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_keys_keep_array_order_and_numeric_type() {
        let a = identity(br#"{"z":[2,1],"a":{"y":60.0,"x":60}}"#,
            "contacts", "abc", 1_792_400_000_000).unwrap();
        assert_eq!(a.canonical_delta, br#"{"a":{"x":60,"y":60.0},"z":[2,1]}"#);
        let b = identity(br#"{"a":{"x":60,"y":60},"z":[2,1]}"#,
            "contacts", "abc", 1_792_400_000_000).unwrap();
        assert_ne!(a.digest, b.digest);
        assert_ne!(a.event_id, b.event_id);
    }

    #[test]
    fn stable_identity_ignores_object_field_order() {
        let a = identity(br#"{"z":1,"a":2}"#, "settings", "profile", 1).unwrap();
        let b = identity(br#"{"a":2,"z":1}"#, "settings", "profile", 1).unwrap();
        assert_eq!(a.digest, b.digest);
        assert_eq!(a.event_id, b.event_id);
    }

    #[test]
    fn rejects_unknown_topic_and_unsafe_time() {
        assert!(identity(b"{}", "typing", "x", 1).is_err());
        assert!(identity(b"{}", "contacts", "x", 1 << 53).is_err());
    }
}
