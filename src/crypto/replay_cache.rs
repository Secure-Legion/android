use lru::LruCache;
use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::num::NonZeroUsize;

/// Replay cache entry: (sender_pubkey, ping_hash) -> timestamp
type CacheKey = ([u8; 32], [u8; 32]);

/// Global LRU replay cache for PING deduplication
/// Capacity: 10,000 entries (most recent PINGs)
static REPLAY_CACHE: Lazy<Mutex<LruCache<CacheKey, i64>>> = Lazy::new(|| {
    let capacity = NonZeroUsize::new(10_000).unwrap();
    Mutex::new(LruCache::new(capacity))
});

/// Check if PING is a replay, and insert if not
///
/// Returns true if PING is NEW (should be processed)
/// Returns false if PING is a REPLAY (should be dropped)
///
/// # Arguments
/// * `sender_pubkey` - 32-byte Ed25519 public key of sender
/// * `ping_hash` - 32-byte Blake3 hash of PING ciphertext
pub fn check_ping_replay(sender_pubkey: [u8; 32], ping_hash: [u8; 32]) -> bool {
    let mut cache = REPLAY_CACHE.lock().unwrap();
    let key = (sender_pubkey, ping_hash);

    if cache.contains(&key) {
        // Replay detected!
        log::warn!("⚠️  REPLAY ATTACK: Duplicate PING detected from sender {}",
            hex::encode(&sender_pubkey[..8]));
        return false;
    }

    // New PING - add to cache
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    cache.put(key, now);

    log::debug!("✓ PING replay check passed (cache size: {})", cache.len());
    true
}

/// Compute Blake3 hash of PING wire bytes
pub fn compute_ping_hash(ping_bytes: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(ping_bytes);
    *hash.as_bytes()
}

/// Clear the replay cache (for testing)
#[cfg(test)]
pub fn clear_replay_cache() {
    let mut cache = REPLAY_CACHE.lock().unwrap();
    cache.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_detection() {
        clear_replay_cache();

        let sender = [1u8; 32];
        let ping_hash = [2u8; 32];

        // First PING should pass
        assert!(check_ping_replay(sender, ping_hash));

        // Duplicate PING should be rejected
        assert!(!check_ping_replay(sender, ping_hash));
    }

    #[test]
    fn test_different_pings_allowed() {
        clear_replay_cache();

        let sender = [1u8; 32];
        let ping_hash_1 = [2u8; 32];
        let ping_hash_2 = [3u8; 32];

        // Different PINGs should both pass
        assert!(check_ping_replay(sender, ping_hash_1));
        assert!(check_ping_replay(sender, ping_hash_2));
    }
}
