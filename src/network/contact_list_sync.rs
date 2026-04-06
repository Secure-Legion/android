//! Contact list backup mesh — wire protocol for message types 0x80/0x81/0x82.
//!
//! Spec: `CONTACT_LIST_SYNC_PROTOCOL.md` at repo root.
//!
//! Responsibilities of this module:
//!   - Build outbound frames (REQUEST / RESPONSE / PUSH) with Ed25519 signing
//!   - Parse + verify inbound frames (structural, signature, timestamp, rate limit)
//!   - Hold an inbound queue that Kotlin drains via JNI polling
//!
//! Authorization (CID ↔ sender_pk binding, contact DB lookup) is intentionally
//! done in Kotlin after poll, because this module has no access to the app DB.
//! See §6.3 of the spec.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use once_cell::sync::Lazy;

use crate::network::tor::{
    MSG_TYPE_CONTACT_LIST_PUSH, MSG_TYPE_CONTACT_LIST_REQUEST, MSG_TYPE_CONTACT_LIST_RESPONSE,
};

// ─── Protocol constants ───────────────────────────────────────────────────────

pub const CL_MAX_CID_LEN: usize = 128;
pub const CL_MAX_BLOB_LEN: usize = 2 * 1024 * 1024; // 2 MiB
pub const CL_TIMESTAMP_SKEW_SECS: i64 = 300;
pub const CL_INBOUND_QUEUE_CAP: usize = 256;
pub const CL_RATE_LIMIT_PUSH_SECS: u64 = 30;
pub const CL_RATE_LIMIT_REQUEST_SECS: u64 = 60;

const SIG_LEN: usize = 64;
const PK_LEN: usize = 32;
const TS_LEN: usize = 8;
const CID_LEN_FIELD: usize = 2;
const BLOB_LEN_FIELD: usize = 4;

/// Header = type(1) + sender_pk(32) + timestamp(8) + cid_len(2)
const HEADER_LEN: usize = 1 + PK_LEN + TS_LEN + CID_LEN_FIELD;

// ─── Data types ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct InboundFrame {
    pub msg_type: u8,
    pub sender_pk: [u8; 32],
    pub timestamp: u64,
    pub cid: String,
    pub blob: Vec<u8>,
}

// ─── Global state ─────────────────────────────────────────────────────────────

static INBOUND_QUEUE: Lazy<Mutex<VecDeque<InboundFrame>>> =
    Lazy::new(|| Mutex::new(VecDeque::with_capacity(CL_INBOUND_QUEUE_CAP)));

static PUSH_RATE: Lazy<Mutex<HashMap<[u8; 32], Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static REQUEST_RATE: Lazy<Mutex<HashMap<[u8; 32], Instant>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn lock_or_recover<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ─── Outbound frame builders ──────────────────────────────────────────────────

/// Build a CONTACT_LIST_REQUEST (0x80) frame.
/// Signature covers every byte preceding it.
pub fn build_request_frame(signing_key: &SigningKey, cid: &str) -> Result<Vec<u8>, String> {
    let cid_bytes = cid.as_bytes();
    if cid_bytes.is_empty() || cid_bytes.len() > CL_MAX_CID_LEN {
        return Err(format!("cid length {} out of range 1..={}", cid_bytes.len(), CL_MAX_CID_LEN));
    }

    let sender_pk = signing_key.verifying_key().to_bytes();
    let ts = now_secs();

    let mut frame = Vec::with_capacity(HEADER_LEN + cid_bytes.len() + SIG_LEN);
    frame.push(MSG_TYPE_CONTACT_LIST_REQUEST);
    frame.extend_from_slice(&sender_pk);
    frame.extend_from_slice(&ts.to_be_bytes());
    frame.extend_from_slice(&(cid_bytes.len() as u16).to_be_bytes());
    frame.extend_from_slice(cid_bytes);

    let sig = signing_key.sign(&frame);
    frame.extend_from_slice(&sig.to_bytes());

    debug_assert_eq!(frame.len(), HEADER_LEN + cid_bytes.len() + SIG_LEN);
    Ok(frame)
}

/// Internal helper — build RESPONSE or PUSH (both share the blob-bearing layout).
fn build_blob_bearing_frame(
    msg_type: u8,
    signing_key: &SigningKey,
    cid: &str,
    blob: &[u8],
) -> Result<Vec<u8>, String> {
    let cid_bytes = cid.as_bytes();
    if cid_bytes.is_empty() || cid_bytes.len() > CL_MAX_CID_LEN {
        return Err(format!("cid length {} out of range 1..={}", cid_bytes.len(), CL_MAX_CID_LEN));
    }
    if blob.len() > CL_MAX_BLOB_LEN {
        return Err(format!("blob length {} exceeds max {}", blob.len(), CL_MAX_BLOB_LEN));
    }

    let sender_pk = signing_key.verifying_key().to_bytes();
    let ts = now_secs();

    let mut frame = Vec::with_capacity(
        HEADER_LEN + cid_bytes.len() + BLOB_LEN_FIELD + blob.len() + SIG_LEN,
    );
    frame.push(msg_type);
    frame.extend_from_slice(&sender_pk);
    frame.extend_from_slice(&ts.to_be_bytes());
    frame.extend_from_slice(&(cid_bytes.len() as u16).to_be_bytes());
    frame.extend_from_slice(cid_bytes);
    frame.extend_from_slice(&(blob.len() as u32).to_be_bytes());
    frame.extend_from_slice(blob);

    let sig = signing_key.sign(&frame);
    frame.extend_from_slice(&sig.to_bytes());

    debug_assert_eq!(
        frame.len(),
        HEADER_LEN + cid_bytes.len() + BLOB_LEN_FIELD + blob.len() + SIG_LEN
    );
    Ok(frame)
}

/// Build a CONTACT_LIST_PUSH (0x82) frame.
pub fn build_push_frame(
    signing_key: &SigningKey,
    cid: &str,
    blob: &[u8],
) -> Result<Vec<u8>, String> {
    build_blob_bearing_frame(MSG_TYPE_CONTACT_LIST_PUSH, signing_key, cid, blob)
}

/// Build a CONTACT_LIST_RESPONSE (0x81) frame. `blob` may be empty for a NACK.
pub fn build_response_frame(
    signing_key: &SigningKey,
    cid: &str,
    blob: &[u8],
) -> Result<Vec<u8>, String> {
    build_blob_bearing_frame(MSG_TYPE_CONTACT_LIST_RESPONSE, signing_key, cid, blob)
}

// ─── Inbound handler ──────────────────────────────────────────────────────────

fn check_rate_limit(
    map: &Lazy<Mutex<HashMap<[u8; 32], Instant>>>,
    sender_pk: &[u8; 32],
    window_secs: u64,
) -> bool {
    let mut guard = lock_or_recover(map);
    let now = Instant::now();
    let window = Duration::from_secs(window_secs);

    // Opportunistic cleanup — drop entries older than 4× window
    let cutoff = window * 4;
    guard.retain(|_, last| now.duration_since(*last) < cutoff);

    if let Some(last) = guard.get(sender_pk) {
        if now.duration_since(*last) < window {
            return false;
        }
    }
    guard.insert(*sender_pk, now);
    true
}

/// Parse + validate an inbound contact-list frame and push to the queue.
///
/// `buf` is the frame body (NO 4-byte length prefix) starting with the type byte.
/// Returns Ok(()) on accept, Err(reason) on structural/crypto/rate-limit failure.
/// All errors result in the frame being dropped — callers just log and move on.
pub fn handle_inbound(buf: &[u8]) -> Result<(), String> {
    // Minimum frame: REQUEST with 1-byte CID = HEADER_LEN + 1 + SIG_LEN
    if buf.len() < HEADER_LEN + 1 + SIG_LEN {
        return Err(format!("frame too short: {} bytes", buf.len()));
    }

    let msg_type = buf[0];
    match msg_type {
        MSG_TYPE_CONTACT_LIST_REQUEST
        | MSG_TYPE_CONTACT_LIST_RESPONSE
        | MSG_TYPE_CONTACT_LIST_PUSH => {}
        _ => return Err(format!("not a contact-list frame: 0x{:02x}", msg_type)),
    }

    // Parse header
    let mut off = 1;

    let mut sender_pk = [0u8; 32];
    sender_pk.copy_from_slice(&buf[off..off + PK_LEN]);
    off += PK_LEN;

    // Reject all-zero sender_pk (invalid Ed25519 point)
    if sender_pk.iter().all(|b| *b == 0) {
        return Err("sender_pk is all zero".to_string());
    }

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&buf[off..off + TS_LEN]);
    let timestamp = u64::from_be_bytes(ts_bytes);
    off += TS_LEN;

    let cid_len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    off += CID_LEN_FIELD;

    if cid_len == 0 || cid_len > CL_MAX_CID_LEN {
        return Err(format!("bad cid_len: {}", cid_len));
    }
    if buf.len() < off + cid_len + SIG_LEN {
        return Err("frame too short for cid+sig".to_string());
    }

    let cid = std::str::from_utf8(&buf[off..off + cid_len])
        .map_err(|_| "cid not valid utf-8".to_string())?
        .to_string();
    off += cid_len;

    // Type-specific body
    let blob: Vec<u8> = match msg_type {
        MSG_TYPE_CONTACT_LIST_REQUEST => {
            if buf.len() != off + SIG_LEN {
                return Err(format!(
                    "REQUEST length mismatch: got {}, expected {}",
                    buf.len(),
                    off + SIG_LEN
                ));
            }
            Vec::new()
        }
        MSG_TYPE_CONTACT_LIST_RESPONSE | MSG_TYPE_CONTACT_LIST_PUSH => {
            if buf.len() < off + BLOB_LEN_FIELD + SIG_LEN {
                return Err("frame too short for blob_len".to_string());
            }
            let blob_len = u32::from_be_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ]) as usize;
            off += BLOB_LEN_FIELD;

            if blob_len > CL_MAX_BLOB_LEN {
                return Err(format!("blob_len {} exceeds max", blob_len));
            }
            if buf.len() != off + blob_len + SIG_LEN {
                return Err(format!(
                    "length mismatch: got {}, expected {}",
                    buf.len(),
                    off + blob_len + SIG_LEN
                ));
            }
            let b = buf[off..off + blob_len].to_vec();
            off += blob_len;
            b
        }
        _ => unreachable!(),
    };

    // Verify signature over bytes [0 .. off)
    let sig_bytes = &buf[off..off + SIG_LEN];
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    let verifying_key = VerifyingKey::from_bytes(&sender_pk)
        .map_err(|e| format!("invalid sender_pk: {}", e))?;

    verifying_key
        .verify(&buf[..off], &signature)
        .map_err(|e| format!("signature verification failed: {}", e))?;

    // Timestamp skew check
    let now_ts = now_secs() as i64;
    let ts_i64 = timestamp as i64;
    if (now_ts - ts_i64).abs() > CL_TIMESTAMP_SKEW_SECS {
        return Err(format!(
            "timestamp skew too large: frame_ts={} now={}",
            timestamp, now_ts
        ));
    }

    // Rate limit
    let rate_ok = match msg_type {
        MSG_TYPE_CONTACT_LIST_PUSH => {
            check_rate_limit(&PUSH_RATE, &sender_pk, CL_RATE_LIMIT_PUSH_SECS)
        }
        MSG_TYPE_CONTACT_LIST_REQUEST => {
            check_rate_limit(&REQUEST_RATE, &sender_pk, CL_RATE_LIMIT_REQUEST_SECS)
        }
        _ => true, // RESPONSE: correlation check in Kotlin
    };
    if !rate_ok {
        return Err(format!("rate limited: type=0x{:02x}", msg_type));
    }

    // Enqueue
    let mut queue = lock_or_recover(&INBOUND_QUEUE);
    if queue.len() >= CL_INBOUND_QUEUE_CAP {
        queue.pop_front();
        log::warn!("CONTACT_LIST_SYNC: inbound queue full, dropped oldest frame");
    }

    log::info!(
        "CONTACT_LIST_SYNC: accepted type=0x{:02x} pk_prefix={} cid={} blob_len={}",
        msg_type,
        hex::encode(&sender_pk[..8]),
        cid,
        blob.len()
    );

    queue.push_back(InboundFrame {
        msg_type,
        sender_pk,
        timestamp,
        cid,
        blob,
    });

    Ok(())
}

// ─── Inbound polling (for JNI) ────────────────────────────────────────────────

/// Pop the oldest inbound frame, or None if the queue is empty.
pub fn poll_inbound_frame() -> Option<InboundFrame> {
    let mut queue = lock_or_recover(&INBOUND_QUEUE);
    queue.pop_front()
}

pub fn inbound_queue_len() -> usize {
    lock_or_recover(&INBOUND_QUEUE).len()
}

// ─── Outbound send (over Arti messaging HS) ───────────────────────────────────

/// Messaging hidden service port — same as other outbound messaging frames.
pub const MESSAGING_PORT: u16 = 9150;

/// Open an Arti stream to the target messaging .onion and write a framed payload.
///
/// The frame bytes passed in should be the raw frame (NO 4-byte length prefix).
/// `ArtiStream::write_message` will add the u32 BE length prefix per wire protocol.
pub async fn send_frame_to_onion(
    onion_address: &str,
    frame: Vec<u8>,
) -> Result<(), String> {
    let mut stream = super::arti::arti_connect_to_onion(onion_address, MESSAGING_PORT)
        .await
        .map_err(|e| format!("arti connect failed: {}", e))?;
    stream
        .write_message(&frame)
        .await
        .map_err(|e| format!("write_message failed: {}", e))?;
    log::info!(
        "CONTACT_LIST_SYNC: sent {} bytes to {}:{}",
        frame.len(),
        onion_address,
        MESSAGING_PORT
    );
    Ok(())
}

// ─── Test-only helpers ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn roundtrip_request() {
        let key = test_key();
        let cid = "QmTestCidAbcdef123456";
        let frame = build_request_frame(&key, cid).unwrap();
        assert!(handle_inbound(&frame).is_ok());
        let got = poll_inbound_frame().unwrap();
        assert_eq!(got.msg_type, MSG_TYPE_CONTACT_LIST_REQUEST);
        assert_eq!(got.cid, cid);
        assert!(got.blob.is_empty());
        assert_eq!(got.sender_pk, key.verifying_key().to_bytes());
    }

    #[test]
    fn roundtrip_push_with_blob() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let cid = "QmAnotherCid";
        let blob = vec![0xAB; 1024];
        let frame = build_push_frame(&key, cid, &blob).unwrap();
        assert!(handle_inbound(&frame).is_ok());
        let got = poll_inbound_frame().unwrap();
        assert_eq!(got.msg_type, MSG_TYPE_CONTACT_LIST_PUSH);
        assert_eq!(got.cid, cid);
        assert_eq!(got.blob, blob);
    }

    #[test]
    fn tampered_signature_rejected() {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let mut frame = build_request_frame(&key, "QmCid").unwrap();
        // Flip a bit in the CID
        let cid_start = HEADER_LEN;
        frame[cid_start] ^= 0x01;
        assert!(handle_inbound(&frame).is_err());
    }

    #[test]
    fn cid_length_limits() {
        let key = test_key();
        let too_long = "x".repeat(CL_MAX_CID_LEN + 1);
        assert!(build_request_frame(&key, &too_long).is_err());
        assert!(build_request_frame(&key, "").is_err());
    }

    #[test]
    fn response_empty_blob_is_nack() {
        let key = test_key();
        let frame = build_response_frame(&key, "QmX", &[]).unwrap();
        assert!(handle_inbound(&frame).is_ok());
        let got = poll_inbound_frame().unwrap();
        assert_eq!(got.msg_type, MSG_TYPE_CONTACT_LIST_RESPONSE);
        assert!(got.blob.is_empty());
    }
}
