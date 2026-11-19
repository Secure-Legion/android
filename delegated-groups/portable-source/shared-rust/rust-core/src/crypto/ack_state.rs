use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use once_cell::sync::Lazy;
use crate::util::lock_recover;

/// ACK state for a single contact
/// Protocol v2: Only PING_ACK and MESSAGE_ACK remain (PONG_ACK removed).
#[derive(Debug, Clone, Default)]
pub struct AckState {
    pub ping_ack_received: bool,
    pub message_ack_received: bool,
    /// Track which ACK types have been processed (for idempotency)
    pub processed_acks: HashSet<u8>,
}

/// Global ACK state manager
static ACK_STATES: Lazy<Mutex<HashMap<String, AckState>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

/// ACK type constants (Protocol v2: PONG_ACK removed — PONG itself is the acknowledgment)
pub const ACK_TYPE_PING: u8 = 0;
pub const ACK_TYPE_MESSAGE: u8 = 2;

/// Validate ACK ordering and update state with idempotent handling
///
/// Returns true if ACK is valid (new or duplicate)
/// Returns false only for truly invalid ACKs
///
/// IDEMPOTENCY: Duplicates return true (ACK was successfully processed previously)
/// FORWARD PROGRESS: Out-of-order ACKs are allowed if they advance state forward
///
/// # Arguments
/// * `contact_id` - Contact identifier
/// * `ack_type` - Type of ACK (0=PING_ACK, 2=MESSAGE_ACK)
pub fn validate_and_record_ack(contact_id: &str, ack_type: u8) -> bool {
    let mut states = lock_recover(&ACK_STATES);
    let state = states.entry(contact_id.to_string()).or_default();

    // Guard 1: Handle duplicate ACKs (idempotency)
    if state.processed_acks.contains(&ack_type) {
        log::debug!("Duplicate ACK (idempotent) for contact {} type {} - already processed, returning success", contact_id, ack_type);
        return true;
    }

    match ack_type {
        ACK_TYPE_PING => {
            // PING_ACK always valid (first ACK in sequence)
            state.ping_ack_received = true;
            state.processed_acks.insert(ACK_TYPE_PING);
            log::info!("PING_ACK accepted for contact {}", contact_id);
            true
        }
        ACK_TYPE_MESSAGE => {
            // MESSAGE_ACK: always allowed (forward progress — PONG replaces old PONG_ACK step)
            state.message_ack_received = true;
            state.processed_acks.insert(ACK_TYPE_MESSAGE);
            log::info!("MESSAGE_ACK accepted for contact {}", contact_id);
            true
        }
        _ => {
            log::error!("Invalid ACK type: {}", ack_type);
            false
        }
    }
}

/// Reset ACK state for a contact (e.g., after completing a message exchange)
pub fn reset_ack_state(contact_id: &str) {
    let mut states = lock_recover(&ACK_STATES);
    states.remove(contact_id);
    log::debug!("ACK state reset for contact {}", contact_id);
}

/// Clear all ACK states (for testing)
#[cfg(test)]
pub fn clear_ack_states() {
    let mut states = lock_recover(&ACK_STATES);
    states.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_ordering() {
        clear_ack_states();
        let contact = "test_contact";

        // PING_ACK should always be valid
        assert!(validate_and_record_ack(contact, ACK_TYPE_PING));

        // MESSAGE_ACK should be valid after PING_ACK
        assert!(validate_and_record_ack(contact, ACK_TYPE_MESSAGE));
    }

    #[test]
    fn test_ack_out_of_order_allowed() {
        clear_ack_states();
        let contact = "test_contact2";

        // MESSAGE_ACK should be ALLOWED (forward progress) even without PING_ACK
        assert!(validate_and_record_ack(contact, ACK_TYPE_MESSAGE));
    }

    #[test]
    fn test_ack_idempotency() {
        clear_ack_states();
        let contact = "test_contact_dup";

        // First PING_ACK should be accepted
        assert!(validate_and_record_ack(contact, ACK_TYPE_PING));

        // Duplicate PING_ACK should also return true (idempotent)
        assert!(validate_and_record_ack(contact, ACK_TYPE_PING));

        // MESSAGE_ACK should be accepted
        assert!(validate_and_record_ack(contact, ACK_TYPE_MESSAGE));

        // Duplicate MESSAGE_ACK should also return true (idempotent)
        assert!(validate_and_record_ack(contact, ACK_TYPE_MESSAGE));
    }
}
