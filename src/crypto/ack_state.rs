use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use once_cell::sync::Lazy;

/// ACK state for a single contact
#[derive(Debug, Clone, Default)]
pub struct AckState {
    pub ping_ack_received: bool,
    pub pong_ack_received: bool,
    pub message_ack_received: bool,
    /// Track which ACK types have been processed (for idempotency)
    pub processed_acks: HashSet<u8>,
}

/// Global ACK state manager
static ACK_STATES: Lazy<Mutex<HashMap<String, AckState>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

/// ACK type constants
pub const ACK_TYPE_PING: u8 = 0;
pub const ACK_TYPE_PONG: u8 = 1;
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
/// * `ack_type` - Type of ACK (0=PING_ACK, 1=PONG_ACK, 2=MESSAGE_ACK)
pub fn validate_and_record_ack(contact_id: &str, ack_type: u8) -> bool {
    let mut states = ACK_STATES.lock().unwrap();
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
        ACK_TYPE_PONG => {
            // PONG_ACK normally requires PING_ACK first, but allow forward progress after circuit churn
            if !state.ping_ack_received {
                log::warn!("Out-of-order PONG_ACK allowed (forward progress) for contact {} - PING_ACK not received", contact_id);
            }
            state.pong_ack_received = true;
            state.processed_acks.insert(ACK_TYPE_PONG);
            log::info!("PONG_ACK accepted for contact {}", contact_id);
            true
        }
        ACK_TYPE_MESSAGE => {
            // MESSAGE_ACK normally requires PONG_ACK first, but allow forward progress after circuit churn
            if !state.pong_ack_received {
                log::warn!("Out-of-order MESSAGE_ACK allowed (forward progress) for contact {} - PONG_ACK not received", contact_id);
            }
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
    let mut states = ACK_STATES.lock().unwrap();
    states.remove(contact_id);
    log::debug!("ACK state reset for contact {}", contact_id);
}

/// Clear all ACK states (for testing)
#[cfg(test)]
pub fn clear_ack_states() {
    let mut states = ACK_STATES.lock().unwrap();
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

        // PONG_ACK should be valid after PING_ACK
        assert!(validate_and_record_ack(contact, ACK_TYPE_PONG));

        // MESSAGE_ACK should be valid after PONG_ACK
        assert!(validate_and_record_ack(contact, ACK_TYPE_MESSAGE));
    }

    #[test]
    fn test_ack_out_of_order_allowed() {
        clear_ack_states();
        let contact = "test_contact2";

        // MESSAGE_ACK should be ALLOWED (forward progress) even without PONG_ACK
        assert!(validate_and_record_ack(contact, ACK_TYPE_MESSAGE));

        clear_ack_states();
        let contact2 = "test_contact3";

        // PONG_ACK should be ALLOWED (forward progress) even without PING_ACK
        assert!(validate_and_record_ack(contact2, ACK_TYPE_PONG));
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
