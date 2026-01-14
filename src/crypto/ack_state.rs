use std::collections::HashMap;
use std::sync::Mutex;
use once_cell::sync::Lazy;

/// ACK state for a single contact
#[derive(Debug, Clone, Default)]
pub struct AckState {
    pub ping_ack_received: bool,
    pub pong_ack_received: bool,
    pub message_ack_received: bool,
}

/// Global ACK state manager
static ACK_STATES: Lazy<Mutex<HashMap<String, AckState>>> = Lazy::new(|| {
    Mutex::new(HashMap::new())
});

/// ACK type constants
pub const ACK_TYPE_PING: u8 = 0;
pub const ACK_TYPE_PONG: u8 = 1;
pub const ACK_TYPE_MESSAGE: u8 = 2;

/// Validate ACK ordering and update state
///
/// Returns true if ACK is valid according to protocol ordering
/// Returns false if ACK violates ordering (should be rejected)
///
/// # Arguments
/// * `contact_id` - Contact identifier
/// * `ack_type` - Type of ACK (0=PING_ACK, 1=PONG_ACK, 2=MESSAGE_ACK)
pub fn validate_and_record_ack(contact_id: &str, ack_type: u8) -> bool {
    let mut states = ACK_STATES.lock().unwrap();
    let state = states.entry(contact_id.to_string()).or_default();

    match ack_type {
        ACK_TYPE_PING => {
            // PING_ACK always valid (first ACK in sequence)
            state.ping_ack_received = true;
            log::info!("✓ PING_ACK accepted for contact {}", contact_id);
            true
        }
        ACK_TYPE_PONG => {
            // PONG_ACK requires PING_ACK first
            if !state.ping_ack_received {
                log::warn!("⚠️  PONG_ACK rejected for contact {} - PING_ACK not received", contact_id);
                return false;
            }
            state.pong_ack_received = true;
            log::info!("✓ PONG_ACK accepted for contact {}", contact_id);
            true
        }
        ACK_TYPE_MESSAGE => {
            // MESSAGE_ACK requires PONG_ACK first
            if !state.pong_ack_received {
                log::warn!("⚠️  MESSAGE_ACK rejected for contact {} - PONG_ACK not received", contact_id);
                return false;
            }
            state.message_ack_received = true;
            log::info!("✓ MESSAGE_ACK accepted for contact {}", contact_id);
            true
        }
        _ => {
            log::error!("✗ Invalid ACK type: {}", ack_type);
            false
        }
    }
}

/// Reset ACK state for a contact (e.g., after completing a message exchange)
pub fn reset_ack_state(contact_id: &str) {
    let mut states = ACK_STATES.lock().unwrap();
    states.remove(contact_id);
    log::debug!("✓ ACK state reset for contact {}", contact_id);
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
    fn test_ack_ordering_violation() {
        clear_ack_states();
        let contact = "test_contact2";

        // MESSAGE_ACK should be rejected without PONG_ACK
        assert!(!validate_and_record_ack(contact, ACK_TYPE_MESSAGE));

        // PONG_ACK should be rejected without PING_ACK
        assert!(!validate_and_record_ack(contact, ACK_TYPE_PONG));
    }
}
