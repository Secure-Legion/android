pub mod tor;
pub mod arti;
pub mod friend_request_server;
pub mod socks5_client;
pub mod contact_list_sync;

pub use tor::{TorManager, PENDING_CONNECTIONS, PendingConnection, compute_onion_address_from_ed25519_seed};
pub use friend_request_server::{ContactExchangeEndpoint, get_endpoint};
pub use socks5_client::Socks5Client;

// Diagnostic counters shared between network modules and FFI
use std::sync::atomic::AtomicU64;
pub static RX_MESSAGE_ACCEPT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static RX_MESSAGE_TX_DROP_COUNT: AtomicU64 = AtomicU64::new(0);

// Public A4/A5 roster controls arriving on the contact messaging onion stay
// separate from both the legacy message parser and the private device onion.
static CONTACT_ROSTER_FRAMES: once_cell::sync::Lazy<std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::VecDeque::new()));

pub fn enqueue_contact_roster_frame(frame: Vec<u8>) -> bool {
    let size = frame.len();
    if size < 43 || size > 32_773 || !matches!(frame[0], 0xA4 | 0xA5) ||
        u32::from_be_bytes(frame[1..5].try_into().unwrap()) as usize != size - 5 ||
        (frame[0] == 0xA4 && &frame[5..11] != b"SLDR01") ||
        (frame[0] == 0xA5 && (size != 198 || frame[5] != 1)) { return false; }
    let mut queue = crate::util::lock_recover(&CONTACT_ROSTER_FRAMES);
    if queue.len() >= 16 || queue.iter().map(Vec::len).sum::<usize>() + size > 256 * 1024 {
        return false;
    }
    queue.push_back(frame);
    true
}

pub fn poll_contact_roster_frame() -> Option<Vec<u8>> {
    crate::util::lock_recover(&CONTACT_ROSTER_FRAMES).pop_front()
}
