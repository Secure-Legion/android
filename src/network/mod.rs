pub mod tor;
pub mod arti;
pub mod friend_request_server;
pub mod socks5_client;

pub use tor::{TorManager, PENDING_CONNECTIONS, PendingConnection, compute_onion_address_from_ed25519_seed};
pub use friend_request_server::{ContactExchangeEndpoint, get_endpoint};
pub use socks5_client::Socks5Client;

// Diagnostic counters shared between network modules and FFI
use std::sync::atomic::AtomicU64;
pub static RX_MESSAGE_ACCEPT_COUNT: AtomicU64 = AtomicU64::new(0);
pub static RX_MESSAGE_TX_DROP_COUNT: AtomicU64 = AtomicU64::new(0);
