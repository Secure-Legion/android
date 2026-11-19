pub mod pingpong;

// Re-export public network modules from securelegion-crypto
pub use securelegion_crypto::network::tor;
pub use securelegion_crypto::network::arti;
pub use securelegion_crypto::network::friend_request_server;
pub use securelegion_crypto::network::socks5_client;
pub use securelegion_crypto::network::contact_list_sync;

#[cfg(not(target_os = "windows"))]
pub use securelegion_crypto::network::{TorManager, PENDING_CONNECTIONS, PendingConnection, compute_onion_address_from_ed25519_seed};
pub use securelegion_crypto::network::{ContactExchangeEndpoint, get_endpoint};
pub use securelegion_crypto::network::Socks5Client;
pub use securelegion_crypto::network::{RX_MESSAGE_ACCEPT_COUNT, RX_MESSAGE_TX_DROP_COUNT};

pub use pingpong::{
    PingToken,
    PongToken,
    PingPongManager,
    store_ping_session,
    get_ping_session,
    remove_ping_session,
    cleanup_expired_pings,
    remove_pong_session,
    cleanup_expired_pongs,
    remove_ack_session,
    cleanup_expired_acks,
};
