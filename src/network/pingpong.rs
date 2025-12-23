use serde::{Deserialize, Serialize};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::OnceLock;
use serde_big_array::BigArray;
use super::tor::TorManager;

/// Ping Token - sent from sender to recipient to initiate handshake
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PingToken {
    /// Sender's Ed25519 signing public key (32 bytes)
    pub sender_pubkey: [u8; 32],

    /// Recipient's Ed25519 signing public key (32 bytes)
    pub recipient_pubkey: [u8; 32],

    /// Sender's X25519 encryption public key (32 bytes)
    pub sender_x25519_pubkey: [u8; 32],

    /// Recipient's X25519 encryption public key (32 bytes)
    pub recipient_x25519_pubkey: [u8; 32],

    /// Cryptographic nonce to prevent replay attacks (24 bytes)
    pub nonce: [u8; 24],

    /// Unix timestamp when Ping was created
    pub timestamp: i64,

    /// Ed25519 signature of (sender_pubkey || recipient_pubkey || sender_x25519_pubkey || recipient_x25519_pubkey || nonce || timestamp)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Pong Token - response from recipient confirming readiness
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PongToken {
    /// Original Ping nonce (links Pong to Ping)
    pub ping_nonce: [u8; 24],

    /// New Pong nonce for this response
    pub pong_nonce: [u8; 24],

    /// Unix timestamp when Pong was created
    pub timestamp: i64,

    /// Whether user authenticated successfully
    pub authenticated: bool,

    /// Recipient's Ed25519 signature
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Delivery Confirmation (ACK) Token - confirms receipt of protocol messages
/// Sent by receiver to confirm they've received and processed the data
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeliveryAck {
    /// ID of the item being acknowledged (ping_id, message_id, tap_nonce, or pong_nonce)
    pub item_id: String,

    /// Type of ACK: "PING_ACK", "MESSAGE_ACK", "TAP_ACK", or "PONG_ACK"
    pub ack_type: String,

    /// Unix timestamp when ACK was created
    pub timestamp: i64,

    /// Sender's Ed25519 signature (proves this ACK is from the expected party)
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

/// Ping-Pong Protocol Manager
/// Handles the Secure Legion Ping-Pong Wake Protocol
pub struct PingPongManager {
    /// Local keypair for signing
    keypair: SigningKey,

    /// Tor network manager
    tor_manager: Arc<Mutex<TorManager>>,

    /// Active Ping sessions: ping_nonce -> PingSession
    ping_sessions: Arc<Mutex<HashMap<[u8; 24], PingSession>>>,

    /// Active Pong waiters: ping_nonce -> PongWaiter
    pong_waiters: Arc<Mutex<HashMap<[u8; 24], PongWaiter>>>,
}

/// Internal Ping session tracking
#[derive(Clone)]
struct PingSession {
    ping_token: PingToken,
    _recipient_onion: String,
    created_at: i64,
}

/// Internal Pong waiter for async waiting
struct PongWaiter {
    sender: tokio::sync::oneshot::Sender<PongToken>,
}

// ====================  GLOBAL PING SESSION STORAGE ====================

/// Global storage for received Ping tokens
/// Used by FFI methods to store and retrieve Pings when creating Pongs
static GLOBAL_PING_SESSIONS: OnceLock<Arc<Mutex<HashMap<String, StoredPingSession>>>> = OnceLock::new();

/// Stored Ping session for FFI access
#[derive(Clone)]
pub struct StoredPingSession {
    pub ping_token: PingToken,
    pub received_at: i64,
}

/// Get or initialize the global Ping sessions storage
fn get_ping_sessions() -> Arc<Mutex<HashMap<String, StoredPingSession>>> {
    GLOBAL_PING_SESSIONS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

/// Store a received Ping token by ping_id (hex-encoded nonce)
pub fn store_ping_session(ping_id: &str, ping_token: PingToken) {
    let sessions = get_ping_sessions();
    let mut sessions_lock = sessions.lock().unwrap();

    let session = StoredPingSession {
        ping_token,
        received_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    };

    sessions_lock.insert(ping_id.to_string(), session);
}

/// Retrieve a stored Ping token by ping_id
pub fn get_ping_session(ping_id: &str) -> Option<StoredPingSession> {
    let sessions = get_ping_sessions();
    let sessions_lock = sessions.lock().unwrap();
    sessions_lock.get(ping_id).cloned()
}

/// Remove a Ping session after Pong is sent
pub fn remove_ping_session(ping_id: &str) {
    let sessions = get_ping_sessions();
    let mut sessions_lock = sessions.lock().unwrap();
    sessions_lock.remove(ping_id);
}

/// Clean up expired Ping sessions (older than 5 minutes)
pub fn cleanup_expired_pings() {
    let sessions = get_ping_sessions();
    let mut sessions_lock = sessions.lock().unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    const MAX_AGE_SECONDS: i64 = 300; // 5 minutes

    sessions_lock.retain(|_, session| {
        let age = now - session.received_at;
        age < MAX_AGE_SECONDS
    });
}

// ====================  GLOBAL PONG SESSION STORAGE ====================

/// Global storage for received Pong tokens
/// Used by FFI methods to store and retrieve Pongs when waiting for responses
static GLOBAL_PONG_SESSIONS: OnceLock<Arc<Mutex<HashMap<String, StoredPongSession>>>> = OnceLock::new();

/// Stored Pong session for FFI access
#[derive(Clone)]
pub struct StoredPongSession {
    pub pong_token: PongToken,
    pub received_at: i64,
}

/// Get or initialize the global Pong sessions storage
fn get_pong_sessions() -> Arc<Mutex<HashMap<String, StoredPongSession>>> {
    GLOBAL_PONG_SESSIONS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

/// Store a received Pong token by ping_id (hex-encoded nonce from original Ping)
pub fn store_pong_session(ping_id: &str, pong_token: PongToken) {
    log::info!("╔════════════════════════════════════════");
    log::info!("║ 💾 STORING PONG SESSION");
    log::info!("║ Ping ID: {}", ping_id);
    log::info!("║ Authenticated: {}", pong_token.authenticated);
    log::info!("╚════════════════════════════════════════");

    let sessions = get_pong_sessions();
    let mut sessions_lock = sessions.lock().unwrap();

    let session = StoredPongSession {
        pong_token,
        received_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    };

    sessions_lock.insert(ping_id.to_string(), session);
    log::info!("✓ Pong stored successfully. Total Pongs in storage: {}", sessions_lock.len());
}

/// Retrieve a stored Pong token by ping_id
pub fn get_pong_session(ping_id: &str) -> Option<StoredPongSession> {
    let sessions = get_pong_sessions();
    let sessions_lock = sessions.lock().unwrap();
    let result = sessions_lock.get(ping_id).cloned();

    if result.is_some() {
        log::info!("✓ Found Pong for Ping ID: {}", ping_id);
    } else {
        log::debug!("✗ No Pong found for Ping ID: {} (have {} Pongs in storage)", ping_id, sessions_lock.len());
    }

    result
}

/// Remove a Pong session after it's been processed
pub fn remove_pong_session(ping_id: &str) {
    let sessions = get_pong_sessions();
    let mut sessions_lock = sessions.lock().unwrap();
    sessions_lock.remove(ping_id);
}

/// Clean up expired Pong sessions (older than 5 minutes)
pub fn cleanup_expired_pongs() {
    let sessions = get_pong_sessions();
    let mut sessions_lock = sessions.lock().unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    const MAX_AGE_SECONDS: i64 = 300; // 5 minutes

    sessions_lock.retain(|_, session| {
        let age = now - session.received_at;
        age < MAX_AGE_SECONDS
    });
}

// ====================  GLOBAL ACK SESSION STORAGE ====================

/// Global storage for received ACK tokens
/// Used by FFI methods to store and retrieve ACKs when confirming delivery
static GLOBAL_ACK_SESSIONS: OnceLock<Arc<Mutex<HashMap<String, StoredAckSession>>>> = OnceLock::new();

/// Stored ACK session for FFI access
#[derive(Clone)]
pub struct StoredAckSession {
    pub ack_token: DeliveryAck,
    pub received_at: i64,
}

/// Get or initialize the global ACK sessions storage
fn get_ack_sessions() -> Arc<Mutex<HashMap<String, StoredAckSession>>> {
    GLOBAL_ACK_SESSIONS
        .get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
        .clone()
}

/// Store a received ACK token by item_id (ping_id or message_id)
pub fn store_ack_session(item_id: &str, ack_token: DeliveryAck) {
    log::info!("╔════════════════════════════════════════");
    log::info!("║ 💾 STORING ACK SESSION");
    log::info!("║ Item ID: {}", item_id);
    log::info!("║ ACK Type: {}", ack_token.ack_type);
    log::info!("╚════════════════════════════════════════");

    let sessions = get_ack_sessions();
    let mut sessions_lock = sessions.lock().unwrap();

    let session = StoredAckSession {
        ack_token,
        received_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    };

    sessions_lock.insert(item_id.to_string(), session);
    log::info!("✓ ACK stored successfully. Total ACKs in storage: {}", sessions_lock.len());
}

/// Retrieve a stored ACK token by item_id
pub fn get_ack_session(item_id: &str) -> Option<StoredAckSession> {
    let sessions = get_ack_sessions();
    let sessions_lock = sessions.lock().unwrap();
    let result = sessions_lock.get(item_id).cloned();

    if result.is_some() {
        log::info!("✓ Found ACK for Item ID: {}", item_id);
    } else {
        log::debug!("✗ No ACK found for Item ID: {} (have {} ACKs in storage)", item_id, sessions_lock.len());
    }

    result
}

/// Remove an ACK session after it's been processed
pub fn remove_ack_session(item_id: &str) {
    let sessions = get_ack_sessions();
    let mut sessions_lock = sessions.lock().unwrap();
    sessions_lock.remove(item_id);
}

/// Clean up expired ACK sessions (older than 5 minutes)
pub fn cleanup_expired_acks() {
    let sessions = get_ack_sessions();
    let mut sessions_lock = sessions.lock().unwrap();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    const MAX_AGE_SECONDS: i64 = 300; // 5 minutes

    sessions_lock.retain(|_, session| {
        let age = now - session.received_at;
        age < MAX_AGE_SECONDS
    });
}

impl PingToken {
    /// Create a new Ping token
    pub fn new(
        sender_keypair: &SigningKey,
        recipient_pubkey: &VerifyingKey,
        sender_x25519_pubkey: &[u8; 32],
        recipient_x25519_pubkey: &[u8; 32],
    ) -> Result<Self, Box<dyn std::error::Error>> {

        // Generate random nonce
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce)?;

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        // Create the Ping token (without signature first)
        let mut ping = PingToken {
            sender_pubkey: sender_keypair.verifying_key().to_bytes(),
            recipient_pubkey: recipient_pubkey.to_bytes(),
            sender_x25519_pubkey: *sender_x25519_pubkey,
            recipient_x25519_pubkey: *recipient_x25519_pubkey,
            nonce,
            timestamp,
            signature: [0u8; 64],
        };

        // Sign the Ping
        let signature = ping.sign(sender_keypair)?;
        ping.signature = signature.to_bytes();

        Ok(ping)
    }

    /// Create a Ping token with a specific nonce and timestamp (for consistent retries)
    /// This ensures retries use identical encrypted bytes (same nonce + same timestamp = safe)
    pub fn with_nonce(
        sender_keypair: &SigningKey,
        recipient_pubkey: &VerifyingKey,
        sender_x25519_pubkey: &[u8; 32],
        recipient_x25519_pubkey: &[u8; 32],
        nonce: [u8; 24],
        timestamp: i64,  // Use provided timestamp instead of generating
    ) -> Result<Self, Box<dyn std::error::Error>> {

        // Create the Ping token (without signature first)
        let mut ping = PingToken {
            sender_pubkey: sender_keypair.verifying_key().to_bytes(),
            recipient_pubkey: recipient_pubkey.to_bytes(),
            sender_x25519_pubkey: *sender_x25519_pubkey,
            recipient_x25519_pubkey: *recipient_x25519_pubkey,
            nonce,
            timestamp,
            signature: [0u8; 64],
        };

        // Sign the Ping
        let signature = ping.sign(sender_keypair)?;
        ping.signature = signature.to_bytes();

        Ok(ping)
    }

    /// Sign the Ping token
    fn sign(&self, keypair: &SigningKey) -> Result<Signature, Box<dyn std::error::Error>> {
        let message = self.serialize_for_signing();
        Ok(keypair.sign(&message))
    }

    /// Verify the Ping signature
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let sender_pubkey = VerifyingKey::from_bytes(&self.sender_pubkey)?;
        let signature = Signature::from_bytes(&self.signature);
        let message = self.serialize_for_signing();

        Ok(sender_pubkey.verify(&message, &signature).is_ok())
    }

    /// Serialize Ping for signing (everything except the signature field)
    fn serialize_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.sender_pubkey);
        bytes.extend_from_slice(&self.recipient_pubkey);
        bytes.extend_from_slice(&self.sender_x25519_pubkey);
        bytes.extend_from_slice(&self.recipient_x25519_pubkey);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Serialize to bytes for network transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(self)?)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(bincode::deserialize(bytes)?)
    }
}

impl PongToken {
    /// Create a new Pong token in response to a Ping
    pub fn new(
        ping: &PingToken,
        recipient_keypair: &SigningKey,
        authenticated: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {

        // Generate new Pong nonce
        let mut pong_nonce = [0u8; 24];
        getrandom::getrandom(&mut pong_nonce)?;

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        // Create Pong token (without signature)
        let mut pong = PongToken {
            ping_nonce: ping.nonce,
            pong_nonce,
            timestamp,
            authenticated,
            signature: [0u8; 64],
        };

        // Sign the Pong
        let signature = pong.sign(recipient_keypair)?;
        pong.signature = signature.to_bytes();

        Ok(pong)
    }

    /// Sign the Pong token
    fn sign(&self, keypair: &SigningKey) -> Result<Signature, Box<dyn std::error::Error>> {
        let message = self.serialize_for_signing();
        Ok(keypair.sign(&message))
    }

    /// Verify the Pong signature
    pub fn verify(&self, signer_pubkey: &VerifyingKey) -> Result<bool, Box<dyn std::error::Error>> {
        let signature = Signature::from_bytes(&self.signature);
        let message = self.serialize_for_signing();

        Ok(signer_pubkey.verify(&message, &signature).is_ok())
    }

    /// Serialize Pong for signing
    fn serialize_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.ping_nonce);
        bytes.extend_from_slice(&self.pong_nonce);
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.push(if self.authenticated { 1 } else { 0 });
        bytes
    }

    /// Serialize to bytes for network transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(self)?)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(bincode::deserialize(bytes)?)
    }
}

impl DeliveryAck {
    /// ACK type constants
    pub const ACK_TYPE_PING: &'static str = "PING_ACK";
    pub const ACK_TYPE_MESSAGE: &'static str = "MESSAGE_ACK";
    pub const ACK_TYPE_TAP: &'static str = "TAP_ACK";
    pub const ACK_TYPE_PONG: &'static str = "PONG_ACK";

    /// Create a new Delivery ACK token
    /// item_id: ping_id, message_id, tap_nonce, or pong_nonce being acknowledged
    /// ack_type: "PING_ACK", "MESSAGE_ACK", "TAP_ACK", or "PONG_ACK"
    /// keypair: Ed25519 signing key of the party sending the ACK
    pub fn new(
        item_id: &str,
        ack_type: &str,
        keypair: &SigningKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {

        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;

        // Create ACK token (without signature)
        let mut ack = DeliveryAck {
            item_id: item_id.to_string(),
            ack_type: ack_type.to_string(),
            timestamp,
            signature: [0u8; 64],
        };

        // Sign the ACK
        let signature = ack.sign(keypair)?;
        ack.signature = signature.to_bytes();

        Ok(ack)
    }

    /// Sign the ACK token
    fn sign(&self, keypair: &SigningKey) -> Result<Signature, Box<dyn std::error::Error>> {
        let message = self.serialize_for_signing();
        Ok(keypair.sign(&message))
    }

    /// Verify the ACK signature
    pub fn verify(&self, signer_pubkey: &VerifyingKey) -> Result<bool, Box<dyn std::error::Error>> {
        let signature = Signature::from_bytes(&self.signature);
        let message = self.serialize_for_signing();

        Ok(signer_pubkey.verify(&message, &signature).is_ok())
    }

    /// Serialize ACK for signing
    fn serialize_for_signing(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.item_id.as_bytes());
        bytes.extend_from_slice(self.ack_type.as_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Serialize to bytes for network transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(bincode::serialize(self)?)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(bincode::deserialize(bytes)?)
    }
}

impl PingPongManager {
    /// Create a new PingPongManager with a keypair and Tor manager
    pub fn new(keypair: SigningKey, tor_manager: TorManager) -> Self {
        PingPongManager {
            keypair,
            tor_manager: Arc::new(Mutex::new(tor_manager)),
            ping_sessions: Arc::new(Mutex::new(HashMap::new())),
            pong_waiters: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Send a Ping token to recipient via Tor
    /// Returns the Ping ID (nonce as hex string)
    pub async fn send_ping(
        &self,
        recipient_pubkey: &VerifyingKey,
        sender_x25519_pubkey: &[u8; 32],
        recipient_x25519_pubkey: &[u8; 32],
        recipient_onion: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {

        // Create Ping token
        let ping = PingToken::new(&self.keypair, recipient_pubkey, sender_x25519_pubkey, recipient_x25519_pubkey)?;
        let ping_id = hex::encode(&ping.nonce);

        // Store Ping session
        let session = PingSession {
            ping_token: ping.clone(),
            _recipient_onion: recipient_onion.to_string(),
            created_at: ping.timestamp,
        };

        self.ping_sessions.lock().unwrap().insert(ping.nonce, session);

        // Serialize Ping token
        let ping_bytes = ping.to_bytes()?;

        // Send Ping via Tor to recipient's .onion address
        let tor_manager = self.tor_manager.lock().unwrap();

        // Default Ping-Pong port
        const PING_PONG_PORT: u16 = 9150;

        // Connect to recipient via Tor
        let mut conn = tor_manager.connect(recipient_onion, PING_PONG_PORT).await?;

        // Send Ping token
        tor_manager.send(&mut conn, &ping_bytes).await?;

        Ok(ping_id)
    }

    /// Wait for Pong response with timeout
    /// Returns true if Pong received, false on timeout
    pub async fn wait_for_pong(
        &self,
        ping_id: &str,
        timeout_seconds: u64,
    ) -> Result<bool, Box<dyn std::error::Error>> {

        // Decode ping_id (hex nonce)
        let nonce_bytes = hex::decode(ping_id)?;
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

        // Create oneshot channel for Pong notification
        let (tx, rx) = tokio::sync::oneshot::channel();

        // Register Pong waiter
        self.pong_waiters.lock().unwrap().insert(nonce, PongWaiter { sender: tx });

        // Wait for Pong with timeout
        let timeout_duration = std::time::Duration::from_secs(timeout_seconds);

        match tokio::time::timeout(timeout_duration, rx).await {
            Ok(Ok(pong)) => {
                // Pong received!
                // Verify it's authenticated
                Ok(pong.authenticated)
            }
            Ok(Err(_)) => {
                // Channel closed unexpectedly
                Ok(false)
            }
            Err(_) => {
                // Timeout
                Ok(false)
            }
        }
    }

    /// Handle incoming Ping token
    /// Returns Pong token if user authenticated, None otherwise
    pub async fn handle_incoming_ping(
        &self,
        ping_bytes: &[u8],
        user_authenticated: bool,
    ) -> Result<Option<PongToken>, Box<dyn std::error::Error>> {

        // Deserialize Ping
        let ping = PingToken::from_bytes(ping_bytes)?;

        // Verify Ping signature
        if !ping.verify()? {
            return Err("Invalid Ping signature".into());
        }

        // Check if Ping is for us
        if ping.recipient_pubkey != self.keypair.verifying_key().to_bytes() {
            return Err("Ping not for this device".into());
        }

        // Check Ping age (reject old Pings)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let age = now - ping.timestamp;
        if age > 300 { // 5 minutes max age
            return Err("Ping too old".into());
        }

        if user_authenticated {
            // Create and return Pong
            let pong = PongToken::new(&ping, &self.keypair, true)?;
            Ok(Some(pong))
        } else {
            // User not authenticated - don't send Pong yet
            Ok(None)
        }
    }

    /// Handle incoming Pong token
    /// Notifies waiting sender
    pub async fn handle_incoming_pong(
        &self,
        pong_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {

        // Deserialize Pong
        let pong = PongToken::from_bytes(pong_bytes)?;

        // Save ping_nonce before moving pong
        let ping_nonce = pong.ping_nonce;

        // Find corresponding Ping session
        let session = self.ping_sessions
            .lock()
            .unwrap()
            .get(&ping_nonce)
            .cloned();

        if let Some(session) = session {
            // Verify Pong signature
            let recipient_pubkey = VerifyingKey::from_bytes(&session.ping_token.recipient_pubkey)?;
            if !pong.verify(&recipient_pubkey)? {
                return Err("Invalid Pong signature".into());
            }

            // Notify waiter
            if let Some(waiter) = self.pong_waiters.lock().unwrap().remove(&ping_nonce) {
                let _ = waiter.sender.send(pong);
            }

            // Clean up session
            self.ping_sessions.lock().unwrap().remove(&ping_nonce);
        }

        Ok(())
    }

    /// Clean up expired Ping sessions
    pub fn cleanup_expired_sessions(&self, max_age_seconds: i64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut sessions = self.ping_sessions.lock().unwrap();
        sessions.retain(|_, session| {
            let age = now - session.created_at;
            age < max_age_seconds
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_token_creation() {
        let mut csprng = OsRng{};
        let sender_keypair = Keypair::generate(&mut csprng);
        let recipient_keypair = Keypair::generate(&mut csprng);

        let ping = PingToken::new(&sender_keypair, &recipient_keypair.public).unwrap();

        // Verify signature
        assert!(ping.verify().unwrap());
    }

    #[test]
    fn test_pong_token_creation() {
        let mut csprng = OsRng{};
        let sender_keypair = Keypair::generate(&mut csprng);
        let recipient_keypair = Keypair::generate(&mut csprng);

        let ping = PingToken::new(&sender_keypair, &recipient_keypair.public).unwrap();
        let pong = PongToken::new(&ping, &recipient_keypair, true).unwrap();

        // Verify signature
        assert!(pong.verify(&recipient_keypair.public).unwrap());
        assert_eq!(pong.ping_nonce, ping.nonce);
        assert!(pong.authenticated);
    }

    #[test]
    fn test_ping_pong_serialization() {
        let mut csprng = OsRng{};
        let sender_keypair = Keypair::generate(&mut csprng);
        let recipient_keypair = Keypair::generate(&mut csprng);

        let ping = PingToken::new(&sender_keypair, &recipient_keypair.public).unwrap();
        let ping_bytes = ping.to_bytes().unwrap();
        let ping_deserialized = PingToken::from_bytes(&ping_bytes).unwrap();

        assert_eq!(ping.nonce, ping_deserialized.nonce);
        assert_eq!(ping.timestamp, ping_deserialized.timestamp);
    }
}
