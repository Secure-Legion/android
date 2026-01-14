/// Tor Network Manager (using Tor_Onion_Proxy_Library)
/// Connects to Tor via SOCKS5 proxy managed by OnionProxyManager
///
/// The Android OnionProxyManager handles Tor lifecycle, we just use SOCKS5

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};
use std::sync::Mutex as StdMutex;
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Global bootstrap status (0-100%) - updated by event listener
pub static BOOTSTRAP_STATUS: AtomicU32 = AtomicU32::new(0);

/// Get bootstrap status from the global atomic (fast, no control port query)
/// This is updated in real-time by the event listener
pub fn get_bootstrap_status_fast() -> u32 {
    BOOTSTRAP_STATUS.load(Ordering::SeqCst)
}

/// Start the bootstrap event listener on a separate control port connection
/// This spawns a background task that listens for STATUS_CLIENT events
/// and updates BOOTSTRAP_STATUS in real-time
pub fn start_bootstrap_event_listener() {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create runtime for event listener");

        rt.block_on(async {
            if let Err(e) = bootstrap_event_listener_task().await {
                log::error!("Bootstrap event listener failed: {}", e);
            }
        });
    });
}

/// Background task that subscribes to STATUS_CLIENT events and updates bootstrap status
async fn bootstrap_event_listener_task() -> Result<(), Box<dyn Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{sleep, Duration};

    log::info!("Starting bootstrap event listener...");

    // Connect to control port (separate connection from main TorManager)
    // Retry up to 60 times (60 seconds) if control port not ready yet
    let mut control = None;
    for attempt in 1..=60 {
        match TcpStream::connect("127.0.0.1:9051").await {
            Ok(s) => {
                log::info!("Event listener: Connected to control port on attempt {}", attempt);
                control = Some(s);
                break;
            }
            Err(e) => {
                if attempt == 1 {
                    log::info!("Event listener: Waiting for control port to become ready...");
                }
                if attempt == 60 {
                    log::error!("Event listener: Failed to connect to control port after {} attempts: {}", attempt, e);
                    return Err(e.into());
                }
                sleep(Duration::from_secs(1)).await;
            }
        }
    }

    let mut control = control.unwrap();

    // Authenticate
    control.write_all(b"AUTHENTICATE\r\n").await?;
    let mut buf = vec![0u8; 1024];
    let n = control.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if !response.contains("250 OK") {
        log::error!("Event listener: Auth failed: {}", response);
        return Err("Event listener auth failed".into());
    }

    log::info!("Event listener: Authenticated to control port");

    // Subscribe to STATUS_CLIENT events for bootstrap progress
    control.write_all(b"SETEVENTS STATUS_CLIENT\r\n").await?;
    let n = control.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    if !response.contains("250 OK") {
        log::error!("Event listener: Failed to subscribe to events: {}", response);
        return Err("Failed to subscribe to STATUS_CLIENT events".into());
    }

    log::info!("Event listener: Subscribed to STATUS_CLIENT events");

    // Also get initial bootstrap status
    control.write_all(b"GETINFO status/bootstrap-phase\r\n").await?;
    let n = control.read(&mut buf).await?;
    let response = String::from_utf8_lossy(&buf[..n]);

    // Parse initial status
    if let Some(progress) = parse_bootstrap_progress(&response) {
        BOOTSTRAP_STATUS.store(progress, Ordering::SeqCst);
        log::info!("Event listener: Initial bootstrap status: {}%", progress);
    }

    // Now continuously read events
    log::info!("Event listener: Listening for bootstrap events...");
    let mut event_buf = vec![0u8; 4096];

    loop {
        match control.read(&mut event_buf).await {
            Ok(0) => {
                log::info!("Event listener: Control connection closed");
                break;
            }
            Ok(n) => {
                let event = String::from_utf8_lossy(&event_buf[..n]);

                // Check for bootstrap progress event
                // Format: 650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=XX TAG=... SUMMARY="..."
                if event.contains("BOOTSTRAP") && event.contains("PROGRESS=") {
                    if let Some(progress) = parse_bootstrap_progress(&event) {
                        let old_value = BOOTSTRAP_STATUS.swap(progress, Ordering::SeqCst);
                        if progress != old_value {
                            log::info!("Bootstrap progress: {}%", progress);
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("Event listener: Read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Parse bootstrap progress percentage from Tor control response/event
fn parse_bootstrap_progress(response: &str) -> Option<u32> {
    // Look for PROGRESS=XX in the response
    if let Some(progress_str) = response.split("PROGRESS=").nth(1) {
        if let Some(percentage_str) = progress_str.split_whitespace().next() {
            if let Ok(percentage) = percentage_str.parse::<u32>() {
                return Some(percentage);
            }
        }
    }
    None
}

/// Wire protocol message type constants
pub const MSG_TYPE_PING: u8 = 0x01;
pub const MSG_TYPE_PONG: u8 = 0x02;
pub const MSG_TYPE_TEXT: u8 = 0x03;
pub const MSG_TYPE_VOICE: u8 = 0x04;
pub const MSG_TYPE_TAP: u8 = 0x05;
pub const MSG_TYPE_DELIVERY_CONFIRMATION: u8 = 0x06;
pub const MSG_TYPE_FRIEND_REQUEST: u8 = 0x07;
pub const MSG_TYPE_FRIEND_REQUEST_ACCEPTED: u8 = 0x08;
pub const MSG_TYPE_IMAGE: u8 = 0x09;
pub const MSG_TYPE_PAYMENT_REQUEST: u8 = 0x0A;
pub const MSG_TYPE_PAYMENT_SENT: u8 = 0x0B;
pub const MSG_TYPE_PAYMENT_ACCEPTED: u8 = 0x0C;
pub const MSG_TYPE_CALL_SIGNALING: u8 = 0x0D;  // Voice call signaling (OFFER/ANSWER/REJECT/END/BUSY)

/// Structure representing a pending connection waiting for Pong response
pub struct PendingConnection {
    pub socket: TcpStream,
    pub encrypted_ping: Vec<u8>,
}

/// Global map of pending connections: connection_id -> PendingConnection
pub static PENDING_CONNECTIONS: Lazy<Arc<StdMutex<HashMap<u64, PendingConnection>>>> =
    Lazy::new(|| Arc::new(StdMutex::new(HashMap::new())));

/// Counter for generating unique connection IDs
pub static CONNECTION_ID_COUNTER: Lazy<Arc<StdMutex<u64>>> =
    Lazy::new(|| Arc::new(StdMutex::new(0)));

/// Global friend request channel sender
/// Separate from regular message channels to avoid interference with working message system
/// Initialized from JNI via startFriendRequestListener()
pub static FRIEND_REQUEST_TX: once_cell::sync::OnceCell<Arc<StdMutex<tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>> = once_cell::sync::OnceCell::new();

/// Global channel for MESSAGE types (TEXT/VOICE/IMAGE/PAYMENT)
/// Separate from PING channel to enable direct routing without trial decryption
/// Initialized when listener starts
pub static MESSAGE_TX: once_cell::sync::OnceCell<Arc<StdMutex<tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>>>> = once_cell::sync::OnceCell::new();

/// Global channel for VOICE CALL types (CALL_SIGNALING)
/// Completely separate from MESSAGE to allow simultaneous text messaging during voice calls
/// Initialized when voice listener starts
pub static VOICE_TX: once_cell::sync::OnceCell<Arc<StdMutex<tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>>>> = once_cell::sync::OnceCell::new();

/// Global channel for DELIVERY_CONFIRMATION (ACK) types
/// Shared between port 8080 (main listener - error recovery) and port 9153 (dedicated ACK listener)
/// This ensures ACKs arriving on wrong port still get processed (no message loss)
/// Initialized when ACK listener starts on port 9153
pub static ACK_TX: once_cell::sync::OnceCell<Arc<StdMutex<tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>>>> = once_cell::sync::OnceCell::new();

pub struct TorManager {
    control_stream: Option<Arc<Mutex<TcpStream>>>,
    voice_control_stream: Option<Arc<Mutex<TcpStream>>>,  // VOICE TOR: port 9052 (Single Onion)
    hidden_service_address: Option<String>,
    listener_handle: Option<tokio::task::JoinHandle<()>>,
    incoming_ping_tx: Option<tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>>,
    hs_service_port: u16,
    hs_local_port: u16,
    socks_port: u16,
}

impl TorManager {
    /// Initialize Tor manager
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(TorManager {
            control_stream: None,
            voice_control_stream: None,  // VOICE TOR initialized separately
            hidden_service_address: None,
            listener_handle: None,
            incoming_ping_tx: None,
            hs_service_port: 9150, // Virtual port on .onion
            hs_local_port: 8080,   // Local port where app listens
            socks_port: 9050,      // SOCKS proxy port (managed by OnionProxyManager)
        })
    }

    /// Connect to Tor control port (Tor daemon managed by OnionProxyManager)
    /// Returns status message
    pub async fn initialize(&mut self) -> Result<String, Box<dyn Error>> {
        log::info!("Connecting to Tor control port (OnionProxyManager handles Tor daemon)...");

        // Connect to control port (OnionProxyManager starts Tor on port 9051)
        let mut control = TcpStream::connect("127.0.0.1:9051").await?;

        // Authenticate with NULL auth (OnionProxyManager configures this)
        control.write_all(b"AUTHENTICATE\r\n").await?;

        let mut buf = vec![0u8; 1024];
        let n = control.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.contains("250 OK") {
            return Err(format!("Control port authentication failed: {}", response).into());
        }

        self.control_stream = Some(Arc::new(Mutex::new(control)));

        log::info!("Connected to Tor control port successfully");

        // Wait for Tor to bootstrap (build circuits)
        log::info!("Waiting for Tor to bootstrap...");
        self.wait_for_bootstrap().await?;

        log::info!("Tor fully bootstrapped and ready");
        Ok("Tor client ready (managed by OnionProxyManager)".to_string())
    }

    /// Connect to VOICE Tor control port (port 9052 - Single Onion Service instance)
    /// This is a separate Tor daemon specifically for voice hidden service
    /// Must be called AFTER voice Tor daemon is started by TorManager.kt
    pub async fn initialize_voice_control(&mut self) -> Result<String, Box<dyn Error>> {
        log::info!("Connecting to VOICE Tor control port (9052)...");

        // Connect to voice Tor control port
        let mut control = TcpStream::connect("127.0.0.1:9052").await?;

        // Read voice Tor cookie file
        let cookie_path = "/data/data/com.securelegion/files/voice_tor/control_auth_cookie";
        let cookie = match std::fs::read(cookie_path) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("Failed to read voice Tor cookie at {}: {}", cookie_path, e);
                log::warn!("Trying alternate path...");
                // Try alternate path
                let alt_path = "/data/user/0/com.securelegion/files/voice_tor/control_auth_cookie";
                std::fs::read(alt_path)?
            }
        };

        // Hex-encode the cookie
        let cookie_hex = hex::encode(&cookie);

        // Authenticate with cookie
        let auth_cmd = format!("AUTHENTICATE {}\r\n", cookie_hex);
        control.write_all(auth_cmd.as_bytes()).await?;

        let mut buf = vec![0u8; 1024];
        let n = control.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.contains("250 OK") {
            return Err(format!("Voice Tor control port authentication failed: {}", response).into());
        }

        self.voice_control_stream = Some(Arc::new(Mutex::new(control)));

        log::info!("Connected to VOICE Tor control port (9052) successfully");
        Ok("Voice Tor control ready (Single Onion Service mode)".to_string())
    }

    /// Wait for Tor to finish bootstrapping (100%)
    async fn wait_for_bootstrap(&self) -> Result<(), Box<dyn Error>> {
        let max_attempts = 60; // 60 seconds max

        for attempt in 1..=max_attempts {
            let status = self.get_bootstrap_status().await?;

            if status >= 100 {
                log::info!("Tor bootstrap complete ({}%)", status);
                return Ok(());
            }

            if attempt % 5 == 0 {
                log::info!("Tor bootstrapping: {}%", status);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Err("Tor bootstrap timeout - took longer than 60 seconds".into())
    }

    /// Get current Tor bootstrap percentage
    pub async fn get_bootstrap_status(&self) -> Result<u32, Box<dyn Error>> {
        let control_stream = self.control_stream.as_ref()
            .ok_or("Control port not connected")?;

        let mut control = control_stream.lock().await;

        // Send GETINFO status/bootstrap-phase command
        control.write_all(b"GETINFO status/bootstrap-phase\r\n").await?;

        let mut buf = vec![0u8; 2048];
        let n = control.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        // Parse bootstrap percentage from response
        // Format: 250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
        if let Some(progress_str) = response.split("PROGRESS=").nth(1) {
            if let Some(percentage_str) = progress_str.split_whitespace().next() {
                if let Ok(percentage) = percentage_str.parse::<u32>() {
                    return Ok(percentage);
                }
            }
        }

        // If can't parse, assume 0%
        Ok(0)
    }

    /// Create a deterministic .onion address from seed-derived key
    ///
    /// Uses ADD_ONION command on control port to create hidden service
    ///
    /// # Arguments
    /// * `service_port` - The virtual port on the .onion address (e.g., 9150)
    /// * `local_port` - The local port to forward connections to (e.g., 8080)
    /// * `hs_private_key` - 32-byte Ed25519 private key from KeyManager (seed-derived)
    ///
    /// # Returns
    /// A deterministic v3 .onion address
    pub async fn create_hidden_service(
        &mut self,
        service_port: u16,
        local_port: u16,
        hs_private_key: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        // Validate key length
        if hs_private_key.len() != 32 {
            return Err("Hidden service private key must be 32 bytes".into());
        }

        // Create Ed25519 signing key from provided seed-derived key
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(hs_private_key);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Get public key
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        // Generate .onion address from public key
        let mut onion_bytes = Vec::new();
        onion_bytes.extend_from_slice(&verifying_key.to_bytes());

        // Add checksum
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(&verifying_key.to_bytes());
        hasher.update(&[0x03]); // version 3
        let checksum = hasher.finalize();
        onion_bytes.extend_from_slice(&checksum[..2]);

        // Add version
        onion_bytes.push(0x03);

        // Encode to base32
        let onion_addr = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &onion_bytes);
        let full_address = format!("{}.onion", onion_addr);

        // Store ports for listener configuration
        self.hs_service_port = service_port;
        self.hs_local_port = local_port;

        // Format private key for ADD_ONION command (base64 of 64-byte expanded key)
        let expanded_key = signing_key.to_keypair_bytes();
        let key_base64 = base64::encode(&expanded_key);

        // Subscribe to HS_DESC events BEFORE creating the hidden service
        // This ensures we catch all descriptor upload events
        let control = self.control_stream.as_ref()
            .ok_or("Control port not connected")?;

        log::info!("Subscribing to HS_DESC events before creating hidden service...");
        {
            let mut stream = control.lock().await;
            stream.write_all(b"SETEVENTS HS_DESC\r\n").await?;
            let mut buf = vec![0u8; 512];
            let n = stream.read(&mut buf).await?;
            let response = String::from_utf8_lossy(&buf[..n]);
            if !response.contains("250 OK") {
                log::warn!("Failed to subscribe to HS_DESC events: {}", response);
            } else {
                log::info!("Subscribed to HS_DESC events successfully");
            }
        }

        // Now create the hidden service - descriptors will be uploaded and we'll receive events
        // IMPORTANT: Expose FOUR ports for Ping-Pong-Tap-ACK protocol:
        //   - Port 9150 → local 8080 (Ping listener - main hidden service port)
        //   - Port 8080 → local 8080 (Pong listener - SAME as main listener for routing)
        //   - Port 9151 → local 9151 (Tap listener)
        //   - Port 9153 → local 9153 (ACK/Delivery Confirmation listener)
        let (actual_onion_address, is_new_service) = {
            let mut stream = control.lock().await;

            // Create ephemeral hidden service with Detach flag
            // Detach allows the service to persist beyond the control connection and be deleted from any connection
            // This fixes "service already registered" errors from crashed/orphaned services
            let command = format!(
                "ADD_ONION ED25519-V3:{} Flags=Detach Port={},127.0.0.1:{} Port=8080,127.0.0.1:8080 Port=9151,127.0.0.1:9151 Port=9153,127.0.0.1:9153\r\n",
                key_base64, service_port, local_port
            );

            stream.write_all(command.as_bytes()).await?;

            let mut buf = vec![0u8; 2048];
            let n = stream.read(&mut buf).await?;
            let mut response = String::from_utf8_lossy(&buf[..n]).to_string();

            log::info!("ADD_ONION response: {}", response);

            // Check if service was created successfully
            if !response.contains("250 OK") {
                // If collision detected, delete the existing service and retry
                if response.contains("550") && response.contains("collision") {
                    log::warn!("Onion address collision detected - attempting to delete existing service and retry...");

                    // Delete the colliding service
                    let del_command = format!("DEL_ONION {}\r\n", onion_addr);
                    stream.write_all(del_command.as_bytes()).await?;

                    let mut del_buf = vec![0u8; 2048];
                    let del_n = stream.read(&mut del_buf).await?;
                    let del_response = String::from_utf8_lossy(&del_buf[..del_n]);
                    log::info!("DEL_ONION response: {}", del_response);

                    // Retry ADD_ONION
                    stream.write_all(command.as_bytes()).await?;
                    let retry_n = stream.read(&mut buf).await?;
                    response = String::from_utf8_lossy(&buf[..retry_n]).to_string();
                    log::info!("ADD_ONION retry response: {}", response);

                    if !response.contains("250 OK") {
                        return Err(format!("Failed to create hidden service after cleanup: {}", response).into());
                    }
                } else {
                    return Err(format!("Failed to create hidden service: {}", response).into());
                }
            }

            // Successfully created new service - extract the actual ServiceID from Tor's response
            let actual_onion = if let Some(service_line) = response.lines().find(|l| l.contains("ServiceID=")) {
                if let Some(start_idx) = service_line.find("ServiceID=") {
                    let service_id = &service_line[start_idx + 10..]; // Skip "ServiceID="
                    format!("{}.onion", service_id.trim())
                } else {
                    full_address.clone()
                }
            } else {
                full_address.clone()
            };

            self.hidden_service_address = Some(actual_onion.clone());
            log::info!("Hidden service registered: {}", actual_onion);
            log::info!("Service port: {}, Local forward: 127.0.0.1:{}", service_port, local_port);
            // Return the address and mark as new
            (actual_onion, true)
        };

        // Use the actual onion address from Tor's response
        let full_address = actual_onion_address;

        // Skip descriptor wait for ephemeral services (without Flags=Detach)
        // Tor will publish descriptors in the background automatically
        // Waiting for HS_DESC UPLOADED events doesn't work reliably with ephemeral services
        log::info!("Ephemeral hidden service created - Tor will publish descriptors in background");
        log::info!("Hidden service is now reachable: {}", full_address);

        Ok(full_address)
    }

    /// Create voice hidden service for voice calling (port 9152 only)
    /// This is a dedicated hidden service separate from messaging
    pub async fn create_voice_hidden_service(
        &mut self,
        voice_private_key: &[u8],
    ) -> Result<String, Box<dyn Error>> {
        // Validate key length
        if voice_private_key.len() != 32 {
            return Err("Voice service private key must be 32 bytes".into());
        }

        // Create Ed25519 signing key from provided seed-derived key
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(voice_private_key);
        let signing_key = SigningKey::from_bytes(&key_bytes);

        // Get public key
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        // Generate .onion address from public key
        let mut onion_bytes = Vec::new();
        onion_bytes.extend_from_slice(&verifying_key.to_bytes());

        // Add checksum
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(&verifying_key.to_bytes());
        hasher.update(&[0x03]); // version 3
        let checksum = hasher.finalize();
        onion_bytes.extend_from_slice(&checksum[..2]);

        // Add version
        onion_bytes.push(0x03);

        // Encode to base32
        let onion_addr = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &onion_bytes);
        let full_address = format!("{}.onion", onion_addr);

        // Format private key for ADD_ONION command (base64 of 64-byte expanded key)
        let expanded_key = signing_key.to_keypair_bytes();
        let key_base64 = base64::encode(&expanded_key);

        // Create voice hidden service on port 9152 using VOICE TOR (port 9052)
        // Voice Tor is configured with HiddenServiceNonAnonymousMode 1 and HiddenServiceSingleHopMode 1
        // This creates a Single Onion Service (3-hop instead of 6-hop)
        let control = self.voice_control_stream.as_ref()
            .ok_or("Voice Tor control port not connected - did you call initialize_voice_control()?")?;

        let actual_onion_address = {
            let mut stream = control.lock().await;

            // Create ephemeral voice hidden service with Detach flag and only port 9152
            // Single Onion mode is configured in voice torrc (HiddenServiceNonAnonymousMode 1)
            // Detach allows cleanup of orphaned services from previous crashes
            let command = format!(
                "ADD_ONION ED25519-V3:{} Flags=Detach Port=9152,127.0.0.1:9152\r\n",
                key_base64
            );

            stream.write_all(command.as_bytes()).await?;

            let mut buf = vec![0u8; 2048];
            let n = stream.read(&mut buf).await?;
            let response = String::from_utf8_lossy(&buf[..n]);

            log::info!("ADD_ONION (voice) response: {}", response);

            // Check if service was created successfully
            if !response.contains("250 OK") {
                return Err(format!("Failed to create voice hidden service: {}", response).into());
            }

            // Extract the actual ServiceID from Tor's response
            if let Some(service_line) = response.lines().find(|l| l.contains("ServiceID=")) {
                if let Some(start_idx) = service_line.find("ServiceID=") {
                    let service_id = &service_line[start_idx + 10..]; // Skip "ServiceID="
                    format!("{}.onion", service_id.trim())
                } else {
                    full_address.clone()
                }
            } else {
                full_address.clone()
            }
        };

        log::info!("✓ VOICE SINGLE ONION SERVICE registered: {}", actual_onion_address);
        log::info!("✓ Voice service port: 9152 → local 9152 (voice streaming)");
        log::info!("✓ Service mode: Single Onion (3-hop latency, service location visible)");

        Ok(actual_onion_address)
    }

    /// Wait for HS_DESC UPLOADED events (assumes events are already subscribed)
    async fn wait_for_descriptor_uploads_already_subscribed(&self, onion_address: &str) -> Result<(), Box<dyn Error>> {
        log::info!("Waiting for UPLOADED events for {}", onion_address);

        let control = self.control_stream.as_ref()
            .ok_or("Control port not connected")?;

        let mut stream = control.lock().await;

        // Wait for at least 2 UPLOADED events (v3 onions upload to multiple HSDirs)
        let mut uploaded_count = 0;
        let target_uploads = 2;
        let timeout = tokio::time::Duration::from_secs(90);
        let start_time = tokio::time::Instant::now();

        let short_onion = onion_address.trim_end_matches(".onion");

        while uploaded_count < target_uploads && start_time.elapsed() < timeout {
            // Read events with timeout
            let mut event_buf = vec![0u8; 4096];

            match tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.read(&mut event_buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let event = String::from_utf8_lossy(&event_buf[..n]);

                    // Log ALL events to see what Tor is sending
                    log::info!("Received Tor event: {}", event.trim());

                    // Check for HS_DESC UPLOADED event for our onion address
                    if event.contains("HS_DESC") && event.contains("UPLOADED") && event.contains(short_onion) {
                        uploaded_count += 1;
                        log::info!("Descriptor uploaded to HSDir ({}/{})", uploaded_count, target_uploads);
                    }
                },
                Ok(Ok(_)) => {
                    // Connection closed
                    break;
                },
                Ok(Err(e)) => {
                    log::error!("Error reading HS_DESC events: {}", e);
                    break;
                },
                Err(_) => {
                    // Timeout - continue waiting
                    if start_time.elapsed().as_secs() % 10 == 0 {
                        log::info!("Still waiting for descriptor uploads... ({}/{})", uploaded_count, target_uploads);
                    }
                }
            }
        }

        if uploaded_count >= target_uploads {
            log::info!("Successfully uploaded descriptors to {} HSDirs", uploaded_count);
        } else if start_time.elapsed() >= timeout {
            log::warn!("Descriptor upload timeout after 90s - continuing anyway (uploaded to {} HSDirs)", uploaded_count);
        }

        Ok(())
    }

    /// Connect to a peer via Tor SOCKS5 proxy (.onion address)
    pub async fn connect(&self, onion_address: &str, port: u16) -> Result<TorConnection, Box<dyn Error>> {
        log::info!("Connecting to {}:{} via Tor SOCKS5 proxy", onion_address, port);

        // Connect to local SOCKS5 proxy
        log::info!("Connecting to SOCKS5 proxy at 127.0.0.1:9050...");
        let mut stream = match TcpStream::connect("127.0.0.1:9050").await {
            Ok(s) => {
                log::info!("✓ Connected to SOCKS5 proxy");
                s
            }
            Err(e) => {
                log::error!("✗ Failed to connect to SOCKS5 proxy at 127.0.0.1:9050: {}", e);
                log::error!("  Possible causes:");
                log::error!("  1. Tor daemon not running");
                log::error!("  2. SOCKS proxy not listening on port 9050");
                log::error!("  3. Port blocked by firewall");
                return Err(format!("SOCKS proxy unreachable: {}", e).into());
            }
        };

        // Perform SOCKS5 handshake
        log::info!("Performing SOCKS5 handshake for {}:{}...", onion_address, port);
        self.socks5_connect(&mut stream, onion_address, port).await?;

        log::info!("✓ Successfully connected to {}", onion_address);

        Ok(TorConnection {
            stream,
            onion_address: onion_address.to_string(),
            port,
        })
    }

    /// Perform SOCKS5 handshake to connect to .onion address
    async fn socks5_connect(&self, stream: &mut TcpStream, addr: &str, port: u16) -> Result<(), Box<dyn Error>> {
        // SOCKS5 greeting: [version, num_methods, methods...]
        stream.write_all(&[0x05, 0x01, 0x00]).await?; // Version 5, 1 method, No auth

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != 0x05 || buf[1] != 0x00 {
            log::error!("SOCKS5 auth failed: version={}, method={}", buf[0], buf[1]);
            return Err("SOCKS5 auth failed".into());
        }
        log::info!("✓ SOCKS5 auth successful");

        // SOCKS5 connect request: [version, cmd, reserved, addr_type, addr, port]
        let mut request = vec![0x05, 0x01, 0x00, 0x03]; // Ver 5, CONNECT, reserved, domain name
        request.push(addr.len() as u8);
        request.extend_from_slice(addr.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await?;
        log::info!("Sent SOCKS5 connect request for {}:{}", addr, port);

        // Read SOCKS5 response
        let mut response = [0u8; 10];
        stream.read(&mut response).await?;

        if response[0] != 0x05 || response[1] != 0x00 {
            let status_code = response[1];
            let error_message = match status_code {
                0x00 => "succeeded".to_string(),
                0x01 => "general SOCKS server failure".to_string(),
                0x02 => "connection not allowed by ruleset".to_string(),
                0x03 => "Network unreachable".to_string(),
                0x04 => "Host unreachable".to_string(),
                0x05 => "Connection refused".to_string(),
                0x06 => "TTL expired".to_string(),
                0x07 => "Command not supported".to_string(),
                0x08 => "Address type not supported".to_string(),
                _ => format!("Unknown error code {}", status_code),
            };

            log::error!("✗ SOCKS5 connect failed: status {} ({})", status_code, error_message);
            log::error!("  Target: {}:{}", addr, port);

            // Provide specific diagnostic hints based on error code
            match status_code {
                0x05 => {
                    log::error!("  Diagnosis: Connection refused by Tor proxy");
                    log::error!("  Possible causes:");
                    log::error!("    1. Tor not fully bootstrapped (check bootstrap status)");
                    log::error!("    2. Recipient's hidden service not reachable");
                    log::error!("    3. Recipient's hidden service listener not running on port {}", port);
                    log::error!("    4. .onion address is invalid or doesn't exist");
                    log::error!("  Recommended action: Verify Tor bootstrap is 100% before retrying");
                }
                0x03 => {
                    log::error!("  Diagnosis: Network unreachable");
                    log::error!("  Possible causes:");
                    log::error!("    1. Tor circuits not established");
                    log::error!("    2. No network connectivity");
                }
                0x04 => {
                    log::error!("  Diagnosis: Host unreachable");
                    log::error!("  Possible causes:");
                    log::error!("    1. Hidden service descriptors not published");
                    log::error!("    2. Hidden service offline");
                }
                _ => {}
            }

            return Err(format!("SOCKS5 connect failed: status {} ({})", status_code, error_message).into());
        }

        log::info!("✓ SOCKS5 handshake complete");
        Ok(())
    }

    /// Start listening for incoming connections on the hidden service
    pub async fn start_listener(&mut self, local_port: Option<u16>) -> Result<tokio::sync::mpsc::UnboundedReceiver<(u64, Vec<u8>)>, Box<dyn Error>> {
        let port = local_port.unwrap_or(self.hs_local_port);
        let bind_addr = format!("127.0.0.1:{}", port);

        log::info!("Starting hidden service listener on {}", bind_addr);

        // Use TcpSocket to set SO_REUSEADDR before binding
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket.bind(bind_addr.parse()?)?;
        let listener = socket.listen(1024)?;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let incoming_tx = tx.clone();
        self.incoming_ping_tx = Some(tx);

        // Spawn listener task
        let handle = tokio::spawn(async move {
            log::info!("Listener task started, waiting for connections...");

            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        log::info!("Incoming connection from {}", addr);

                        // Generate unique connection ID
                        let conn_id = {
                            let mut counter = CONNECTION_ID_COUNTER.lock().unwrap();
                            *counter += 1;
                            *counter
                        };

                        // Spawn handler for this connection
                        let tx = incoming_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_incoming_connection(socket, conn_id, tx).await {
                                log::error!("Error handling connection {}: {}", conn_id, e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Error accepting connection: {}", e);
                    }
                }
            }
        });

        self.listener_handle = Some(handle);

        log::info!("Hidden service listener started on {}", bind_addr);

        Ok(rx)
    }

    /// Handle incoming connection (receive Ping token)
    async fn handle_incoming_connection(
        mut socket: TcpStream,
        conn_id: u64,
        tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
    ) -> Result<(), Box<dyn Error>> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        socket.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;

        // Increased limit to support voice messages (typical voice: ~50KB, allow up to 10MB)
        if total_len > 10_000_000 {
            return Err("Message too large (>10MB)".into());
        }

        // Read message type byte
        let mut type_byte = [0u8; 1];
        socket.read_exact(&mut type_byte).await?;
        let msg_type = type_byte[0];

        // Read the rest of the data (total_len includes type byte, so subtract 1)
        let data_len = total_len.saturating_sub(1);
        let mut data = vec![0u8; data_len];
        socket.read_exact(&mut data).await?;

        log::info!("╔════════════════════════════════════════");
        log::info!("║ INCOMING CONNECTION {} (type=0x{:02x}, {} bytes)", conn_id, msg_type, data_len);
        log::info!("╚════════════════════════════════════════");

        // Route based on message type
        match msg_type {
            MSG_TYPE_PING => {
                log::info!("→ Routing to PING handler");

                // Store connection for instant Pong response
                {
                    let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                    pending.insert(conn_id, PendingConnection {
                        socket,
                        encrypted_ping: data.clone(),
                    });
                }

                // Send to Ping receiver channel
                tx.send((conn_id, data)).ok();
            }
            MSG_TYPE_PONG => {
                log::info!("→ Routing to PONG handler");
                // Pongs don't need connection stored (no reply needed)
                // Send directly to whichever channel is listening
                tx.send((conn_id, data)).ok();
            }
            MSG_TYPE_TEXT | MSG_TYPE_VOICE | MSG_TYPE_IMAGE | MSG_TYPE_PAYMENT_REQUEST | MSG_TYPE_PAYMENT_SENT | MSG_TYPE_PAYMENT_ACCEPTED => {
                log::info!("→ Routing to MESSAGE handler (separate channel, type={})",
                    match msg_type {
                        MSG_TYPE_TEXT => "TEXT",
                        MSG_TYPE_VOICE => "VOICE",
                        MSG_TYPE_IMAGE => "IMAGE",
                        MSG_TYPE_PAYMENT_REQUEST => "PAYMENT_REQUEST",
                        MSG_TYPE_PAYMENT_SENT => "PAYMENT_SENT",
                        MSG_TYPE_PAYMENT_ACCEPTED => "PAYMENT_ACCEPTED",
                        _ => "UNKNOWN"
                    });

                // Messages might need connection stored for delivery confirmation
                {
                    let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                    pending.insert(conn_id, PendingConnection {
                        socket,
                        encrypted_ping: data.clone(),
                    });
                }

                // Route to MESSAGE channel (not PING channel)
                if let Some(message_tx) = MESSAGE_TX.get() {
                    let tx_lock = message_tx.lock().unwrap();
                    if let Err(e) = tx_lock.send((conn_id, data)) {
                        log::error!("Failed to send message to MESSAGE channel: {}", e);
                    }
                } else {
                    log::warn!("MESSAGE channel not initialized - dropping message");
                }
            }
            MSG_TYPE_CALL_SIGNALING => {
                log::info!("→ Routing to VOICE handler (dedicated channel for call signaling)");

                // Store connection for delivery confirmation
                {
                    let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                    pending.insert(conn_id, PendingConnection {
                        socket,
                        encrypted_ping: data.clone(),
                    });
                }

                // Route to VOICE channel (separate from MESSAGE to allow simultaneous messaging during calls)
                if let Some(voice_tx) = VOICE_TX.get() {
                    let tx_lock = voice_tx.lock().unwrap();
                    if let Err(e) = tx_lock.send((conn_id, data)) {
                        log::error!("Failed to send call signaling to VOICE channel: {}", e);
                    }
                } else {
                    log::warn!("VOICE channel not initialized - dropping call signaling");
                }
            }
            MSG_TYPE_TAP => {
                log::info!("→ Routing to TAP handler");
                tx.send((conn_id, data)).ok();
            }
            MSG_TYPE_DELIVERY_CONFIRMATION => {
                log::warn!("⚠️  Received ACK on main listener (port 8080) - should go to port 9153!");
                log::info!("→ Routing to ACK channel (error recovery - ensures no message loss)");

                // ERROR RECOVERY: ACK arrived on wrong port, but we MUST NOT drop it!
                // Route to shared ACK_TX channel so it still gets processed.
                // This prevents permanent message delivery failures.
                if let Some(ack_tx) = ACK_TX.get() {
                    let tx_lock = ack_tx.lock().unwrap();
                    if let Err(e) = tx_lock.send((conn_id, data)) {
                        log::error!("Failed to send ACK to ACK channel: {}", e);
                    } else {
                        log::info!("✓ ACK successfully routed to ACK channel from port 8080");
                    }
                } else {
                    log::error!("✗ ACK channel not initialized - ACK will be lost!");
                    log::error!("   Start ACK listener on port 9153 to initialize ACK_TX channel");
                }
            }
            MSG_TYPE_FRIEND_REQUEST => {
                log::info!("→ Routing to FRIEND_REQUEST handler (separate channel)");
                // Friend requests routed to dedicated channel to avoid interference with message system
                // Include type byte so Kotlin can distinguish Phase 1 (0x07) from Phase 2 (0x08)
                if let Some(friend_tx) = FRIEND_REQUEST_TX.get() {
                    let tx_lock = friend_tx.lock().unwrap();
                    let mut wire_data = vec![msg_type]; // Prepend type byte
                    wire_data.extend_from_slice(&data);
                    if let Err(e) = tx_lock.send(wire_data) {
                        log::error!("Failed to send friend request to channel: {}", e);
                    }
                } else {
                    log::warn!("Friend request channel not initialized - dropping message");
                }
            }
            MSG_TYPE_FRIEND_REQUEST_ACCEPTED => {
                log::info!("→ Routing to FRIEND_REQUEST_ACCEPTED handler (separate channel)");
                // Friend request accepted routed to dedicated channel to avoid interference with message system
                // Include type byte so Kotlin can distinguish Phase 1 (0x07) from Phase 2 (0x08)
                if let Some(friend_tx) = FRIEND_REQUEST_TX.get() {
                    let tx_lock = friend_tx.lock().unwrap();
                    let mut wire_data = vec![msg_type]; // Prepend type byte
                    wire_data.extend_from_slice(&data);
                    if let Err(e) = tx_lock.send(wire_data) {
                        log::error!("Failed to send friend request accepted to channel: {}", e);
                    }
                } else {
                    log::warn!("Friend request channel not initialized - dropping message");
                }
            }
            _ => {
                log::warn!("⚠️  Unknown message type: 0x{:02x}, treating as PING", msg_type);

                // Default to Ping behavior for unknown types
                {
                    let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                    pending.insert(conn_id, PendingConnection {
                        socket,
                        encrypted_ping: data.clone(),
                    });
                }

                tx.send((conn_id, data)).ok();
            }
        }

        Ok(())
    }

    /// Get the hidden service .onion address (if created)
    pub fn get_hidden_service_address(&self) -> Option<String> {
        self.hidden_service_address.clone()
    }

    /// Stop the hidden service listener
    pub fn stop_listener(&mut self) {
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
            log::info!("Hidden service listener stopped");
        }
    }

    /// Clear all ephemeral hidden services via Tor control port
    /// This removes any orphaned services from previous failed account creation attempts
    /// Returns the number of services deleted
    pub async fn clear_all_ephemeral_services(&self) -> Result<u32, Box<dyn Error>> {
        log::info!("Clearing all ephemeral hidden services...");

        let control = self.control_stream.as_ref()
            .ok_or("Control port not connected")?;

        let mut stream = control.lock().await;

        // Get list of all onion services
        stream.write_all(b"GETINFO onions/current\r\n").await?;

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        log::info!("GETINFO onions/current response: {}", response);

        // Parse service IDs from response
        // Format: 250-onions/current=service1 service2 service3
        let mut service_ids = Vec::new();
        for line in response.lines() {
            if line.contains("onions/current=") {
                if let Some(services_str) = line.split("onions/current=").nth(1) {
                    // Services are space-separated
                    for service_id in services_str.split_whitespace() {
                        service_ids.push(service_id.to_string());
                    }
                }
            }
        }

        if service_ids.is_empty() {
            log::info!("No ephemeral services found to clear");
            return Ok(0);
        }

        log::info!("Found {} ephemeral service(s) to delete: {:?}", service_ids.len(), service_ids);

        // Delete each service
        let mut deleted_count = 0;
        for service_id in &service_ids {
            let del_command = format!("DEL_ONION {}\r\n", service_id);
            stream.write_all(del_command.as_bytes()).await?;

            let n = stream.read(&mut buf).await?;
            let del_response = String::from_utf8_lossy(&buf[..n]);

            if del_response.contains("250 OK") {
                log::info!("✓ Deleted ephemeral service: {}", service_id);
                deleted_count += 1;
            } else {
                log::warn!("Failed to delete service {}: {}", service_id, del_response);
            }
        }

        log::info!("Cleared {} ephemeral service(s)", deleted_count);
        Ok(deleted_count)
    }

    /// Start SOCKS proxy (C Tor always runs SOCKS on 9050, so this is a no-op)
    pub async fn start_socks_proxy(&self) -> Result<bool, Box<dyn Error>> {
        log::info!("SOCKS proxy already running on 127.0.0.1:9050 (C Tor)");
        Ok(true)
    }

    /// Stop SOCKS proxy (C Tor manages this, so this is a no-op)
    pub fn stop_socks_proxy(&self) {
        log::info!("SOCKS proxy is managed by C Tor daemon");
    }

    /// Check if SOCKS proxy is running (always true with C Tor)
    pub fn is_socks_proxy_running(&self) -> bool {
        true
    }

    /// Test Tor health using control port (privacy-preserving approach)
    /// Queries local Tor control port to check circuit status
    /// No external connections - same approach used by Briar
    /// Returns true if Tor has established circuits
    pub async fn test_socks_connectivity(&self) -> bool {
        use tokio::time::{timeout, Duration};
        use tokio::net::TcpStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        log::info!("Testing Tor health via control port...");

        // Connect to Tor control port (local only, no external traffic)
        let connect_result = timeout(
            Duration::from_secs(3),
            TcpStream::connect("127.0.0.1:9051")
        ).await;

        let mut stream = match connect_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log::error!("✗ Tor control port: Cannot connect - {}", e);
                log::error!("   Tor daemon may not be running or control port disabled");
                return false;
            }
            Err(_) => {
                log::error!("✗ Tor control port: Connection timeout");
                return false;
            }
        };

        // Authenticate (try NULL auth first, common on Android)
        if let Err(e) = stream.write_all(b"AUTHENTICATE\r\n").await {
            log::error!("✗ Tor control port: Auth write failed - {}", e);
            return false;
        }

        let mut auth_response = vec![0u8; 512];
        let n = match timeout(Duration::from_secs(2), stream.read(&mut auth_response)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                log::error!("✗ Tor control port: Auth read failed - {}", e);
                return false;
            }
            Err(_) => {
                log::error!("✗ Tor control port: Auth timeout");
                return false;
            }
        };

        let auth_str = String::from_utf8_lossy(&auth_response[..n]);
        if !auth_str.starts_with("250") {
            log::error!("✗ Tor control port: Auth failed - {}", auth_str.trim());
            return false;
        }

        // Query circuit status
        if let Err(e) = stream.write_all(b"GETINFO status/circuit-established\r\n").await {
            log::error!("✗ Tor control port: Query write failed - {}", e);
            return false;
        }

        let mut response = vec![0u8; 512];
        let n = match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                log::error!("✗ Tor control port: Query read failed - {}", e);
                return false;
            }
            Err(_) => {
                log::error!("✗ Tor control port: Query timeout");
                return false;
            }
        };

        let response_str = String::from_utf8_lossy(&response[..n]);

        // Check if circuits are established
        // Response format: "250-status/circuit-established=1\r\n250 OK\r\n"
        let circuits_ok = response_str.contains("circuit-established=1");

        // Close connection gracefully
        let _ = stream.write_all(b"QUIT\r\n").await;

        if circuits_ok {
            log::info!("✓ Tor health check: PASSED (circuits established)");
            true
        } else {
            log::error!("✗ Tor health check: FAILED (no circuits)");
            log::error!("   Response: {}", response_str.trim());
            false
        }
    }

    /// Send Pong response back through pending connection and wait for message
    pub async fn send_pong_response(connection_id: u64, pong_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Temporarily take the connection out to do async I/O (can't hold lock across await)
        let mut conn = {
            let mut pending = PENDING_CONNECTIONS.lock().unwrap();
            pending.remove(&connection_id)
                .ok_or("Connection not found")?
        };

        // Build wire message with type byte
        let mut wire_message = Vec::new();
        wire_message.push(MSG_TYPE_PONG); // Add type byte
        wire_message.extend_from_slice(pong_bytes);

        // Send length prefix (includes type byte)
        let len = wire_message.len() as u32;
        conn.socket.write_all(&len.to_be_bytes()).await?;

        // Send wire message (type + pong data)
        conn.socket.write_all(&wire_message).await?;
        conn.socket.flush().await?;

        log::info!("Sent Pong response: {} bytes (connection {})", pong_bytes.len(), connection_id);

        // NOW WAIT FOR THE ACTUAL MESSAGE!
        // The sender will send the message immediately after receiving our Pong
        log::info!("Waiting for incoming message on connection {}...", connection_id);

        // Read message length prefix (with timeout - sender should send immediately)
        let mut len_buf = [0u8; 4];
        let read_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            conn.socket.read_exact(&mut len_buf)
        ).await;

        match read_result {
            Ok(Ok(_)) => {
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                log::info!("Incoming message length: {} bytes", msg_len);

                if msg_len > 10_000_000 {  // 10MB limit (consistent with voice message support)
                    return Err("Message too large (>10MB)".into());
                }

                // Read message data
                let mut message_data = vec![0u8; msg_len];
                conn.socket.read_exact(&mut message_data).await?;

                log::info!("Received message: {} bytes (connection {})", msg_len, connection_id);

                // Connection closes naturally when dropped
                Ok(message_data)
            }
            Ok(Err(e)) => {
                log::error!("Failed to read message length: {}", e);
                Err(e.into())
            }
            Err(_) => {
                log::error!("Timeout waiting for message on connection {}", connection_id);
                Err("Timeout waiting for message after sending Pong".into())
            }
        }
    }

    /// Send ACK on an existing connection (fire-and-forget, connection closes after sending)
    pub async fn send_ack_on_connection(connection_id: u64, ack_type: u8, ack_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        // Take the connection out (it will be closed after sending ACK)
        let mut conn = {
            let mut pending = PENDING_CONNECTIONS.lock().unwrap();
            pending.remove(&connection_id)
                .ok_or("Connection not found")?
        };

        // Build wire message with type byte
        let mut wire_message = Vec::new();
        wire_message.push(ack_type); // Add ACK type byte
        wire_message.extend_from_slice(ack_bytes);

        // Send length prefix (includes type byte)
        let len = wire_message.len() as u32;
        conn.socket.write_all(&len.to_be_bytes()).await?;

        // Send wire message (type + ACK data)
        conn.socket.write_all(&wire_message).await?;
        conn.socket.flush().await?;

        log::info!("Sent ACK (type={:02x}) on connection {}: {} bytes", ack_type, connection_id, ack_bytes.len());

        // Connection will close when dropped (fire-and-forget)
        Ok(())
    }

    /// Send data over a Tor connection
    pub async fn send(&self, conn: &mut TorConnection, data: &[u8]) -> Result<(), Box<dyn Error>> {
        conn.send(data).await
    }

    /// Receive data from a Tor connection
    pub async fn receive(&self, conn: &mut TorConnection, _max_len: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        conn.receive().await
    }
}

/// Tor connection wrapper
pub struct TorConnection {
    pub stream: TcpStream,
    pub onion_address: String,
    pub port: u16,
}

impl TorConnection {
    pub async fn send(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        // Send length prefix
        let len = data.len() as u32;
        self.stream.write_all(&len.to_be_bytes()).await?;

        // Send data
        self.stream.write_all(data).await?;
        self.stream.flush().await?;

        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let data_len = u32::from_be_bytes(len_buf) as usize;

        if data_len > 10_000_000 {
            return Err("Message too large (>10MB)".into());
        }

        // Read data
        let mut data = vec![0u8; data_len];
        self.stream.read_exact(&mut data).await?;

        Ok(data)
    }
}
