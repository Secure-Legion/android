/// Contact Exchange Endpoint (v2.0 + v5 Contact List Backup + Push Recovery)
///
/// P2P endpoint that listens on localhost and serves contact data:
/// - GET /contact-card — Returns encrypted contact card
/// - GET /contact-list/{cid} — Returns encrypted contact list (v5 architecture)
/// - GET /recovery/beacon — Returns whether this device is in recovery mode
/// - POST /recovery/push/{cid} — Accept raw encrypted contact list bytes from a friend
///
/// This endpoint is accessible via the friend request .onion address.
/// The friend request .onion serves HTTP (contact cards, contact lists, recovery).
/// Actual friend request wire protocol messages (0x07/0x08) go over the messaging .onion.

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Recovery state for push-based contact list recovery on new devices.
/// When a user restores from seed on a new phone, their .onion comes back online.
/// Friends check GET /recovery/beacon, see recovering=true, and POST the encrypted
/// contact list blob. Rust writes it to ipfs_pins/{cid} on disk. Kotlin's existing
/// getContactList() finds it → AES-GCM decrypt → import contacts.
struct RecoveryState {
    /// Whether this device is in recovery mode
    mode: bool,
    /// The expected CID (derived from seed) — only accept blobs for this CID
    expected_cid: Option<String>,
    /// Path to app data directory (e.g. /data/data/com.securelegion/files)
    data_dir: Option<String>,
    /// Set to true after a blob has been written to disk
    file_written: bool,
}

/// Global state for the contact exchange endpoint
pub struct ContactExchangeEndpoint {
    /// The encrypted contact card to serve
    contact_card: Arc<Mutex<Option<Vec<u8>>>>,
    /// IPFS CID for the contact card
    cid: Arc<Mutex<Option<String>>>,
    /// Contact lists (CID → encrypted data) for v5 architecture
    contact_lists: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Endpoint shutdown signal
    shutdown: Arc<Mutex<bool>>,
    /// Recovery state for new-device push recovery
    recovery: Arc<Mutex<RecoveryState>>,
}

impl ContactExchangeEndpoint {
    pub fn new() -> Self {
        Self {
            contact_card: Arc::new(Mutex::new(None)),
            cid: Arc::new(Mutex::new(None)),
            contact_lists: Arc::new(Mutex::new(HashMap::new())),
            shutdown: Arc::new(Mutex::new(false)),
            recovery: Arc::new(Mutex::new(RecoveryState {
                mode: false,
                expected_cid: None,
                data_dir: None,
                file_written: false,
            })),
        }
    }

    /// Set the contact card to serve
    pub async fn set_contact_card(&self, card: Vec<u8>, cid: String) {
        let card_len = card.len();

        let mut card_lock = self.contact_card.lock().await;
        *card_lock = Some(card);

        let mut cid_lock = self.cid.lock().await;
        *cid_lock = Some(cid);

        log::info!("Contact card set for serving (length: {} bytes)", card_len);
    }

    /// Set a contact list to serve (v5 architecture)
    pub async fn set_contact_list(&self, cid: String, encrypted_list: Vec<u8>) {
        let list_len = encrypted_list.len();

        let mut lists_lock = self.contact_lists.lock().await;
        lists_lock.insert(cid.clone(), encrypted_list);

        log::info!("Contact list stored for CID: {} ({} bytes)", cid, list_len);
    }

    /// Enable recovery mode. Kotlin passes the expected CID and app data dir.
    pub async fn set_recovery_mode(&self, enabled: bool, expected_cid: Option<String>, data_dir: Option<String>) {
        let mut state = self.recovery.lock().await;
        state.mode = enabled;
        state.expected_cid = expected_cid;
        state.data_dir = data_dir;
        state.file_written = false;
        log::info!("Recovery mode: {} (has cid: {}, has dir: {})",
            enabled, state.expected_cid.is_some(), state.data_dir.is_some());
    }

    /// Check if a recovery blob has been written to disk (Kotlin polls this)
    pub async fn is_recovery_ready(&self) -> bool {
        let state = self.recovery.lock().await;
        state.mode && state.file_written
    }

    /// Clear recovery mode (called after Kotlin successfully imports contacts)
    pub async fn clear_recovery_mode(&self) {
        let mut state = self.recovery.lock().await;
        state.mode = false;
        state.expected_cid = None;
        state.data_dir = None;
        state.file_written = false;
        log::info!("Recovery mode cleared");
    }

    /// Start the contact exchange listener on the specified port
    pub async fn start(&self, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await?;

        log::info!("Contact exchange endpoint listening on {}", addr);

        // Clone Arc pointers for the listener task
        let contact_card = self.contact_card.clone();
        let cid = self.cid.clone();
        let contact_lists = self.contact_lists.clone();
        let shutdown = self.shutdown.clone();
        let recovery = self.recovery.clone();

        tokio::spawn(async move {
            loop {
                // Check shutdown signal
                {
                    let shutdown_lock = shutdown.lock().await;
                    if *shutdown_lock {
                        log::info!("Contact exchange endpoint shutting down");
                        break;
                    }
                }

                // Accept incoming connection
                let (mut socket, addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        log::error!("Failed to accept connection: {}", e);
                        continue;
                    }
                };

                log::debug!("Incoming connection from {}", addr);

                // Clone Arc pointers for this connection
                let contact_card = contact_card.clone();
                let cid = cid.clone();
                let contact_lists = contact_lists.clone();
                let recovery = recovery.clone();

                // Spawn a task to handle this connection
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(
                        &mut socket, contact_card, cid, contact_lists, recovery
                    ).await {
                        log::error!("Error handling connection: {}", e);
                    }
                });
            }
        });

        Ok(())
    }

    /// Stop the listener
    pub async fn stop(&self) {
        let mut shutdown_lock = self.shutdown.lock().await;
        *shutdown_lock = true;
        log::info!("Contact exchange endpoint stop signal sent");
    }

    /// Poll for incoming friend request (stub - friend requests handled by wire protocol)
    pub async fn poll_request(&self) -> Option<FriendRequest> {
        None
    }

    /// Poll for friend request response (stub - friend requests handled by wire protocol)
    pub async fn poll_response(&self) -> Option<FriendResponse> {
        None
    }
}

/// Friend request structure (for wire protocol compatibility)
pub struct FriendRequest {
    pub encrypted_card: Vec<u8>,
    pub sender_onion: String,
    pub sender_cid: String,
    pub timestamp: i64,
}

/// Friend response structure (for wire protocol compatibility)
pub struct FriendResponse {
    pub encrypted_card: Vec<u8>,
    pub sender_onion: String,
    pub sender_cid: String,
    pub timestamp: i64,
    pub approved: bool,
}

/// Parse Content-Length from HTTP headers
fn parse_content_length(headers: &str) -> usize {
    for line in headers.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            if let Ok(len) = line[15..].trim().parse::<usize>() {
                return len;
            }
        }
    }
    0
}

/// Handle incoming HTTP request from peer
async fn handle_connection(
    socket: &mut tokio::net::TcpStream,
    contact_card: Arc<Mutex<Option<Vec<u8>>>>,
    cid: Arc<Mutex<Option<String>>>,
    contact_lists: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    recovery: Arc<Mutex<RecoveryState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read HTTP request headers (+ possibly start of body)
    let mut buffer = vec![0u8; 8192];
    let n = socket.read(&mut buffer).await?;

    if n == 0 {
        return Ok(());
    }

    // Find header/body boundary in raw bytes
    let header_end_pos = buffer[..n]
        .windows(4)
        .position(|w| w == b"\r\n\r\n");

    let (headers_str, body_start) = match header_end_pos {
        Some(pos) => {
            let h = String::from_utf8_lossy(&buffer[..pos]).to_string();
            (h, pos + 4)
        }
        None => {
            let h = String::from_utf8_lossy(&buffer[..n]).to_string();
            (h, n)
        }
    };

    let lines: Vec<&str> = headers_str.lines().collect();
    if lines.is_empty() {
        return Err("Empty request".into());
    }

    let parts: Vec<&str> = lines[0].split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Invalid request line".into());
    }

    let method = parts[0];
    let path = parts[1].to_string();

    log::debug!("HTTP Request: {} {}", method, path);

    // For POST requests, read the full body as raw bytes
    let post_body: Option<Vec<u8>> = if method == "POST" {
        let content_length = parse_content_length(&headers_str);

        // Security: cap body at 256KB
        if content_length > 256 * 1024 {
            let resp = "HTTP/1.1 413 Payload Too Large\r\n\r\n";
            socket.write_all(resp.as_bytes()).await?;
            return Ok(());
        }

        // Collect body bytes already in buffer
        let mut body_bytes: Vec<u8> = if body_start < n {
            buffer[body_start..n].to_vec()
        } else {
            Vec::new()
        };

        // Read remaining body if needed
        while body_bytes.len() < content_length {
            let remaining = content_length - body_bytes.len();
            let mut tmp = vec![0u8; remaining.min(8192)];
            let read = socket.read(&mut tmp).await?;
            if read == 0 { break; }
            body_bytes.extend_from_slice(&tmp[..read]);
        }

        Some(body_bytes)
    } else {
        None
    };

    match (method, path.as_str()) {
        ("GET", "/contact-card") => {
            let card_lock = contact_card.lock().await;
            let cid_lock = cid.lock().await;

            if let (Some(card), Some(cid_str)) = (card_lock.as_ref(), cid_lock.as_ref()) {
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/octet-stream\r\n\
                     X-IPFS-CID: {}\r\n\
                     Content-Length: {}\r\n\
                     \r\n",
                    cid_str,
                    card.len()
                );

                socket.write_all(response.as_bytes()).await?;
                socket.write_all(card).await?;

                log::info!("Served contact card ({} bytes)", card.len());
            } else {
                let response = "HTTP/1.1 404 Not Found\r\n\r\nNo contact card available";
                socket.write_all(response.as_bytes()).await?;
                log::warn!("Contact card requested but not available");
            }
        }

        ("GET", p) if p.starts_with("/contact-list/") => {
            let requested_cid = &p[14..]; // Skip "/contact-list/"
            let lists_lock = contact_lists.lock().await;

            if let Some(list_data) = lists_lock.get(requested_cid) {
                let response = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/octet-stream\r\n\
                     X-IPFS-CID: {}\r\n\
                     Content-Length: {}\r\n\
                     \r\n",
                    requested_cid,
                    list_data.len()
                );

                socket.write_all(response.as_bytes()).await?;
                socket.write_all(list_data).await?;

                log::info!("Served contact list for CID: {} ({} bytes)", requested_cid, list_data.len());
            } else {
                let response = "HTTP/1.1 404 Not Found\r\n\r\nContact list not found";
                socket.write_all(response.as_bytes()).await?;
                log::warn!("Contact list requested but not found: {}", requested_cid);
            }
        }

        ("GET", "/recovery/beacon") => {
            // Don't leak CID — friends already know it from their contact DB
            let state = recovery.lock().await;
            let body = if state.mode {
                "{\"recovering\":true}"
            } else {
                "{\"recovering\":false}"
            };

            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 \r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await?;
            log::debug!("Served recovery beacon (recovering: {})", state.mode);
        }

        ("POST", p) if p.starts_with("/recovery/push/") => {
            let pushed_cid = &p[16..]; // Skip "/recovery/push/"

            // Gate 1: Must be in recovery mode
            let mut state = recovery.lock().await;
            if !state.mode {
                let response = "HTTP/1.1 403 Forbidden\r\n\r\n";
                socket.write_all(response.as_bytes()).await?;
                log::warn!("Recovery push rejected: not in recovery mode");
                return Ok(());
            }

            // Gate 2: Expected CID must exist
            let expected_cid = match &state.expected_cid {
                Some(c) => c.clone(),
                None => {
                    let response = "HTTP/1.1 403 Forbidden\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                    log::warn!("Recovery push rejected: no expected CID configured");
                    return Ok(());
                }
            };

            // Gate 3: Pushed CID must match expected CID
            if pushed_cid != expected_cid {
                let response = "HTTP/1.1 403 Forbidden\r\n\r\n";
                socket.write_all(response.as_bytes()).await?;
                log::warn!("Recovery push rejected: CID mismatch (got: {}, expected: {})",
                    pushed_cid, expected_cid);
                return Ok(());
            }

            // Gate 4: Data dir must be configured
            let data_dir = match &state.data_dir {
                Some(d) => d.clone(),
                None => {
                    let response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                    log::error!("Recovery push failed: no data_dir configured");
                    return Ok(());
                }
            };

            // Gate 5: Body must exist and not be empty
            let body_bytes = match &post_body {
                Some(b) if !b.is_empty() => b.clone(),
                _ => {
                    let response = "HTTP/1.1 400 Bad Request\r\n\r\n";
                    socket.write_all(response.as_bytes()).await?;
                    log::warn!("Recovery push rejected: empty body");
                    return Ok(());
                }
            };

            // Already have a file? Don't overwrite — Kotlin will validate and clear.
            if state.file_written {
                let response = "HTTP/1.1 409 Conflict\r\n\r\n";
                socket.write_all(response.as_bytes()).await?;
                log::info!("Recovery push rejected: file already written, pending validation");
                return Ok(());
            }

            // Write directly to disk at ipfs_pins/{expectedCid}
            let pins_dir = format!("{}/ipfs_pins", data_dir);
            let file_path = format!("{}/{}", pins_dir, expected_cid);

            // Release lock before disk I/O
            drop(state);

            if let Err(e) = std::fs::create_dir_all(&pins_dir) {
                log::error!("Recovery push: failed to create ipfs_pins dir: {}", e);
                let response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                socket.write_all(response.as_bytes()).await?;
                return Ok(());
            }

            if let Err(e) = std::fs::write(&file_path, &body_bytes) {
                log::error!("Recovery push: failed to write file: {}", e);
                let response = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
                socket.write_all(response.as_bytes()).await?;
                return Ok(());
            }

            // Mark file as written so Kotlin knows to check
            let mut state = recovery.lock().await;
            state.file_written = true;

            log::info!("Recovery push: wrote {} bytes to {}", body_bytes.len(), file_path);

            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            socket.write_all(response.as_bytes()).await?;
        }

        _ => {
            let response = "HTTP/1.1 404 Not Found\r\n\r\n";
            socket.write_all(response.as_bytes()).await?;
            log::warn!("Unknown endpoint: {} {}", method, path);
        }
    }

    Ok(())
}

// Global endpoint instance
use once_cell::sync::Lazy;
static GLOBAL_ENDPOINT: Lazy<Arc<ContactExchangeEndpoint>> =
    Lazy::new(|| Arc::new(ContactExchangeEndpoint::new()));

/// Get the global contact exchange endpoint instance
pub async fn get_endpoint() -> Arc<ContactExchangeEndpoint> {
    GLOBAL_ENDPOINT.clone()
}
