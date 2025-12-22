/// Contact Card HTTP Server (v2.0 + v5 Contact List Backup)
///
/// Lightweight HTTP server that runs on localhost and serves:
/// - GET /contact-card - Returns encrypted contact card
/// - GET /contact-list/{cid} - Returns encrypted contact list (v5 architecture)
///
/// This server is accessible via the friend request .onion address.
/// Friend requests are handled by the v1.0 wire protocol (0x07/0x08) on messaging .onion.

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Global state for the contact card server
pub struct FriendRequestServer {
    /// The encrypted contact card to serve
    contact_card: Arc<Mutex<Option<Vec<u8>>>>,
    /// IPFS CID for the contact card
    cid: Arc<Mutex<Option<String>>>,
    /// Contact lists (CID → encrypted data) for v5 architecture
    contact_lists: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    /// Server shutdown signal
    shutdown: Arc<Mutex<bool>>,
}

impl FriendRequestServer {
    pub fn new() -> Self {
        Self {
            contact_card: Arc::new(Mutex::new(None)),
            cid: Arc::new(Mutex::new(None)),
            contact_lists: Arc::new(Mutex::new(HashMap::new())),
            shutdown: Arc::new(Mutex::new(false)),
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

    /// Start the HTTP server on the specified port
    pub async fn start(&self, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&addr).await?;

        log::info!("Contact card server listening on {}", addr);

        // Clone Arc pointers for the server task
        let contact_card = self.contact_card.clone();
        let cid = self.cid.clone();
        let contact_lists = self.contact_lists.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            loop {
                // Check shutdown signal
                {
                    let shutdown_lock = shutdown.lock().await;
                    if *shutdown_lock {
                        log::info!("Contact card server shutting down");
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

                // Spawn a task to handle this connection
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(&mut socket, contact_card, cid, contact_lists).await {
                        log::error!("Error handling connection: {}", e);
                    }
                });
            }
        });

        Ok(())
    }

    /// Stop the server
    pub async fn stop(&self) {
        let mut shutdown_lock = self.shutdown.lock().await;
        *shutdown_lock = true;
        log::info!("Contact card server stop signal sent");
    }

    /// Poll for incoming friend request (stub - friend requests handled by wire protocol)
    /// Friend requests are processed via v1.0 wire protocol (0x07/0x08) on messaging .onion
    pub async fn poll_request(&self) -> Option<FriendRequest> {
        // Friend requests are handled by TorService wire protocol, not HTTP server
        None
    }

    /// Poll for friend request response (stub - friend requests handled by wire protocol)
    /// Friend request responses are processed via v1.0 wire protocol (0x07/0x08) on messaging .onion
    pub async fn poll_response(&self) -> Option<FriendResponse> {
        // Friend request responses are handled by TorService wire protocol, not HTTP server
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

/// Handle an individual HTTP connection
async fn handle_connection(
    socket: &mut tokio::net::TcpStream,
    contact_card: Arc<Mutex<Option<Vec<u8>>>>,
    cid: Arc<Mutex<Option<String>>>,
    contact_lists: Arc<Mutex<HashMap<String, Vec<u8>>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read HTTP request
    let mut buffer = vec![0u8; 8192];
    let n = socket.read(&mut buffer).await?;

    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buffer[..n]);
    let lines: Vec<&str> = request.lines().collect();

    if lines.is_empty() {
        return Err("Empty request".into());
    }

    let request_line = lines[0];
    let parts: Vec<&str> = request_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Err("Invalid request line".into());
    }

    let method = parts[0];
    let path = parts[1];

    log::debug!("HTTP Request: {} {}", method, path);

    match (method, path) {
        ("GET", "/contact-card") => {
            // Serve the contact card
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

        ("GET", path) if path.starts_with("/contact-list/") => {
            // Serve a contact list (v5 architecture)
            let requested_cid = &path[14..]; // Skip "/contact-list/"
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

        _ => {
            let response = "HTTP/1.1 404 Not Found\r\n\r\n";
            socket.write_all(response.as_bytes()).await?;
            log::warn!("Unknown endpoint: {} {}", method, path);
        }
    }

    Ok(())
}

// Global server instance
use once_cell::sync::Lazy;
static GLOBAL_SERVER: Lazy<Arc<FriendRequestServer>> =
    Lazy::new(|| Arc::new(FriendRequestServer::new()));

/// Get the global server instance
pub async fn get_server() -> Arc<FriendRequestServer> {
    GLOBAL_SERVER.clone()
}
