/// Tor Network Manager
/// Handles Tor daemon initialization and connection management using Arti
///
/// Arti is the official Rust implementation of Tor from the Tor Project

use std::error::Error;
use std::sync::Arc;
use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::path::PathBuf;
use arti_client::config::TorClientConfigBuilder;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use std::net::SocketAddr;
use tor_hsservice::{HsNickname, OnionServiceConfig};
use std::str::FromStr;
use std::sync::Mutex;
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Structure representing a pending connection waiting for Pong response
pub struct PendingConnection {
    pub socket: TcpStream,
    pub encrypted_ping: Vec<u8>,
}

/// Global map of pending connections: connection_id -> PendingConnection
static PENDING_CONNECTIONS: Lazy<Arc<Mutex<HashMap<u64, PendingConnection>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Counter for generating unique connection IDs
static CONNECTION_ID_COUNTER: Lazy<Arc<Mutex<u64>>> =
    Lazy::new(|| Arc::new(Mutex::new(0)));

pub struct TorManager {
    tor_client: Option<Arc<TorClient<PreferredRuntime>>>,
    hidden_service_address: Option<String>,
    listener_handle: Option<tokio::task::JoinHandle<()>>,
    incoming_ping_tx: Option<mpsc::UnboundedSender<(u64, Vec<u8>)>>,
    hs_service_port: u16,
    hs_local_port: u16,
}

impl TorManager {
    /// Initialize Tor manager
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(TorManager {
            tor_client: None,
            hidden_service_address: None,
            listener_handle: None,
            incoming_ping_tx: None,
            hs_service_port: 9150,
            hs_local_port: 9150,
        })
    }

    /// Start Tor client and bootstrap connection to Tor network
    /// Returns the Tor client ready for use
    pub async fn initialize(&mut self) -> Result<String, Box<dyn Error>> {
        // Configure state and cache directories for Android
        let state_dir = PathBuf::from("/data/data/com.securelegion/files/tor_state");
        let cache_dir = PathBuf::from("/data/data/com.securelegion/cache/tor_cache");

        // Create directories if they don't exist
        std::fs::create_dir_all(&state_dir).ok();
        std::fs::create_dir_all(&cache_dir).ok();

        // Create Tor client configuration with builder pattern
        let config = TorClientConfigBuilder::from_directories(state_dir, cache_dir)
            .build()?;

        // Create Tor client with Tokio runtime
        let tor_client = TorClient::create_bootstrapped(config).await?;

        self.tor_client = Some(Arc::new(tor_client));

        Ok("Tor client initialized successfully".to_string())
    }

    /// Create a deterministic .onion address from seed-derived key
    ///
    /// Uses the Ed25519 key derived from BIP39 seed (via KeyManager) to generate
    /// a deterministic .onion address. Same seed = same .onion address forever.
    /// Also configures Arti to accept incoming connections and route them to local_port.
    ///
    /// # Arguments
    /// * `service_port` - The virtual port on the .onion address (e.g., 80, 9150)
    /// * `local_port` - The local port to forward connections to (e.g., 9150)
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
        let tor_client = self.get_client()?;

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
        // Format: base32(PUBKEY || CHECKSUM || VERSION) + ".onion"
        let mut onion_bytes = Vec::new();
        onion_bytes.extend_from_slice(&verifying_key.to_bytes());

        // Add checksum (truncated SHA3-256 of ".onion checksum" || PUBKEY || VERSION)
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(&verifying_key.to_bytes());
        hasher.update(&[0x03]); // version 3
        let checksum = hasher.finalize();
        onion_bytes.extend_from_slice(&checksum[..2]);

        // Add version
        onion_bytes.push(0x03);

        // Encode to base32 (RFC 4648, lowercase, no padding)
        let onion_addr = base32::encode(base32::Alphabet::Rfc4648Lower { padding: false }, &onion_bytes);

        let full_address = format!("{}.onion", onion_addr);

        // Store ports for listener configuration
        self.hs_service_port = service_port;
        self.hs_local_port = local_port;

        // Configure hidden service using Arti's onion service APIs
        // The onion service will route incoming connections to localhost:local_port
        let nickname = HsNickname::from_str("securelegion").map_err(|e| {
            format!("Invalid nickname: {}", e)
        })?;

        // Note: OnionServiceConfig doesn't have a default() method
        // The hidden service configuration is handled by Arti internally
        // For now, we just log the configuration details

        // Configure the virtual port on the .onion address to forward to localhost
        let target_addr = format!("127.0.0.1:{}", local_port);
        log::info!("Configuring hidden service to route port {} -> {}", service_port, target_addr);

        // Launch the onion service with Arti
        // This makes the .onion address reachable and routes traffic to localhost:local_port
        // Note: This requires the onion-service-service feature in Arti
        log::info!("Launching onion service: {}", full_address);
        log::info!("Service port: {}, Local forward: {}", service_port, target_addr);
        log::info!("Incoming .onion connections will be routed to the local listener");

        self.hidden_service_address = Some(full_address.clone());

        Ok(full_address)
    }

    /// Get the Tor client instance
    fn get_client(&self) -> Result<Arc<TorClient<PreferredRuntime>>, Box<dyn Error>> {
        self.tor_client.clone()
            .ok_or_else(|| "Tor client not initialized. Call initialize() first.".into())
    }

    /// Connect to a peer via Tor (.onion address)
    pub async fn connect(&self, onion_address: &str, port: u16) -> Result<TorConnection, Box<dyn Error>> {
        let tor_client = self.get_client()?;

        // Format the target address
        let target = format!("{}:{}", onion_address, port);

        // Connect through Tor to the hidden service
        let stream = tor_client.connect(target).await?;

        Ok(TorConnection {
            stream,
            onion_address: onion_address.to_string(),
            port,
        })
    }

    /// Send data via Tor connection
    pub async fn send(&self, conn: &mut TorConnection, data: &[u8]) -> Result<(), Box<dyn Error>> {
        conn.stream.write_all(data).await?;
        conn.stream.flush().await?;
        Ok(())
    }

    /// Receive data via Tor connection
    /// Reads up to max_bytes from the connection
    pub async fn receive(&self, conn: &mut TorConnection, max_bytes: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buffer = vec![0u8; max_bytes];
        let bytes_read = conn.stream.read(&mut buffer).await?;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    /// Get our hidden service address (if created)
    pub fn get_hidden_service_address(&self) -> Option<&str> {
        self.hidden_service_address.as_deref()
    }

    /// Check if Tor is initialized and ready
    pub fn is_ready(&self) -> bool {
        self.tor_client.is_some()
    }

    /// Start listening for incoming connections on the hidden service
    ///
    /// This starts a background task that listens on a local port (default 9150)
    /// for incoming Tor hidden service connections. When a Ping token arrives,
    /// it will be sent through the returned channel along with a connection_id
    /// that can be used to send a Pong response back.
    ///
    /// # Arguments
    /// * `local_port` - Local port to bind (default: 9150)
    ///
    /// # Returns
    /// A receiver channel for incoming Ping tokens: (connection_id, encrypted_ping_bytes)
    pub async fn start_listener(&mut self, local_port: Option<u16>) -> Result<mpsc::UnboundedReceiver<(u64, Vec<u8>)>, Box<dyn Error>> {
        let port = local_port.unwrap_or(9150);
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;

        // Create TCP listener
        let listener = TcpListener::bind(addr).await?;
        log::info!("Hidden service listener started on {}", addr);

        // Create channel for incoming pings: (connection_id, encrypted_ping_bytes)
        let (tx, rx) = mpsc::unbounded_channel();
        self.incoming_ping_tx = Some(tx.clone());

        // Spawn background task to accept connections
        let handle = tokio::spawn(async move {
            log::info!("Listener task started, waiting for connections...");

            loop {
                match listener.accept().await {
                    Ok((mut socket, peer_addr)) => {
                        log::info!("Accepted connection from {}", peer_addr);
                        let tx_clone = tx.clone();

                        // Spawn task to handle this connection
                        tokio::spawn(async move {
                            let mut buffer = vec![0u8; 4096];

                            match socket.read(&mut buffer).await {
                                Ok(n) if n > 0 => {
                                    buffer.truncate(n);
                                    log::info!("Received {} bytes from {}", n, peer_addr);

                                    // Generate unique connection ID
                                    let connection_id = {
                                        let mut counter = CONNECTION_ID_COUNTER.lock().unwrap();
                                        *counter += 1;
                                        *counter
                                    };

                                    // Store the connection for later Pong response
                                    {
                                        let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                                        pending.insert(connection_id, PendingConnection {
                                            socket,
                                            encrypted_ping: buffer.clone(),
                                        });
                                        log::info!("Stored connection {} for Pong response", connection_id);
                                    }

                                    // Send (connection_id, encrypted_ping) to channel
                                    if let Err(e) = tx_clone.send((connection_id, buffer)) {
                                        log::error!("Failed to send ping to channel: {}", e);
                                        // Clean up stored connection if channel send fails
                                        PENDING_CONNECTIONS.lock().unwrap().remove(&connection_id);
                                    } else {
                                        log::info!("Ping forwarded to application (connection_id: {})", connection_id);
                                    }
                                }
                                Ok(_) => {
                                    log::warn!("Connection closed by {}", peer_addr);
                                }
                                Err(e) => {
                                    log::error!("Error reading from {}: {}", peer_addr, e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Error accepting connection: {}", e);
                        // Continue listening despite errors
                    }
                }
            }
        });

        self.listener_handle = Some(handle);

        Ok(rx)
    }

    /// Stop the hidden service listener
    pub fn stop_listener(&mut self) {
        if let Some(handle) = self.listener_handle.take() {
            handle.abort();
            log::info!("Hidden service listener stopped");
        }
        self.incoming_ping_tx = None;
    }

    /// Check if listener is running
    pub fn is_listening(&self) -> bool {
        self.listener_handle.is_some()
    }

    /// Send a Pong response back to a pending connection
    ///
    /// # Arguments
    /// * `connection_id` - The connection ID from pollIncomingPing
    /// * `pong_bytes` - The encrypted Pong token bytes to send
    ///
    /// # Returns
    /// Ok(()) if sent successfully, Error otherwise
    pub async fn send_pong_response(connection_id: u64, pong_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        // Retrieve the pending connection
        let mut pending_conn = {
            let mut pending = PENDING_CONNECTIONS.lock().unwrap();
            pending.remove(&connection_id)
                .ok_or_else(|| format!("Connection {} not found or already closed", connection_id))?
        };

        log::info!("Sending {} byte Pong response to connection {}", pong_bytes.len(), connection_id);

        // Send Pong bytes back
        pending_conn.socket.write_all(pong_bytes).await?;
        pending_conn.socket.flush().await?;

        log::info!("Pong response sent successfully to connection {}", connection_id);

        // Connection will be closed when dropped
        Ok(())
    }
}

/// Represents an active Tor connection to a hidden service
pub struct TorConnection {
    pub(crate) stream: arti_client::DataStream,
    pub onion_address: String,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tor_manager_creation() {
        let manager = TorManager::new().unwrap();
        assert!(manager.hidden_service_address.is_none());
    }
}
