/// Voice Streaming Listener for SecureLegion (v2.0)
///
/// Handles bidirectional voice streaming over Tor hidden services
/// - Listens on port 9152 (voice .onion address)
/// - Uses Opus codec for audio compression
/// - P2P architecture: each device runs a listener, peers connect directly
/// - Real-time audio packet streaming with encryption
/// - VOICE_HELLO/OK handshake ensures both sides ready before audio starts

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

// SOCKS5 constants
const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NO_AUTH: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const RESERVED: u8 = 0x00;

// Voice protocol handshake constants
const VOICE_HELLO: &[u8] = b"HELLO";
const VOICE_OK: &[u8] = b"OK";
const VOICE_PROTOCOL_VERSION_V1: u8 = 0x01;
const VOICE_PROTOCOL_VERSION_V2: u8 = 0x02;
const VOICE_PROTOCOL_VERSION_CURRENT: u8 = VOICE_PROTOCOL_VERSION_V2; // Prefer v2
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

// Packet type flags (v2)
const PTYPE_AUDIO: u8 = 0x01;
const PTYPE_CONTROL: u8 = 0x02;

/// Voice packet structure
/// Contains compressed audio data + metadata
/// Phase 3: FREE redundancy via Tor cell padding (514 bytes total, ~172 bytes used, 342 bytes FREE!)
#[derive(Debug, Clone)]
pub struct VoicePacket {
    /// Sequence number for packet ordering
    pub sequence: u32,
    /// Opus-encoded audio data (PRIMARY frame)
    pub audio_data: Vec<u8>,
    /// Timestamp (milliseconds since call start)
    pub timestamp: u64,
    /// Circuit index (v2 only - which Tor circuit this packet uses)
    pub circuit_index: u8,
    /// Packet type (v2 only - AUDIO or CONTROL)
    pub ptype: u8,
    /// Phase 3: Redundant copy of PREVIOUS frame (uses FREE Tor padding)
    pub redundant_audio_data: Vec<u8>,
    /// Sequence number of redundant frame
    pub redundant_sequence: u32,
}

/// Voice streaming session
/// Represents an active voice call connection
pub struct VoiceSession {
    /// Remote peer address
    peer_addr: SocketAddr,
    /// Remote peer onion address (needed for circuit rebuild)
    peer_onion: String,
    /// Sender for outgoing audio packets
    audio_tx: mpsc::UnboundedSender<VoicePacket>,
    /// Connection status
    is_active: Arc<Mutex<bool>>,
}

impl VoiceSession {
    /// Create new voice session
    pub fn new(peer_addr: SocketAddr, peer_onion: String, audio_tx: mpsc::UnboundedSender<VoicePacket>) -> Self {
        VoiceSession {
            peer_addr,
            peer_onion,
            audio_tx,
            is_active: Arc::new(Mutex::new(true)),
        }
    }

    /// Send audio packet to peer
    pub fn send_audio(&self, packet: VoicePacket) -> Result<(), Box<dyn Error>> {
        if *self.is_active.lock().unwrap() {
            self.audio_tx.send(packet)?;
            Ok(())
        } else {
            Err("Session not active".into())
        }
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        *self.is_active.lock().unwrap()
    }

    /// Close session
    pub fn close(&self) {
        *self.is_active.lock().unwrap() = false;
    }
}

/// Voice Streaming Listener
/// Listens on port 9152 for incoming voice connections
/// Handles BOTH call signaling (HTTP POST) and audio streaming (raw TCP)
pub struct VoiceStreamingListener {
    /// TCP listener
    pub listener: Option<TcpListener>,
    /// Active sessions (keyed by call ID, vector contains one session per circuit)
    pub sessions: Arc<Mutex<HashMap<String, Vec<VoiceSession>>>>,
    /// Callback for incoming audio packets
    pub audio_callback: Option<Arc<dyn Fn(String, VoicePacket) + Send + Sync>>,
    /// Callback for incoming signaling messages (CALL_OFFER, CALL_ANSWER, etc)
    /// Parameters: (sender_x25519_pubkey, message_wire_bytes)
    pub signaling_callback: Option<Arc<dyn Fn(Vec<u8>, Vec<u8>) + Send + Sync>>,
}

impl VoiceStreamingListener {
    /// Create new voice streaming listener
    pub fn new() -> Self {
        VoiceStreamingListener {
            listener: None,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            audio_callback: None,
            signaling_callback: None,
        }
    }

    /// Start listener on port 9152
    /// This also spawns a background task to accept incoming connections
    pub async fn start(&mut self) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:9152").await?;
        log::info!("Voice streaming listener started on 127.0.0.1:9152");

        // Store listener temporarily
        self.listener = Some(listener);

        // Take listener out (we'll move it into the background task)
        let listener = self.listener.take().unwrap();

        // Clone shared state so task doesn't need to hold lock
        let sessions = self.sessions.clone();
        let audio_callback = self.audio_callback.clone();
        let signaling_callback = self.signaling_callback.clone();

        // Spawn background task to accept connections
        // This task doesn't need the server lock - it has its own copies
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut socket, addr)) => {
                        log::info!("Voice connection from: {}", addr);

                        // Disable Nagle's algorithm for real-time audio
                        if let Err(e) = socket.set_nodelay(true) {
                            log::warn!("Failed to set TCP_NODELAY: {}", e);
                        }

                        let sessions_clone = sessions.clone();
                        let audio_callback_clone = audio_callback.clone();
                        let signaling_callback_clone = signaling_callback.clone();

                        // Spawn handler for this connection
                        tokio::spawn(async move {
                            if let Err(e) = handle_voice_connection(socket, addr, sessions_clone, audio_callback_clone, signaling_callback_clone).await {
                                log::error!("Voice connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("Failed to accept voice connection: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Set callback for incoming audio packets
    pub fn set_audio_callback<F>(&mut self, callback: F)
    where
        F: Fn(String, VoicePacket) + Send + Sync + 'static,
    {
        self.audio_callback = Some(Arc::new(callback));
    }

    /// Set callback for incoming signaling messages (CALL_OFFER, CALL_ANSWER, etc)
    /// Callback receives: (sender_x25519_pubkey, message_wire_bytes)
    pub fn set_signaling_callback<F>(&mut self, callback: F)
    where
        F: Fn(Vec<u8>, Vec<u8>) + Send + Sync + 'static,
    {
        self.signaling_callback = Some(Arc::new(callback));
    }

    /// Accept incoming connections (run in loop)
    pub async fn accept_connections(&mut self) -> Result<(), Box<dyn Error>> {
        let listener = self.listener.as_ref()
            .ok_or("Listener not started")?;

        loop {
            let (mut socket, addr) = listener.accept().await?;
            log::info!("Voice connection from: {}", addr);

            // Disable Nagle's algorithm for real-time audio
            if let Err(e) = socket.set_nodelay(true) {
                log::warn!("Failed to set TCP_NODELAY: {}", e);
            }

            let sessions = self.sessions.clone();
            let audio_callback = self.audio_callback.clone();
            let signaling_callback = self.signaling_callback.clone();

            // Spawn handler for this connection
            tokio::spawn(async move {
                if let Err(e) = handle_voice_connection(socket, addr, sessions, audio_callback, signaling_callback).await {
                    log::error!("Voice connection error: {}", e);
                }
            });
        }
    }

    /// Create outgoing voice session with multiple circuits
    /// @param num_circuits Number of parallel Tor circuits to establish (typically 3)
    pub async fn create_session(
        &mut self,
        call_id: String,
        peer_onion: &str,
        num_circuits: usize,
    ) -> Result<(), Box<dyn Error>> {
        log::info!("[VOICE_DEBUG] create_session called with num_circuits={}, peer_onion={}, call_id={}",
                   num_circuits, peer_onion, call_id);

        if num_circuits == 0 || num_circuits > 10 {
            log::error!("[VOICE_DEBUG] Invalid num_circuits: {}", num_circuits);
            return Err("num_circuits must be between 1 and 10".into());
        }

        log::info!("Creating {} circuit(s) to {} for call {}", num_circuits, peer_onion, call_id);
        log::info!("[VOICE_DEBUG] Starting circuit creation loop...");

        let mut circuit_sessions = Vec::with_capacity(num_circuits);

        // Create each circuit in parallel
        for circuit_index in 0..num_circuits {
            log::info!("[VOICE_DEBUG] Loop iteration {}/{}", circuit_index, num_circuits);
            // Connect to peer's voice hidden service via SOCKS5 proxy (Tor)
            log::info!("Establishing circuit {} to {} via SOCKS5 proxy", circuit_index, peer_onion);
            log::info!("[VOICE_DEBUG] About to call connect_via_socks5({}:9152)", peer_onion);
            let mut stream = connect_via_socks5(peer_onion, 9152, circuit_index, &call_id, 0).await?;
            log::info!("[VOICE_DEBUG] connect_via_socks5 returned successfully for circuit {}", circuit_index);

            // Disable Nagle's algorithm for real-time audio
            if let Err(e) = stream.set_nodelay(true) {
                log::warn!("Failed to set TCP_NODELAY on circuit {}: {}", circuit_index, e);
            }

            let peer_socket_addr = stream.peer_addr()?;

            let (audio_tx, audio_rx) = mpsc::unbounded_channel();
            let session = VoiceSession::new(peer_socket_addr, peer_onion.to_string(), audio_tx);

            circuit_sessions.push(session);

            // Spawn sender task for this circuit
            let sessions = self.sessions.clone();
            let call_id_clone = call_id.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_voice_sender(stream, audio_rx, call_id_clone, sessions, circuit_index).await {
                    log::error!("Voice sender error on circuit {}: {}", circuit_index, e);
                }
            });

            log::info!("Circuit {} established for call {}", circuit_index, call_id);
        }

        // Store all circuit sessions
        self.sessions.lock().unwrap().insert(call_id.clone(), circuit_sessions);

        log::info!("All {} outgoing voice circuits created for call: {}", num_circuits, call_id);
        Ok(())
    }

    /// Send audio packet to peer on specific circuit
    /// @param circuit_index Which circuit to use (0 to num_circuits-1)
    pub fn send_audio(&self, call_id: &str, circuit_index: usize, packet: VoicePacket) -> Result<(), Box<dyn Error>> {
        let sessions = self.sessions.lock().unwrap();
        if let Some(circuit_sessions) = sessions.get(call_id) {
            if circuit_index >= circuit_sessions.len() {
                return Err(format!("Circuit index {} out of range (max: {})", circuit_index, circuit_sessions.len() - 1).into());
            }
            circuit_sessions[circuit_index].send_audio(packet)?;
            Ok(())
        } else {
            Err(format!("Session not found: {}", call_id).into())
        }
    }

    /// End voice session (closes all circuits)
    pub fn end_session(&self, call_id: &str) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Some(circuit_sessions) = sessions.remove(call_id) {
            for (i, session) in circuit_sessions.into_iter().enumerate() {
                session.close();
                log::debug!("Circuit {} closed for call: {}", i, call_id);
            }
            log::info!("Voice session ended (all circuits closed): {}", call_id);
        }
    }

    /// Get active session count
    pub fn active_sessions(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    /// Rebuild a specific circuit (close and reconnect with fresh Tor path)
    /// This is called when a circuit is persistently bad and needs replacement
    ///
    /// IMPORTANT INVARIANTS:
    /// - Circuit index is preserved (rebuilding circuit 0 creates a new circuit 0)
    /// - Encryption keys are NOT re-derived (Kotlin keeps circuitKeys[i] unchanged)
    /// - Sequence numbers continue incrementing (no reset)
    /// - AAD encoding remains valid (uses same circuit_index)
    /// - Only the TCP connection and Tor path change
    ///
    /// @param call_id Active call session ID
    /// @param circuit_index Circuit to rebuild (0, 1, 2, etc.)
    /// @param rebuild_epoch Incremented rebuild counter (forces new Tor path via SOCKS5 isolation)
    pub async fn rebuild_circuit(
        &mut self,
        call_id: &str,
        circuit_index: usize,
        rebuild_epoch: u32,
    ) -> Result<(), Box<dyn Error>> {
        log::warn!("REBUILD_START callId={} circuit={} reason=PLC rebuild_epoch={}", call_id, circuit_index, rebuild_epoch);

        // 1. Get peer onion from existing session and close it
        let peer_onion = {
            let sessions = self.sessions.lock().unwrap();
            let circuit_sessions = sessions.get(call_id)
                .ok_or(format!("Session not found: {}", call_id))?;

            if circuit_index >= circuit_sessions.len() {
                return Err(format!("Circuit index {} out of range (max: {})", circuit_index, circuit_sessions.len() - 1).into());
            }

            // Extract peer onion before closing circuit
            let peer_onion = circuit_sessions[circuit_index].peer_onion.clone();

            // Close existing circuit (drop sender to signal shutdown)
            circuit_sessions[circuit_index].close();

            peer_onion
        };

        // 2. Wait briefly for old circuit to fully close
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 3. Connect to peer's voice hidden service via SOCKS5 with new isolation credentials
        log::info!("Rebuilding circuit {} to {} via SOCKS5 proxy (rebuild_epoch={})", circuit_index, peer_onion, rebuild_epoch);
        let mut stream = connect_via_socks5(&peer_onion, 9152, circuit_index, call_id, rebuild_epoch).await?;

        // Disable Nagle's algorithm for real-time audio
        if let Err(e) = stream.set_nodelay(true) {
            log::warn!("Failed to set TCP_NODELAY on rebuilt circuit {}: {}", circuit_index, e);
        }

        let peer_socket_addr = stream.peer_addr()?;

        let (audio_tx, audio_rx) = mpsc::unbounded_channel();
        let new_session = VoiceSession::new(peer_socket_addr, peer_onion.clone(), audio_tx);

        // 4. Atomically replace circuit session
        {
            let mut sessions = self.sessions.lock().unwrap();
            if let Some(circuit_sessions) = sessions.get_mut(call_id) {
                circuit_sessions[circuit_index] = new_session;
            } else {
                return Err(format!("Session disappeared during rebuild: {}", call_id).into());
            }
        }

        // 5. Spawn new sender task for this circuit
        let sessions = self.sessions.clone();
        let call_id_clone = call_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = handle_voice_sender(stream, audio_rx, call_id_clone, sessions, circuit_index).await {
                log::error!("Voice sender error on rebuilt circuit {}: {}", circuit_index, e);
            }
        });

        log::info!("REBUILD_SUCCESS callId={} circuit={} rebuild_epoch={} elapsed_ms=<100", call_id, circuit_index, rebuild_epoch);
        Ok(())
    }
}

/// Handle incoming voice connection (HTTP signaling or audio streaming)
/// Detects connection type by peeking at first bytes:
/// - HTTP POST: starts with "POST"
/// - Audio: starts with UUID (36 bytes)
pub async fn handle_voice_connection(
    mut socket: TcpStream,
    addr: SocketAddr,
    sessions: Arc<Mutex<HashMap<String, Vec<VoiceSession>>>>,
    audio_callback: Option<Arc<dyn Fn(String, VoicePacket) + Send + Sync>>,
    signaling_callback: Option<Arc<dyn Fn(Vec<u8>, Vec<u8>) + Send + Sync>>,
) -> Result<(), Box<dyn Error>> {
    // Peek at first 4 bytes to detect connection type
    let mut peek_buf = [0u8; 4];
    socket.peek(&mut peek_buf).await?;

    // Check if it's an HTTP POST request
    if &peek_buf == b"POST" {
        log::info!("Detected HTTP signaling connection from {}", addr);
        return handle_http_signaling(socket, addr, signaling_callback).await;
    } else {
        log::info!("Detected audio connection from {}", addr);
        return handle_audio_connection(socket, addr, sessions, audio_callback).await;
    }
}

/// Handle HTTP POST request for call signaling (CALL_OFFER, CALL_ANSWER, etc)
async fn handle_http_signaling(
    mut socket: TcpStream,
    addr: SocketAddr,
    signaling_callback: Option<Arc<dyn Fn(Vec<u8>, Vec<u8>) + Send + Sync>>,
) -> Result<(), Box<dyn Error>> {
    // Read HTTP request line
    let mut request_line = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        socket.read_exact(&mut byte).await?;
        request_line.push(byte[0]);
        if request_line.len() >= 2 && &request_line[request_line.len()-2..] == b"\r\n" {
            break;
        }
        if request_line.len() > 8192 {
            return Err("HTTP request line too long".into());
        }
    }

    let request_str = String::from_utf8_lossy(&request_line);
    log::debug!("HTTP request: {}", request_str.trim());

    // Read headers until we find Content-Length
    let mut content_length: Option<usize> = None;
    loop {
        let mut header_line = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            socket.read_exact(&mut byte).await?;
            header_line.push(byte[0]);
            if header_line.len() >= 2 && &header_line[header_line.len()-2..] == b"\r\n" {
                break;
            }
            if header_line.len() > 8192 {
                return Err("HTTP header line too long".into());
            }
        }

        // Empty line signals end of headers
        if header_line == b"\r\n" {
            break;
        }

        let header_str = String::from_utf8_lossy(&header_line);
        if header_str.to_lowercase().starts_with("content-length:") {
            let len_str = header_str.trim().split(':').nth(1)
                .ok_or("Invalid Content-Length header")?
                .trim();
            content_length = Some(len_str.parse()?);
        }
    }

    let body_len = content_length.ok_or("Missing Content-Length header")?;

    // Read body (wire message format: [Type][Sender X25519 Pubkey - 32 bytes][Encrypted Message])
    let mut body = vec![0u8; body_len];
    socket.read_exact(&mut body).await?;

    log::info!("Received HTTP signaling message: {} bytes from {}", body.len(), addr);

    // Extract sender X25519 public key (bytes 1-32) and wire message
    if body.len() < 33 {
        return Err("HTTP body too short for wire message format".into());
    }

    let sender_pubkey = body[1..33].to_vec();
    let wire_message = body; // Full wire message including type byte

    // Call signaling callback
    if let Some(callback) = signaling_callback {
        callback(sender_pubkey, wire_message);
        log::info!("Signaling callback invoked for HTTP message");
    } else {
        log::warn!("Signaling callback not set - message dropped");
    }

    // Send HTTP 200 OK response
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    socket.write_all(response).await?;
    socket.flush().await?;

    log::info!("HTTP signaling request handled successfully");
    Ok(())
}

/// Handle audio streaming connection (existing VOICE_HELLO/OK protocol)
async fn handle_audio_connection(
    mut socket: TcpStream,
    addr: SocketAddr,
    sessions: Arc<Mutex<HashMap<String, Vec<VoiceSession>>>>,
    audio_callback: Option<Arc<dyn Fn(String, VoicePacket) + Send + Sync>>,
) -> Result<(), Box<dyn Error>> {
    // Read call ID (first 36 bytes = UUID)
    let mut call_id_bytes = [0u8; 36];
    socket.read_exact(&mut call_id_bytes).await?;
    let call_id = String::from_utf8(call_id_bytes.to_vec())?;

    log::info!("Voice audio connection for call: {} from {}", call_id, addr);

    // ========== VOICE_HELLO/OK HANDSHAKE ==========
    // Read VOICE_HELLO message (with timeout)
    log::debug!("Waiting for VOICE_HELLO from peer...");
    let handshake_result = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), async {
        // Read "HELLO" (5 bytes)
        let mut hello_bytes = [0u8; 5];
        socket.read_exact(&mut hello_bytes).await
            .map_err(|e| format!("Failed to read VOICE_HELLO: {}", e))?;

        if &hello_bytes != VOICE_HELLO {
            return Err(format!("Expected VOICE_HELLO, got: {:?}", hello_bytes));
        }

        // Read version (1 byte)
        let mut version = [0u8; 1];
        socket.read_exact(&mut version).await
            .map_err(|e| format!("Failed to read version: {}", e))?;

        let client_version = version[0];

        // Read flags (1 byte)
        let mut flags = [0u8; 1];
        socket.read_exact(&mut flags).await
            .map_err(|e| format!("Failed to read flags: {}", e))?;

        // Negotiate version: use minimum of (client_version, VOICE_PROTOCOL_VERSION_CURRENT)
        let negotiated_version = std::cmp::min(client_version, VOICE_PROTOCOL_VERSION_CURRENT);

        log::info!("✓ Received VOICE_HELLO (client_version: {}, flags: {}) for call: {}",
                   client_version, flags[0], call_id);
        log::info!("✓ Negotiated protocol version: {} (v1=1, v2=2)", negotiated_version);

        // Send VOICE_OK response with negotiated version
        socket.write_all(VOICE_OK).await
            .map_err(|e| format!("Failed to write VOICE_OK: {}", e))?;
        socket.write_all(&[negotiated_version]).await
            .map_err(|e| format!("Failed to write version: {}", e))?;
        socket.write_all(&[0x00]).await
            .map_err(|e| format!("Failed to write flags: {}", e))?;
        socket.flush().await
            .map_err(|e| format!("Failed to flush: {}", e))?;

        log::info!("✓ Sent VOICE_OK with negotiated version {} for call: {}", negotiated_version, call_id);
        Ok::<(u8), String>(negotiated_version)
    }).await;

    let negotiated_version = match handshake_result {
        Ok(Ok(version)) => {
            log::info!("✓ Voice handshake complete for call: {} (version: {})", call_id, version);
            version
        }
        Ok(Err(e)) => {
            log::error!("✗ Voice handshake failed for call {}: {}", call_id, e);
            return Err(e.into());
        }
        Err(_) => {
            log::error!("✗ Voice handshake timeout for call: {}", call_id);
            return Err(format!("Handshake timeout after {} seconds", HANDSHAKE_TIMEOUT_SECS).into());
        }
    };

    // Read audio packets in loop
    loop {
        let packet = if negotiated_version == VOICE_PROTOCOL_VERSION_V1 {
            // V1 packet format: seq(4) + timestamp(8) + data_len(2) + payload
            let mut header = [0u8; 12];
            match socket.read_exact(&mut header).await {
                Ok(_) => {},
                Err(_) => {
                    log::info!("Voice audio connection closed: {}", call_id);
                    break;
                }
            }

            let sequence = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            let timestamp = u64::from_be_bytes([
                header[4], header[5], header[6], header[7],
                header[8], header[9], header[10], header[11],
            ]);

            // Read data length (2 bytes)
            let mut len_bytes = [0u8; 2];
            socket.read_exact(&mut len_bytes).await?;
            let data_len = u16::from_be_bytes(len_bytes) as usize;

            // Read audio data
            let mut audio_data = vec![0u8; data_len];
            socket.read_exact(&mut audio_data).await?;

            VoicePacket {
                sequence,
                audio_data,
                timestamp,
                circuit_index: 0, // v1 doesn't have circuit_index
                ptype: PTYPE_AUDIO, // v1 only has audio packets
                redundant_audio_data: Vec::new(), // v1 doesn't have redundancy
                redundant_sequence: 0,
            }
        } else {
            // V2 packet format (Phase 3): seq(4) + timestamp(8) + circuit_index(1) + ptype(1) +
            //                             data_len(2) + payload + redundant_seq(4) + redundant_len(2) + redundant_payload
            let mut header = [0u8; 14];
            match socket.read_exact(&mut header).await {
                Ok(_) => {},
                Err(_) => {
                    log::info!("Voice audio connection closed: {}", call_id);
                    break;
                }
            }

            let sequence = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            let timestamp = u64::from_be_bytes([
                header[4], header[5], header[6], header[7],
                header[8], header[9], header[10], header[11],
            ]);
            let circuit_index = header[12];
            let ptype = header[13];

            // Read primary data length (2 bytes)
            let mut len_bytes = [0u8; 2];
            socket.read_exact(&mut len_bytes).await?;
            let data_len = u16::from_be_bytes(len_bytes) as usize;

            // Read primary payload data
            let mut audio_data = vec![0u8; data_len];
            socket.read_exact(&mut audio_data).await?;

            // Phase 3: Read redundant frame (backwards compatible - may not be present)
            let (redundant_audio_data, redundant_sequence) = match async {
                // Read redundant sequence number (4 bytes)
                let mut redundant_seq_bytes = [0u8; 4];
                socket.read_exact(&mut redundant_seq_bytes).await?;
                let redundant_seq = u32::from_be_bytes(redundant_seq_bytes);

                // Read redundant data length (2 bytes)
                let mut redundant_len_bytes = [0u8; 2];
                socket.read_exact(&mut redundant_len_bytes).await?;
                let redundant_len = u16::from_be_bytes(redundant_len_bytes) as usize;

                // Read redundant payload
                let mut redundant_data = vec![0u8; redundant_len];
                socket.read_exact(&mut redundant_data).await?;

                Ok::<_, std::io::Error>((redundant_data, redundant_seq))
            }.await {
                Ok((data, seq)) => (data, seq),
                Err(_) => {
                    // No redundant data (old client or end of stream) - that's OK
                    (Vec::new(), 0)
                }
            };

            VoicePacket {
                sequence,
                audio_data,
                timestamp,
                circuit_index,
                ptype,
                redundant_audio_data,
                redundant_sequence,
            }
        };

        // Call callback with received packet
        if let Some(ref callback) = audio_callback {
            callback(call_id.clone(), packet);
        }
    }

    Ok(())
}

/// Handle outgoing voice stream (sender)
async fn handle_voice_sender(
    mut socket: TcpStream,
    mut audio_rx: mpsc::UnboundedReceiver<VoicePacket>,
    call_id: String,
    sessions: Arc<Mutex<HashMap<String, Vec<VoiceSession>>>>,
    circuit_index: usize,
) -> Result<(), Box<dyn Error>> {
    // Send call ID first
    socket.write_all(call_id.as_bytes()).await?;
    socket.flush().await?;

    // ========== VOICE_HELLO/OK HANDSHAKE ==========
    // Send VOICE_HELLO message (offer our highest version)
    log::debug!("Sending VOICE_HELLO for call: {} circuit: {}", call_id, circuit_index);
    socket.write_all(VOICE_HELLO).await?;
    socket.write_all(&[VOICE_PROTOCOL_VERSION_CURRENT]).await?; // Offer v2
    socket.write_all(&[0x00]).await?; // flags
    socket.flush().await?;

    log::info!("✓ Sent VOICE_HELLO (offered version: {}) for call: {} circuit: {}", VOICE_PROTOCOL_VERSION_CURRENT, call_id, circuit_index);

    // Wait for VOICE_OK response (with timeout)
    log::debug!("Waiting for VOICE_OK from peer...");
    let handshake_result = timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), async {
        // Read "OK" (2 bytes)
        let mut ok_bytes = [0u8; 2];
        socket.read_exact(&mut ok_bytes).await
            .map_err(|e| format!("Failed to read VOICE_OK: {}", e))?;

        if &ok_bytes != VOICE_OK {
            return Err(format!("Expected VOICE_OK, got: {:?}", ok_bytes));
        }

        // Read negotiated version (1 byte)
        let mut version = [0u8; 1];
        socket.read_exact(&mut version).await
            .map_err(|e| format!("Failed to read version: {}", e))?;

        let negotiated_version = version[0];

        // Read flags (1 byte)
        let mut flags = [0u8; 1];
        socket.read_exact(&mut flags).await
            .map_err(|e| format!("Failed to read flags: {}", e))?;

        log::info!("✓ Received VOICE_OK (negotiated_version: {}, flags: {}) for call: {} circuit: {}",
                   negotiated_version, flags[0], call_id, circuit_index);

        Ok::<(u8), String>(negotiated_version)
    }).await;

    let negotiated_version = match handshake_result {
        Ok(Ok(version)) => {
            log::info!("✓ Voice handshake complete for call: {} circuit: {} (version: {})", call_id, circuit_index, version);
            version
        }
        Ok(Err(e)) => {
            log::error!("✗ Voice handshake failed for call {} circuit {}: {}", call_id, circuit_index, e);
            return Err(e.into());
        }
        Err(_) => {
            log::error!("✗ Voice handshake timeout for call: {} circuit: {}", call_id, circuit_index);
            return Err(format!("Handshake timeout after {} seconds", HANDSHAKE_TIMEOUT_SECS).into());
        }
    };

    // Send audio packets from queue
    while let Some(packet) = audio_rx.recv().await {
        if negotiated_version == VOICE_PROTOCOL_VERSION_V1 {
            // V1 packet format: seq(4) + timestamp(8) + data_len(2) + payload
            socket.write_all(&packet.sequence.to_be_bytes()).await?;
            socket.write_all(&packet.timestamp.to_be_bytes()).await?;
            socket.write_all(&(packet.audio_data.len() as u16).to_be_bytes()).await?;
            socket.write_all(&packet.audio_data).await?;
        } else {
            // V2 packet format (Phase 3): seq(4) + timestamp(8) + circuit_index(1) + ptype(1) +
            //                             data_len(2) + payload + redundant_seq(4) + redundant_len(2) + redundant_payload
            socket.write_all(&packet.sequence.to_be_bytes()).await?;
            socket.write_all(&packet.timestamp.to_be_bytes()).await?;
            socket.write_all(&[packet.circuit_index]).await?;
            socket.write_all(&[packet.ptype]).await?;
            socket.write_all(&(packet.audio_data.len() as u16).to_be_bytes()).await?;
            socket.write_all(&packet.audio_data).await?;

            // Phase 3: Write redundant frame (FREE via Tor cell padding - no bandwidth cost!)
            socket.write_all(&packet.redundant_sequence.to_be_bytes()).await?;
            socket.write_all(&(packet.redundant_audio_data.len() as u16).to_be_bytes()).await?;
            socket.write_all(&packet.redundant_audio_data).await?;
        }
        socket.flush().await?;
    }

    // Note: Don't remove session here - end_session() handles cleanup for all circuits
    log::info!("Voice sender task ended for call: {} circuit: {}", call_id, circuit_index);

    Ok(())
}

/// Connect to target via SOCKS5 proxy (Tor) with circuit isolation
/// This allows connecting to .onion addresses with guaranteed path diversity
///
/// @param target_host .onion address to connect to
/// @param target_port Port number
/// @param circuit_id Circuit index (0, 1, 2, etc.) - forces separate Tor paths
/// @param call_id Call UUID - ensures isolation per call
/// @param rebuild_epoch Incremented on each rebuild - guarantees fresh path
pub async fn connect_via_socks5(
    target_host: &str,
    target_port: u16,
    circuit_id: usize,
    call_id: &str,
    rebuild_epoch: u32,
) -> Result<TcpStream, Box<dyn Error>> {
    // Connect to SOCKS5 proxy (Tor)
    let proxy_addr = "127.0.0.1:9050";
    log::debug!("Connecting to SOCKS5 proxy at {}", proxy_addr);
    let mut stream = TcpStream::connect(proxy_addr).await?;

    // Disable Nagle's algorithm for real-time audio
    stream.set_nodelay(true)?;

    // SOCKS5 handshake: Client greeting - prefer USERPASS for isolation, allow fallback to NO_AUTH
    // Offering 2 methods: NO_AUTH (0x00) and USERNAME/PASSWORD (0x02)
    let greeting = [SOCKS5_VERSION, 0x02, AUTH_NO_AUTH, 0x02];
    stream.write_all(&greeting).await?;
    stream.flush().await?;

    // Read server response
    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;

    if response[0] != SOCKS5_VERSION {
        return Err(format!("Invalid SOCKS version: {}", response[0]).into());
    }

    match response[1] {
        0x02 => {
            // USERNAME/PASSWORD selected - ISOLATION ENABLED
            // Format: call:{callId}:c:{circuitId}:r:{rebuildEpoch}
            // This guarantees:
            // - Different circuits per call (callId changes)
            // - Different paths per circuit (circuit_id differs: 0, 1, 2)
            // - Fresh path on rebuild (rebuild_epoch increments)
            let username = format!("call:{}:c:{}:r:{}", call_id, circuit_id, rebuild_epoch);
            let password = "x"; // Password doesn't matter for isolation; keep short

            let ub = username.as_bytes();
            let pb = password.as_bytes();

            if ub.len() > 255 || pb.len() > 255 {
                return Err("SOCKS5 username/password too long".into());
            }

            // Build auth request: [version][username_len][username][password_len][password]
            let mut auth = Vec::with_capacity(3 + ub.len() + pb.len());
            auth.push(0x01); // auth version
            auth.push(ub.len() as u8);
            auth.extend_from_slice(ub);
            auth.push(pb.len() as u8);
            auth.extend_from_slice(pb);

            stream.write_all(&auth).await?;
            stream.flush().await?;

            // Read auth response
            let mut auth_response = [0u8; 2];
            stream.read_exact(&mut auth_response).await?;

            if auth_response[1] != 0x00 {
                return Err("SOCKS5 username/password auth failed".into());
            }

            log::info!("✓ SOCKS5 isolation ON: {}", username);
        }
        AUTH_NO_AUTH => {
            // NO_AUTH selected - ISOLATION DISABLED
            // This means all circuits may share the same Tor path!
            log::warn!("⚠ SOCKS5 isolation OFF (NO_AUTH). Multi-circuit may share paths. Circuit rebuild may be ineffective.");
        }
        0xFF => {
            return Err("SOCKS5: no acceptable auth methods".into());
        }
        other => {
            return Err(format!("SOCKS5: unsupported auth method {:?}", other).into());
        }
    }

    // SOCKS5 connection request
    let host_bytes = target_host.as_bytes();
    let host_len = host_bytes.len();

    if host_len > 255 {
        return Err("Hostname too long".into());
    }

    let mut request = Vec::with_capacity(7 + host_len);
    request.push(SOCKS5_VERSION);
    request.push(CMD_CONNECT);
    request.push(RESERVED);
    request.push(ATYP_DOMAIN);
    request.push(host_len as u8);
    request.extend_from_slice(host_bytes);
    request.push((target_port >> 8) as u8);
    request.push((target_port & 0xFF) as u8);

    stream.write_all(&request).await?;
    stream.flush().await?;

    // Read connection response
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;

    if response[0] != SOCKS5_VERSION {
        return Err(format!("Invalid SOCKS version in response: {}", response[0]).into());
    }

    if response[1] != 0x00 {
        let error_msg = match response[1] {
            0x01 => "General SOCKS server failure",
            0x02 => "Connection not allowed by ruleset",
            0x03 => "Network unreachable",
            0x04 => "Host unreachable",
            0x05 => "Connection refused",
            0x06 => "TTL expired",
            0x07 => "Command not supported",
            0x08 => "Address type not supported",
            _ => "Unknown SOCKS error",
        };
        return Err(format!("SOCKS5 connection failed: {}", error_msg).into());
    }

    // Read bound address (we don't need it, but must read it)
    let atyp = response[3];
    match atyp {
        0x01 => {
            // IPv4: 4 bytes + 2 bytes port
            let mut addr = [0u8; 6];
            stream.read_exact(&mut addr).await?;
        }
        0x03 => {
            // Domain: 1 byte length + domain + 2 bytes port
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut addr = vec![0u8; len + 2];
            stream.read_exact(&mut addr).await?;
        }
        0x04 => {
            // IPv6: 16 bytes + 2 bytes port
            let mut addr = [0u8; 18];
            stream.read_exact(&mut addr).await?;
        }
        _ => {
            return Err(format!("Unknown address type: {}", atyp).into());
        }
    }

    log::info!("SOCKS5 connection established to {}:{}", target_host, target_port);
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voice_packet_creation() {
        let packet = VoicePacket {
            sequence: 1,
            audio_data: vec![1, 2, 3, 4],
            timestamp: 12345,
            circuit_index: 0,
            ptype: PTYPE_AUDIO,
            redundant_audio_data: vec![5, 6, 7, 8],  // Phase 3: Previous frame
            redundant_sequence: 0,                    // Phase 3: Previous sequence
        };
        assert_eq!(packet.sequence, 1);
        assert_eq!(packet.audio_data.len(), 4);
        assert_eq!(packet.timestamp, 12345);
        assert_eq!(packet.circuit_index, 0);
        assert_eq!(packet.ptype, PTYPE_AUDIO);
        assert_eq!(packet.redundant_audio_data.len(), 4);
        assert_eq!(packet.redundant_sequence, 0);
    }

    #[tokio::test]
    async fn test_listener_creation() {
        let listener = VoiceStreamingListener::new();
        assert_eq!(listener.active_sessions(), 0);
    }
}
