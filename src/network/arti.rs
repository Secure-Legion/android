/// Arti (Rust Tor) in-process client — replaces C Tor subprocess + control port.
///
/// Architecture:
///   - `initialize_arti()` creates a bootstrapped `TorClient` (stored globally)
///   - `connect_to_onion()` replaces SOCKS5 handshake with direct `client.connect()`
///   - `create_onion_service()` replaces `ADD_ONION` control port command
///   - Bootstrap events are streamed (no polling, no control port)
///   - Incoming connections come from `RendRequest` stream (no TCP listener)

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::Mutex as StdMutex;

use arti_client::TorClient;
use arti_client::config::TorClientConfigBuilder;
use tor_rtcompat::PreferredRuntime;
use tor_config_path::CfgPath;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::{HsNickname, OnionServiceConfig, StreamRequest};
use tor_cell::relaycell::msg::Connected;
use tokio_util::sync::CancellationToken;
use futures::StreamExt;

use crate::network::tor::{
    BOOTSTRAP_STATUS, CIRCUIT_ESTABLISHED, LAST_CIRCUIT_ESTABLISHED_MS,
    MESSAGE_TX, VOICE_TX, ACK_TX, FRIEND_REQUEST_TX, TAP_TX,
    CONNECTION_ID_COUNTER,
    touch_hs_accept_heartbeat, reset_hs_heartbeats,
    MSG_TYPE_PING, MSG_TYPE_PONG, MSG_TYPE_TEXT, MSG_TYPE_VOICE, MSG_TYPE_TAP,
    MSG_TYPE_DELIVERY_CONFIRMATION, MSG_TYPE_FRIEND_REQUEST, MSG_TYPE_FRIEND_REQUEST_ACCEPTED,
    MSG_TYPE_IMAGE, MSG_TYPE_PAYMENT_REQUEST, MSG_TYPE_PAYMENT_SENT, MSG_TYPE_PAYMENT_ACCEPTED,
    MSG_TYPE_CALL_SIGNALING, MSG_TYPE_STICKER, MSG_TYPE_PROFILE_UPDATE, MSG_TYPE_REACTION,
    MSG_TYPE_CRDT_OPS, MSG_TYPE_SYNC_REQUEST, MSG_TYPE_SYNC_CHUNK,
    MSG_TYPE_ROUTING_UPDATE, MSG_TYPE_ROUTING_REQUEST,
};
use crate::util::lock_recover;

use once_cell::sync::OnceCell;

// ───── Global Arti State ─────

/// The in-process Arti TorClient — replaces C Tor subprocess entirely.
/// Set once by `initialize_arti()`, read by all connect/HS operations.
static ARTI_CLIENT: OnceCell<Arc<TorClient<PreferredRuntime>>> = OnceCell::new();

/// Stored tokio runtime handle — captured during initialize_arti() (which runs inside
/// GLOBAL_RUNTIME.block_on()). Used by sync JNI functions that need to spawn async tasks
/// without being inside a tokio runtime context.
static RUNTIME_HANDLE: OnceCell<tokio::runtime::Handle> = OnceCell::new();

/// CancellationToken for the onion service acceptor task.
static HS_ACCEPTOR_CANCEL: StdMutex<Option<CancellationToken>> = StdMutex::new(None);

/// CancellationToken for the bootstrap listener task.
static BOOTSTRAP_LISTENER_CANCEL: StdMutex<Option<CancellationToken>> = StdMutex::new(None);

/// The .onion address of the currently running onion service.
static ONION_ADDRESS: StdMutex<Option<String>> = StdMutex::new(None);

/// Handle to the running onion service — dropping this stops the service.
static RUNNING_HS: StdMutex<Option<Arc<tor_hsservice::RunningOnionService>>> = StdMutex::new(None);

/// Stored RendRequest stream from create_onion_service(), consumed by start_arti_listener().
/// We box the stream so we can store it in a global (the concrete type is opaque `impl Stream`).
static REND_REQUEST_STREAM: StdMutex<Option<Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin>>> = StdMutex::new(None);

/// Handle to the running voice onion service.
static RUNNING_VOICE_HS: StdMutex<Option<Arc<tor_hsservice::RunningOnionService>>> = StdMutex::new(None);

/// The .onion address of the voice onion service.
static VOICE_ONION_ADDRESS: StdMutex<Option<String>> = StdMutex::new(None);

// ───── Friend Request Onion Service State ─────

/// Handle to the running friend-request onion service — separate .onion from messaging.
static RUNNING_FR_HS: StdMutex<Option<Arc<tor_hsservice::RunningOnionService>>> = StdMutex::new(None);

/// The .onion address of the friend-request onion service (public/discoverable).
static FR_ONION_ADDRESS: StdMutex<Option<String>> = StdMutex::new(None);

/// RendRequest stream for friend-request HS, consumed by start_fr_listener().
static FR_REND_REQUEST_STREAM: StdMutex<Option<Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin>>> = StdMutex::new(None);

/// CancellationToken for the friend-request HS acceptor task.
static FR_ACCEPTOR_CANCEL: StdMutex<Option<CancellationToken>> = StdMutex::new(None);

// ───── Initialization ─────

/// Spawn an async task on the stored runtime handle.
/// Falls back to tokio::spawn if already inside a runtime context.
fn runtime_spawn<F>(future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    // Try current runtime first (works when called from block_on or another spawn)
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return handle.spawn(future);
    }
    // Fall back to stored handle (for JNI calls from non-tokio threads)
    RUNTIME_HANDLE
        .get()
        .expect("Runtime not initialized — call initialize_arti first")
        .spawn(future)
}

/// Initialize Arti and bootstrap to the Tor network.
///
/// This replaces:
///   1. TorService starting C Tor subprocess
///   2. Connecting to Unix domain socket control port
///   3. Sending AUTHENTICATE command
///   4. Polling GETINFO status/bootstrap-phase
///
/// After this returns, the client is fully bootstrapped and ready for connections.
pub async fn initialize_arti(data_dir: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if ARTI_CLIENT.get().is_some() {
        log::info!("Arti already initialized, skipping");
        return Ok(());
    }

    log::info!("Initializing Arti (in-process Tor)...");
    log::info!("Data directory: {}", data_dir);

    // Capture the tokio runtime handle for later use by sync JNI functions.
    // This runs inside GLOBAL_RUNTIME.block_on(), so Handle::current() is valid.
    if RUNTIME_HANDLE.get().is_none() {
        let _ = RUNTIME_HANDLE.set(tokio::runtime::Handle::current());
    }

    let state_dir = format!("{}/arti/state", data_dir);
    let cache_dir = format!("{}/arti/cache", data_dir);

    // Ensure directories exist (including keystore)
    let keystore_dir = format!("{}/keystore", state_dir);
    std::fs::create_dir_all(&state_dir)?;
    std::fs::create_dir_all(&cache_dir)?;
    std::fs::create_dir_all(&keystore_dir)?;

    // Android file permissions don't match Unix expectations — disable fs-mistrust checks.
    // This is safe because Android's app sandbox enforces data isolation.
    // Belt-and-suspenders: set BOTH env vars (tor-config's and fs-mistrust's own).
    std::env::set_var("ARTI_FS_DISABLE_PERMISSION_CHECKS", "1");
    std::env::set_var("FS_MISTRUST_DISABLE_PERMISSIONS_CHECKS", "1");

    let mut config_builder = TorClientConfigBuilder::default();
    config_builder.storage().state_dir(CfgPath::new_literal(std::path::PathBuf::from(&state_dir)));
    config_builder.storage().cache_dir(CfgPath::new_literal(std::path::PathBuf::from(&cache_dir)));

    // Explicitly disable permission checks via builder API — most reliable on Android.
    // The env vars above are fallbacks; this direct call bypasses env var timing issues.
    config_builder.storage().permissions().dangerously_trust_everyone();

    let config = config_builder.build()?;

    // Create client without blocking on bootstrap
    BOOTSTRAP_STATUS.store(5, Ordering::SeqCst);
    log::info!("Creating Arti client (unbootstrapped)...");

    let client = TorClient::builder()
        .config(config)
        .bootstrap_behavior(arti_client::BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .map_err(|e| {
            log::error!("Arti client creation failed: {}", e);
            BOOTSTRAP_STATUS.store(0, Ordering::SeqCst);
            format!("Arti client creation failed: {}", e)
        })?;

    let client_arc = Arc::new(client);

    // Store client early so is_arti_ready() can check BOOTSTRAP_STATUS separately
    let _ = ARTI_CLIENT.set(client_arc.clone());

    // Spawn progress poller — ramps up smoothly while bootstrap runs
    let progress_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let progress_done_clone = progress_done.clone();
    runtime_spawn(async move {
        // Synthetic progress: 5 → 10 → 20 → 30 → 45 → 60 → 75 → 85 → 90 → 95
        // Each step ~3s, total ~30s ramp to 95%. Real bootstrap sets 100 when done.
        let steps = [10u32, 20, 30, 45, 60, 75, 85, 90, 95];
        for &pct in &steps {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            if progress_done_clone.load(Ordering::SeqCst) {
                break;
            }
            let current = BOOTSTRAP_STATUS.load(Ordering::SeqCst);
            if current < 100 && current < pct {
                BOOTSTRAP_STATUS.store(pct, Ordering::SeqCst);
                log::info!("Arti bootstrap progress: {}%", pct);
            }
        }
    });

    // Actually bootstrap (downloads consensus, builds circuits)
    log::info!("Starting Arti bootstrap...");
    client_arc.bootstrap().await.map_err(|e| {
        log::error!("Arti bootstrap failed: {}", e);
        progress_done.store(true, Ordering::SeqCst);
        BOOTSTRAP_STATUS.store(0, Ordering::SeqCst);
        format!("Arti bootstrap failed: {}", e)
    })?;

    // Bootstrap complete — stop progress poller and set final values
    progress_done.store(true, Ordering::SeqCst);
    BOOTSTRAP_STATUS.store(100, Ordering::SeqCst);
    CIRCUIT_ESTABLISHED.store(1, Ordering::SeqCst);
    LAST_CIRCUIT_ESTABLISHED_MS.store(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        Ordering::SeqCst,
    );

    log::info!("Arti bootstrapped successfully");

    Ok(())
}

/// Get the Arti client, if initialized.
pub fn get_arti_client() -> Option<Arc<TorClient<PreferredRuntime>>> {
    ARTI_CLIENT.get().cloned()
}

/// Check if Arti is initialized and bootstrapped.
pub fn is_arti_ready() -> bool {
    ARTI_CLIENT.get().is_some() && BOOTSTRAP_STATUS.load(Ordering::SeqCst) >= 100
}

// ───── Bootstrap Event Listener ─────

/// Start bootstrap event listener.
///
/// With Arti, bootstrap is handled by `create_bootstrapped()` which blocks until done.
/// This function exists for compatibility with the JNI API — it starts a background
/// task that monitors the Arti client's readiness and updates the atomics.
///
/// Replaces: `start_bootstrap_event_listener()` which connected to C Tor's control port,
/// sent `SETEVENTS STATUS_CLIENT`, and parsed 650 event lines.
pub fn start_bootstrap_listener() {
    use std::sync::atomic::AtomicBool;
    static RUNNING: AtomicBool = AtomicBool::new(false);

    if RUNNING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        log::info!("Bootstrap listener already running");
        return;
    }

    let cancel = CancellationToken::new();
    {
        let mut guard = lock_recover(&BOOTSTRAP_LISTENER_CANCEL);
        *guard = Some(cancel.clone());
    }

    std::thread::spawn(move || {
        log::info!("Arti bootstrap listener thread started");

        loop {
            if cancel.is_cancelled() {
                log::info!("Bootstrap listener: shutdown signal received");
                break;
            }

            // If Arti client exists, we're bootstrapped
            if ARTI_CLIENT.get().is_some() {
                BOOTSTRAP_STATUS.store(100, Ordering::SeqCst);
                CIRCUIT_ESTABLISHED.store(1, Ordering::SeqCst);

                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                LAST_CIRCUIT_ESTABLISHED_MS.store(now_ms, Ordering::SeqCst);
            }

            // Sleep 2s between checks (vs C Tor's 1s poll)
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        RUNNING.store(false, Ordering::SeqCst);
        log::info!("Arti bootstrap listener thread exited");
    });
}

/// Stop the bootstrap listener.
pub fn stop_bootstrap_listener() {
    let cancel = {
        let mut guard = lock_recover(&BOOTSTRAP_LISTENER_CANCEL);
        guard.take()
    };
    if let Some(c) = cancel {
        c.cancel();
        log::info!("Bootstrap listener stop signaled");
    }
}

// ───── Outbound Connections ─────

/// Connect to a .onion address via Arti.
///
/// Replaces: `connect_to_onion()` which did SOCKS5 handshake to 127.0.0.1:9050.
/// Now uses `client.connect()` directly — no proxy, no handshake, no localhost TCP.
///
/// Returns a `TorConnection` with a `TcpStream`-compatible async stream.
/// Note: Arti's `DataStream` implements AsyncRead + AsyncWrite.
/// We convert it to work with the existing TorConnection struct by wrapping in a
/// tokio task that bridges Arti's DataStream to a local TCP socket pair.
pub async fn arti_connect_to_onion(
    onion_address: &str,
    port: u16,
) -> Result<ArtiStream, Box<dyn Error + Send + Sync>> {
    let client = ARTI_CLIENT.get().ok_or("Arti not initialized")?;

    log::info!("Arti: connecting to {}:{}", onion_address, port);

    let stream = client.connect((onion_address, port)).await.map_err(|e| {
        log::error!("Arti connect to {}:{} failed: {}", onion_address, port, e);
        format!("Arti connect failed: {}", e)
    })?;

    log::info!("Arti: connected to {}:{}", onion_address, port);

    Ok(ArtiStream {
        stream,
        onion_address: onion_address.to_string(),
        port,
    })
}

/// Arti stream wrapper — replaces TorConnection (which held a TcpStream from SOCKS5).
/// Implements the same read/write pattern used by sendPing/sendMessage.
pub struct ArtiStream {
    pub stream: arti_client::DataStream,
    pub onion_address: String,
    pub port: u16,
}

impl ArtiStream {
    /// Write a length-prefixed message (same wire format as existing protocol).
    pub async fn write_message(&mut self, data: &[u8]) -> Result<(), Box<dyn Error + Send + Sync>> {
        use futures::io::AsyncWriteExt as FuturesWriteExt;

        let len = data.len() as u32;
        let len_bytes = len.to_be_bytes();

        self.stream.write_all(&len_bytes).await?;
        self.stream.write_all(data).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Read a length-prefixed message (same wire format as existing protocol).
    pub async fn read_message(&mut self) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        use futures::io::AsyncReadExt as FuturesReadExt;

        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;

        if total_len > 10_000_000 {
            return Err("Message too large (>10MB)".into());
        }

        let mut buf = vec![0u8; total_len];
        self.stream.read_exact(&mut buf).await?;

        Ok(buf)
    }
}

// ───── Onion Service Hosting ─────

/// Create and launch an onion service using Arti with our Ed25519 key.
///
/// Replaces: `ADD_ONION ED25519-V3:<key> Port=9150,127.0.0.1:8080` via control port.
///
/// Flow:
///   1. Convert 32-byte Ed25519 seed → HsIdKeypair (Arti's onion service identity key)
///   2. Build OnionServiceConfig with nickname "securelegion"
///   3. Call launch_onion_service_with_hsid() — registers key + starts publishing descriptors
///   4. Store RendRequest stream for later use by start_arti_listener()
///
/// The acceptor is NOT spawned here — call start_arti_listener() after this to begin
/// accepting incoming connections with proper channels.
///
/// Returns the .onion address.
pub async fn create_onion_service(
    ed25519_seed: &[u8; 32],
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let client = ARTI_CLIENT.get().ok_or("Arti not initialized")?;

    // Compute expected .onion address from seed (for verification)
    let expected_addr = super::tor::compute_onion_address_from_ed25519_seed(ed25519_seed);
    log::info!("Arti: creating onion service, expected address: {}", expected_addr);

    // Step 1: Convert Ed25519 seed → HsIdKeypair
    // Arti uses ExpandedKeypair (SHA-512 expansion of the 32-byte seed)
    let ed_keypair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(ed25519_seed);
    let expanded = tor_llcrypto::pk::ed25519::ExpandedKeypair::from(&ed_keypair);
    let hsid_keypair = HsIdKeypair::from(expanded);
    log::info!("Arti: HsIdKeypair created from Ed25519 seed");

    // Step 2: Build OnionServiceConfig with deterministic nickname tied to onion.
    // This prevents stale key alias collisions across identity changes.
    let nickname_str = format!("sl-msg-{}", &expected_addr[..12]);
    let nickname = HsNickname::new(nickname_str.clone()).map_err(|e| {
        format!("Invalid HS nickname: {}", e)
    })?;
    let config = OnionServiceConfig::builder()
        .nickname(nickname)
        .build()
        .map_err(|e| format!("OnionServiceConfig build failed: {}", e))?;

    // Step 3: Launch with our key — try insert first, fall back if key already exists.
    // On service restart, the key persists in Arti's native keystore, so the insert
    // fails with KeyAlreadyExists. In that case, launch_onion_service reads it back.
    // We box the RendRequest stream because the two launch functions return different
    // opaque `impl Stream` types.
    let (running_service, rend_requests): (Arc<tor_hsservice::RunningOnionService>, Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin>) =
        match client.launch_onion_service_with_hsid(config, hsid_keypair) {
            Ok(Some((svc, stream))) => (svc, Box::new(stream)),
            Ok(None) => return Err("Onion service was disabled in config".into()),
            Err(e) => {
                log::warn!("launch_onion_service_with_hsid failed ({}), key may already exist — retrying", e);
                let nickname2 = HsNickname::new(nickname_str).map_err(|e| format!("Invalid HS nickname: {}", e))?;
                let config2 = OnionServiceConfig::builder()
                    .nickname(nickname2)
                    .build()
                    .map_err(|e| format!("OnionServiceConfig rebuild failed: {}", e))?;
                match client.launch_onion_service(config2)
                    .map_err(|e| {
                        log::error!("launch_onion_service also failed: {:?}", e);
                        format!("launch_onion_service failed: {}", e)
                    })? {
                    Some((svc, stream)) => (svc, Box::new(stream)),
                    None => return Err("Onion service was disabled in config".into()),
                }
            }
        };

    log::info!("Arti: onion service launched for {}", expected_addr);

    // DIAGNOSTIC: Verify the key is in the keystore and Arti can publish
    if running_service.onion_address().is_some() {
        log::info!("Arti: messaging HS key VERIFIED in keystore — descriptor should publish for {}", expected_addr);
    } else {
        log::error!("Arti: messaging HS onion_address() returned None — KEY NOT IN KEYSTORE, descriptor WILL NOT publish!");
    }

    // Log initial HS status
    let initial_status = running_service.status();
    log::info!("Arti: messaging HS initial status: {:?}", initial_status);

    // Spawn background task to monitor HS status until it reaches Running
    let svc_clone = Arc::clone(&running_service);
    let addr_clone = expected_addr.clone();
    runtime_spawn(async move {
        let mut events = svc_clone.status_events();
        loop {
            let status = svc_clone.status();
            log::info!("Arti: messaging HS status update: {:?} for {}", status, addr_clone);
            // Wait for next status change (or timeout after 60s)
            tokio::select! {
                _ = events.next() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        }
    });

    // Store the running service handle (dropping it would stop the service)
    {
        let mut guard = lock_recover(&RUNNING_HS);
        *guard = Some(running_service);
    }
    {
        let mut guard = lock_recover(&ONION_ADDRESS);
        *guard = Some(expected_addr.clone());
    }

    // Step 4: Store the RendRequest stream for start_arti_listener() to consume
    {
        let mut guard = lock_recover(&REND_REQUEST_STREAM);
        *guard = Some(Box::new(rend_requests));
    }

    log::info!("Arti: onion service created at {} (call start_arti_listener to accept connections)", expected_addr);

    Ok(expected_addr)
}

/// Start the Arti onion service listener — creates channels, spawns acceptor.
///
/// Must be called AFTER create_onion_service(). This consumes the stored RendRequest
/// stream and starts routing incoming connections to PING/PONG/MESSAGE/etc channels.
///
/// Returns (ping_rx, pong_rx) — same interface as TorManager::start_listener().
pub fn start_arti_listener() -> Result<(
    tokio::sync::mpsc::UnboundedReceiver<(u64, Vec<u8>)>,
    tokio::sync::mpsc::UnboundedReceiver<(u64, Vec<u8>)>,
), Box<dyn Error + Send + Sync>> {
    // Take the stored RendRequest stream
    let rend_stream = {
        let mut guard = lock_recover(&REND_REQUEST_STREAM);
        guard.take().ok_or("No RendRequest stream — call create_onion_service first")?
    };

    // Create PING/PONG channels (same as TorManager::start_listener)
    let (ping_tx, ping_rx) = tokio::sync::mpsc::unbounded_channel();
    let (pong_tx, pong_rx) = tokio::sync::mpsc::unbounded_channel();

    // Reset HS heartbeats
    reset_hs_heartbeats();

    // Spawn the acceptor with proper channels
    spawn_hs_acceptor(rend_stream, ping_tx, pong_tx);

    log::info!("Arti: listener started with PING/PONG channels");

    Ok((ping_rx, pong_rx))
}

/// Spawn the HS acceptor task that processes incoming connections.
///
/// Uses `handle_rend_requests()` to convert RendRequests → StreamRequests,
/// then accepts each StreamRequest to get a DataStream for reading wire messages.
fn spawn_hs_acceptor<S>(
    rend_requests: S,
    ping_tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
    pong_tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
)
where
    S: futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin + 'static,
{
    // Cancel any existing acceptor
    {
        let mut guard = lock_recover(&HS_ACCEPTOR_CANCEL);
        if let Some(old) = guard.take() {
            old.cancel();
        }
    }

    let cancel = CancellationToken::new();
    {
        let mut guard = lock_recover(&HS_ACCEPTOR_CANCEL);
        *guard = Some(cancel.clone());
    }

    runtime_spawn(async move {
        log::info!("Arti: HS acceptor task started");

        // Convert RendRequest stream → StreamRequest stream
        // handle_rend_requests automatically accepts all rendezvous handshakes
        let mut stream_requests = tor_hsservice::handle_rend_requests(rend_requests);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    log::info!("Arti: HS acceptor cancelled");
                    break;
                }
                maybe_req = stream_requests.next() => {
                    match maybe_req {
                        Some(stream_req) => {
                            let conn_id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
                            let ptx = ping_tx.clone();
                            let potx = pong_tx.clone();
                            runtime_spawn(async move {
                                if let Err(e) = accept_and_handle(stream_req, conn_id, ptx, potx).await {
                                    log::error!("Arti: incoming conn {} error: {}", conn_id, e);
                                }
                            });
                        }
                        None => {
                            log::warn!("Arti: RendRequest stream ended");
                            break;
                        }
                    }
                }
            }
        }

        log::info!("Arti: HS acceptor task exited");
    });
}

/// Accept a StreamRequest and handle the resulting DataStream.
async fn accept_and_handle(
    stream_req: StreamRequest,
    conn_id: u64,
    ping_tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
    pong_tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    // Accept the stream request — sends CONNECTED back to the client
    let data_stream = stream_req.accept(Connected::new_empty()).await.map_err(|e| {
        format!("StreamRequest accept failed: {}", e)
    })?;

    touch_hs_accept_heartbeat();

    // Hand off to the existing message router
    handle_arti_incoming(data_stream, conn_id, ping_tx, pong_tx).await
}

/// Handle an incoming connection from an Arti onion service stream.
///
/// This is the Arti equivalent of `TorManager::handle_incoming_connection()`.
/// Same wire protocol, same routing, same channels — just different stream type.
///
/// Flow: Read length prefix → read payload → validate type byte → route to channel.
async fn handle_arti_incoming(
    mut stream: arti_client::DataStream,
    conn_id: u64,
    ping_tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
    pong_tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    use futures::io::AsyncReadExt as FuturesReadExt;

    // Read length prefix (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;

    if total_len > 10_000_000 {
        return Err("Message too large (>10MB)".into());
    }

    // Read full buffer including type byte
    let mut buf = vec![0u8; total_len];
    stream.read_exact(&mut buf).await?;

    if buf.is_empty() {
        return Err("Empty message".into());
    }

    let msg_type = buf[0];

    // Validate message type (same check as tor.rs handle_incoming_connection)
    match msg_type {
        MSG_TYPE_PING | MSG_TYPE_PONG | MSG_TYPE_TEXT | MSG_TYPE_VOICE |
        MSG_TYPE_TAP | MSG_TYPE_DELIVERY_CONFIRMATION |
        MSG_TYPE_FRIEND_REQUEST | MSG_TYPE_FRIEND_REQUEST_ACCEPTED |
        MSG_TYPE_IMAGE | MSG_TYPE_PAYMENT_REQUEST | MSG_TYPE_PAYMENT_SENT |
        MSG_TYPE_PAYMENT_ACCEPTED | MSG_TYPE_CALL_SIGNALING |
        MSG_TYPE_STICKER | MSG_TYPE_PROFILE_UPDATE | MSG_TYPE_REACTION |
        MSG_TYPE_CRDT_OPS | MSG_TYPE_SYNC_REQUEST | MSG_TYPE_SYNC_CHUNK |
        MSG_TYPE_ROUTING_UPDATE | MSG_TYPE_ROUTING_REQUEST => {}
        _ => {
            log::error!("ARTI INVALID_MSG_TYPE_DROP: 0x{:02x}", msg_type);
            return Err(format!("Invalid message type: 0x{:02x}", msg_type).into());
        }
    }

    // Minimum length check (same as tor.rs)
    let is_signed_type = !matches!(
        msg_type,
        MSG_TYPE_PING | MSG_TYPE_PONG | MSG_TYPE_TAP |
        MSG_TYPE_DELIVERY_CONFIRMATION |
        MSG_TYPE_FRIEND_REQUEST | MSG_TYPE_FRIEND_REQUEST_ACCEPTED
    );
    let sig_len = if is_signed_type { 64 } else { 0 };
    let min_wire_len: usize = match msg_type {
        MSG_TYPE_CRDT_OPS | MSG_TYPE_SYNC_REQUEST | MSG_TYPE_SYNC_CHUNK |
        MSG_TYPE_ROUTING_UPDATE | MSG_TYPE_ROUTING_REQUEST => 1 + 32 + 32 + sig_len,
        _ => 1 + 32 + 16 + sig_len,
    };
    if buf.len() < min_wire_len {
        log::error!("ARTI WIRE_TOO_SHORT_DROP: type=0x{:02x}, len={} (min={})", msg_type, buf.len(), min_wire_len);
        return Err(format!("Wire message too short: {} bytes (min {})", buf.len(), min_wire_len).into());
    }

    // Valid frame — touch heartbeat
    touch_hs_accept_heartbeat();

    log::info!("ARTI INCOMING conn={} type=0x{:02x} len={}", conn_id, msg_type, buf.len());

    // Route based on message type (same routing as tor.rs handle_incoming_connection)
    // NOTE: For PING/MESSAGE types that need PendingConnection, we cannot store the
    // Arti DataStream in PendingConnection (which expects TcpStream). For Arti,
    // we'll need to handle Pong responses differently — this is addressed in Phase 3.
    match msg_type {
        MSG_TYPE_PING => {
            log::info!("ARTI → PING handler");
            // NOTE: Cannot store DataStream in PendingConnection (expects TcpStream).
            // For Arti, Pong response will use a new outbound connection.
            if let Err(_) = ping_tx.send((conn_id, buf)) {
                log::error!("ARTI ROUTER_DROP: PING_TX send failed");
            }
        }
        MSG_TYPE_PONG => {
            log::info!("ARTI → PONG handler");
            if let Err(_) = pong_tx.send((conn_id, buf)) {
                log::error!("ARTI ROUTER_DROP: PONG_TX send failed");
            }
        }
        MSG_TYPE_TEXT | MSG_TYPE_VOICE | MSG_TYPE_IMAGE |
        MSG_TYPE_PAYMENT_REQUEST | MSG_TYPE_PAYMENT_SENT | MSG_TYPE_PAYMENT_ACCEPTED |
        MSG_TYPE_STICKER | MSG_TYPE_PROFILE_UPDATE | MSG_TYPE_REACTION |
        MSG_TYPE_CRDT_OPS | MSG_TYPE_SYNC_REQUEST | MSG_TYPE_SYNC_CHUNK |
        MSG_TYPE_ROUTING_UPDATE | MSG_TYPE_ROUTING_REQUEST => {
            log::info!("ARTI → MESSAGE handler (type=0x{:02x})", msg_type);
            if let Some(message_tx) = MESSAGE_TX.load_full() {
                let tx_lock = lock_recover(&message_tx);
                if let Err(e) = tx_lock.send((conn_id, buf)) {
                    log::error!("ARTI: Failed to send to MESSAGE channel: {}", e);
                } else {
                    crate::ffi::android::RX_MESSAGE_ACCEPT_COUNT.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                log::warn!("ARTI: MESSAGE channel not initialized");
                crate::ffi::android::RX_MESSAGE_TX_DROP_COUNT.fetch_add(1, Ordering::Relaxed);
            }
        }
        MSG_TYPE_CALL_SIGNALING => {
            log::info!("ARTI → VOICE handler");
            if let Some(voice_tx) = VOICE_TX.load_full() {
                let tx_lock = lock_recover(&voice_tx);
                if let Err(e) = tx_lock.send((conn_id, buf)) {
                    log::error!("ARTI: Failed to send to VOICE channel: {}", e);
                }
            } else {
                log::warn!("ARTI: VOICE channel not initialized");
            }
        }
        MSG_TYPE_TAP => {
            log::info!("ARTI → TAP handler");
            if let Some(tap_tx) = TAP_TX.load_full() {
                let tx_lock = lock_recover(&tap_tx);
                if let Err(e) = tx_lock.send(buf) {
                    log::error!("ARTI: Failed to send TAP: {}", e);
                }
            } else {
                log::warn!("ARTI: TAP channel not initialized, dropping TAP");
            }
        }
        MSG_TYPE_DELIVERY_CONFIRMATION => {
            log::info!("ARTI → ACK handler");
            if let Some(ack_tx) = ACK_TX.load_full() {
                let tx_lock = lock_recover(&ack_tx);
                if let Err(e) = tx_lock.send((conn_id, buf)) {
                    log::error!("ARTI: Failed to send ACK: {}", e);
                }
            } else {
                log::error!("ARTI: ACK channel not initialized");
            }
        }
        MSG_TYPE_FRIEND_REQUEST | MSG_TYPE_FRIEND_REQUEST_ACCEPTED => {
            // STRICT PROTOCOL ISOLATION: FR frames MUST arrive on the FR onion, NOT messaging onion.
            // Hard reject — this is a security boundary violation.
            log::error!(
                "ARTI PROTOCOL_VIOLATION: conn={} type=0x{:02x} — FR frame REJECTED on messaging onion (must use FR onion)",
                conn_id, msg_type
            );
            return Err(format!(
                "Protocol violation: FR frame (0x{:02x}) rejected on messaging onion — use FR onion", msg_type
            ).into());
        }
        _ => {
            log::warn!("ARTI: Unknown type 0x{:02x}, routing to PING", msg_type);
            ping_tx.send((conn_id, buf)).ok();
        }
    }

    Ok(())
}

// ───── HTTP via Tor ─────

/// HTTP GET via Arti (replaces SOCKS5-based HTTP GET).
pub async fn http_get_via_arti(url: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    use futures::io::{AsyncReadExt as FuturesReadExt, AsyncWriteExt as FuturesWriteExt};

    let client = ARTI_CLIENT.get().ok_or("Arti not initialized")?;

    // Parse URL to extract host and path
    let (host, port, path, is_https) = parse_url(url)?;

    let connect_port = if is_https { port.unwrap_or(443) } else { port.unwrap_or(80) };

    let mut stream = client.connect((&*host, connect_port)).await.map_err(|e| {
        format!("Arti HTTP connect to {}:{} failed: {}", host, connect_port, e)
    })?;

    // Send HTTP GET request
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: SecureLegion/1.0\r\n\r\n",
        path, host
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    // Read response
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let response_str = String::from_utf8_lossy(&response).to_string();

    // Extract body (after \r\n\r\n)
    if let Some(pos) = response_str.find("\r\n\r\n") {
        Ok(response_str[pos + 4..].to_string())
    } else {
        Ok(response_str)
    }
}

/// HTTP POST via Arti (replaces SOCKS5-based HTTP POST).
pub async fn http_post_via_arti(url: &str, body: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    use futures::io::{AsyncReadExt as FuturesReadExt, AsyncWriteExt as FuturesWriteExt};

    let client = ARTI_CLIENT.get().ok_or("Arti not initialized")?;

    let (host, port, path, is_https) = parse_url(url)?;
    let connect_port = if is_https { port.unwrap_or(443) } else { port.unwrap_or(80) };

    let mut stream = client.connect((&*host, connect_port)).await.map_err(|e| {
        format!("Arti HTTP connect to {}:{} failed: {}", host, connect_port, e)
    })?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\nUser-Agent: SecureLegion/1.0\r\n\r\n{}",
        path, host, body.len(), body
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    let response_str = String::from_utf8_lossy(&response).to_string();

    if let Some(pos) = response_str.find("\r\n\r\n") {
        Ok(response_str[pos + 4..].to_string())
    } else {
        Ok(response_str)
    }
}

/// Send NEWNYM equivalent — create an isolated client for fresh circuits.
///
/// Replaces: `SIGNAL NEWNYM` via control port.
/// Arti doesn't have a direct NEWNYM equivalent, but `isolated_client()` creates
/// a new circuit isolation context, which achieves the same effect.
pub fn send_newnym() {
    if let Some(client) = ARTI_CLIENT.get() {
        // Cycle dormant mode to force Arti to drop existing circuits and rebuild fresh ones.
        // This is the Arti equivalent of C Tor's SIGNAL NEWNYM.
        log::info!("Arti: NEWNYM — cycling dormant mode to retire circuits");
        client.set_dormant(arti_client::DormantMode::Soft);
        client.set_dormant(arti_client::DormantMode::Normal);
        log::info!("Arti: NEWNYM complete — circuits will rebuild, HS will re-establish IPTs");
    } else {
        log::warn!("Arti: NEWNYM requested but client not initialized");
    }
}

/// Notify Arti that the network changed (e.g., WiFi → mobile, offline → online).
/// Cycles dormant mode to force dead circuit teardown and HS descriptor re-publication.
pub fn notify_network_changed() {
    if let Some(client) = ARTI_CLIENT.get() {
        log::info!("Arti: network change detected — cycling dormant mode to rebuild circuits + HS");
        client.set_dormant(arti_client::DormantMode::Soft);
        client.set_dormant(arti_client::DormantMode::Normal);
        log::info!("Arti: dormant cycle complete — Arti will rebuild circuits and re-publish HS descriptors");
    } else {
        log::warn!("Arti: network change notified but client not initialized");
    }
}

// ───── Accessors ─────

/// Get the .onion address of the currently running messaging onion service.
pub fn get_onion_address() -> Option<String> {
    lock_recover(&ONION_ADDRESS).clone()
}

/// Stop the Arti HS acceptor task.
pub fn stop_arti_listener() {
    let cancel = {
        let mut guard = lock_recover(&HS_ACCEPTOR_CANCEL);
        guard.take()
    };
    if let Some(c) = cancel {
        c.cancel();
        log::info!("Arti: HS acceptor cancelled");
    }
}

// ───── Voice Onion Service ─────

/// Create a voice onion service using the same Arti client but a different Ed25519 seed.
///
/// This replaces the C Tor voice daemon (SingleOnion mode on port 9052).
/// Voice HS uses the same 3-hop anonymity as messaging (no SingleOnion in Arti).
pub async fn create_voice_onion_service(
    ed25519_seed: &[u8; 32],
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let client = ARTI_CLIENT.get().ok_or("Arti not initialized")?;

    let expected_addr = super::tor::compute_onion_address_from_ed25519_seed(ed25519_seed);
    log::info!("Arti: creating voice onion service, expected address: {}", expected_addr);

    let ed_keypair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(ed25519_seed);
    let expanded = tor_llcrypto::pk::ed25519::ExpandedKeypair::from(&ed_keypair);
    let hsid_keypair = HsIdKeypair::from(expanded);

    let nickname_str = "securelegion-voice".to_string();
    let nickname = HsNickname::new(nickname_str.clone()).map_err(|e| {
        format!("Invalid voice HS nickname: {}", e)
    })?;
    let config = OnionServiceConfig::builder()
        .nickname(nickname)
        .build()
        .map_err(|e| format!("Voice OnionServiceConfig build failed: {}", e))?;

    let (running_service, _rend_requests): (Arc<tor_hsservice::RunningOnionService>, Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin>) =
        match client.launch_onion_service_with_hsid(config, hsid_keypair) {
            Ok(Some((svc, stream))) => (svc, Box::new(stream)),
            Ok(None) => return Err("Voice onion service was disabled in config".into()),
            Err(e) => {
                log::warn!("Voice launch_onion_service_with_hsid failed ({}), retrying", e);
                let nickname2 = HsNickname::new(nickname_str).map_err(|e| format!("Invalid voice HS nickname: {}", e))?;
                let config2 = OnionServiceConfig::builder()
                    .nickname(nickname2)
                    .build()
                    .map_err(|e| format!("Voice OnionServiceConfig rebuild failed: {}", e))?;
                match client.launch_onion_service(config2)
                    .map_err(|e| {
                        log::error!("Voice launch_onion_service also failed: {:?}", e);
                        format!("Voice launch_onion_service failed: {}", e)
                    })? {
                    Some((svc, stream)) => (svc, Box::new(stream)),
                    None => return Err("Voice onion service was disabled in config".into()),
                }
            }
        };

    log::info!("Arti: voice onion service launched for {}", expected_addr);

    {
        let mut guard = lock_recover(&RUNNING_VOICE_HS);
        *guard = Some(running_service);
    }
    {
        let mut guard = lock_recover(&VOICE_ONION_ADDRESS);
        *guard = Some(expected_addr.clone());
    }

    Ok(expected_addr)
}

// ───── Friend Request Onion Service ─────

/// Create and launch a friend-request onion service using a separate Ed25519 key.
///
/// This is the SECOND hosted .onion — distinct from the messaging HS.
/// The FR onion is public/discoverable and only accepts FRIEND_REQUEST / FR_ACCEPTED frames.
/// Protocol isolation is enforced: messaging frames are rejected on this HS.
pub async fn create_friend_request_onion_service(
    ed25519_seed: &[u8; 32],
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let client = ARTI_CLIENT.get().ok_or("Arti not initialized")?;

    let expected_addr = super::tor::compute_onion_address_from_ed25519_seed(ed25519_seed);
    log::info!("Arti: creating friend-request onion service, expected address: {}", expected_addr);

    let ed_keypair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(ed25519_seed);
    let expanded = tor_llcrypto::pk::ed25519::ExpandedKeypair::from(&ed_keypair);
    let hsid_keypair = HsIdKeypair::from(expanded);

    // Deterministic nickname tied to FR onion to avoid stale keystore alias/key mismatch.
    let nickname_str = format!("sl-fr-{}", &expected_addr[..12]);
    let nickname = HsNickname::new(nickname_str.clone()).map_err(|e| {
        format!("Invalid FR HS nickname: {}", e)
    })?;
    let config = OnionServiceConfig::builder()
        .nickname(nickname)
        .build()
        .map_err(|e| format!("FR OnionServiceConfig build failed: {}", e))?;

    // Try insert first, fall back if key already exists (service restart).
    let (running_service, rend_requests): (Arc<tor_hsservice::RunningOnionService>, Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin>) =
        match client.launch_onion_service_with_hsid(config, hsid_keypair) {
            Ok(Some((svc, stream))) => (svc, Box::new(stream)),
            Ok(None) => return Err("FR onion service was disabled in config".into()),
            Err(e) => {
                log::warn!("FR launch_onion_service_with_hsid failed ({}), retrying", e);
                let nickname2 = HsNickname::new(nickname_str).map_err(|e| format!("Invalid FR HS nickname: {}", e))?;
                let config2 = OnionServiceConfig::builder()
                    .nickname(nickname2)
                    .build()
                    .map_err(|e| format!("FR OnionServiceConfig rebuild failed: {}", e))?;
                match client.launch_onion_service(config2)
                    .map_err(|e| {
                        log::error!("FR launch_onion_service also failed: {:?}", e);
                        format!("FR launch_onion_service failed: {}", e)
                    })? {
                    Some((svc, stream)) => (svc, Box::new(stream)),
                    None => return Err("FR onion service was disabled in config".into()),
                }
            }
        };

    log::info!("Arti: friend-request onion service launched for {}", expected_addr);

    // DIAGNOSTIC: Verify the FR key is in the keystore
    if running_service.onion_address().is_some() {
        log::info!("Arti: FR HS key VERIFIED in keystore — descriptor should publish for {}", expected_addr);
    } else {
        log::error!("Arti: FR HS onion_address() returned None — KEY NOT IN KEYSTORE, descriptor WILL NOT publish!");
    }

    // Log initial FR HS status
    let fr_initial_status = running_service.status();
    log::info!("Arti: FR HS initial status: {:?}", fr_initial_status);

    // Spawn background task to monitor FR HS status
    let fr_svc_clone = Arc::clone(&running_service);
    let fr_addr_clone = expected_addr.clone();
    runtime_spawn(async move {
        let mut events = fr_svc_clone.status_events();
        loop {
            let status = fr_svc_clone.status();
            log::info!("Arti: FR HS status update: {:?} for {}", status, fr_addr_clone);
            tokio::select! {
                _ = events.next() => {}
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
            }
        }
    });

    {
        let mut guard = lock_recover(&RUNNING_FR_HS);
        *guard = Some(running_service);
    }
    {
        let mut guard = lock_recover(&FR_ONION_ADDRESS);
        *guard = Some(expected_addr.clone());
    }
    {
        let mut guard = lock_recover(&FR_REND_REQUEST_STREAM);
        *guard = Some(Box::new(rend_requests));
    }

    log::info!("Arti: FR onion service created at {} (call start_fr_listener to accept)", expected_addr);

    Ok(expected_addr)
}

/// Start the friend-request onion service listener.
///
/// Must be called AFTER create_friend_request_onion_service().
/// Only routes FRIEND_REQUEST and FRIEND_REQUEST_ACCEPTED frames.
/// All other message types are rejected (strict protocol isolation).
pub fn start_fr_listener() -> Result<(), Box<dyn Error + Send + Sync>> {
    let rend_stream = {
        let mut guard = lock_recover(&FR_REND_REQUEST_STREAM);
        guard.take().ok_or("No FR RendRequest stream — call create_friend_request_onion_service first")?
    };

    spawn_fr_acceptor(rend_stream);

    log::info!("Arti: friend-request listener started (FR/FR_ACCEPTED only)");

    Ok(())
}

/// Spawn the FR HS acceptor task — strict protocol isolation.
fn spawn_fr_acceptor<S>(rend_requests: S)
where
    S: futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin + 'static,
{
    // Cancel any existing FR acceptor
    {
        let mut guard = lock_recover(&FR_ACCEPTOR_CANCEL);
        if let Some(old) = guard.take() {
            old.cancel();
        }
    }

    let cancel = CancellationToken::new();
    {
        let mut guard = lock_recover(&FR_ACCEPTOR_CANCEL);
        *guard = Some(cancel.clone());
    }

    runtime_spawn(async move {
        log::info!("Arti: FR HS acceptor task started");

        let mut stream_requests = tor_hsservice::handle_rend_requests(rend_requests);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    log::info!("Arti: FR HS acceptor cancelled");
                    break;
                }
                maybe_req = stream_requests.next() => {
                    match maybe_req {
                        Some(stream_req) => {
                            let conn_id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::SeqCst) + 1;
                            runtime_spawn(async move {
                                if let Err(e) = accept_and_handle_fr(stream_req, conn_id).await {
                                    log::error!("Arti: FR incoming conn {} error: {}", conn_id, e);
                                }
                            });
                        }
                        None => {
                            log::warn!("Arti: FR RendRequest stream ended");
                            break;
                        }
                    }
                }
            }
        }

        log::info!("Arti: FR HS acceptor task exited");
    });
}

/// Accept a StreamRequest on the FR HS and enforce protocol isolation.
/// Only FRIEND_REQUEST (0x07) and FRIEND_REQUEST_ACCEPTED (0x08) are allowed.
async fn accept_and_handle_fr(
    stream_req: StreamRequest,
    conn_id: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut stream = stream_req.accept(Connected::new_empty()).await.map_err(|e| {
        format!("FR StreamRequest accept failed: {}", e)
    })?;

    touch_hs_accept_heartbeat();

    use futures::io::AsyncReadExt as FuturesReadExt;

    // Read length prefix (4 bytes, big-endian)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let total_len = u32::from_be_bytes(len_buf) as usize;

    if total_len > 10_000_000 {
        return Err("FR message too large (>10MB)".into());
    }

    let mut buf = vec![0u8; total_len];
    stream.read_exact(&mut buf).await?;

    if buf.is_empty() {
        return Err("Empty FR message".into());
    }

    let msg_type = buf[0];

    // STRICT PROTOCOL ISOLATION: Only FR frames allowed on the FR onion
    match msg_type {
        MSG_TYPE_FRIEND_REQUEST | MSG_TYPE_FRIEND_REQUEST_ACCEPTED => {
            log::info!("ARTI-FR INCOMING conn={} type=0x{:02x} len={}", conn_id, msg_type, buf.len());

            if let Some(friend_tx) = FRIEND_REQUEST_TX.load_full() {
                let tx_lock = lock_recover(&friend_tx);
                if let Err(e) = tx_lock.send(buf) {
                    log::error!("ARTI-FR: Failed to send to FRIEND_REQUEST channel: {}", e);
                }
            } else {
                log::warn!("ARTI-FR: Friend request channel not initialized");
            }
        }
        _ => {
            // HARD FAIL: Cross-protocol traffic on FR onion is a security violation
            log::error!(
                "ARTI-FR PROTOCOL_VIOLATION: conn={} type=0x{:02x} REJECTED — only FR/FR_ACCEPTED allowed on FR onion",
                conn_id, msg_type
            );
            return Err(format!(
                "Protocol violation: message type 0x{:02x} not allowed on friend-request onion", msg_type
            ).into());
        }
    }

    Ok(())
}

/// Get the .onion address of the friend-request onion service.
pub fn get_fr_onion_address() -> Option<String> {
    lock_recover(&FR_ONION_ADDRESS).clone()
}

/// Stop the FR HS acceptor task.
pub fn stop_fr_listener() {
    let cancel = {
        let mut guard = lock_recover(&FR_ACCEPTOR_CANCEL);
        guard.take()
    };
    if let Some(c) = cancel {
        c.cancel();
        log::info!("Arti: FR HS acceptor cancelled");
    }
}

// ───── Utilities ─────

/// Parse a URL into (host, optional_port, path, is_https).
fn parse_url(url: &str) -> Result<(String, Option<u16>, String, bool), Box<dyn Error + Send + Sync>> {
    let is_https = url.starts_with("https://");
    let url_no_scheme = if url.starts_with("https://") {
        &url[8..]
    } else if url.starts_with("http://") {
        &url[7..]
    } else {
        url
    };

    let (host_port, path) = match url_no_scheme.find('/') {
        Some(pos) => (&url_no_scheme[..pos], &url_no_scheme[pos..]),
        None => (url_no_scheme, "/"),
    };

    let (host, port) = match host_port.rfind(':') {
        Some(pos) => {
            let port_str = &host_port[pos + 1..];
            match port_str.parse::<u16>() {
                Ok(p) => (host_port[..pos].to_string(), Some(p)),
                Err(_) => (host_port.to_string(), None),
            }
        }
        None => (host_port.to_string(), None),
    };

    Ok((host, port, path.to_string(), is_https))
}
