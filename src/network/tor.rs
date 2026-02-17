/// Tor Network Manager (using Tor_Onion_Proxy_Library)
/// Connects to Tor via SOCKS5 proxy managed by OnionProxyManager
///
/// The Android OnionProxyManager handles Tor lifecycle, we just use SOCKS5

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use tokio::io::{AsyncWriteExt, AsyncReadExt, BufReader, AsyncBufReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};
use std::sync::Mutex as StdMutex;
use std::collections::HashMap;
use once_cell::sync::Lazy;

/// Global bootstrap status (0-100%) - updated by event listener
pub static BOOTSTRAP_STATUS: AtomicU32 = AtomicU32::new(0);

/// Circuit established status (0 = no circuits, 1 = circuits established)
/// Updated by event listener polling GETINFO status/circuit-established
pub static CIRCUIT_ESTABLISHED: AtomicU8 = AtomicU8::new(0);

/// Get bootstrap status — always returns immediately (atomic read).
/// When the atomic is 0 (event listener hasn't caught up), spawns a background
/// thread that keeps a persistent control port connection and polls every 500ms
/// until bootstrap reaches 100% or 10 seconds elapse.
pub fn get_bootstrap_status_fast() -> u32 {
    let cached = BOOTSTRAP_STATUS.load(Ordering::SeqCst);
    if cached > 0 {
        return cached;
    }

    // Atomic is 0 — kick off a persistent background poller (at most one at a time)
    static QUERY_RUNNING: AtomicBool = AtomicBool::new(false);
    if QUERY_RUNNING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
        std::thread::spawn(move || {
            bootstrap_direct_poll_loop();
            QUERY_RUNNING.store(false, Ordering::SeqCst);
        });
    }

    0 // Return immediately; background thread will update atomic for next poll
}

/// Background polling loop: opens one TCP connection to the control port,
/// then queries GETINFO status/bootstrap-phase every 500ms until 100%.
fn bootstrap_direct_poll_loop() {
    use std::io::{Read, Write};
    use std::net::TcpStream as StdTcpStream;
    use std::time::Duration;

    // Try to connect (retry up to 30 times = 6 seconds at 200ms)
    let mut stream = None;
    for _ in 0..30 {
        let addr: std::net::SocketAddr = match "127.0.0.1:9051".parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        match StdTcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }

    let mut stream = match stream {
        Some(s) => s,
        None => return, // Control port not available
    };

    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(300)));

    // Authenticate (same empty auth as event listener)
    if stream.write_all(b"AUTHENTICATE\r\n").is_err() {
        return;
    }
    let mut buf = vec![0u8; 2048];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let response = String::from_utf8_lossy(&buf[..n]);
    if !response.contains("250 OK") {
        return;
    }

    log::info!("Direct bootstrap poller: connected and authenticated");

    // Poll loop: query every 500ms until bootstrap >= 100 or 20 iterations (10s)
    for i in 0..20 {
        // If the event listener has already updated the atomic, we can stop
        let current = BOOTSTRAP_STATUS.load(Ordering::SeqCst);
        if current >= 100 {
            log::info!("Direct bootstrap poller: event listener caught up ({}%), stopping", current);
            break;
        }

        // Send GETINFO
        if stream.write_all(b"GETINFO status/bootstrap-phase\r\n").is_err() {
            break;
        }

        // Accumulate response until "250 OK"
        let mut resp = String::new();
        loop {
            let n = match stream.read(&mut buf) {
                Ok(0) => { resp.clear(); break; }
                Ok(n) => n,
                Err(_) => { break; }
            };
            resp.push_str(&String::from_utf8_lossy(&buf[..n]));
            if resp.contains("\r\n250 OK\r\n") || resp.ends_with("250 OK\r\n") {
                break;
            }
            if resp.len() > 8192 {
                break;
            }
        }

        if let Some(progress) = parse_bootstrap_progress(&resp) {
            let old = BOOTSTRAP_STATUS.swap(progress, Ordering::SeqCst);
            if progress != old {
                log::info!("Direct bootstrap poller: {}% (poll #{})", progress, i + 1);
            }
            if progress >= 100 {
                break;
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    let _ = stream.write_all(b"QUIT\r\n");
    log::info!("Direct bootstrap poller: done");
}

/// Get circuit established status from the global atomic (fast, no control port query)
/// Returns 0 (no circuits) or 1 (circuits established)
pub fn get_circuit_established_fast() -> u8 {
    CIRCUIT_ESTABLISHED.load(Ordering::SeqCst)
}

/// HS descriptor upload counter - incremented by event listener each time Tor confirms UPLOADED to an HSDir
/// v3 onion services upload to multiple HSDirs (typically 6-8), so count >= 1 means partially reachable
pub static HS_DESC_UPLOAD_COUNT: AtomicU32 = AtomicU32::new(0);

/// Guard: ensures only one event listener is spawned at a time
/// swap(true) returns the old value — if it was already true, a listener is running
static EVENT_LISTENER_RUNNING: AtomicBool = AtomicBool::new(false);

/// Shutdown signal for the event listener — set to true to tell it to exit
static EVENT_LISTENER_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Get HS descriptor upload count (fast, no control port query)
pub fn get_hs_desc_upload_count() -> u32 {
    HS_DESC_UPLOAD_COUNT.load(Ordering::SeqCst)
}

/// Reset HS descriptor upload counter (call before creating a new hidden service)
pub fn reset_hs_desc_upload_count() {
    HS_DESC_UPLOAD_COUNT.store(0, Ordering::SeqCst);
}

/// Tor event types for ControlPort event monitoring
#[derive(Debug, Clone)]
pub enum TorEventType {
    Bootstrap { progress: u32 },
    CircuitBuilt { circ_id: String },
    CircuitFailed { circ_id: String, reason: String },
    CircuitClosed { circ_id: String, reason: String },
    HsDescUploaded { address: String },
    HsDescUploadFailed { address: String, reason: String },
    StatusGeneral { severity: String, message: String },
}

/// Callback type for forwarding events to Kotlin
/// This will be called from the event listener thread
type TorEventCallback = Arc<dyn Fn(TorEventType) + Send + Sync>;

/// Global event callback (set by Kotlin via FFI)
static GLOBAL_TOR_EVENT_CALLBACK: Lazy<StdMutex<Option<TorEventCallback>>> = Lazy::new(|| StdMutex::new(None));

/// Register a callback to receive Tor events
/// Called from FFI layer (android.rs) to set the Kotlin callback
pub fn register_tor_event_callback<F>(callback: F)
where
    F: Fn(TorEventType) + Send + Sync + 'static,
{
    let mut cb = GLOBAL_TOR_EVENT_CALLBACK.lock().unwrap();
    *cb = Some(Arc::new(callback));
    log::info!("Tor event callback registered");
}

/// Forward event to Kotlin callback (if registered)
fn forward_tor_event(event: TorEventType) {
    if let Some(ref callback) = *GLOBAL_TOR_EVENT_CALLBACK.lock().unwrap() {
        callback(event);
    }
}

/// Stop the event listener (call before restart to allow a fresh listener)
pub fn stop_bootstrap_event_listener() {
    EVENT_LISTENER_SHUTDOWN.store(true, Ordering::SeqCst);
    log::info!("Event listener shutdown signal sent");
    // The listener thread checks this flag and will exit on next iteration.
    // The RUNNING flag is cleared by the listener itself on exit.
}

/// Start the bootstrap event listener on a separate control port connection
/// This spawns a background task that listens for STATUS_CLIENT events
/// and updates BOOTSTRAP_STATUS in real-time
///
/// Guarded: only one listener can run at a time. If already running, this is a no-op.
pub fn start_bootstrap_event_listener() {
    // Atomically swap true → if old value was already true, a listener is running
    if EVENT_LISTENER_RUNNING.swap(true, Ordering::SeqCst) {
        log::warn!("Bootstrap event listener already running; skipping spawn");
        return;
    }

    // Clear shutdown signal for the new listener
    EVENT_LISTENER_SHUTDOWN.store(false, Ordering::SeqCst);

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

        // Clear the guard so a new listener can be spawned after this one exits
        EVENT_LISTENER_RUNNING.store(false, Ordering::SeqCst);
        log::info!("Event listener thread exited, guard cleared");
    });
}

/// Background task that subscribes to STATUS_CLIENT events and updates bootstrap status
async fn bootstrap_event_listener_task() -> Result<(), Box<dyn Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{sleep, Duration};

    log::info!("Starting bootstrap event listener...");

    // Connect to control port (separate connection from main TorManager)
    // Retry up to 300 times (60s at 200ms intervals) if control port not ready yet.
    // Fast retries so we catch early bootstrap progress on fast networks.
    let mut control = None;
    for attempt in 1..=300 {
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
                if attempt == 300 {
                    log::error!("Event listener: Failed to connect to control port after {} attempts: {}", attempt, e);
                    return Err(e.into());
                }
                sleep(Duration::from_millis(200)).await;
            }
        }
    }

    let mut control = control.unwrap();

    // Authenticate (accumulate until 250 OK in case of split reads)
    control.write_all(b"AUTHENTICATE\r\n").await?;
    let mut buf = vec![0u8; 1024];
    let mut auth_resp = String::new();
    let auth_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = auth_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() { break; }
        let n = match tokio::time::timeout(remaining, control.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        };
        auth_resp.push_str(&String::from_utf8_lossy(&buf[..n]));
        if auth_resp.contains("250 OK") { break; }
        if auth_resp.len() > 4096 { break; }
    }

    if !auth_resp.contains("250 OK") {
        log::error!("Event listener: Auth failed: {}", auth_resp);
        return Err("Event listener auth failed".into());
    }

    log::info!("Event listener: Authenticated to control port");

    // Subscribe to multiple events for comprehensive monitoring
    // STATUS_CLIENT: Bootstrap progress
    // CIRC: Circuit lifecycle (build/extend/fail/close)
    // HS_DESC: Onion service descriptor upload/download events
    // STATUS_GENERAL: General Tor state changes
    control.write_all(b"SETEVENTS STATUS_CLIENT CIRC HS_DESC STATUS_GENERAL\r\n").await?;
    let mut sub_resp = String::new();
    let sub_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = sub_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() { break; }
        let n = match tokio::time::timeout(remaining, control.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => break,
        };
        sub_resp.push_str(&String::from_utf8_lossy(&buf[..n]));
        if sub_resp.contains("250 OK") { break; }
        if sub_resp.len() > 4096 { break; }
    }

    if !sub_resp.contains("250 OK") {
        log::error!("Event listener: Failed to subscribe to events: {}", sub_resp);
        return Err("Failed to subscribe to events".into());
    }

    log::info!("Event listener: Subscribed to STATUS_CLIENT, CIRC, HS_DESC, STATUS_GENERAL events");

    // Get initial bootstrap status (hardened: accumulate until 250 OK,
    // ignoring any buffered 650 async events from SETEVENTS)
    control.write_all(b"GETINFO status/bootstrap-phase\r\n").await?;
    {
        let mut resp = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                log::warn!("Event listener: Initial bootstrap GETINFO timed out after 1.5s");
                break;
            }
            let n = match tokio::time::timeout(remaining, control.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    log::error!("Event listener: Failed to read initial bootstrap: {}", e);
                    break;
                }
                Err(_) => {
                    log::warn!("Event listener: Initial bootstrap read timed out");
                    break;
                }
            };
            resp.push_str(&String::from_utf8_lossy(&buf[..n]));
            if resp.contains("\r\n250 OK\r\n") || resp.ends_with("250 OK\r\n") {
                break;
            }
            if resp.len() > 16_384 {
                break;
            }
        }
        if let Some(progress) = parse_bootstrap_progress(&resp) {
            BOOTSTRAP_STATUS.store(progress, Ordering::SeqCst);
            log::info!("Event listener: Initial bootstrap status: {}%", progress);
        } else {
            log::warn!("Event listener: Could not parse initial bootstrap status");
        }
    }

    // Get initial circuit-established status (same hardened read)
    control.write_all(b"GETINFO status/circuit-established\r\n").await?;
    {
        let mut resp = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(1500);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let n = match tokio::time::timeout(remaining, control.read(&mut buf)).await {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    log::error!("Event listener: Failed to read initial circuit-established: {}", e);
                    break;
                }
                Err(_) => break,
            };
            resp.push_str(&String::from_utf8_lossy(&buf[..n]));
            if resp.contains("\r\n250 OK\r\n") || resp.ends_with("250 OK\r\n") {
                break;
            }
            if resp.len() > 16_384 {
                break;
            }
        }
        let circuits_established = if resp.contains("circuit-established=1") { 1 } else { 0 };
        CIRCUIT_ESTABLISHED.store(circuits_established, Ordering::SeqCst);
        log::info!("Event listener: Initial circuit-established: {}", circuits_established);
    }

    // Now continuously read events
    log::info!("Event listener: Listening for bootstrap events...");
    let mut event_buf = vec![0u8; 4096];
    // Start fast (1s) during bootstrap, switch to 5s once at 100%
    let mut poll_interval = tokio::time::interval(Duration::from_secs(1));

    loop {
        // Check shutdown signal
        if EVENT_LISTENER_SHUTDOWN.load(Ordering::SeqCst) {
            log::info!("Event listener: Shutdown signal received, exiting");
            break;
        }

        tokio::select! {
            // Poll circuit-established every 5 seconds
            _ = poll_interval.tick() => {
                // Check shutdown signal on each tick
                if EVENT_LISTENER_SHUTDOWN.load(Ordering::SeqCst) {
                    log::info!("Event listener: Shutdown signal received during tick, exiting");
                    break;
                }
                // Poll circuit-established status (accumulate until 250 OK,
                // forwarding any 650 async events that arrive interleaved)
                if let Err(e) = control.write_all(b"GETINFO status/circuit-established\r\n").await {
                    log::error!("Event listener: Failed to query circuit-established: {}", e);
                    break;
                }

                let mut circ_resp = String::new();
                let circ_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
                loop {
                    let remaining = circ_deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        log::warn!("Event listener: circuit-established poll timed out");
                        break;
                    }
                    let n = match tokio::time::timeout(remaining, control.read(&mut buf)).await {
                        Ok(Ok(0)) => break,
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => {
                            log::error!("Event listener: Failed to read circuit-established: {}", e);
                            circ_resp.clear();
                            break;
                        }
                        Err(_) => break,
                    };
                    let chunk = String::from_utf8_lossy(&buf[..n]);
                    // Forward any 650 events so they're not lost
                    for line in chunk.lines() {
                        if line.starts_with("650 ") {
                            if let Some(evt) = parse_tor_event(line) {
                                if let TorEventType::Bootstrap { progress } = evt {
                                    let old = BOOTSTRAP_STATUS.swap(progress, Ordering::SeqCst);
                                    if progress != old {
                                        log::info!("Bootstrap progress (during poll): {}%", progress);
                                    }
                                }
                                forward_tor_event(evt);
                            }
                        }
                    }
                    circ_resp.push_str(&chunk);
                    if circ_resp.contains("\r\n250 OK\r\n") || circ_resp.ends_with("250 OK\r\n") {
                        break;
                    }
                    if circ_resp.len() > 16_384 {
                        break;
                    }
                }

                let new_status = if circ_resp.contains("circuit-established=1") { 1 } else { 0 };
                let old_status = CIRCUIT_ESTABLISHED.swap(new_status, Ordering::SeqCst);

                if new_status != old_status {
                    log::info!("Circuit established status changed: {} → {}", old_status, new_status);
                }

                // Poll bootstrap status if not yet at 100%.
                // Runs every 1s during bootstrap for responsive splash screen progress.
                // Switches to 5s interval once bootstrap complete.
                if BOOTSTRAP_STATUS.load(Ordering::SeqCst) < 100 {
                    if let Err(e) = control.write_all(b"GETINFO status/bootstrap-phase\r\n").await {
                        log::error!("Event listener: Failed to query bootstrap status: {}", e);
                        break;
                    }
                    // Accumulate reads until we see "250 OK" (response may be split across reads
                    // or interleaved with async 650 events)
                    let mut resp = String::new();
                    loop {
                        let n = match control.read(&mut buf).await {
                            Ok(n) => n,
                            Err(e) => {
                                log::error!("Event listener: Failed to read bootstrap response: {}", e);
                                resp.clear();
                                break;
                            }
                        };
                        resp.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if resp.contains("\r\n250 OK\r\n") || resp.ends_with("250 OK\r\n") {
                            break;
                        }
                        if resp.len() > 16_384 {
                            log::warn!("Event listener: Bootstrap response too large, giving up");
                            break;
                        }
                    }
                    if let Some(progress) = parse_bootstrap_progress(&resp) {
                        let old = BOOTSTRAP_STATUS.swap(progress, Ordering::SeqCst);
                        if progress != old {
                            log::info!("Bootstrap status updated via periodic poll: {}%", progress);
                        }
                        // Switch to slow poll once bootstrap complete
                        if progress >= 100 {
                            log::info!("Bootstrap complete — switching poll interval to 5s");
                            poll_interval = tokio::time::interval(Duration::from_secs(5));
                        }
                    }
                }
            }

            // Read and parse ControlPort events
            read_result = control.read(&mut event_buf) => {
                match read_result {
                    Ok(0) => {
                        log::info!("Event listener: Control connection closed");
                        break;
                    }
                    Ok(n) => {
                        let event_text = String::from_utf8_lossy(&event_buf[..n]);

                        // Parse events line by line (can receive multiple events in one read)
                        for line in event_text.lines() {
                            if line.is_empty() {
                                continue;
                            }

                            // Parse and forward event to Kotlin
                            if let Some(event) = parse_tor_event(line) {
                                // Special handling for bootstrap to update atomic
                                if let TorEventType::Bootstrap { progress } = event {
                                    let old_value = BOOTSTRAP_STATUS.swap(progress, Ordering::SeqCst);
                                    if progress != old_value {
                                        log::info!("Bootstrap progress: {}%", progress);
                                    }
                                    forward_tor_event(event);
                                } else {
                                    // Log other events
                                    match &event {
                                        TorEventType::CircuitBuilt { circ_id } => {
                                            log::info!("Circuit BUILT: {}", circ_id);
                                        }
                                        TorEventType::CircuitFailed { circ_id, reason } => {
                                            log::warn!("Circuit FAILED: {} (reason: {})", circ_id, reason);
                                        }
                                        TorEventType::CircuitClosed { circ_id, reason } => {
                                            log::info!("Circuit CLOSED: {} (reason: {})", circ_id, reason);
                                        }
                                        TorEventType::HsDescUploaded { address } => {
                                            let count = HS_DESC_UPLOAD_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
                                            log::info!("HS descriptor UPLOADED: {} (total: {}/6 HSDirs)", address, count);
                                        }
                                        TorEventType::HsDescUploadFailed { address, reason } => {
                                            log::warn!("HS descriptor UPLOAD FAILED: {} (reason: {})", address, reason);
                                        }
                                        TorEventType::StatusGeneral { severity, message } => {
                                            log::info!("STATUS_GENERAL [{}]: {}", severity, message);
                                        }
                                        _ => {}
                                    }
                                    forward_tor_event(event);
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

/// Parse ControlPort events and return TorEventType
/// Events come in format: "650 EVENT_TYPE [params]"
fn parse_tor_event(event_line: &str) -> Option<TorEventType> {
    // Skip if not an event (650 is async event code)
    if !event_line.starts_with("650 ") {
        return None;
    }

    // BOOTSTRAP event: 650 STATUS_CLIENT NOTICE BOOTSTRAP PROGRESS=XX TAG=... SUMMARY="..."
    if event_line.contains("BOOTSTRAP") && event_line.contains("PROGRESS=") {
        if let Some(progress) = parse_bootstrap_progress(event_line) {
            return Some(TorEventType::Bootstrap { progress });
        }
    }

    // CIRC events: 650 CIRC <CircuitID> <Status> [<Path>] [BUILD_FLAGS=...] [PURPOSE=...] [REASON=...]
    // Status: LAUNCHED, BUILT, EXTENDED, FAILED, CLOSED
    if event_line.starts_with("650 CIRC ") {
        let parts: Vec<&str> = event_line.split_whitespace().collect();
        if parts.len() >= 3 {
            let circ_id = parts[2].to_string();
            let status = parts.get(3).unwrap_or(&"");

            match *status {
                "BUILT" => {
                    return Some(TorEventType::CircuitBuilt { circ_id });
                }
                "FAILED" => {
                    // Extract REASON=XXX if present
                    let reason = extract_param(event_line, "REASON=")
                        .unwrap_or_else(|| "UNKNOWN".to_string());
                    return Some(TorEventType::CircuitFailed { circ_id, reason });
                }
                "CLOSED" => {
                    let reason = extract_param(event_line, "REASON=")
                        .unwrap_or_else(|| "UNKNOWN".to_string());
                    return Some(TorEventType::CircuitClosed { circ_id, reason });
                }
                _ => {} // Ignore LAUNCHED, EXTENDED, etc.
            }
        }
    }

    // HS_DESC events: 650 HS_DESC <Action> <HSAddress> <AuthType> <HsDir> [<DescriptorID>] [REASON=...]
    // Action: UPLOAD, UPLOADED, FAILED, RECEIVED, etc.
    if event_line.starts_with("650 HS_DESC ") {
        let parts: Vec<&str> = event_line.split_whitespace().collect();
        if parts.len() >= 4 {
            let action = parts[2];
            let address = parts.get(3).unwrap_or(&"").to_string();

            match action {
                "UPLOADED" => {
                    return Some(TorEventType::HsDescUploaded { address });
                }
                "FAILED" => {
                    let reason = extract_param(event_line, "REASON=")
                        .unwrap_or_else(|| "UNKNOWN".to_string());
                    return Some(TorEventType::HsDescUploadFailed { address, reason });
                }
                _ => {} // Ignore UPLOAD, RECEIVED, etc.
            }
        }
    }

    // STATUS_GENERAL events: 650 STATUS_GENERAL <Severity> <Action> <Arguments>
    if event_line.starts_with("650 STATUS_GENERAL ") {
        let parts: Vec<&str> = event_line.splitn(4, ' ').collect();
        if parts.len() >= 4 {
            let severity = parts[2].to_string();
            let message = parts[3].to_string();
            return Some(TorEventType::StatusGeneral { severity, message });
        }
    }

    None
}

/// Extract parameter value from event line (e.g., REASON=XXX)
fn extract_param(line: &str, param: &str) -> Option<String> {
    if let Some(param_start) = line.find(param) {
        let value_start = param_start + param.len();
        let value = &line[value_start..];
        // Take until next space or end of line
        let value = value.split_whitespace().next().unwrap_or("");
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// ============================================================================
/// PORT MAPPING SPECIFICATION
/// ============================================================================
/// This is the canonical port mapping for all Tor hidden services.
/// CRITICAL: All services must use this mapping consistently.
///
/// Message Hidden Service Ports (port 9051 control, SOCKS 9050):
/// - 9150: PING/PONG/ACK control flow (main listener port 9150→8080)
/// - 8080: PONG responses (fallback, port 8080→8080)
/// - 9151: TAP messages (reserved for future use)
/// - 9153: ACK/Delivery confirmations (dedicated ACK listener)
/// - All ports also accept: TEXT, VOICE, IMAGE, FRIEND_REQUEST (routed to dedicated channels)
///
/// Voice Hidden Service Ports (port 9052 control, voice Tor only):
/// - 9152: Voice streaming (single onion, low-latency, CALL_SIGNALING only)
///
/// Control Ports (Tor daemon only, not hidden services):
/// - 9051: Main Tor daemon control port (message Tor)
/// - 9052: Voice Tor daemon control port (single onion voice)
///
/// SOCKS Proxy (for outbound connections):
/// - 9050: SOCKS5 proxy (main Tor)
///
/// ============================================================================

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
pub const MSG_TYPE_CALL_SIGNALING: u8 = 0x0D; // Voice call signaling (OFFER/ANSWER/REJECT/END/BUSY)

/// Canonical port constants (from PORT_MAP.md)
pub const PORT_HS_PING_PONG: u16 = 9150; // Message HS: PING/PONG/ACK
pub const PORT_HS_PONG_LOCAL: u16 = 8080; // Message HS: Local PONG response fallback
pub const PORT_HS_TAP: u16 = 9151; // Message HS: TAP (reserved)
pub const PORT_HS_ACK: u16 = 9153; // Message HS: Dedicated ACK listener
pub const PORT_HS_VOICE: u16 = 9152; // Voice HS: Voice streaming (single onion)
pub const PORT_LOCAL_HS: u16 = 8080; // Local listener port (where HS connects to)
pub const PORT_VOICE_LOCAL: u16 = 9152; // Local voice listener port
pub const PORT_CONTROL_MAIN: u16 = 9051; // Main Tor control port
pub const PORT_CONTROL_VOICE: u16 = 9052; // Voice Tor control port
pub const PORT_SOCKS: u16 = 9050; // SOCKS5 proxy port

/// JNI context availability check
/// CRITICAL: Some Android lifecycle contexts don't have application context
/// This is used by JNI FFI to ensure safe context access
pub fn has_jni_context() -> bool {
    // SAFETY: This should be called from JNI after checking Android context availability
    // The actual context validation happens in Kotlin before calling Rust
    // This is a placeholder to ensure JNI code doesn't panic on missing context
    true
}

/// Structure representing a pending connection waiting for Pong response
pub struct PendingConnection {
    pub socket: TcpStream,
    pub encrypted_ping: Vec<u8>,
}

/// Global map of pending connections: connection_id -> PendingConnection
/// CRITICAL: Uses std::sync::Mutex (not async) because accessed from JNI FFI code
/// Lock is held only briefly in async code (insert/remove operations complete quickly)
/// JNI code: isConnectionAlive() reads synchronously (brief lock)
/// Async code: Briefly locks to insert/remove, then immediately releases
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
/// Line-oriented Tor control protocol reader
/// CRITICAL: Handles multi-line Tor responses properly
/// Response formats:
/// SingleLine: "250 OK\r\n"
/// MultiLine: "250-...\r\n250-...\r\n250 OK\r\n"
/// Events: "650 EVENT data...\r\n"
struct TorControlReader {
    reader: BufReader<TcpStream>,
}

impl TorControlReader {
    fn new(stream: TcpStream) -> Self {
        TorControlReader {
            reader: BufReader::new(stream),
        }
    }

    /// Read a complete Tor control response (one or more lines until final status line)
    /// Returns the complete multi-line response as a String
    async fn read_response(&mut self) -> Result<String, Box<dyn Error + Send + Sync>> {
        let mut response = String::new();
        let mut line = String::new();
        let mut is_final = false;

        while !is_final {
            line.clear();
            let n = self.reader.read_line(&mut line).await?;

            if n == 0 {
                return Err("Connection closed while reading response".into());
            }

            // Check if this is the final line (status code without dash)
            // Tor format: "250 ..." (final) or "250-..." (continuation)
            if line.len() >= 4 {
                let status_code = &line[0..3];
                if let Some(fourth_char) = line.chars().nth(3) {
                    is_final = fourth_char == ' ' || fourth_char == '\r' || fourth_char == '\n';
                }
            }

            response.push_str(&line);
        }

        Ok(response)
    }

    /// Read until a specific pattern is found
    /// Used for events that don't have strict response format
    async fn read_until_pattern(&mut self, pattern: &str, timeout_secs: u64) -> Result<String, Box<dyn Error + Send + Sync>> {
        let mut response = String::new();
        let mut line = String::new();

        let start = tokio::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);

        loop {
            if start.elapsed() > timeout {
                return Err(format!("Timeout waiting for pattern '{}'", pattern).into());
            }

            line.clear();
            match tokio::time::timeout(
                timeout - start.elapsed(),
                self.reader.read_line(&mut line)
            ).await {
                Ok(Ok(0)) => return Err("Connection closed".into()),
                Ok(Ok(_)) => {
                    response.push_str(&line);
                    if response.contains(pattern) {
                        return Ok(response);
                    }
                }
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Err("Timeout".into()),
            }
        }
    }
}

/// Hidden service state tracking for crash recovery
/// CRITICAL: Prevents ghost onions from previous crashes consuming resources
struct HiddenServiceState {
    /// Currently active messaging HS address
    message_hs_address: Option<String>,
    /// Currently active voice HS address
    voice_hs_address: Option<String>,
    /// Event subscriptions currently active
    subscribed_events: Vec<String>,
}

pub struct TorManager {
    control_stream: Option<Arc<Mutex<TcpStream>>>,
    voice_control_stream: Option<Arc<Mutex<TcpStream>>>, // VOICE TOR: port 9052 (Single Onion)
    hidden_service_address: Option<String>,
    voice_hidden_service_address: Option<String>,
    listener_handle: Option<tokio::task::JoinHandle<()>>,
    incoming_ping_tx: Option<tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>>,
    pub(crate) incoming_pong_tx: Option<tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>>,
    hs_state: HiddenServiceState,
    hs_service_port: u16,
    hs_local_port: u16,
    socks_port: u16,
    bound_port: Option<u16>, // Track currently bound port for idempotency check
}

impl TorManager {
    /// Initialize Tor manager
    pub fn new() -> Result<Self, Box<dyn Error>> {
        Ok(TorManager {
            control_stream: None,
            voice_control_stream: None, // VOICE TOR initialized separately
            hidden_service_address: None,
            voice_hidden_service_address: None,
            listener_handle: None,
            incoming_ping_tx: None,
            incoming_pong_tx: None,
            hs_state: HiddenServiceState {
                message_hs_address: None,
                voice_hs_address: None,
                subscribed_events: Vec::new(),
            },
            hs_service_port: PORT_HS_PING_PONG, // 9150: PING/PONG/ACK
            hs_local_port: PORT_LOCAL_HS, // 8080: Local listener
            socks_port: PORT_SOCKS, // 9050: SOCKS proxy
            bound_port: None, // No port bound initially
        })
    }

    /// Check and recover control port connection if disconnected
    /// CRITICAL: Prevents silent failures when Tor restarts
    /// Returns true if connection is healthy, false if recovery failed
    async fn check_control_connection(&mut self) -> Result<bool, Box<dyn Error>> {
        let control = match &self.control_stream {
            Some(c) => c,
            None => {
                log::warn!("Control port not connected, attempting to reconnect...");
                return self.reconnect_control_port().await.map(|_| true);
            }
        };

        // Test control connection with a simple command
        let mut stream = control.lock().await;

        match tokio::time::timeout(
            std::time::Duration::from_secs(3),
            stream.write_all(b"GETINFO version\r\n")
        ).await {
            Ok(Ok(_)) => {
                // Connection is alive
                Ok(true)
            }
            Ok(Err(e)) => {
                log::error!("Control port write error: {}", e);
                // Drop stream to release lock before reconnecting
                drop(stream);
                self.reconnect_control_port().await.map(|_| true)
            }
            Err(_) => {
                log::error!("Control port timeout");
                // Drop stream to release lock before reconnecting
                drop(stream);
                self.reconnect_control_port().await.map(|_| true)
            }
        }
    }

    /// Reconnect to Tor control port with re-authentication and re-subscription
    /// CRITICAL: Called when connection drops
    async fn reconnect_control_port(&mut self) -> Result<(), Box<dyn Error>> {
        log::info!("Reconnecting to Tor control port (127.0.0.1:9051)...");

        // Connect to control port
        let mut control = TcpStream::connect("127.0.0.1:9051").await?;

        // Authenticate with NULL auth
        control.write_all(b"AUTHENTICATE\r\n").await?;

        let mut buf = vec![0u8; 1024];
        let n = control.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        if !response.contains("250 OK") {
            return Err(format!("Control port authentication failed after reconnect: {}", response).into());
        }

        log::info!("Reconnected to Tor control port");

        // Re-subscribe to previously subscribed events
        for event in &self.hs_state.subscribed_events.clone() {
            let command = format!("SETEVENTS {}\r\n", event);
            control.write_all(command.as_bytes()).await?;

            let n = control.read(&mut buf).await?;
            let resp = String::from_utf8_lossy(&buf[..n]);

            if !resp.contains("250 OK") {
                log::warn!("Failed to re-subscribe to event {}: {}", event, resp);
            } else {
                log::info!("Re-subscribed to {} events", event);
            }
        }

        self.control_stream = Some(Arc::new(Mutex::new(control)));

        log::info!("Control port recovery complete");
        Ok(())
    }

    /// Reconcile hidden services on startup (crash recovery)
    /// CRITICAL: Cleans up orphaned services from previous crashes
    /// Returns (message_count, voice_count) of deleted services
    async fn reconcile_hidden_services(&mut self) -> Result<(u32, u32), Box<dyn Error>> {
        log::info!("Reconciling hidden services after startup...");

        let control = self.control_stream.as_ref()
            .ok_or("Control port not connected")?;

        let mut stream = control.lock().await;

        // Query existing services
        stream.write_all(b"GETINFO onions/current\r\n").await?;

        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);

        log::info!("Existing onion services: {}", response);

        // Parse service IDs from response
        let mut existing_services = Vec::new();
        for line in response.lines() {
            if line.contains("onions/current=") {
                if let Some(services_str) = line.split("onions/current=").nth(1) {
                    for service_id in services_str.split_whitespace() {
                        existing_services.push(service_id.to_string());
                    }
                }
            }
        }

        // Expected services we created in this session:
        // - message_hs_address (if initialized)
        // - voice_hs_address (if initialized)
        let expected_services = {
            let mut expected = Vec::new();
            if let Some(msg_addr) = &self.hs_state.message_hs_address {
                let short = msg_addr.trim_end_matches(".onion");
                expected.push(short.to_string());
            }
            if let Some(voice_addr) = &self.hs_state.voice_hs_address {
                let short = voice_addr.trim_end_matches(".onion");
                expected.push(short.to_string());
            }
            expected
        };

        // Find orphaned services (exist in Tor but not in our registry)
        let mut orphaned = Vec::new();
        for existing in &existing_services {
            if !expected_services.contains(existing) {
                orphaned.push(existing.clone());
            }
        }

        let mut msg_deleted = 0u32;
        let mut voice_deleted = 0u32;

        // Delete orphaned services
        for service_id in orphaned {
            log::warn!("Deleting orphaned hidden service: {}", service_id);
            let del_command = format!("DEL_ONION {}\r\n", service_id);
            stream.write_all(del_command.as_bytes()).await?;

            let n = stream.read(&mut buf).await?;
            let del_response = String::from_utf8_lossy(&buf[..n]);

            if del_response.contains("250 OK") {
                log::info!("Deleted orphaned service: {}", service_id);
                // Guess whether it was message or voice based on expected (heuristic)
                if service_id.len() > 16 { // v3 onion addresses are 56 chars
                    msg_deleted += 1;
                } else {
                    voice_deleted += 1;
                }
            } else {
                log::warn!("Failed to delete service {}: {}", service_id, del_response);
            }
        }

        if msg_deleted > 0 || voice_deleted > 0 {
            log::info!("Reconciliation complete: deleted {} message HS, {} voice HS", msg_deleted, voice_deleted);
        } else {
            log::info!("No orphaned services found");
        }

        Ok((msg_deleted, voice_deleted))
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

        // Reconcile hidden services from previous crashes
        if let Err(e) = self.reconcile_hidden_services().await {
            log::warn!("Failed to reconcile hidden services: {}", e);
            // Don't fail initialization - continue anyway
        }

        // Wait for Tor to bootstrap (build circuits)
        log::info!("Waiting for Tor to bootstrap...");
        self.wait_for_bootstrap().await?;

        log::info!("Tor fully bootstrapped and ready");
        Ok("Tor client ready (managed by OnionProxyManager)".to_string())
    }

    /// ============================================================================
    /// VOICE HIDDEN SERVICE LIFECYCLE (Separate from messaging)
    /// ============================================================================
    /// Voice and messaging are COMPLETELY SEPARATE state machines:
    /// - Voice uses separate Tor daemon (port 9052) - Single Onion mode
    /// - Messaging uses main Tor daemon (port 9051) - Standard v3 onion
    /// - Voice HS only exposes port 9152 (voice streaming)
    /// - Message HS exposes ports 9150, 8080, 9151, 9153 (PING/PONG/ACK/TAP)
    /// CRITICAL: Failures in one should not affect the other
    /// ============================================================================

    /// Connect to VOICE Tor control port (port 9052 - Single Onion Service instance)
    /// This is a separate Tor daemon specifically for voice hidden service
    /// Must be called AFTER voice Tor daemon is started by TorManager.kt
    pub async fn initialize_voice_control(&mut self, cookie_path: &str) -> Result<String, Box<dyn Error>> {
        log::info!("Connecting to VOICE Tor control port (9052)...");

        // Connect to voice Tor control port
        let mut control = TcpStream::connect("127.0.0.1:9052").await?;

        // Read voice Tor cookie file (path provided by Kotlin caller)
        log::info!("Reading voice Tor cookie from: {}", cookie_path);
        let cookie = std::fs::read(cookie_path)?;

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
    /// Uses 180s timeout to accommodate bridge transports on slow networks
    /// (e.g. 500kbps in Iran through snowflake/webtunnel/obfs4)
    async fn wait_for_bootstrap(&self) -> Result<(), Box<dyn Error>> {
        let max_attempts = 180; // 180 seconds max (bridges on slow networks need more time)

        for attempt in 1..=max_attempts {
            let status = self.get_bootstrap_status().await?;

            if status >= 100 {
                log::info!("Tor bootstrap complete ({}%)", status);
                return Ok(());
            }

            if attempt % 10 == 0 {
                log::info!("Tor bootstrapping: {}% (attempt {}/{})", status, attempt, max_attempts);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Err("Tor bootstrap timeout - took longer than 180 seconds".into())
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

    /// ============================================================================
    /// MESSAGE HIDDEN SERVICE LIFECYCLE (Separate from voice)
    /// ============================================================================
    /// Messaging hidden service lifecycle for PING/PONG/ACK/TAP messages
    /// Uses main Tor daemon (control port 9051, SOCKS 9050)
    /// CRITICAL: Separate from voice HS to prevent cross-interference
    /// ============================================================================

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
        // Reset descriptor upload counter so Kotlin can track fresh propagation
        reset_hs_desc_upload_count();
        log::info!("HS_DESC upload counter reset for new hidden service");

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

        // NOTE: HS_DESC event subscription is handled by the main event listener (spawn_event_listener)
        // No need to subscribe again here - would cause duplicate events

        // CRITICAL: Verify control port is alive before issuing ADD_ONION
        // Prevents "Broken pipe" failures when Tor restarts between bootstrap and account creation
        match self.check_control_connection().await {
            Ok(true) => log::info!("Control port healthy for create_hidden_service"),
            Ok(false) => log::warn!("Control port check returned false, attempting anyway..."),
            Err(e) => {
                log::error!("Control port reconnection failed: {} - will retry from Kotlin side", e);
                return Err(format!("Control port not available: {}", e).into());
            }
        }

        let control = self.control_stream.as_ref()
            .ok_or("Control port not connected")?;

        // Now create the hidden service - descriptors will be uploaded and we'll receive events
        // IMPORTANT: Expose FOUR ports for Ping-Pong-Tap-ACK protocol:
        // - Port 9150 → local 8080 (Ping listener - main hidden service port)
        // - Port 8080 → local 8080 (Pong listener - SAME as main listener for routing)
        // - Port 9151 → local 9151 (Tap listener)
        // - Port 9153 → local 9153 (ACK/Delivery Confirmation listener)
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
            self.hs_state.message_hs_address = Some(actual_onion.clone()); // Track for crash recovery
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

        // Track voice HS for crash recovery
        self.voice_hidden_service_address = Some(actual_onion_address.clone());
        self.hs_state.voice_hs_address = Some(actual_onion_address.clone());

        log::info!("VOICE SINGLE ONION SERVICE registered: {}", actual_onion_address);
        log::info!("Voice service port: 9152 → local 9152 (voice streaming)");
        log::info!("Service mode: Single Onion (3-hop latency, service location visible)");

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
        log::info!("Connecting to SOCKS5 proxy at 127.0.0.1:{}...", PORT_SOCKS);
        let socks_addr = format!("127.0.0.1:{}", PORT_SOCKS);
        let mut stream = match TcpStream::connect(&socks_addr).await {
            Ok(s) => {
                log::info!("Connected to SOCKS5 proxy");
                s
            }
            Err(e) => {
                log::error!("Failed to connect to SOCKS5 proxy at 127.0.0.1:9050: {}", e);
                log::error!("Possible causes:");
                log::error!("1. Tor daemon not running");
                log::error!("2. SOCKS proxy not listening on port 9050");
                log::error!("3. Port blocked by firewall");
                return Err(format!("SOCKS proxy unreachable: {}", e).into());
            }
        };

        // Perform SOCKS5 handshake
        log::info!("Performing SOCKS5 handshake for {}:{}...", onion_address, port);
        self.socks5_connect(&mut stream, onion_address, port).await?;

        log::info!("Successfully connected to {}", onion_address);

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
        log::info!("SOCKS5 auth successful");

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

            log::error!("SOCKS5 connect failed: status {} ({})", status_code, error_message);
            log::error!("Target: {}:{}", addr, port);

            // Provide specific diagnostic hints based on error code
            match status_code {
                0x05 => {
                    log::error!("Diagnosis: Connection refused by Tor proxy");
                    log::error!("Possible causes:");
                    log::error!("1. Tor not fully bootstrapped (check bootstrap status)");
                    log::error!("2. Recipient's hidden service not reachable");
                    log::error!("3. Recipient's hidden service listener not running on port {}", port);
                    log::error!("4. .onion address is invalid or doesn't exist");
                    log::error!("Recommended action: Verify Tor bootstrap is 100% before retrying");
                }
                0x03 => {
                    log::error!("Diagnosis: Network unreachable");
                    log::error!("Possible causes:");
                    log::error!("1. Tor circuits not established");
                    log::error!("2. No network connectivity");
                }
                0x04 => {
                    log::error!("Diagnosis: Host unreachable");
                    log::error!("Possible causes:");
                    log::error!("1. Hidden service descriptors not published");
                    log::error!("2. Hidden service offline");
                }
                _ => {}
            }

            return Err(format!("SOCKS5 connect failed: status {} ({})", status_code, error_message).into());
        }

        log::info!("SOCKS5 handshake complete");
        Ok(())
    }

    /// Start listening for incoming connections on the hidden service
    ///
    /// CRITICAL FIXES:
    /// 1. Idempotency: Skip restart if already running on requested port
    /// 2. Await stop_listener() to ensure port is released before rebind
    /// 3. Retry on EADDRINUSE with exponential backoff (bounded)
    /// 4. Detailed logging at each fallible step
    pub async fn start_listener(&mut self, local_port: Option<u16>) -> Result<(tokio::sync::mpsc::UnboundedReceiver<(u64, Vec<u8>)>, tokio::sync::mpsc::UnboundedReceiver<(u64, Vec<u8>)>), Box<dyn Error>> {
        let port = local_port.unwrap_or(self.hs_local_port);

        // IDEMPOTENCY: If already running on same port, return success (NO-OP)
        if self.listener_handle.is_some() && self.bound_port == Some(port) {
            log::info!("Listener already running on port {}, returning success (idempotent NO-OP)", port);

            // Create dummy channels to satisfy return type (both receivers already stored in FFI)
            // FFI wrapper will try to store them in GLOBAL_PING_RECEIVER and GLOBAL_PONG_RECEIVER (already set),
            // OnceCell will reject them, and FFI returns true to Kotlin
            let (_ping_tx, ping_rx) = tokio::sync::mpsc::unbounded_channel();
            let (_pong_tx, pong_rx) = tokio::sync::mpsc::unbounded_channel();
            return Ok((ping_rx, pong_rx));
        }

        // If port changed or not running, stop existing listener
        // if self.listener_handle.is_some() {
        // log::info!("Listener running on different port, stopping before restart...");
        // self.stop_listener().await;
        // }

        let bind_addr = format!("127.0.0.1:{}", port);
        log::info!("Starting hidden service listener on {} (requested port: {})", bind_addr, port);

        // BIND WITH RETRY: Handle EADDRINUSE with exponential backoff
        log::info!("Creating TCP socket...");
        let listener = self.bind_with_retry(&bind_addr).await
            .map_err(|e| {
                log::error!("FATAL: Failed to bind listener on {}: {:?}", bind_addr, e);
                e
            })?;

        log::info!("Successfully bound to {}", bind_addr);

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let incoming_tx = tx.clone();
        self.incoming_ping_tx = Some(tx);

        // Create PONG channel (separate from PING to prevent misrouting)
        let (pong_tx, pong_rx) = tokio::sync::mpsc::unbounded_channel();
        let incoming_pong_tx = pong_tx.clone();
        self.incoming_pong_tx = Some(pong_tx);

        // Clone bind_addr for the async move block
        let bind_addr_for_task = bind_addr.clone();

        // Spawn listener task
        log::info!("Spawning listener accept loop...");
        let handle = tokio::spawn(async move {
            log::info!("Listener task started, waiting for connections on {}...", bind_addr_for_task);

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
                        let ping_tx = incoming_tx.clone();
                        let pong_tx = incoming_pong_tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_incoming_connection(socket, conn_id, ping_tx, pong_tx).await {
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
        self.bound_port = Some(port);

        log::info!("Hidden service listener FULLY STARTED on {}", bind_addr);

        // Return both PING and PONG receivers (local channels, no globals)
        Ok((rx, pong_rx))
    }

    /// Bind to address with retry on EADDRINUSE (exponential backoff, bounded)
    ///
    /// This handles the race condition where stop_listener() awaits task cancellation
    /// but the OS hasn't fully released the port yet (TIME_WAIT, kernel cleanup delay, etc.)
    async fn bind_with_retry(&self, bind_addr: &str) -> Result<TcpListener, Box<dyn Error>> {
        use std::io;
        use tokio::time::{sleep, Duration};

        let addr: std::net::SocketAddr = bind_addr.parse()?;
        let mut delay_ms = 25u64;
        const MAX_ATTEMPTS: u32 = 8;

        for attempt in 1..=MAX_ATTEMPTS {
            log::info!("Bind attempt {}/{} to {}", attempt, MAX_ATTEMPTS, addr);

            // Try binding with SO_REUSEADDR
            match tokio::net::TcpSocket::new_v4() {
                Ok(socket) => {
                    log::debug!("TcpSocket::new_v4() succeeded");

                    if let Err(e) = socket.set_reuseaddr(true) {
                        log::error!("set_reuseaddr() failed: {:?}", e);
                        return Err(e.into());
                    }
                    log::debug!("SO_REUSEADDR set");

                    match socket.bind(addr) {
                        Ok(_) => {
                            log::info!("bind() succeeded on attempt {}", attempt);
                            match socket.listen(1024) {
                                Ok(listener) => {
                                    log::info!("listen() succeeded, returning TcpListener");
                                    return Ok(listener);
                                }
                                Err(e) => {
                                    log::error!("listen() failed: {:?}", e);
                                    return Err(e.into());
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                            if attempt < MAX_ATTEMPTS {
                                log::warn!("bind() EADDRINUSE (attempt {}), retrying in {}ms...", attempt, delay_ms);
                                sleep(Duration::from_millis(delay_ms)).await;
                                delay_ms = (delay_ms * 2).min(500); // Exponential backoff, cap at 500ms
                                continue;
                            } else {
                                log::error!("FATAL: bind() EADDRINUSE after {} attempts, giving up", MAX_ATTEMPTS);
                                return Err(format!("bind({}) exhausted {} retry attempts (EADDRINUSE)", addr, MAX_ATTEMPTS).into());
                            }
                        }
                        Err(e) => {
                            log::error!("bind() failed with non-EADDRINUSE error: {:?}", e);
                            return Err(e.into());
                        }
                    }
                }
                Err(e) => {
                    log::error!("TcpSocket::new_v4() failed: {:?}", e);
                    return Err(e.into());
                }
            }
        }

        Err(format!("bind_with_retry: unreachable (exhausted {} attempts)", MAX_ATTEMPTS).into())
    }

    /// Handle incoming connection (receive Ping token)
    async fn handle_incoming_connection(
        mut socket: TcpStream,
        conn_id: u64,
        ping_tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
        pong_tx: tokio::sync::mpsc::UnboundedSender<(u64, Vec<u8>)>,
    ) -> Result<(), Box<dyn Error>> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        socket.read_exact(&mut len_buf).await?;
        let total_len = u32::from_be_bytes(len_buf) as usize;

        // Increased limit to support voice messages (typical voice: ~50KB, allow up to 10MB)
        if total_len > 10_000_000 {
            return Err("Message too large (>10MB)".into());
        }

        // Read full buffer INCLUDING type byte (don't strip it)
        let mut buf = vec![0u8; total_len];
        socket.read_exact(&mut buf).await?;

        // DIAGNOSTIC: Log raw wire bytes at earliest receive point
        log::info!("EARLIEST RECEIVE POINT (connection {}) ", conn_id);
        log::info!("len: {} bytes", buf.len());
        if !buf.is_empty() {
            log::info!("type_byte: 0x{:02x}", buf[0]);
            log::info!("first 8 bytes: {}",
                buf.iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            if buf.len() > 1 {
                log::info!("second byte: 0x{:02x}", buf[1]);
            }
            if buf[0] == MSG_TYPE_PING && buf.len() >= 5 {
                log::info!("PING pubkey_first4: {}",
                    buf[1..5].iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
            }
        }
        log::info!("");

        // Validate: first byte must be a known message type
        if buf.is_empty() {
            log::error!("Empty buffer received on connection {}", conn_id);
            return Err("Empty message".into());
        }

        let msg_type = buf[0];

        // STRICT VALIDATION: First byte must be EXACTLY one of the known protocol types
        // This prevents random pubkey first bytes from legacy packets (missing type byte)
        // from accidentally passing validation (~5% chance of being in 0x01-0x0D range)
        match msg_type {
            MSG_TYPE_PING |
            MSG_TYPE_PONG |
            MSG_TYPE_TEXT |
            MSG_TYPE_VOICE |
            MSG_TYPE_TAP |
            MSG_TYPE_DELIVERY_CONFIRMATION |
            MSG_TYPE_FRIEND_REQUEST |
            MSG_TYPE_FRIEND_REQUEST_ACCEPTED |
            MSG_TYPE_IMAGE |
            MSG_TYPE_PAYMENT_REQUEST |
            MSG_TYPE_PAYMENT_SENT |
            MSG_TYPE_PAYMENT_ACCEPTED |
            MSG_TYPE_CALL_SIGNALING => {
                // Valid type, continue to length check
            }
            _ => {
                log::error!("INVALID_MSG_TYPE_DROP: 0x{:02x} (not in known protocol types)", msg_type);
                log::error!("Connection {}, {} bytes, first 4 bytes: {:02x} {:02x} {:02x} {:02x}",
                    conn_id, buf.len(),
                    buf.get(0).unwrap_or(&0), buf.get(1).unwrap_or(&0),
                    buf.get(2).unwrap_or(&0), buf.get(3).unwrap_or(&0));
                return Err(format!("Invalid message type: 0x{:02x}", msg_type).into());
            }
        }

        // MINIMUM LENGTH CHECK: All protocol messages have format [type][pubkey32][encrypted_payload]
        // Minimum encrypted payload is 16 bytes (AES-GCM tag), so absolute minimum is 1+32+16=49 bytes
        const MIN_WIRE_LEN: usize = 1 + 32 + 16; // type + pubkey + smallest possible ciphertext
        if buf.len() < MIN_WIRE_LEN {
            log::error!("WIRE_TOO_SHORT_DROP: type=0x{:02x}, len={} (min={})", msg_type, buf.len(), MIN_WIRE_LEN);
            log::error!("Connection {}, rejecting packet (likely garbage/corruption)", conn_id);
            return Err(format!("Wire message too short: {} bytes (min {})", buf.len(), MIN_WIRE_LEN).into());
        }

        log::info!("");
        log::info!("INCOMING CONNECTION {} (type=0x{:02x}, {} bytes total)", conn_id, msg_type, buf.len());
        log::info!("First byte: 0x{:02x} (validated as known type)", msg_type);
        log::info!("");

        // ROUTER INVARIANT: Log route decision for debugging
        let head_hex: String = buf.iter().take(8).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("");
        log::info!("ROUTE: type=0x{:02x} conn={} len={} head={}", msg_type, conn_id, buf.len(), head_hex);

        // Route based on message type (buf INCLUDES type byte at offset 0)
        match msg_type {
            MSG_TYPE_PING => {
                log::info!("→ Routing to PING handler");

                // Store connection for instant Pong response
                // BRIEF LOCK: Insert only, no async operations held
                {
                    let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                    pending.insert(conn_id, PendingConnection {
                        socket,
                        encrypted_ping: buf.clone(),
                    });
                }

                // ROUTER INVARIANT: Check send result
                let buf_len = buf.len();
                if let Err(_) = ping_tx.send((conn_id, buf)) {
                    log::error!("ROUTER_DROP: PING_TX send failed (receiver dropped), conn={} len={}", conn_id, buf_len);
                }
            }
            MSG_TYPE_PONG => {
                log::info!("→ Routing to PONG handler");
                // Pongs don't need connection stored (no reply needed)
                // Send full buffer (INCLUDING type byte at offset 0) to PONG_TX (NOT PING_TX!)
                // ROUTER INVARIANT: Check send result
                if let Err(_) = pong_tx.send((conn_id, buf.clone())) {
                    log::error!("ROUTER_DROP: PONG_TX send failed (receiver dropped), conn={} len={} head={}", conn_id, buf.len(), head_hex);
                } else {
                    log::info!("ROUTER: PONG dispatch ok, conn={} len={}", conn_id, buf.len());
                }
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
                // BRIEF LOCK: Insert only, no async operations held
                {
                    let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                    pending.insert(conn_id, PendingConnection {
                        socket,
                        encrypted_ping: buf.clone(),
                    });
                }

                // Route to MESSAGE channel (not PING channel)
                // Send full buffer (INCLUDING type byte at offset 0)
                if let Some(message_tx) = MESSAGE_TX.get() {
                    let tx_lock = message_tx.lock().unwrap();
                    if let Err(e) = tx_lock.send((conn_id, buf)) {
                        log::error!("Failed to send message to MESSAGE channel: {}", e);
                    } else {
                        // Successfully accepted message
                        crate::ffi::android::RX_MESSAGE_ACCEPT_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                } else {
                    log::warn!("MESSAGE channel not initialized - dropping message");
                    // Increment drop counter for stress test diagnostics
                    crate::ffi::android::RX_MESSAGE_TX_DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            MSG_TYPE_CALL_SIGNALING => {
                log::info!("→ Routing to VOICE handler (dedicated channel for call signaling)");

                // Store connection for delivery confirmation
                // BRIEF LOCK: Insert only, no async operations held
                {
                    let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                    pending.insert(conn_id, PendingConnection {
                        socket,
                        encrypted_ping: buf.clone(),
                    });
                }

                // Route to VOICE channel (separate from MESSAGE to allow simultaneous messaging during calls)
                // Send full buffer (INCLUDING type byte at offset 0)
                if let Some(voice_tx) = VOICE_TX.get() {
                    let tx_lock = voice_tx.lock().unwrap();
                    if let Err(e) = tx_lock.send((conn_id, buf)) {
                        log::error!("Failed to send call signaling to VOICE channel: {}", e);
                    }
                } else {
                    log::warn!("VOICE channel not initialized - dropping call signaling");
                }
            }
            MSG_TYPE_TAP => {
                log::info!("→ Routing to TAP handler");
                // Send full buffer (INCLUDING type byte at offset 0)
                ping_tx.send((conn_id, buf)).ok();
            }
            MSG_TYPE_DELIVERY_CONFIRMATION => {
                log::warn!("Received ACK on main listener (port 8080) - should go to port 9153!");
                log::info!("→ Routing to ACK channel (error recovery - ensures no message loss)");

                // ERROR RECOVERY: ACK arrived on wrong port, but we MUST NOT drop it!
                // Route to shared ACK_TX channel so it still gets processed.
                // This prevents permanent message delivery failures.
                // Send full buffer (INCLUDING type byte at offset 0)
                if let Some(ack_tx) = ACK_TX.get() {
                    let tx_lock = ack_tx.lock().unwrap();
                    if let Err(e) = tx_lock.send((conn_id, buf)) {
                        log::error!("Failed to send ACK to ACK channel: {}", e);
                    } else {
                        log::info!("ACK successfully routed to ACK channel from port 8080");
                    }
                } else {
                    log::error!("ACK channel not initialized - ACK will be lost!");
                    log::error!("Start ACK listener on port 9153 to initialize ACK_TX channel");
                }
            }
            MSG_TYPE_FRIEND_REQUEST => {
                log::info!("→ Routing to FRIEND_REQUEST handler (separate channel)");
                // Friend requests routed to dedicated channel to avoid interference with message system
                // buf already includes type byte - no need to prepend
                if let Some(friend_tx) = FRIEND_REQUEST_TX.get() {
                    let tx_lock = friend_tx.lock().unwrap();
                    if let Err(e) = tx_lock.send(buf) {
                        log::error!("Failed to send friend request to channel: {}", e);
                    }
                } else {
                    log::warn!("Friend request channel not initialized - dropping message");
                }
            }
            MSG_TYPE_FRIEND_REQUEST_ACCEPTED => {
                log::info!("→ Routing to FRIEND_REQUEST_ACCEPTED handler (separate channel)");
                // Friend request accepted routed to dedicated channel to avoid interference with message system
                // buf already includes type byte at offset 0 so Kotlin can distinguish Phase 1 (0x07) from Phase 2 (0x08)
                if let Some(friend_tx) = FRIEND_REQUEST_TX.get() {
                    let tx_lock = friend_tx.lock().unwrap();
                    if let Err(e) = tx_lock.send(buf) { // Changed from constructing wire_data
                        log::error!("Failed to send friend request accepted to channel: {}", e);
                    }
                } else {
                    log::warn!("Friend request channel not initialized - dropping message");
                }
            }
            _ => {
                log::warn!("Unknown message type: 0x{:02x}, treating as PING", msg_type);

                // Default to Ping behavior for unknown types
                // BRIEF LOCK: Insert only, no async operations held
                {
                    let mut pending = PENDING_CONNECTIONS.lock().unwrap();
                    pending.insert(conn_id, PendingConnection {
                        socket,
                        encrypted_ping: buf.clone(),
                    });
                }

                ping_tx.send((conn_id, buf)).ok();
            }
        }

        Ok(())
    }

    /// Get the hidden service .onion address (if created)
    pub fn get_hidden_service_address(&self) -> Option<String> {
        self.hidden_service_address.clone()
    }

    /// Stop the hidden service listener (async to ensure proper cleanup)
    ///
    /// CRITICAL: This awaits the aborted task to ensure the TCP socket is fully released
    /// before returning. Without this, immediate rebind fails with EADDRINUSE.
    pub async fn stop_listener(&mut self) {
        if let Some(handle) = self.listener_handle.take() {
            log::info!("Aborting hidden service listener task...");
            handle.abort();

            // CRITICAL: Await the handle to ensure task is fully dropped and socket is released
            // This prevents EADDRINUSE when rebinding immediately after
            match handle.await {
                Ok(_) => log::info!("Hidden service listener exited cleanly"),
                Err(e) if e.is_cancelled() => log::info!("Hidden service listener aborted (cancelled)"),
                Err(e) => log::warn!("Hidden service listener aborted with error: {:?}", e),
            }

            // Clear bound port tracking
            self.bound_port = None;
        }

        // Close all pending connections (forces fresh circuits on restart)
        let mut pending = PENDING_CONNECTIONS.lock().unwrap();
        let count = pending.len();
        if count > 0 {
            log::info!("Closing {} pending connection(s) with stale circuits", count);
            pending.clear(); // Dropping TcpStream closes the socket
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
                log::info!("Deleted ephemeral service: {}", service_id);
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

    /// Check if SOCKS proxy is running by attempting a handshake
    ///
    /// CRITICAL: This does NOT try to CONNECT (which requires circuits).
    /// It only tests if the SOCKS proxy is listening and accepting connections.
    pub fn is_socks_proxy_running(&self) -> bool {
        use std::net::TcpStream;
        use std::io::{Write, Read};
        use std::time::Duration;

        match TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], self.socks_port)),
            Duration::from_millis(2000)
        ) {
            Ok(mut stream) => {
                // Set read timeout so we don't block forever
                if let Err(e) = stream.set_read_timeout(Some(Duration::from_millis(2000))) {
                    log::warn!("SOCKS health: Failed to set read timeout: {}", e);
                    return false;
                }

                // Send SOCKS5 version + auth request: [version=5, n_methods=1, method=0 (no auth)]
                let handshake = [0x05, 0x01, 0x00];
                if let Err(e) = stream.write_all(&handshake) {
                    log::warn!("SOCKS health: Failed to send handshake: {}", e);
                    return false;
                }

                // Read response: [version=5, chosen_method]
                let mut response = [0u8; 2];
                match stream.read_exact(&mut response) {
                    Ok(_) => {
                        if response[0] == 0x05 && response[1] == 0x00 {
                            log::debug!("SOCKS health: Proxy reachable and accepting connections (127.0.0.1:{})", self.socks_port);
                            true
                        } else {
                            log::warn!("SOCKS health: Unexpected handshake response: {:?}", response);
                            false
                        }
                    }
                    Err(e) => {
                        log::warn!("SOCKS health: Failed to read handshake response: {}", e);
                        false
                    }
                }
            }
            Err(e) => {
                log::warn!("SOCKS health: Cannot connect to 127.0.0.1:{} - {}", self.socks_port, e);
                false
            }
        }
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
                log::error!("Tor control port: Cannot connect - {}", e);
                log::error!("Tor daemon may not be running or control port disabled");
                return false;
            }
            Err(_) => {
                log::error!("Tor control port: Connection timeout");
                return false;
            }
        };

        // Authenticate (try NULL auth first, common on Android)
        if let Err(e) = stream.write_all(b"AUTHENTICATE\r\n").await {
            log::error!("Tor control port: Auth write failed - {}", e);
            return false;
        }

        let mut auth_response = vec![0u8; 512];
        let n = match timeout(Duration::from_secs(2), stream.read(&mut auth_response)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                log::error!("Tor control port: Auth read failed - {}", e);
                return false;
            }
            Err(_) => {
                log::error!("Tor control port: Auth timeout");
                return false;
            }
        };

        let auth_str = String::from_utf8_lossy(&auth_response[..n]);
        if !auth_str.starts_with("250") {
            log::error!("Tor control port: Auth failed - {}", auth_str.trim());
            return false;
        }

        // Query circuit status
        if let Err(e) = stream.write_all(b"GETINFO status/circuit-established\r\n").await {
            log::error!("Tor control port: Query write failed - {}", e);
            return false;
        }

        let mut response = vec![0u8; 512];
        let n = match timeout(Duration::from_secs(2), stream.read(&mut response)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                log::error!("Tor control port: Query read failed - {}", e);
                return false;
            }
            Err(_) => {
                log::error!("Tor control port: Query timeout");
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
            log::info!("Tor health check: PASSED (circuits established)");
            true
        } else {
            log::error!("Tor health check: FAILED (no circuits)");
            log::error!("Response: {}", response_str.trim());
            false
        }
    }

    /// Send Pong response back through pending connection and wait for message
    pub async fn send_pong_response(connection_id: u64, pong_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // Temporarily take the connection out to do async I/O (brief lock, then released)
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

                if msg_len > 10_000_000 { // 10MB limit (consistent with voice message support)
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
        // Take the connection out (brief lock, then released)
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

    /// Send NEWNYM signal to Tor via ControlPort
    /// Rotates Tor guards and circuits (rate-limited by Tor itself, ~10 seconds)
    /// Returns true on success, false if control port unavailable or command failed
    pub async fn send_newnym(&self) -> bool {
        let control = match self.control_stream.as_ref() {
            Some(c) => c,
            None => {
                log::warn!("Cannot send NEWNYM - control port not connected");
                return false;
            }
        };

        let mut stream = control.lock().await;

        // Send SIGNAL NEWNYM command
        if let Err(e) = stream.write_all(b"SIGNAL NEWNYM\r\n").await {
            log::error!("Failed to send NEWNYM command: {}", e);
            return false;
        }

        // Read response
        let mut buf = vec![0u8; 1024];
        let n = match stream.read(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                log::error!("Failed to read NEWNYM response: {}", e);
                return false;
            }
        };

        let response = String::from_utf8_lossy(&buf[..n]);

        // Check for success (250 OK) or rate-limiting (551)
        if response.contains("250 OK") {
            log::info!("NEWNYM signal sent successfully (Tor will rotate guards)");
            true
        } else if response.contains("551") {
            log::warn!("NEWNYM rate-limited by Tor (too soon since last NEWNYM)");
            false
        } else {
            log::error!("NEWNYM command failed: {}", response.trim());
            false
        }
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
