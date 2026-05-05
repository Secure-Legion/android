/// Arti (Rust Tor) in-process client — replaces C Tor subprocess + control port.
///
/// Architecture:
///   - `initialize_arti()` creates a bootstrapped `TorClient` (stored globally)
///   - `connect_to_onion()` replaces SOCKS5 handshake with direct `client.connect()`
///   - `create_onion_service()` replaces `ADD_ONION` control port command
///   - Bootstrap events are streamed (no polling, no control port)
///   - Incoming connections come from `RendRequest` stream (no TCP listener)

use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::Mutex as StdMutex;
use std::time::SystemTime;
use once_cell::sync::Lazy;

use arti_client::TorClient;
use arti_client::config::TorClientConfigBuilder;
use tor_rtcompat::PreferredRuntime;
use tor_config_path::CfgPath;
use tor_hscrypto::pk::HsIdKeypair;
use tor_hsservice::{HsNickname, OnionServiceConfig, StreamRequest};
use tor_cell::relaycell::msg::Connected;
use tokio_util::sync::CancellationToken;
use futures::StreamExt;
use tor_proto::client::stream::ClientStreamCtrl;
use tor_linkspec::{HasAddrs, HasRelayIds};
use tor_netdir::{NetDirProvider, Timeliness};
use tor_geoip::HasCountryCode;
use tor_error::{ErrorReport as _, HasKind as _};

use crate::network::tor::{
    BOOTSTRAP_STATUS, CIRCUIT_ESTABLISHED, LAST_CIRCUIT_ESTABLISHED_MS,
    MESSAGE_TX, VOICE_TX, ACK_TX, FRIEND_REQUEST_TX, TAP_TX,
    CONNECTION_ID_COUNTER,
    touch_hs_accept_heartbeat, touch_hs_loop_heartbeat, reset_hs_heartbeats,
};
use crate::network::tor::{
    MSG_TYPE_PING, MSG_TYPE_PONG, MSG_TYPE_TEXT, MSG_TYPE_VOICE, MSG_TYPE_TAP,
    MSG_TYPE_DELIVERY_CONFIRMATION, MSG_TYPE_FRIEND_REQUEST, MSG_TYPE_FRIEND_REQUEST_ACCEPTED,
    MSG_TYPE_IMAGE, MSG_TYPE_PAYMENT_REQUEST, MSG_TYPE_PAYMENT_SENT, MSG_TYPE_PAYMENT_ACCEPTED,
    MSG_TYPE_CALL_SIGNALING, MSG_TYPE_STICKER, MSG_TYPE_PROFILE_UPDATE, MSG_TYPE_REACTION,
    MSG_TYPE_CRDT_OPS, MSG_TYPE_SYNC_HELLO, MSG_TYPE_SYNC_REQUEST, MSG_TYPE_SYNC_CHUNK, MSG_TYPE_SYNC_ACK,
    MSG_TYPE_ROUTING_UPDATE, MSG_TYPE_ROUTING_REQUEST,
    MSG_TYPE_CONTACT_LIST_REQUEST, MSG_TYPE_CONTACT_LIST_RESPONSE, MSG_TYPE_CONTACT_LIST_PUSH,
};
use crate::util::lock_recover;

const STALE_DIRECTORY_CACHE_SECS: u64 = 3 * 60 * 60;

#[derive(Debug, Clone)]
struct DirectoryCacheSnapshot {
    newest_path: String,
    newest_age_secs: u64,
    candidate_files: usize,
}

#[derive(Debug, Clone)]
struct StorageInventoryEntry {
    rel_path: String,
    size_bytes: u64,
    age_secs: u64,
    is_directory_cache_candidate: bool,
}

// ───── Global Arti State ─────

/// Stored Arti DataStreams from incoming connections, keyed by conn_id.
/// After reading a message, the stream is held here so Kotlin can write an ACK
/// back on the SAME connection (instant, no circuit setup).
/// Entries are cleaned up after 60s or when used.
static ARTI_PENDING_STREAMS: Lazy<StdMutex<std::collections::HashMap<u64, arti_client::DataStream>>> =
    Lazy::new(|| StdMutex::new(std::collections::HashMap::new()));

/// Write an ACK on a stored Arti stream, then remove it from the map.
pub async fn write_ack_on_stored_stream(conn_id: u64, wire_bytes: &[u8]) -> Result<(), String> {
    use futures::io::AsyncWriteExt as FuturesWriteExt;

    let mut stream = {
        let mut map: std::sync::MutexGuard<'_, std::collections::HashMap<u64, arti_client::DataStream>> =
            match ARTI_PENDING_STREAMS.lock() { Ok(g) => g, Err(p) => p.into_inner() };
        map.remove(&conn_id).ok_or_else(|| format!("no stored stream for conn_id={}", conn_id))?
    };

    let len = wire_bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await.map_err(|e| format!("write len failed: {}", e))?;
    stream.write_all(wire_bytes).await.map_err(|e| format!("write body failed: {}", e))?;
    stream.flush().await.map_err(|e| format!("flush failed: {}", e))?;

    log::info!("ACK_SAME_CONN: wrote {} bytes on conn_id={}", wire_bytes.len(), conn_id);
    Ok(())
}

/// Clean up stale stored streams. Caps at 50 entries.
pub fn cleanup_stale_streams() {
    let mut map: std::sync::MutexGuard<'_, std::collections::HashMap<u64, arti_client::DataStream>> =
        match ARTI_PENDING_STREAMS.lock() { Ok(g) => g, Err(p) => p.into_inner() };
    while map.len() > 50 {
        if let Some(&oldest_key) = map.keys().min() {
            map.remove(&oldest_key);
            log::debug!("ARTI_PENDING_STREAMS: pruned stale conn_id={}", oldest_key);
        }
    }
}

fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn is_directory_cache_candidate(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    name.contains("consensus")
        || name.contains("microdesc")
        || name.contains("netdir")
        || name.contains("cached-")
        || name.ends_with(".sqlite")
        || name.ends_with(".sqlite3")
        || name.ends_with(".db")
}

fn inspect_directory_cache(cache_dir: &str) -> Option<DirectoryCacheSnapshot> {
    fn visit(
        dir: &std::path::Path,
        best: &mut Option<(std::path::PathBuf, SystemTime)>,
        count: &mut usize,
    ) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                visit(&path, best, count);
                continue;
            }
            if !meta.is_file() || !is_directory_cache_candidate(&path) {
                continue;
            }
            let Ok(modified) = meta.modified() else { continue };
            *count += 1;
            match best {
                Some((_, best_time)) if modified <= *best_time => {}
                _ => *best = Some((path, modified)),
            }
        }
    }

    let mut best: Option<(std::path::PathBuf, SystemTime)> = None;
    let mut count = 0usize;
    visit(std::path::Path::new(cache_dir), &mut best, &mut count);

    let (path, modified) = best?;
    let newest_age_secs = SystemTime::now()
        .duration_since(modified)
        .unwrap_or_default()
        .as_secs();

    Some(DirectoryCacheSnapshot {
        newest_path: path.display().to_string(),
        newest_age_secs,
        candidate_files: count,
    })
}

fn log_directory_cache_snapshot(label: &str, cache_dir: &str) -> Option<DirectoryCacheSnapshot> {
    let snapshot = inspect_directory_cache(cache_dir);
    match snapshot.as_ref() {
        Some(s) => {
            log::info!(
                "Arti directory cache {}: newestAge={}s candidateFiles={} newest={}",
                label,
                s.newest_age_secs,
                s.candidate_files,
                s.newest_path
            );
        }
        None => {
            log::info!("Arti directory cache {}: no consensus/cache candidates in {}", label, cache_dir);
        }
    }
    snapshot
}

fn purge_directory_cache(cache_dir: &str) -> std::io::Result<()> {
    let path = std::path::Path::new(cache_dir);
    if !path.exists() {
        return Ok(());
    }

    let entries = std::fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        let entry_path = entry.path();
        let meta = entry.metadata()?;
        if meta.is_dir() {
            std::fs::remove_dir_all(&entry_path)?;
        } else {
            std::fs::remove_file(&entry_path)?;
        }
    }
    Ok(())
}

fn dir_exists_writable(dir: &str) -> (bool, bool) {
    let path = Path::new(dir);
    let exists = path.exists();
    let writable = if exists {
        let probe = path.join(".securelegion_diag_probe");
        let ok = std::fs::write(&probe, b"ok").is_ok();
        let _ = std::fs::remove_file(&probe);
        ok
    } else {
        false
    };
    (exists, writable)
}

fn collect_storage_inventory(root: &str, max_entries: usize) -> (usize, Vec<StorageInventoryEntry>) {
    fn visit(root: &Path, dir: &Path, entries: &mut Vec<StorageInventoryEntry>, total: &mut usize) {
        let Ok(read_dir) = std::fs::read_dir(dir) else { return };
        for item in read_dir.flatten() {
            let path = item.path();
            let Ok(meta) = item.metadata() else { continue };
            if meta.is_dir() {
                visit(root, &path, entries, total);
                continue;
            }
            if !meta.is_file() {
                continue;
            }

            *total += 1;
            let modified = meta.modified().ok();
            let age_secs = modified
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let rel_path = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            entries.push(StorageInventoryEntry {
                rel_path,
                size_bytes: meta.len(),
                age_secs,
                is_directory_cache_candidate: is_directory_cache_candidate(&path),
            });
        }
    }

    let root_path = Path::new(root);
    let mut total = 0usize;
    let mut entries = Vec::new();
    if root_path.exists() {
        visit(root_path, root_path, &mut entries, &mut total);
    }
    entries.sort_by_key(|entry| entry.age_secs);
    entries.truncate(max_entries);
    (total, entries)
}

fn append_storage_inventory(lines: &mut Vec<String>, label: &str, dir: &str) {
    let (exists, writable) = dir_exists_writable(dir);
    lines.push(format!("{}:exists={} writable={}", label, exists, writable));

    let (total, entries) = collect_storage_inventory(dir, 16);
    lines.push(format!(
        "{}_files_total={} showingNewest={}",
        label,
        total,
        entries.len()
    ));
    for entry in entries {
        lines.push(format!(
            "  {} {}B {}s candidate={}",
            entry.rel_path,
            entry.size_bytes,
            entry.age_secs,
            entry.is_directory_cache_candidate
        ));
    }
}

fn describe_error_chain(err: &(dyn Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(cause) = source {
        parts.push(format!("caused by: {}", cause));
        source = cause.source();
    }
    parts.join(" | ")
}

fn describe_arti_client_error(err: &arti_client::Error) -> String {
    let kind = err.kind();
    let detail = err.detail();
    let report = err.report().to_string().replace('\n', " | ");
    let chain = describe_error_chain(err);
    let desc_fetch_failure = is_descriptor_fetch_failure(err);
    format!(
        "kind={:?} detail={:?} desc_fetch_failure={} report={} chain={}",
        kind,
        detail,
        desc_fetch_failure,
        report,
        chain
    )
}

fn outbound_diagnostic_snapshot() -> String {
    let bootstrap = BOOTSTRAP_STATUS.load(Ordering::SeqCst);
    let circuit = CIRCUIT_ESTABLISHED.load(Ordering::SeqCst);
    let last_circuit_ms = LAST_CIRCUIT_ESTABLISHED_MS.load(Ordering::SeqCst);
    let last_circuit_age_ms = if last_circuit_ms == 0 {
        -1
    } else {
        now_millis().saturating_sub(last_circuit_ms) as i64
    };
    let pending_streams = lock_recover(&ARTI_PENDING_STREAMS).len();
    let hs_publisher = get_hs_publisher_status();

    format!(
        "bootstrap={} circuitEstablishedFlag={} lastCircuitAgeMs={} pendingStreams={} hsPublisher={}",
        bootstrap, circuit, last_circuit_age_ms, pending_streams, hs_publisher
    )
}

/// Last data dir passed to initialize_arti(), for diagnostics.
static ARTI_DATA_DIR: StdMutex<Option<String>> = StdMutex::new(None);
/// Whether the last bootstrap purged the directory cache.
static ARTI_LAST_PURGE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Collect targeted Arti diagnostics for Swift/SystemLogger.
/// Returns a compact multi-line string. No keys, descriptors, or full onion addresses.
pub fn arti_bootstrap_diagnostic() -> String {
    let data_dir = lock_recover(&ARTI_DATA_DIR).clone().unwrap_or_default();
    let state_dir = format!("{}/arti/state", data_dir);
    let cache_dir = format!("{}/arti/cache", data_dir);

    let mut lines = Vec::new();

    // Paths
    lines.push(format!("state_dir={}", state_dir));
    lines.push(format!("cache_dir={}", cache_dir));

    // Dir existence, writability, and recursive inventory. Names/sizes/ages only:
    // no descriptors, keys, consensus contents, or full onion addresses.
    append_storage_inventory(&mut lines, "state", &state_dir);
    append_storage_inventory(&mut lines, "cache", &cache_dir);

    // Bootstrap state
    let bootstrap = BOOTSTRAP_STATUS.load(Ordering::SeqCst);
    let circuit_flag = CIRCUIT_ESTABLISHED.load(Ordering::SeqCst);
    let last_ms = LAST_CIRCUIT_ESTABLISHED_MS.load(Ordering::SeqCst);
    let age_ms = if last_ms == 0 { -1i64 } else { now_millis().saturating_sub(last_ms) as i64 };
    let purged = ARTI_LAST_PURGE.load(Ordering::SeqCst);
    let client_exists = lock_recover(&ARTI_CLIENT).is_some();

    lines.push(format!(
        "bootstrap={} circuitEstablished={} lastCircuitAgeMs={} purgedOnLastInit={} clientExists={}",
        bootstrap, circuit_flag, age_ms, purged, client_exists
    ));

    // Cache snapshot
    if let Some(snap) = inspect_directory_cache(&cache_dir) {
        lines.push(format!("cacheNewestAgeSecs={} candidateFiles={}", snap.newest_age_secs, snap.candidate_files));
    } else {
        lines.push("cacheNewestAgeSecs=N/A candidateFiles=0".to_string());
    }

    lines.join("\n")
}

/// Purge only Arti's cache directory for diagnostics, leaving persistent state/keystore intact.
/// Call shutdown_arti() before this so Arti does not hold open sqlite/cache handles.
pub fn purge_arti_cache_for_data_dir(data_dir: &str) -> Result<String, String> {
    if lock_recover(&ARTI_CLIENT).is_some() {
        return Err("Arti client is still initialized; call shutdown before purging cache".to_string());
    }

    *lock_recover(&ARTI_DATA_DIR) = Some(data_dir.to_string());
    let cache_dir = format!("{}/arti/cache", data_dir);
    let before = inspect_directory_cache(&cache_dir);
    let (before_total, _) = collect_storage_inventory(&cache_dir, 0);

    purge_directory_cache(&cache_dir)
        .map_err(|e| format!("cache purge failed for {}: {}", cache_dir, e))?;
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("cache dir recreate failed for {}: {}", cache_dir, e))?;
    ARTI_LAST_PURGE.store(true, Ordering::SeqCst);

    let after = inspect_directory_cache(&cache_dir);
    let (after_total, _) = collect_storage_inventory(&cache_dir, 0);
    Ok(format!(
        "cache_dir={} beforeFiles={} beforeNewestAgeSecs={} afterFiles={} afterNewestAgeSecs={}",
        cache_dir,
        before_total,
        before
            .as_ref()
            .map(|s| s.newest_age_secs.to_string())
            .unwrap_or_else(|| "N/A".to_string()),
        after_total,
        after
            .as_ref()
            .map(|s| s.newest_age_secs.to_string())
            .unwrap_or_else(|| "N/A".to_string())
    ))
}

/// Classify an HS connect error as descriptor-fetch failure vs other.
pub fn is_descriptor_fetch_failure(err: &(dyn Error + 'static)) -> bool {
    let chain = describe_error_chain(err);
    chain.contains("Unable to download hidden service descriptor")
        || chain.contains("DescNotFound")
        || chain.contains("HsDirFetchError")
}

/// The in-process Arti TorClient — replaces C Tor subprocess entirely.
/// Uses Mutex<Option<>> instead of OnceCell so it can be reset on Android service restart.
/// Android may kill the service while the process survives — ARTI_CLIENT must be clearable
/// so initialize_arti() can create a fresh client with live circuits.
static ARTI_CLIENT: StdMutex<Option<Arc<TorClient<PreferredRuntime>>>> = StdMutex::new(None);

/// Serializes Arti initialization. Without this, a second initialize call can see
/// ARTI_CLIENT while the first call is finishing and tear down the fresh HS.
static ARTI_INIT_MUTEX: Lazy<tokio::sync::Mutex<()>> =
    Lazy::new(|| tokio::sync::Mutex::new(()));

/// Stored tokio runtime handle — captured during initialize_arti() (which runs inside
/// GLOBAL_RUNTIME.block_on()). Used by sync JNI functions that need to spawn async tasks
/// without being inside a tokio runtime context.
/// Resettable for the same reason as ARTI_CLIENT.
static RUNTIME_HANDLE: StdMutex<Option<tokio::runtime::Handle>> = StdMutex::new(None);

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

// ───── Per-Peer Failure Tracking (Stale Descriptor Recovery) ─────

/// Per-peer consecutive `arti_connect_to_onion` failure count, keyed by ".onion" string.
/// Reset on success. When the count crosses [PEER_FAIL_NEWNYM_THRESHOLD] we send NEWNYM
/// (rate-limited by [LAST_PEER_NEWNYM_SENT_MS]), forcing Arti to swap to a fresh isolated
/// client and re-fetch the peer's HS descriptor from a new HSDir.
///
/// This recovers the case where Arti has cached a peer's descriptor whose intro points
/// are dead — every retry hits the same bad intros and fails identically. Without this,
/// the only escape was a manual app restart.
static PEER_FAILURE_COUNTS: Lazy<StdMutex<std::collections::HashMap<String, u32>>> =
    Lazy::new(|| StdMutex::new(std::collections::HashMap::new()));

/// Threshold of consecutive `arti_connect_to_onion` failures (each failure = 3 internal
/// retry attempts already exhausted) before we trigger NEWNYM. With Kotlin's 30s Fast
/// retry loop, hitting this means ~90s of failed sends to the same peer.
const PEER_FAIL_NEWNYM_THRESHOLD: u32 = 3;

/// Last NEWNYM trigger timestamp (epoch ms). Throttle: don't NEWNYM more than once every
/// 60s no matter how many peers are failing — NEWNYM is global and disrupts working
/// circuits to OTHER peers.
static LAST_PEER_NEWNYM_SENT_MS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

const PEER_NEWNYM_COOLDOWN_MS: u64 = 60_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ───── Initialization ─────

/// Spawn an async task on the stored runtime handle.
/// Falls back to tokio::spawn if already inside a runtime context.
fn runtime_spawn<F>(future: F)
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    // Try current runtime first (works when called from block_on or another spawn)
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(future);
        return;
    }
    // Fall back to stored handle (for JNI calls from non-tokio threads)
    let guard = lock_recover(&RUNTIME_HANDLE);
    if let Some(handle) = guard.as_ref() {
        handle.spawn(future);
    } else {
        log::error!("runtime_spawn called before initialize_arti; dropping task");
    }
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
    let _init_guard = ARTI_INIT_MUTEX.lock().await;

    {
        let guard = lock_recover(&ARTI_CLIENT);
        if guard.is_some() {
            if BOOTSTRAP_STATUS.load(Ordering::SeqCst) >= 100 {
                log::info!("Arti already initialized and bootstrapped — reusing existing client");
                drop(guard);
                return Ok(());
            }

            log::warn!("Arti client exists but is not bootstrapped — forcing shutdown + re-init");
            drop(guard);
            shutdown_arti();
        } else {
            drop(guard);
        }
    }

    log::info!("Initializing Arti (in-process Tor)...");
    log::info!("Data directory: {}", data_dir);

    // Store data dir for diagnostics
    *lock_recover(&ARTI_DATA_DIR) = Some(data_dir.to_string());
    ARTI_LAST_PURGE.store(false, Ordering::SeqCst);

    // Capture the tokio runtime handle for later use by sync JNI functions.
    // This runs inside GLOBAL_RUNTIME.block_on(), so Handle::current() is valid.
    // Only set if None — overwriting could panic tasks still using the old handle.
    {
        let mut guard = lock_recover(&RUNTIME_HANDLE);
        if guard.is_none() {
            *guard = Some(tokio::runtime::Handle::current());
        }
    }

    let state_dir = format!("{}/arti/state", data_dir);
    let cache_dir = format!("{}/arti/cache", data_dir);

    // Ensure directories exist (including keystore)
    let keystore_dir = format!("{}/keystore", state_dir);
    std::fs::create_dir_all(&state_dir)?;
    std::fs::create_dir_all(&cache_dir)?;
    std::fs::create_dir_all(&keystore_dir)?;

    if let Some(snapshot) = log_directory_cache_snapshot("before bootstrap", &cache_dir) {
        if snapshot.newest_age_secs > STALE_DIRECTORY_CACHE_SECS {
            log::warn!(
                "Arti directory cache stale before bootstrap: newestAge={}s > {}s; purging cache to force fresh directory download",
                snapshot.newest_age_secs,
                STALE_DIRECTORY_CACHE_SECS
            );
            purge_directory_cache(&cache_dir)?;
            ARTI_LAST_PURGE.store(true, Ordering::SeqCst);
            std::fs::create_dir_all(&cache_dir)?;
            log_directory_cache_snapshot("after stale-cache purge", &cache_dir);
        }
    }

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

    // Pre-build circuits so HS intro points and outbound connections don't block on lazy construction.
    // Default is threshold=12, min_exit_circs=2. We raise both to have more circuits ready
    // for our 2 onion services (each needs 3 intro point circuits) + outbound .onion connections.
    config_builder.preemptive_circuits()
        .disable_at_threshold(16)
        .min_exit_circs_for_port(4);

    let config = config_builder.build()?;

    // Create client without blocking on bootstrap
    BOOTSTRAP_STATUS.store(5, Ordering::SeqCst);
    log::info!("Creating Arti client (unbootstrapped)...");

    let client = TorClient::builder()
        .config(config)
        .bootstrap_behavior(arti_client::BootstrapBehavior::Manual)
        .create_unbootstrapped()
        .map_err(|e| {
            let report = describe_arti_client_error(&e);
            log::error!("Arti client creation failed: {}", report);
            BOOTSTRAP_STATUS.store(0, Ordering::SeqCst);
            format!("Arti client creation failed: {}", report)
        })?;

    let client_arc = Arc::new(client);

    // Store client early so is_arti_ready() can check BOOTSTRAP_STATUS separately
    {
        let mut guard = lock_recover(&ARTI_CLIENT);
        *guard = Some(client_arc.clone());
    }

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
        let report = describe_arti_client_error(&e);
        log::error!("Arti bootstrap failed: {}", report);
        progress_done.store(true, Ordering::SeqCst);
        BOOTSTRAP_STATUS.store(0, Ordering::SeqCst);
        let mut guard = lock_recover(&ARTI_CLIENT);
        *guard = None;
        format!("Arti bootstrap failed: {}", report)
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
    if let Some(snapshot) = log_directory_cache_snapshot("after bootstrap", &cache_dir) {
        if snapshot.newest_age_secs > STALE_DIRECTORY_CACHE_SECS {
            log::warn!(
                "Arti directory cache still appears stale after bootstrap: newestAge={}s > {}s; next init will purge before bootstrap",
                snapshot.newest_age_secs,
                STALE_DIRECTORY_CACHE_SECS
            );
        }
    }

    Ok(())
}

/// Get the Arti client, if initialized.
pub fn get_arti_client() -> Option<Arc<TorClient<PreferredRuntime>>> {
    let guard = lock_recover(&ARTI_CLIENT);
    guard.clone()
}

/// Check if Arti is initialized and bootstrapped.
pub fn is_arti_ready() -> bool {
    let guard = lock_recover(&ARTI_CLIENT);
    guard.is_some() && BOOTSTRAP_STATUS.load(Ordering::SeqCst) >= 100
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
/// Guard for bootstrap listener — module-level so shutdown_arti() can reset it.
static BOOTSTRAP_LISTENER_RUNNING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn is_bootstrap_listener_running() -> bool {
    BOOTSTRAP_LISTENER_RUNNING.load(Ordering::SeqCst)
}

pub fn start_bootstrap_listener() {
    if BOOTSTRAP_LISTENER_RUNNING
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
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

            // Truthful readiness only: never convert "client exists" into
            // "bootstrapped". initialize_arti() sets BOOTSTRAP_STATUS=100 after
            // bootstrap().await completes. This listener is only a heartbeat/compat
            // shim for Kotlin now.
            if is_arti_ready() {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                LAST_CIRCUIT_ESTABLISHED_MS.store(now_ms, Ordering::SeqCst);
            }

            // Sleep 2s between checks (vs C Tor's 1s poll)
            std::thread::sleep(std::time::Duration::from_secs(2));
        }

        BOOTSTRAP_LISTENER_RUNNING.store(false, Ordering::SeqCst);
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

// ───── Circuit Introspection ─────

/// A single hop in the currently-displayed outbound circuit.
///
/// Role is assigned by position: index 0 = Entry, final index = Rendezvous Point
/// (for HS connections the terminal hop is always the rendezvous relay), all
/// others = Middle.
#[derive(Clone, Debug, serde::Serialize)]
struct HopInfo {
    role: String,
    /// Uppercase 40-char RSA identity hex (matches Tor's `$FINGERPRINT` format).
    fp: String,
    /// Relay nickname from the consensus router-status line. `None` when the
    /// NetDir is not available yet or the relay isn't listed.
    nickname: Option<String>,
    /// ISO-3166 two-letter country code from Arti's embedded GeoIP DB.
    country: Option<String>,
    /// First ORPort IP address (prefer IPv4 for display parity with iOS).
    /// Always populated for real relay hops; `None` only for virtual hops.
    ip: Option<String>,
}

/// Path of the most recent successful `client.connect()`. Displayed on the
/// Tor Health screen. Overwritten on every new outbound connection, so the
/// UI shows the user's current route.
static LAST_CIRCUIT_HOPS: StdMutex<Option<Vec<HopInfo>>> = StdMutex::new(None);

fn role_for_hop(i: usize, n: usize) -> &'static str {
    if n == 0 {
        "Hop"
    } else if i == 0 {
        "Entry Node"
    } else if i + 1 == n {
        "Rendezvous Point"
    } else {
        "Middle Node"
    }
}

/// Extract the circuit path from a freshly-connected DataStream, resolve
/// nickname + country via the NetDir, and cache the result in
/// `LAST_CIRCUIT_HOPS` for the UI to poll.
///
/// Silent on any failure — the UI falls back to "—" placeholders when no
/// data is cached yet.
fn capture_circuit_path(
    stream: &arti_client::DataStream,
    client: &TorClient<PreferredRuntime>,
) {
    let ctrl = match stream.client_stream_ctrl() {
        Some(c) => c,
        None => {
            log::warn!("capture_circuit_path: client_stream_ctrl=None (stream-ctrl feature off?)");
            return;
        }
    };
    let tunnel = match ctrl.tunnel() {
        Some(t) => t,
        None => {
            log::warn!("capture_circuit_path: tunnel=None (stream not attached)");
            return;
        }
    };
    let paths = tunnel.all_paths();
    log::info!("capture_circuit_path: all_paths.len()={}", paths.len());
    let path = match paths.first() {
        Some(p) => Arc::clone(p),
        None => {
            log::warn!("capture_circuit_path: all_paths empty");
            return;
        }
    };

    let hops = path.hops();
    let n = hops.len();
    log::info!("capture_circuit_path: hops={}", n);
    if n == 0 { return; }

    // Timely netdir is preferred; fall back to Unchecked so we still fill in
    // what we can when the consensus is borderline stale.
    let netdir = client
        .dirmgr()
        .netdir(Timeliness::Timely)
        .or_else(|_| client.dirmgr().netdir(Timeliness::Unchecked))
        .ok();

    let mut out: Vec<HopInfo> = Vec::with_capacity(n);
    for (i, entry) in hops.iter().enumerate() {
        let ct = match entry.as_chan_target() {
            Some(c) => c,
            None => continue, // virtual hop (e.g. the HS itself) — not a network relay
        };
        // `HasRelayIds::rsa_identity()` returns `Option<&RsaIdentity>`. In practice
        // every network-relay hop has one, but fall back to empty so a single
        // weirdly-built hop can't blank out the whole route card.
        let fp = ct
            .rsa_identity()
            .map(|id| id.as_hex_upper())
            .unwrap_or_default();

        // ORPort IP — prefer IPv4 for display parity with iOS, fall back to the
        // first address of any kind so we still surface *something* for v6-only
        // relays. Public info (lives in the consensus), no privacy leak to show it.
        let ip = {
            let mut v4: Option<String> = None;
            let mut any: Option<String> = None;
            for a in ct.addrs() {
                if any.is_none() { any = Some(a.ip().to_string()); }
                if a.is_ipv4() { v4 = Some(a.ip().to_string()); break; }
            }
            v4.or(any)
        };

        let (nickname, country) = if let Some(nd) = netdir.as_ref() {
            let relay = nd.by_ids(ct);
            let nick = relay.as_ref().map(|r| r.rs().nickname().to_string());
            let cc = relay
                .as_ref()
                .and_then(|r| r.country_code())
                .map(|c| format!("{}", c));
            (nick, cc)
        } else {
            (None, None)
        };

        out.push(HopInfo {
            role: role_for_hop(i, n).to_string(),
            fp,
            nickname,
            country,
            ip,
        });
    }

    log::info!(
        "capture_circuit_path: captured {} hops; sample nickname={:?} country={:?}",
        out.len(),
        out.first().and_then(|h| h.nickname.clone()),
        out.first().and_then(|h| h.country.clone())
    );
    let mut guard = lock_recover(&LAST_CIRCUIT_HOPS);
    *guard = Some(out);
}

/// JSON snapshot of the last captured outbound circuit, for Kotlin polling.
/// Shape: `{"hops":[{"role":..,"fp":..,"nickname":..,"country":..}]}`.
pub fn get_current_circuit_info_json() -> String {
    let guard = lock_recover(&LAST_CIRCUIT_HOPS);
    match guard.as_ref() {
        Some(hops) => serde_json::json!({ "hops": hops }).to_string(),
        None => "{\"hops\":[]}".to_string(),
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
    let client = lock_recover(&ARTI_CLIENT).clone().ok_or("Arti not initialized")?;

    const MAX_RETRIES: u32 = 3;
    const BACKOFF_SECS: [u64; 3] = [5, 10, 20];

    let mut last_err = String::new();
    if onion_address.to_ascii_lowercase().ends_with(".onion") {
        log::info!(
            "Arti HS descriptor mode for {}:{}: public_descriptor=true service_discovery_key=not_configured client_auth=none; client.connect() will use tor-hsclient HSDir descriptor fetch",
            onion_address,
            port
        );
    }

    for attempt in 0..MAX_RETRIES {
        let started = std::time::Instant::now();
        let snapshot = outbound_diagnostic_snapshot();
        log::info!(
            "Arti: connecting to {}:{} (attempt {}/{}) status=[{}]",
            onion_address,
            port,
            attempt + 1,
            MAX_RETRIES,
            snapshot
        );

        match client.connect((onion_address, port)).await {
            Ok(stream) => {
                let elapsed_ms = started.elapsed().as_millis();
                if attempt > 0 {
                    log::info!(
                        "Arti: connected to {}:{} after {} retries in {}ms",
                        onion_address,
                        port,
                        attempt,
                        elapsed_ms
                    );
                } else {
                    log::info!(
                        "Arti: connected to {}:{} in {}ms",
                        onion_address,
                        port,
                        elapsed_ms
                    );
                }
                // Success: clear any accumulated failure count for this peer.
                {
                    let mut counts = lock_recover(&PEER_FAILURE_COUNTS);
                    if counts.remove(onion_address).is_some() {
                        log::debug!("Arti: cleared failure counter for {} after successful connect", onion_address);
                    }
                }
                capture_circuit_path(&stream, &client);
                return Ok(ArtiStream {
                    stream,
                    onion_address: onion_address.to_string(),
                    port,
                });
            }
            Err(e) => {
                let elapsed_ms = started.elapsed().as_millis();
                last_err = describe_arti_client_error(&e);
                let detailed = format_arti_error_chain(&e);
                record_guard_failure_if_poisoned(&detailed);
                let is_desc_fail = is_descriptor_fetch_failure(&e);
                let onion_prefix = if onion_address.len() >= 12 {
                    &onion_address[..12]
                } else {
                    onion_address
                };
                log::warn!(
                    "Arti connect to {}...:{} attempt {}/{} failed after {}ms desc_fetch_fail={} err={} chain={} status=[{}]",
                    onion_prefix,
                    port,
                    attempt + 1,
                    MAX_RETRIES,
                    elapsed_ms,
                    is_desc_fail,
                    last_err,
                    detailed,
                    outbound_diagnostic_snapshot()
                );

                if attempt + 1 < MAX_RETRIES {
                    let delay = BACKOFF_SECS[attempt as usize];
                    log::info!("Arti: retrying {}...:{} in {}s", onion_prefix, port, delay);
                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
                }
            }
        }
    }

    log::error!("Arti connect to {}:{} failed after {} attempts: {}", onion_address, port, MAX_RETRIES, last_err);

    // Per-peer failure tracking: after PEER_FAIL_NEWNYM_THRESHOLD consecutive
    // top-level failures (i.e., 3*N internal attempts), trigger NEWNYM to swap to
    // a fresh isolated client + force a fresh HSDir lookup. Recovers the case
    // where Arti has cached a peer's descriptor whose intro points are dead.
    // Rate-limited via PEER_NEWNYM_COOLDOWN_MS so simultaneous failures across
    // multiple peers don't repeatedly disrupt working circuits.
    let new_count = {
        let mut counts = lock_recover(&PEER_FAILURE_COUNTS);
        let entry = counts.entry(onion_address.to_string()).or_insert(0);
        *entry += 1;
        *entry
    };

    if new_count >= PEER_FAIL_NEWNYM_THRESHOLD {
        let now = now_ms();
        let last_newnym = LAST_PEER_NEWNYM_SENT_MS.load(std::sync::atomic::Ordering::SeqCst);
        if now.saturating_sub(last_newnym) >= PEER_NEWNYM_COOLDOWN_MS {
            log::warn!(
                "Arti: {} consecutive failures to {} — sending NEWNYM to force fresh circuits + HSDir refresh",
                new_count, onion_address
            );
            LAST_PEER_NEWNYM_SENT_MS.store(now, std::sync::atomic::Ordering::SeqCst);
            send_newnym();
            // Reset only THIS peer's counter; counters for other still-failing peers
            // continue and may trigger their own NEWNYM after the cooldown.
            lock_recover(&PEER_FAILURE_COUNTS).remove(onion_address);
        } else {
            let remaining = PEER_NEWNYM_COOLDOWN_MS.saturating_sub(now.saturating_sub(last_newnym));
            log::warn!(
                "Arti: {} consecutive failures to {} — NEWNYM cooldown active ({}ms remaining)",
                new_count, onion_address, remaining
            );
        }
    }

    let final_status = outbound_diagnostic_snapshot();
    log::error!(
        "Arti connect to {}:{} failed after {} attempts: {} finalStatus=[{}]",
        onion_address,
        port,
        MAX_RETRIES,
        last_err,
        final_status
    );
    Err(format!("Arti connect failed: {}; finalStatus=[{}]", last_err, final_status).into())
}

/// Lightweight outbound connect/close probe used before risky sends to a peer
/// that has been failing repeatedly. Mirrors iOS `securelegion_arti_preflight_connect`.
///
/// Performs a single `client.connect()` on the peer's `.onion`, drops the resulting
/// stream immediately, and returns latency on success. Used by the Kotlin retry/send
/// path to gate full sends behind a cheap connectivity test — saves the cost of a
/// full PING+PONG+ACK exchange when the circuit graph to that peer is currently dead.
///
/// Returns:
/// - `Ok(latency_ms)` — connect succeeded within `timeout_ms`
/// - `Err("not_ready")` — Arti not bootstrapped
/// - `Err("timeout")` — connect did not complete within `timeout_ms`
/// - `Err(other)` — connect failed; string is `format_arti_error_chain` output
pub async fn arti_preflight_connect(
    onion_address: &str,
    port: u16,
    timeout_ms: u32,
) -> Result<u32, String> {
    if !is_arti_ready() {
        return Err("not_ready".to_string());
    }
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms.max(1) as u64),
        arti_connect_to_onion(onion_address, port),
    )
    .await;
    match result {
        Ok(Ok(_stream)) => {
            // Drop the ArtiStream → closes the underlying DataStream cleanly.
            let elapsed = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
            Ok(elapsed)
        }
        Ok(Err(e)) => {
            let chain = format_arti_error_chain(&*e);
            Err(chain)
        }
        Err(_) => Err("timeout".to_string()),
    }
}

/// Format an Arti error and its full source chain for diagnostic logs.
///
/// Walks `std::error::Error::source()` to expose nested errors, and includes
/// both Display (`{}`) and Debug (`{:?}`) at the top level. This is required
/// to surface Arti-internal variants like
/// `Guard(AllGuardsDown { n_accepted: 0, n_rejected: 60 })` and
/// `circuit_timeouts.json` references — those are only visible via Debug,
/// never via Display, so the shortened user-facing
/// `tor: Onion Service not found: Failed to obtain hidden service circuit`
/// string hides whether the underlying cause is a peer/offline descriptor
/// miss (normal) or local guard-state poisoning (recovery requires guard
/// reset, not just NEWNYM). See ARTI_GUARD_STATE_RESET_HANDOFF_ANDROID.md.
fn format_arti_error_chain<E: std::error::Error + ?Sized>(err: &E) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = write!(&mut out, "{}", err);
    let _ = write!(&mut out, " | debug={:?}", err);
    let mut src: Option<&(dyn std::error::Error)> = err.source();
    let mut depth = 1usize;
    while let Some(e) = src {
        let _ = write!(&mut out, " | source[{}]={} | source[{}]_debug={:?}", depth, e, depth, e);
        src = e.source();
        depth += 1;
        if depth > 8 { // prevent runaway logs from cyclic chains
            let _ = write!(&mut out, " | source_truncated_at_depth_{}", depth);
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Guard-poison auto-recovery state
// ---------------------------------------------------------------------------
//
// Tracks recent local-poison (`AllGuardsDown`) failures. After 3 in 60s and
// 180s since last reset, `should_auto_reset_guards()` returns true. Kotlin's
// TorService health monitor polls this on every tick.

static LAST_GUARD_RESET_AT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static RECENT_POISON_FAILURES: Lazy<StdMutex<std::collections::VecDeque<u64>>> =
    Lazy::new(|| StdMutex::new(std::collections::VecDeque::new()));

const POISON_WINDOW_MS: u64 = 60_000;
const POISON_THRESHOLD: usize = 3;
const RESET_COOLDOWN_MS: u64 = 180_000;

/// Append a poison-failure timestamp if the error text matches local guard
/// state poisoning. Pruned to the last `POISON_WINDOW_MS` ms on every call.
pub fn record_guard_failure_if_poisoned(error_text: &str) {
    if !is_arti_guard_state_poisoned(error_text) {
        return;
    }
    let now = now_ms();
    let mut q = RECENT_POISON_FAILURES.lock().unwrap_or_else(|e| e.into_inner());
    while let Some(&front) = q.front() {
        if now.saturating_sub(front) > POISON_WINDOW_MS {
            q.pop_front();
        } else {
            break;
        }
    }
    q.push_back(now);
    log::warn!(
        "Arti guard poison detected: {} failures in last {}s",
        q.len(),
        POISON_WINDOW_MS / 1000
    );
}

/// True when poison failures cross threshold AND cooldown has elapsed.
pub fn should_auto_reset_guards() -> bool {
    let now = now_ms();
    let last = LAST_GUARD_RESET_AT_MS.load(std::sync::atomic::Ordering::SeqCst);
    if now.saturating_sub(last) < RESET_COOLDOWN_MS {
        return false;
    }
    let q = RECENT_POISON_FAILURES.lock().unwrap_or_else(|e| e.into_inner());
    let recent = q
        .iter()
        .filter(|&&t| now.saturating_sub(t) <= POISON_WINDOW_MS)
        .count();
    recent >= POISON_THRESHOLD
}

/// Mark a reset as completed: stamps the cooldown and clears recent failures.
pub fn mark_guard_reset_done() {
    LAST_GUARD_RESET_AT_MS.store(now_ms(), std::sync::atomic::Ordering::SeqCst);
    let mut q = RECENT_POISON_FAILURES.lock().unwrap_or_else(|e| e.into_inner());
    q.clear();
    log::info!("Arti guard reset cooldown started");
}

/// Detects whether an Arti error string indicates locally-poisoned guard or
/// circuit-timeout state (vs. a normal peer-offline / descriptor-miss).
///
/// Triggers ONLY on hard local-state markers — not generic "not found" errors,
/// which are usually a peer that is offline or whose HSDir descriptor expired.
/// Used by Kotlin to escalate from NEWNYM to a full guard reset after repeated
/// failures. See ARTI_GUARD_STATE_RESET_HANDOFF_ANDROID.md.
pub fn is_arti_guard_state_poisoned(error: &str) -> bool {
    let text = error.to_ascii_lowercase();
    text.contains("allguardsdown")
        || text.contains("no usable guards")
        || text.contains("rejected 60/60")
        || text.contains("circuit_timeouts.json")
}

/// Result of `reset_arti_guard_state` — callable from Kotlin via JNI summary string.
#[derive(Debug, Default)]
pub struct ArtiResetSummary {
    pub state_files_removed: Vec<String>,
    pub state_files_failed: Vec<(String, String)>,
    pub cache_entries_removed: usize,
}

/// Reset Arti guard / circuit-timeout / dirmgr state, preserving identity material
/// (HS keystore, client keys). Caller MUST `shutdown_arti()` before this and
/// `initialize_arti()` after — this function only touches the on-disk files.
///
/// Deletes:
///   - `arti/state/**/guards*`
///   - `arti/state/**/circuit_timeouts*`
///   - `arti/state/**/bridges*`
///   - `arti/state/**/dirmgr*`
///   - All entries under `arti/cache/` (regenerable from network)
///
/// Preserves:
///   - `arti/state/keystore/` (hidden-service signing keys — losing these
///     would change the user's .onion address and orphan all their contacts)
///
/// Returns a summary listing files removed / failures.
pub fn reset_arti_guard_state(data_dir: &str) -> Result<ArtiResetSummary, String> {
    use std::fs;
    use std::path::Path;

    let state_dir = format!("{}/arti/state", data_dir);
    let cache_dir = format!("{}/arti/cache", data_dir);
    let mut summary = ArtiResetSummary::default();

    fn walk(dir: &std::path::Path, summary: &mut ArtiResetSummary) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                log::warn!("reset: read_dir {} failed: {}", dir.display(), e);
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                // PRESERVE keystore at any depth — holds HS signing keys
                if name == "keystore" || name == "client_keys" {
                    log::info!("reset: preserving keystore subdir at {}", path.display());
                    continue;
                }
                walk(&path, summary);
                continue;
            }
            let lower = name.to_ascii_lowercase();
            let target = lower.starts_with("guards")
                || lower.starts_with("circuit_timeouts")
                || lower.starts_with("bridges")
                || lower.starts_with("dirmgr");
            if !target {
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => summary.state_files_removed.push(path.display().to_string()),
                Err(e) => summary
                    .state_files_failed
                    .push((path.display().to_string(), e.to_string())),
            }
        }
    }

    if Path::new(&state_dir).exists() {
        walk(Path::new(&state_dir), &mut summary);
    }

    // Cache is fully regenerable — purge everything under it.
    if Path::new(&cache_dir).exists() {
        if let Ok(entries) = fs::read_dir(&cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let r = if path.is_dir() {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };
                if r.is_ok() {
                    summary.cache_entries_removed += 1;
                }
            }
        }
    }

    log::info!(
        "Arti guard reset: state_files_removed={} state_files_failed={} cache_entries_removed={}",
        summary.state_files_removed.len(),
        summary.state_files_failed.len(),
        summary.cache_entries_removed
    );

    mark_guard_reset_done();
    Ok(summary)
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

        if total_len > 6_291_456 {
            return Err("Message too large (>6MB)".into());
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
    let client = lock_recover(&ARTI_CLIENT).clone().ok_or("Arti not initialized")?;

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
    //
    // Retry on keystore-busy errors: Arti's async teardown after a prior stop_arti_listener
    // releases the keystore file lock asynchronously and can take several seconds. If we
    // give up early, the listener restart cycle livelocks — see TorService.kt:855.
    // 8 × 1.5s gives us a ~10s window; empirically Arti completes cleanup well within that.
    //
    // Both launch paths are retried per attempt because the same keystore-busy condition
    // surfaces as two different error strings depending on which internal path Arti takes:
    //   - "AlreadyLocked" when the state-dir lock file is still held
    //   - "bad API usage (bug): Error while trying to access a key store" when Arti's
    //     internal registration of the hsid hasn't been cleaned up yet
    const MAX_LAUNCH_ATTEMPTS: u32 = 8;
    const LAUNCH_RETRY_DELAY_MS: u64 = 1500;
    type HsTuple = (Arc<tor_hsservice::RunningOnionService>, Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin>);
    let is_retriable_launch_err = |es: &str| -> bool {
        es.contains("AlreadyLocked")
            || es.contains("bad API usage")
            || es.contains("key store")
    };
    let mut final_err: Option<String> = None;
    let mut launched: Option<HsTuple> = None;
    for attempt in 1..=MAX_LAUNCH_ATTEMPTS {
        // Rebuild keypair + config each attempt — both are consumed by launch.
        let ed_keypair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(ed25519_seed);
        let expanded = tor_llcrypto::pk::ed25519::ExpandedKeypair::from(&ed_keypair);
        let hsid_keypair = HsIdKeypair::from(expanded);
        let nickname = HsNickname::new(nickname_str.clone())
            .map_err(|e| format!("Invalid HS nickname: {}", e))?;
        let config = OnionServiceConfig::builder()
            .nickname(nickname)
            .build()
            .map_err(|e| format!("OnionServiceConfig build failed: {}", e))?;

        // First path: launch_onion_service_with_hsid (fresh key insert).
        let err_with_hsid = match client.launch_onion_service_with_hsid(config, hsid_keypair) {
            Ok(Some((svc, stream))) => {
                launched = Some((svc, Box::new(stream)));
                break;
            }
            Ok(None) => return Err("Onion service was disabled in config".into()),
            Err(e) => format!("{:?}", e),
        };

        // Fallback path: launch_onion_service (reads persisted key from keystore).
        let nickname2 = HsNickname::new(nickname_str.clone())
            .map_err(|e| format!("Invalid HS nickname: {}", e))?;
        let config2 = OnionServiceConfig::builder()
            .nickname(nickname2)
            .build()
            .map_err(|e| format!("OnionServiceConfig rebuild failed: {}", e))?;
        let err_fallback = match client.launch_onion_service(config2) {
            Ok(Some((svc, stream))) => {
                launched = Some((svc, Box::new(stream)));
                break;
            }
            Ok(None) => return Err("Onion service was disabled in config".into()),
            Err(e) => format!("{:?}", e),
        };

        // Both paths failed — retry if either error is retriable and we still have attempts.
        if (is_retriable_launch_err(&err_with_hsid) || is_retriable_launch_err(&err_fallback))
            && attempt < MAX_LAUNCH_ATTEMPTS
        {
            log::warn!(
                "Arti: messaging HS launch attempt {}/{} failed (with_hsid={}; fallback={}); retrying in {}ms",
                attempt, MAX_LAUNCH_ATTEMPTS, err_with_hsid, err_fallback, LAUNCH_RETRY_DELAY_MS
            );
            tokio::time::sleep(std::time::Duration::from_millis(LAUNCH_RETRY_DELAY_MS)).await;
            continue;
        }

        // Non-retriable or attempts exhausted — give up with both errors recorded.
        log::error!(
            "Arti: messaging HS launch failed after {} attempt(s). with_hsid={}; fallback={}",
            attempt, err_with_hsid, err_fallback
        );
        final_err = Some(format!(
            "launch_onion_service_with_hsid: {}; launch_onion_service: {}",
            err_with_hsid, err_fallback
        ));
        break;
    }
    let (running_service, rend_requests): HsTuple = launched
        .ok_or_else(|| final_err.unwrap_or_else(|| "Onion service launch failed".to_string()))?;

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

    // Spawn background task to monitor HS status until it reaches Running.
    //
    // IMPORTANT: hold the service as a Weak ref, not a cloned Arc. A strong clone here
    // would pin the RunningOnionService alive forever, so stop_arti_listener could not
    // release Arti's keystore lock on `sl-msg-<id>` and subsequent create_onion_service
    // calls would fail with "bad API usage (bug): Error while trying to access a key store"
    // followed by AlreadyLocked — livelocking the Kotlin watchdog restart cycle.
    //
    // status_events() returns a postage::watch::Receiver that is decoupled from the
    // service lifetime (src/status.rs:292) — safe to hold across awaits; yields None
    // when the sender side drops, which is our clean shutdown signal.
    let svc_weak = Arc::downgrade(&running_service);
    let addr_clone = expected_addr.clone();
    let mut events = running_service.status_events();
    runtime_spawn(async move {
        let mut was_running = false;
        loop {
            let Some(svc) = svc_weak.upgrade() else {
                log::info!("Arti: messaging HS status task exiting for {} (service dropped)", addr_clone);
                break;
            };
            let status = svc.status();
            let state = status.state();
            log::info!("Arti: messaging HS status update: state={:?} for {}", state, addr_clone);

            // Only set proof when HS is ACTUALLY Running — not just when onion_address exists.
            // onion_address().is_some() is true immediately after launch, which was the old
            // (broken) check that set proof_ok while HS was still Bootstrapping.
            //
            // Refresh on every Running sample. Android clears proof on network loss, and Arti
            // may recover the same RunningOnionService without relaunching this task.
            if state == tor_hsservice::status::State::Running {
                super::tor::set_tor_proof_ok();
                if !was_running {
                    log::info!("Arti: HS RUNNING for {} — set_tor_proof_ok()", addr_clone);
                } else {
                    log::debug!("Arti: HS still Running for {} — refreshed proof", addr_clone);
                }
                was_running = true;
            } else {
                was_running = false;
            }

            // Log degraded/broken states for debugging
            match state {
                tor_hsservice::status::State::Broken => {
                    log::error!("Arti: messaging HS is BROKEN for {} — needs restart", addr_clone);
                }
                tor_hsservice::status::State::DegradedUnreachable => {
                    log::warn!("Arti: messaging HS DEGRADED (unreachable) for {}", addr_clone);
                }
                tor_hsservice::status::State::Recovering => {
                    log::warn!("Arti: messaging HS RECOVERING for {}", addr_clone);
                }
                _ => {}
            }

            // Release the strong ref before awaiting so the service can actually be dropped
            // while we're parked on events.next() / sleep.
            drop(svc);

            // Wait for next status change, timeout after 60s, or stream end (service dropped).
            tokio::select! {
                event = events.next() => {
                    if event.is_none() {
                        log::info!("Arti: messaging HS status stream ended for {} — task exiting", addr_clone);
                        break;
                    }
                }
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
        // Prime the loop heartbeat so the watchdog sees the acceptor as alive.
        touch_hs_loop_heartbeat();

        // Convert RendRequest stream → StreamRequest stream
        // handle_rend_requests automatically accepts all rendezvous handshakes
        let mut stream_requests = tor_hsservice::handle_rend_requests(rend_requests);

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    log::info!("Arti: HS acceptor cancelled");
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                    // Periodic heartbeat tick — proves the select loop is alive even when
                    // no streams are arriving. Required for the Kotlin TorHealthMonitorWorker
                    // watchdog to detect a wedged acceptor (loop alive + accept stale → self-test).
                    touch_hs_loop_heartbeat();
                }
                maybe_req = stream_requests.next() => {
                    // Any wake on this branch means the loop is running — refresh the heartbeat.
                    touch_hs_loop_heartbeat();
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
        MSG_TYPE_CRDT_OPS | MSG_TYPE_SYNC_HELLO | MSG_TYPE_SYNC_REQUEST | MSG_TYPE_SYNC_CHUNK | MSG_TYPE_SYNC_ACK |
        MSG_TYPE_ROUTING_UPDATE | MSG_TYPE_ROUTING_REQUEST |
        MSG_TYPE_CONTACT_LIST_REQUEST | MSG_TYPE_CONTACT_LIST_RESPONSE | MSG_TYPE_CONTACT_LIST_PUSH => {}
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
        MSG_TYPE_CRDT_OPS | MSG_TYPE_SYNC_HELLO | MSG_TYPE_SYNC_REQUEST | MSG_TYPE_SYNC_CHUNK | MSG_TYPE_SYNC_ACK |
        MSG_TYPE_ROUTING_UPDATE | MSG_TYPE_ROUTING_REQUEST => 1 + 32 + 32 + sig_len,
        // Contact-list frames: type(1) + sender_pk(32) + timestamp(8) + cid_len(2) + cid(>=1) + sig(64)
        // = 108 minimum (no blob, 1-byte CID). contact_list_sync handles exact validation.
        MSG_TYPE_CONTACT_LIST_REQUEST | MSG_TYPE_CONTACT_LIST_RESPONSE | MSG_TYPE_CONTACT_LIST_PUSH
            => 1 + 32 + 8 + 2 + 1 + 64,
        _ => 1 + 32 + 16 + sig_len,
    };
    if buf.len() < min_wire_len {
        log::error!("ARTI WIRE_TOO_SHORT_DROP: type=0x{:02x}, len={} (min={})", msg_type, buf.len(), min_wire_len);
        return Err(format!("Wire message too short: {} bytes (min {})", buf.len(), min_wire_len).into());
    }

    // Per-type size caps (iOS parity): drop oversized payloads before routing
    match msg_type {
        MSG_TYPE_IMAGE if buf.len() > 4_194_304 => {
            log::warn!("ARTI IMAGE_TOO_LARGE_DROP: conn={} len={} (max 4MB)", conn_id, buf.len());
            return Err(format!("Image payload too large: {} bytes (max 4MB)", buf.len()).into());
        }
        MSG_TYPE_VOICE if buf.len() > 5_242_880 => {
            log::warn!("ARTI VOICE_TOO_LARGE_DROP: conn={} len={} (max 5MB)", conn_id, buf.len());
            return Err(format!("Voice payload too large: {} bytes (max 5MB)", buf.len()).into());
        }
        _ => {}
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
        MSG_TYPE_CRDT_OPS | MSG_TYPE_SYNC_HELLO | MSG_TYPE_SYNC_REQUEST | MSG_TYPE_SYNC_CHUNK | MSG_TYPE_SYNC_ACK |
        MSG_TYPE_ROUTING_UPDATE | MSG_TYPE_ROUTING_REQUEST => {
            log::info!("ARTI → MESSAGE handler (type=0x{:02x})", msg_type);

            // Store the stream for same-connection ACK reply (TEXT/VOICE/IMAGE/PAYMENT/STICKER).
            // Kotlin calls sendAckOnArtiStream(conn_id) → writes ACK on this stream → instant.
            // Falls back to outbound connection if stream is stale/dropped.
            let needs_ack = matches!(msg_type,
                MSG_TYPE_TEXT | MSG_TYPE_VOICE | MSG_TYPE_IMAGE |
                MSG_TYPE_PAYMENT_REQUEST | MSG_TYPE_PAYMENT_SENT | MSG_TYPE_PAYMENT_ACCEPTED |
                MSG_TYPE_STICKER
            );
            if needs_ack {
                let mut map: std::sync::MutexGuard<'_, std::collections::HashMap<u64, arti_client::DataStream>> =
                    match ARTI_PENDING_STREAMS.lock() { Ok(g) => g, Err(p) => p.into_inner() };
                map.insert(conn_id, stream);
                log::debug!("ARTI: stored stream conn_id={} for same-connection ACK ({} total)", conn_id, map.len());
            }

            if let Some(message_tx) = MESSAGE_TX.load_full() {
                let tx_lock = lock_recover(&message_tx);
                if let Err(e) = tx_lock.send((conn_id, buf)) {
                    log::error!("ARTI: Failed to send to MESSAGE channel: {}", e);
                } else {
                    crate::network::RX_MESSAGE_ACCEPT_COUNT.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                log::warn!("ARTI: MESSAGE channel not initialized");
                crate::network::RX_MESSAGE_TX_DROP_COUNT.fetch_add(1, Ordering::Relaxed);
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
        MSG_TYPE_CONTACT_LIST_REQUEST | MSG_TYPE_CONTACT_LIST_RESPONSE | MSG_TYPE_CONTACT_LIST_PUSH => {
            log::info!("ARTI → CONTACT_LIST_SYNC handler (type=0x{:02x})", msg_type);
            if let Err(e) = crate::network::contact_list_sync::handle_inbound(&buf) {
                log::warn!("ARTI CONTACT_LIST_SYNC drop: {}", e);
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

    let client = lock_recover(&ARTI_CLIENT).clone().ok_or("Arti not initialized")?;

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

    let client = lock_recover(&ARTI_CLIENT).clone().ok_or("Arti not initialized")?;

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

/// Tier 1 NEWNYM — lightweight identity rotation for new connections.
///
/// Swaps the global ARTI_CLIENT to an isolated clone. All NEW outbound connections
/// get fresh circuits that never share paths with the old client. Existing streams
/// on old circuits continue undisturbed (they hold their own Arc<TorClient>).
///
/// This is the correct Arti equivalent of C Tor's `SIGNAL NEWNYM`:
/// - isolated_client() creates a new IsolationToken (unique u64)
/// - Circuit manager won't reuse circuits across different isolation tokens
/// - No bootstrap cost, no teardown, no interruption to active streams
///
/// Use for: circuit suspicion, SOCKS failures, health monitor rotation, privacy rotation.
/// Do NOT use for: network changes (dead transport) — use notify_network_changed() instead.
pub fn send_newnym() {
    let mut guard = lock_recover(&ARTI_CLIENT);
    if let Some(ref client) = *guard {
        let isolated = Arc::new(client.isolated_client());
        *guard = Some(isolated);
        log::info!("Arti: NEWNYM — swapped to isolated client (fresh circuits for new connections)");
    } else {
        log::warn!("Arti: NEWNYM requested but client not initialized");
    }
}

/// Tier 2 network change — full teardown + reinit.
///
/// When the network transport changes (WiFi → LTE, offline → online), the underlying
/// TCP sockets and TLS channels are dead. isolated_client() won't help because even
/// new circuits would try to reuse dead channels. The only reliable recovery is to
/// drop the entire TorClient and bootstrap fresh.
///
/// This tears down all onion services, listeners, and circuits, then reinitializes.
/// Callers must re-create onion services after this returns.
///
/// Use for: WiFi/LTE switch, offline→online recovery, persistent failure escalation.
pub fn notify_network_changed() {
    let has_client = lock_recover(&ARTI_CLIENT).is_some();
    if has_client {
        log::info!("Arti: network change detected — full teardown + reinit required");
        // Signal to Kotlin that a full restart is needed.
        // We don't call shutdown_arti() + initialize_arti() here because
        // initialize_arti() is async and needs the data_dir from Kotlin.
        // Instead, reset bootstrap status so Kotlin's health monitor triggers restart.
        BOOTSTRAP_STATUS.store(0, Ordering::SeqCst);
        CIRCUIT_ESTABLISHED.store(0, Ordering::SeqCst);
        log::info!("Arti: bootstrap status reset to 0 — Kotlin health monitor will trigger full restart");
    } else {
        log::warn!("Arti: network change notified but client not initialized");
    }
}

// ───── Accessors ─────

/// Get the .onion address of the currently running messaging onion service.
pub fn get_onion_address() -> Option<String> {
    lock_recover(&ONION_ADDRESS).clone()
}

/// Stop the Arti HS acceptor task and release the onion service.
///
/// Dropping `RUNNING_HS` releases the Arti keystore lock on
/// `sl-msg-<addr>`; without this, the next `launch_onion_service_with_hsid`
/// fails with `StateDirectoryInaccessible(AlreadyLocked)` and the watchdog
/// can never recover the listener.
pub fn stop_arti_listener() {
    let cancel = {
        let mut guard = lock_recover(&HS_ACCEPTOR_CANCEL);
        guard.take()
    };
    if let Some(c) = cancel {
        c.cancel();
    }
    let dropped_hs = lock_recover(&RUNNING_HS).take().is_some();
    lock_recover(&REND_REQUEST_STREAM).take();
    log::info!("Arti: HS acceptor cancelled (dropped_hs={})", dropped_hs);
}

// ───── Full Shutdown (Android lifecycle) ─────

/// Fully shut down Arti: cancel all listeners, drop onion services, and clear the client.
///
/// MUST be called from Kotlin's onDestroy() / service teardown. Without this, Android can
/// kill the service while the process survives — leaving ARTI_CLIENT pointing at a zombie
/// TorClient with dead circuits. Since we now use Mutex<Option<>> instead of OnceCell,
/// this clears the slot so initialize_arti() can create a fresh client on restart.
pub fn shutdown_arti() {
    log::info!("Arti: shutdown_arti() — tearing down all state");

    // 1. Cancel all acceptor tasks
    stop_arti_listener();
    stop_fr_listener();
    stop_bootstrap_listener();

    // 2. Drop running onion services (stops descriptor publishing)
    {
        let mut guard = lock_recover(&RUNNING_HS);
        if guard.take().is_some() {
            log::info!("Arti: dropped messaging HS");
        }
    }
    {
        let mut guard = lock_recover(&RUNNING_VOICE_HS);
        if guard.take().is_some() {
            log::info!("Arti: dropped voice HS");
        }
    }
    {
        let mut guard = lock_recover(&RUNNING_FR_HS);
        if guard.take().is_some() {
            log::info!("Arti: dropped FR HS");
        }
    }

    // 3. Clear RendRequest streams
    {
        let mut guard = lock_recover(&REND_REQUEST_STREAM);
        *guard = None;
    }
    {
        let mut guard = lock_recover(&FR_REND_REQUEST_STREAM);
        *guard = None;
    }

    // 4. Clear onion addresses
    {
        let mut guard = lock_recover(&ONION_ADDRESS);
        *guard = None;
    }
    {
        let mut guard = lock_recover(&VOICE_ONION_ADDRESS);
        *guard = None;
    }
    {
        let mut guard = lock_recover(&FR_ONION_ADDRESS);
        *guard = None;
    }

    // 5. Drop the TorClient (closes all circuits, releases relay connections)
    {
        let mut guard = lock_recover(&ARTI_CLIENT);
        if guard.take().is_some() {
            log::info!("Arti: dropped TorClient");
        }
    }

    // 6. Clear runtime handle (will be re-captured on next initialize_arti)
    {
        let mut guard = lock_recover(&RUNTIME_HANDLE);
        *guard = None;
    }

    // 7. Reset bootstrap status and listener guard so the next init starts clean
    BOOTSTRAP_STATUS.store(0, Ordering::SeqCst);
    CIRCUIT_ESTABLISHED.store(0, Ordering::SeqCst);
    BOOTSTRAP_LISTENER_RUNNING.store(false, Ordering::SeqCst);

    log::info!("Arti: shutdown complete — ready for re-initialization");
}

// ───── Voice Onion Service ─────

/// Create a voice onion service using the same Arti client but a different Ed25519 seed.
///
/// This replaces the C Tor voice daemon (SingleOnion mode on port 9052).
/// Voice HS uses the same 3-hop anonymity as messaging (no SingleOnion in Arti).
pub async fn create_voice_onion_service(
    ed25519_seed: &[u8; 32],
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let client = lock_recover(&ARTI_CLIENT).clone().ok_or("Arti not initialized")?;

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
    let client = lock_recover(&ARTI_CLIENT).clone().ok_or("Arti not initialized")?;

    let expected_addr = super::tor::compute_onion_address_from_ed25519_seed(ed25519_seed);
    log::info!("Arti: creating friend-request onion service, expected address: {}", expected_addr);

    // Deterministic nickname tied to FR onion to avoid stale keystore alias/key mismatch.
    let nickname_str = format!("sl-fr-{}", &expected_addr[..12]);

    // Retry on keystore-busy errors — see create_onion_service for full rationale.
    // Both launch paths (with_hsid + fallback) are retried per attempt because the same
    // keystore-busy condition surfaces as either "AlreadyLocked" or "bad API usage".
    const FR_MAX_LAUNCH_ATTEMPTS: u32 = 8;
    const FR_LAUNCH_RETRY_DELAY_MS: u64 = 1500;
    type FrHsTuple = (Arc<tor_hsservice::RunningOnionService>, Box<dyn futures::Stream<Item = tor_hsservice::RendRequest> + Send + Unpin>);
    let fr_is_retriable_launch_err = |es: &str| -> bool {
        es.contains("AlreadyLocked")
            || es.contains("bad API usage")
            || es.contains("key store")
    };
    let mut final_err: Option<String> = None;
    let mut launched: Option<FrHsTuple> = None;
    for attempt in 1..=FR_MAX_LAUNCH_ATTEMPTS {
        let ed_keypair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(ed25519_seed);
        let expanded = tor_llcrypto::pk::ed25519::ExpandedKeypair::from(&ed_keypair);
        let hsid_keypair = HsIdKeypair::from(expanded);
        let nickname = HsNickname::new(nickname_str.clone())
            .map_err(|e| format!("Invalid FR HS nickname: {}", e))?;
        let config = OnionServiceConfig::builder()
            .nickname(nickname)
            .build()
            .map_err(|e| format!("FR OnionServiceConfig build failed: {}", e))?;

        // First path: launch_onion_service_with_hsid (fresh key insert).
        let err_with_hsid = match client.launch_onion_service_with_hsid(config, hsid_keypair) {
            Ok(Some((svc, stream))) => {
                launched = Some((svc, Box::new(stream)));
                break;
            }
            Ok(None) => return Err("FR onion service was disabled in config".into()),
            Err(e) => format!("{:?}", e),
        };

        // Fallback path: launch_onion_service (reads persisted key from keystore).
        let nickname2 = HsNickname::new(nickname_str.clone())
            .map_err(|e| format!("Invalid FR HS nickname: {}", e))?;
        let config2 = OnionServiceConfig::builder()
            .nickname(nickname2)
            .build()
            .map_err(|e| format!("FR OnionServiceConfig rebuild failed: {}", e))?;
        let err_fallback = match client.launch_onion_service(config2) {
            Ok(Some((svc, stream))) => {
                launched = Some((svc, Box::new(stream)));
                break;
            }
            Ok(None) => return Err("FR onion service was disabled in config".into()),
            Err(e) => format!("{:?}", e),
        };

        // Both paths failed — retry if either error is retriable and we still have attempts.
        if (fr_is_retriable_launch_err(&err_with_hsid) || fr_is_retriable_launch_err(&err_fallback))
            && attempt < FR_MAX_LAUNCH_ATTEMPTS
        {
            log::warn!(
                "Arti: FR HS launch attempt {}/{} failed (with_hsid={}; fallback={}); retrying in {}ms",
                attempt, FR_MAX_LAUNCH_ATTEMPTS, err_with_hsid, err_fallback, FR_LAUNCH_RETRY_DELAY_MS
            );
            tokio::time::sleep(std::time::Duration::from_millis(FR_LAUNCH_RETRY_DELAY_MS)).await;
            continue;
        }

        // Non-retriable or attempts exhausted — give up with both errors recorded.
        log::error!(
            "Arti: FR HS launch failed after {} attempt(s). with_hsid={}; fallback={}",
            attempt, err_with_hsid, err_fallback
        );
        final_err = Some(format!(
            "FR launch_onion_service_with_hsid: {}; FR launch_onion_service: {}",
            err_with_hsid, err_fallback
        ));
        break;
    }
    let (running_service, rend_requests): FrHsTuple = launched
        .ok_or_else(|| final_err.unwrap_or_else(|| "FR onion service launch failed".to_string()))?;

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

    // Spawn background task to monitor FR HS status.
    // See messaging HS status task above for why this MUST hold a Weak ref, not a cloned Arc.
    let fr_svc_weak = Arc::downgrade(&running_service);
    let fr_addr_clone = expected_addr.clone();
    let mut events = running_service.status_events();
    runtime_spawn(async move {
        loop {
            let Some(svc) = fr_svc_weak.upgrade() else {
                log::info!("Arti: FR HS status task exiting for {} (service dropped)", fr_addr_clone);
                break;
            };
            let status = svc.status();
            log::info!("Arti: FR HS status update: {:?} for {}", status, fr_addr_clone);
            drop(svc);
            tokio::select! {
                event = events.next() => {
                    if event.is_none() {
                        log::info!("Arti: FR HS status stream ended for {} — task exiting", fr_addr_clone);
                        break;
                    }
                }
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

/// Get the messaging HS publisher status for the in-process Arti client.
/// On iOS app-side Arti this will usually be "NotLaunched" because the app
/// only uses Arti for outbound transport; the NE hosts inbound onions.
pub fn get_hs_publisher_status() -> String {
    let guard = lock_recover(&RUNNING_HS);
    if let Some(service) = guard.as_ref() {
        format!("{:?}", service.status())
    } else {
        "NotLaunched".to_string()
    }
}

/// Stop the FR HS acceptor task and release the FR onion service.
///
/// See `stop_arti_listener` for why the Arc must be dropped here.
pub fn stop_fr_listener() {
    let cancel = {
        let mut guard = lock_recover(&FR_ACCEPTOR_CANCEL);
        guard.take()
    };
    if let Some(c) = cancel {
        c.cancel();
    }
    let dropped_hs = lock_recover(&RUNNING_FR_HS).take().is_some();
    lock_recover(&FR_REND_REQUEST_STREAM).take();
    log::info!("Arti: FR HS acceptor cancelled (dropped_hs={})", dropped_hs);
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
