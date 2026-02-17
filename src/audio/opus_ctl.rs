/// Low-level Opus encoder CTL bridge
/// Provides access to opus_encoder_ctl() for settings not exposed by opus crate
use std::os::raw::{c_int, c_void};

// CTL request constants from opus_defines.h (DO NOT MODIFY - stable ABI)
// Source: https://opus-codec.org/docs/opus_api-1.3.1/group__opus__encoder.html

// GET requests (for validation)
const OPUS_GET_APPLICATION_REQUEST: c_int = 4001; // OPUS_GET_APPLICATION(x)
const OPUS_GET_BITRATE_REQUEST: c_int = 4003; // OPUS_GET_BITRATE(x)
const OPUS_GET_SAMPLE_RATE_REQUEST: c_int = 4029; // OPUS_GET_SAMPLE_RATE(x)
const OPUS_GET_INBAND_FEC_REQUEST: c_int = 4013; // OPUS_GET_INBAND_FEC(x)
const OPUS_GET_PACKET_LOSS_PERC_REQUEST: c_int = 4015; // OPUS_GET_PACKET_LOSS_PERC(x)
const OPUS_GET_DTX_REQUEST: c_int = 4017; // OPUS_GET_DTX(x)
const OPUS_GET_VBR_REQUEST: c_int = 4007; // OPUS_GET_VBR(x)
const OPUS_GET_BANDWIDTH_REQUEST: c_int = 4009; // OPUS_GET_BANDWIDTH(x)

// SET requests
const OPUS_SET_BITRATE_REQUEST: c_int = 4002; // OPUS_SET_BITRATE(x)
const OPUS_SET_COMPLEXITY_REQUEST: c_int = 4010; // OPUS_SET_COMPLEXITY(x)
const OPUS_SET_INBAND_FEC_REQUEST: c_int = 4012; // OPUS_SET_INBAND_FEC(x)
const OPUS_SET_PACKET_LOSS_PERC_REQUEST: c_int = 4014; // OPUS_SET_PACKET_LOSS_PERC(x)
const OPUS_SET_DTX_REQUEST: c_int = 4016; // OPUS_SET_DTX(x)
const OPUS_SET_SIGNAL_REQUEST: c_int = 4024; // OPUS_SET_SIGNAL(x)
const OPUS_SET_VBR_REQUEST: c_int = 4006; // OPUS_SET_VBR(x)
const OPUS_SET_VBR_CONSTRAINT_REQUEST: c_int = 4020; // OPUS_SET_VBR_CONSTRAINT(x)
const OPUS_SET_MAX_BANDWIDTH_REQUEST: c_int = 4004; // OPUS_SET_MAX_BANDWIDTH(x)

// Signal type constants
const OPUS_SIGNAL_VOICE: c_int = 3001; // Optimize for voice
const OPUS_SIGNAL_MUSIC: c_int = 3002; // Optimize for music

// Bandwidth constants
const OPUS_BANDWIDTH_NARROWBAND: c_int = 1101; // 4 kHz
const OPUS_BANDWIDTH_MEDIUMBAND: c_int = 1102; // 6 kHz
const OPUS_BANDWIDTH_WIDEBAND: c_int = 1103; // 8 kHz
const OPUS_BANDWIDTH_SUPERWIDEBAND: c_int = 1104; // 12 kHz
const OPUS_BANDWIDTH_FULLBAND: c_int = 1105; // 20 kHz

extern "C" {
    /// Raw libopus encoder control function
    /// Takes variadic arguments - caller must match the request type
    fn opus_encoder_ctl(st: *mut c_void, request: c_int, ...) -> c_int;
}

/// Validate that the encoder pointer is valid and usable
/// Returns true if pointer appears to be a valid OpusEncoder
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn validate_encoder_pointer(encoder_ptr: *mut c_void) -> bool {
    if encoder_ptr.is_null() {
        log::error!("Encoder pointer validation FAILED: null pointer");
        return false;
    }

    // Try to read the application type (should be VOIP = 2048)
    let mut application: c_int = 0;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_GET_APPLICATION_REQUEST, &mut application as *mut c_int);

    if rc != 0 {
        log::error!("Encoder pointer validation FAILED: GET_APPLICATION returned error {}", rc);
        return false;
    }

    // Application should be VOIP (2048), Audio (2049), or Restricted Low Delay (2051)
    if application < 2048 || application > 2051 {
        log::error!("Encoder pointer validation FAILED: invalid application type {}", application);
        return false;
    }

    log::debug!("Encoder pointer validation PASSED: application={}", application);
    true
}

/// Set encoder bitrate in bits per second
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_bitrate(encoder_ptr: *mut c_void, bitrate: i32) -> Result<(), i32> {
    let v: c_int = bitrate as c_int;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_BITRATE_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Enable/disable in-band Forward Error Correction (FEC)
/// FEC adds redundancy to recover from packet loss
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_inband_fec(encoder_ptr: *mut c_void, enabled: bool) -> Result<(), i32> {
    let v: c_int = if enabled { 1 } else { 0 };
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_INBAND_FEC_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Set expected packet loss percentage (0-100)
/// Hints to encoder to add more redundancy for lossy networks
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_packet_loss_perc(encoder_ptr: *mut c_void, loss_perc: i32) -> Result<(), i32> {
    let v: c_int = loss_perc.clamp(0, 100) as c_int;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_PACKET_LOSS_PERC_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Set DTX (Discontinuous Transmission) on/off
/// DTX saves bandwidth by not transmitting during silence periods
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_dtx(encoder_ptr: *mut c_void, enabled: bool) -> Result<(), i32> {
    let v: c_int = if enabled { 1 } else { 0 };
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_DTX_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Set encoder complexity (0-10 scale)
/// Higher complexity = better quality but more CPU
/// Recommended: 8 for mobile devices (good quality/CPU balance)
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_complexity(encoder_ptr: *mut c_void, complexity: i32) -> Result<(), i32> {
    let v: c_int = complexity.clamp(0, 10) as c_int;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_COMPLEXITY_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Set signal type hint (VOICE or MUSIC)
/// Optimizes encoder for the type of audio being encoded
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_signal(encoder_ptr: *mut c_void, is_voice: bool) -> Result<(), i32> {
    let v: c_int = if is_voice { OPUS_SIGNAL_VOICE } else { OPUS_SIGNAL_MUSIC };
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_SIGNAL_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Enable/disable Variable Bitrate (VBR)
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_vbr(encoder_ptr: *mut c_void, enabled: bool) -> Result<(), i32> {
    let v: c_int = if enabled { 1 } else { 0 };
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_VBR_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Enable/disable Constrained VBR
/// Keeps VBR more predictable (less bitrate spikes)
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_vbr_constraint(encoder_ptr: *mut c_void, enabled: bool) -> Result<(), i32> {
    let v: c_int = if enabled { 1 } else { 0 };
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_VBR_CONSTRAINT_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// Set maximum bandwidth
/// Limits audio bandwidth to save bits (e.g., WIDEBAND = 8 kHz for voice)
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_set_max_bandwidth(encoder_ptr: *mut c_void, bandwidth: i32) -> Result<(), i32> {
    let v: c_int = bandwidth as c_int;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_SET_MAX_BANDWIDTH_REQUEST, v);
    if rc == 0 { Ok(()) } else { Err(rc) }
}

// ============================================================================
// GET functions (for validation and debugging)
// ============================================================================

/// Get current encoder bitrate
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_get_bitrate(encoder_ptr: *mut c_void) -> Result<i32, i32> {
    let mut value: c_int = 0;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_GET_BITRATE_REQUEST, &mut value as *mut c_int);
    if rc == 0 { Ok(value as i32) } else { Err(rc) }
}

/// Get encoder sample rate
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_get_sample_rate(encoder_ptr: *mut c_void) -> Result<i32, i32> {
    let mut value: c_int = 0;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_GET_SAMPLE_RATE_REQUEST, &mut value as *mut c_int);
    if rc == 0 { Ok(value as i32) } else { Err(rc) }
}

/// Get FEC enabled status
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_get_inband_fec(encoder_ptr: *mut c_void) -> Result<bool, i32> {
    let mut value: c_int = 0;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_GET_INBAND_FEC_REQUEST, &mut value as *mut c_int);
    if rc == 0 { Ok(value != 0) } else { Err(rc) }
}

/// Get packet loss percentage
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_get_packet_loss_perc(encoder_ptr: *mut c_void) -> Result<i32, i32> {
    let mut value: c_int = 0;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_GET_PACKET_LOSS_PERC_REQUEST, &mut value as *mut c_int);
    if rc == 0 { Ok(value as i32) } else { Err(rc) }
}

/// Get DTX enabled status
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn opus_get_dtx(encoder_ptr: *mut c_void) -> Result<bool, i32> {
    let mut value: c_int = 0;
    let rc = opus_encoder_ctl(encoder_ptr, OPUS_GET_DTX_REQUEST, &mut value as *mut c_int);
    if rc == 0 { Ok(value != 0) } else { Err(rc) }
}

// ============================================================================
// Validation functions
// ============================================================================

/// Validate encoder configuration and health
/// Catches silent misconfig and drift
///
/// Checks:
/// - Encoder pointer is non-null
/// - Sample rate matches expected (48000 Hz)
/// - Bitrate is in sane range (8000-128000)
/// - FEC/packet loss settings are consistent
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn validate_encoder_config(
    encoder_ptr: *mut c_void,
    expected_sample_rate: i32,
    min_bitrate: i32,
    max_bitrate: i32
) -> Result<(), String> {
    if encoder_ptr.is_null() {
        return Err("Encoder pointer is null".to_string());
    }

    // Validate sample rate
    match opus_get_sample_rate(encoder_ptr) {
        Ok(rate) => {
            if rate != expected_sample_rate {
                return Err(format!(
                    "Sample rate mismatch: expected {}, got {}",
                    expected_sample_rate, rate
                ));
            }
        }
        Err(e) => return Err(format!("Failed to get sample rate: error {}", e)),
    }

    // Validate bitrate range
    match opus_get_bitrate(encoder_ptr) {
        Ok(bitrate) => {
            if bitrate < min_bitrate || bitrate > max_bitrate {
                return Err(format!(
                    "Bitrate out of range: {} (expected {}-{})",
                    bitrate, min_bitrate, max_bitrate
                ));
            }
        }
        Err(e) => return Err(format!("Failed to get bitrate: error {}", e)),
    }

    // Validate FEC configuration
    match opus_get_inband_fec(encoder_ptr) {
        Ok(fec_enabled) => {
            if let Ok(loss_perc) = opus_get_packet_loss_perc(encoder_ptr) {
                if loss_perc < 0 || loss_perc > 100 {
                    return Err(format!("Packet loss % out of range: {}", loss_perc));
                }
                // Warn if FEC disabled but high loss expected (might be intentional)
                if !fec_enabled && loss_perc > 15 {
                    log::warn!(
                        "FEC disabled but packet loss set to {}% (usually want FEC enabled)",
                        loss_perc
                    );
                }
            }
        }
        Err(e) => return Err(format!("Failed to get FEC status: error {}", e)),
    }

    // Validate DTX
    match opus_get_dtx(encoder_ptr) {
        Ok(dtx_enabled) => {
            if dtx_enabled {
                log::warn!("DTX is enabled - may cause gaps in Tor audio streaming");
            }
        }
        Err(e) => return Err(format!("Failed to get DTX status: error {}", e)),
    }

    Ok(())
}

/// Log current encoder configuration for debugging
///
/// # Safety
/// encoder_ptr must be a valid OpusEncoder* obtained from opus_encoder_create
pub unsafe fn log_encoder_config(encoder_ptr: *mut c_void) {
    log::info!("=== Opus Encoder Configuration ===");

    if let Ok(rate) = opus_get_sample_rate(encoder_ptr) {
        log::info!("Sample Rate: {} Hz", rate);
    }
    if let Ok(bitrate) = opus_get_bitrate(encoder_ptr) {
        log::info!("Bitrate: {} kbps", bitrate / 1000);
    }
    if let Ok(fec) = opus_get_inband_fec(encoder_ptr) {
        log::info!("FEC Enabled: {}", fec);
    }
    if let Ok(loss) = opus_get_packet_loss_perc(encoder_ptr) {
        log::info!("Packet Loss %: {}", loss);
    }
    if let Ok(dtx) = opus_get_dtx(encoder_ptr) {
        log::info!("DTX Enabled: {}", dtx);
    }

    log::info!("===================================");
}
