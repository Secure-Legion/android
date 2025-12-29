/// Low-level Opus encoder CTL bridge
/// Provides access to opus_encoder_ctl() for settings not exposed by opus crate
use std::os::raw::{c_int, c_void};

// CTL request constants from opus_defines.h (DO NOT MODIFY - stable ABI)
// Source: https://opus-codec.org/docs/opus_api-1.3.1/group__opus__encoder.html
const OPUS_GET_APPLICATION_REQUEST: c_int = 4001;        // OPUS_GET_APPLICATION(x)
const OPUS_SET_BITRATE_REQUEST: c_int = 4002;            // OPUS_SET_BITRATE(x)
const OPUS_SET_COMPLEXITY_REQUEST: c_int = 4010;         // OPUS_SET_COMPLEXITY(x)
const OPUS_SET_INBAND_FEC_REQUEST: c_int = 4012;         // OPUS_SET_INBAND_FEC(x)
const OPUS_SET_PACKET_LOSS_PERC_REQUEST: c_int = 4014;   // OPUS_SET_PACKET_LOSS_PERC(x)
const OPUS_SET_DTX_REQUEST: c_int = 4016;                // OPUS_SET_DTX(x)

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
