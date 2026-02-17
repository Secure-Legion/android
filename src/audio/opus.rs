use jni::JNIEnv;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong, jstring};
use opus::{Decoder as OpusDecoder, Channels};
use std::sync::Mutex;
use std::ffi::CStr;
use std::os::raw::{c_void, c_int};

// Sample rate: 48kHz (Opus native rate)
const SAMPLE_RATE: i32 = 48000;
// Frame size: 40ms frames (MVP) = sample_rate / 25 = 48000 / 25 = 1920 samples
const FRAME_SIZE: usize = 1920;
// Channels: Mono
const CHANNELS: i32 = 1;

// Opus constants from opus_defines.h (stable across versions - do not change)
const OPUS_APPLICATION_VOIP: i32 = 2048;

// Raw libopus FFI
extern "C" {
    fn opus_encoder_create(
        fs: c_int,
        channels: c_int,
        application: c_int,
        error: *mut c_int,
    ) -> *mut c_void;

    fn opus_encoder_destroy(st: *mut c_void);

    fn opus_encode(
        st: *mut c_void,
        pcm: *const i16,
        frame_size: c_int,
        data: *mut u8,
        max_data_bytes: c_int,
    ) -> c_int;
}


/// Create Opus encoder with FEC, DTX, and optimized settings for Tor voice calls
/// Uses raw libopus FFI for full control - no unsafe transmute needed
/// Returns encoder handle (raw pointer) or -1 on error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_opusEncoderCreate(
    _env: JNIEnv,
    _class: JClass,
    bitrate: jint,
) -> jlong {
    unsafe {
        // Create encoder via raw libopus
        let mut error: c_int = 0;
        let encoder_ptr = opus_encoder_create(
            SAMPLE_RATE,
            CHANNELS,
            OPUS_APPLICATION_VOIP,
            &mut error as *mut c_int,
        );

        if encoder_ptr.is_null() || error != 0 {
            log::error!("Failed to create Opus encoder: error={}", error);
            return -1;
        }

        // Validate encoder pointer (sanity check)
        if !crate::audio::opus_ctl::validate_encoder_pointer(encoder_ptr) {
            log::error!("Encoder pointer validation failed after creation");
            opus_encoder_destroy(encoder_ptr);
            return -1;
        }

        // Set bitrate (32kbps CBR for high quality over Tor)
        let target_bitrate = if bitrate > 0 { bitrate } else { 32000 };
        if let Err(e) = crate::audio::opus_ctl::opus_set_bitrate(encoder_ptr, target_bitrate) {
            log::error!("Failed to set bitrate: error={}", e);
            opus_encoder_destroy(encoder_ptr);
            return -1;
        }

        // Enable FEC (Forward Error Correction) for packet loss recovery
        if let Err(e) = crate::audio::opus_ctl::opus_set_inband_fec(encoder_ptr, true) {
            log::error!("Failed to enable FEC: error={}", e);
            opus_encoder_destroy(encoder_ptr);
            return -1;
        }

        // Set expected packet loss percentage (25% for Tor - aggressive FEC)
        if let Err(e) = crate::audio::opus_ctl::opus_set_packet_loss_perc(encoder_ptr, 25) {
            log::error!("Failed to set packet loss percentage: error={}", e);
            opus_encoder_destroy(encoder_ptr);
            return -1;
        }

        // Disable DTX (Discontinuous Transmission) - send continuous audio for smoother Tor streaming
        let dtx_applied = match crate::audio::opus_ctl::opus_set_dtx(encoder_ptr, false) {
            Ok(_) => false,
            Err(e) => {
                log::warn!("Failed to disable DTX: error={} (non-fatal)", e);
                true // Assume DTX stayed enabled on error
            }
        };

        // Set signal type to VOICE (optimizes for speech characteristics)
        let signal_applied = match crate::audio::opus_ctl::opus_set_signal(encoder_ptr, true) {
            Ok(_) => true,
            Err(e) => {
                log::warn!("Failed to set VOICE signal: error={} (non-fatal)", e);
                false
            }
        };

        // Enable constrained VBR (prevents bitrate spikes over Tor)
        let vbr_applied = match crate::audio::opus_ctl::opus_set_vbr(encoder_ptr, true) {
            Ok(_) => {
                // Enable constraint for predictable bandwidth
                crate::audio::opus_ctl::opus_set_vbr_constraint(encoder_ptr, true).ok();
                true
            },
            Err(e) => {
                log::warn!("Failed to enable VBR: error={} (non-fatal)", e);
                false
            }
        };

        // Cap max bandwidth to WIDEBAND (8 kHz) for voice - saves bits
        let bandwidth_applied = match crate::audio::opus_ctl::opus_set_max_bandwidth(
            encoder_ptr,
            1103 // OPUS_BANDWIDTH_WIDEBAND
        ) {
            Ok(_) => true,
            Err(e) => {
                log::warn!("Failed to set max bandwidth: error={} (non-fatal)", e);
                false
            }
        };

        // Set complexity: 8 is mobile-safe (0-10 scale)
        let complexity_applied = match crate::audio::opus_ctl::opus_set_complexity(encoder_ptr, 8) {
            Ok(_) => true,
            Err(e) => {
                log::warn!("Failed to set complexity: error={} (non-fatal)", e);
                false
            }
        };

        // Validate encoder configuration
        if let Err(e) = crate::audio::opus_ctl::validate_encoder_config(
            encoder_ptr,
            SAMPLE_RATE,
            8000, // min bitrate
            128000 // max bitrate
        ) {
            log::error!("Encoder validation failed: {}", e);
            opus_encoder_destroy(encoder_ptr);
            return -1;
        }

        // Log final configuration
        crate::audio::opus_ctl::log_encoder_config(encoder_ptr);

        log::info!(
            "Opus encoder created: {}kbps | FEC=true | loss=25% | DTX={} | signal={} | VBR={} | BW=wideband | complexity={}",
            target_bitrate / 1000,
            if dtx_applied { "ON" } else { "OFF" },
            if signal_applied { "VOICE" } else { "AUTO" },
            if vbr_applied { "constrained" } else { "CBR" },
            complexity_applied
        );

        // Wrap in Mutex and return as jlong
        let boxed = Box::new(Mutex::new(encoder_ptr));
        Box::into_raw(boxed) as jlong
    }
}

/// Destroy Opus encoder
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_opusEncoderDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            let boxed = Box::from_raw(handle as *mut Mutex<*mut c_void>);
            let encoder_ptr = *boxed.lock().unwrap();
            if !encoder_ptr.is_null() {
                opus_encoder_destroy(encoder_ptr);
            }
        }
    }
}

/// Encode PCM audio to Opus
/// @param pcmData - 16-bit PCM audio samples
/// @return Opus-encoded bytes or null on error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_opusEncode(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    pcm_data: JByteArray,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    unsafe {
        // Get encoder pointer
        let encoder_mutex = &*(handle as *const Mutex<*mut c_void>);
        let encoder_ptr = match encoder_mutex.lock() {
            Ok(ptr) => *ptr,
            Err(_) => return std::ptr::null_mut(),
        };

        if encoder_ptr.is_null() {
            return std::ptr::null_mut();
        }

        // Convert JByteArray to Vec<u8>
        let pcm_bytes = match env.convert_byte_array(pcm_data) {
            Ok(bytes) => bytes,
            Err(_) => return std::ptr::null_mut(),
        };

        // Convert bytes to i16 samples
        let mut pcm_samples = vec![0i16; pcm_bytes.len() / 2];
        for (i, chunk) in pcm_bytes.chunks_exact(2).enumerate() {
            pcm_samples[i] = i16::from_le_bytes([chunk[0], chunk[1]]);
        }

        // Encode via raw FFI
        let mut output = vec![0u8; 4000]; // Max Opus frame size
        let size = opus_encode(
            encoder_ptr,
            pcm_samples.as_ptr(),
            FRAME_SIZE as c_int,
            output.as_mut_ptr(),
            output.len() as c_int,
        );

        if size < 0 {
            log::error!("Opus encode error: {}", size);
            return std::ptr::null_mut();
        }

        output.truncate(size as usize);
        match env.byte_array_from_slice(&output) {
            Ok(arr) => arr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

/// Create Opus decoder
/// Returns decoder handle (pointer) or -1 on error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_opusDecoderCreate(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    match OpusDecoder::new(SAMPLE_RATE as u32, Channels::Mono) {
        Ok(decoder) => {
            let boxed = Box::new(Mutex::new(decoder));
            Box::into_raw(boxed) as jlong
        }
        Err(e) => {
            log::error!("Failed to create Opus decoder: {:?}", e);
            -1
        }
    }
}

/// Destroy Opus decoder
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_opusDecoderDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            let _ = Box::from_raw(handle as *mut Mutex<OpusDecoder>);
        }
    }
}

/// Decode Opus to PCM audio
/// @param opusData - Opus-encoded bytes
/// @return 16-bit PCM audio samples or null on error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_opusDecode(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    opus_data: JByteArray,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    // Get decoder
    let decoder_mutex = unsafe { &*(handle as *const Mutex<OpusDecoder>) };
    let mut decoder = match decoder_mutex.lock() {
        Ok(d) => d,
        Err(_) => return std::ptr::null_mut(),
    };

    // Convert JByteArray to Vec<u8>
    let opus_bytes = match env.convert_byte_array(opus_data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    // Decode (limit to FRAME_SIZE for consistent 20ms frames)
    let mut pcm_samples = vec![0i16; FRAME_SIZE];
    match decoder.decode(&opus_bytes, &mut pcm_samples, false) {
        Ok(size) => {
            // CRITICAL FIX: PLC can return multiple frames (e.g., 5760 samples = 6 frames)
            // if decoder is trying to catch up. Always limit to FRAME_SIZE (960) for consistent timing.
            let actual_size = size.min(FRAME_SIZE);
            pcm_samples.truncate(actual_size);

            // Convert i16 samples to bytes
            let mut pcm_bytes = Vec::with_capacity(pcm_samples.len() * 2);
            for sample in pcm_samples {
                pcm_bytes.extend_from_slice(&sample.to_le_bytes());
            }

            match env.byte_array_from_slice(&pcm_bytes) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            log::error!("Opus decode error: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

/// Decode Opus with FEC to recover missing frame
/// @param opusData - Opus-encoded bytes of packet N+1
/// @return 16-bit PCM audio samples for the PREVIOUS frame (N) recovered via FEC, or null on error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_opusDecodeFEC(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    opus_data: JByteArray,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }

    // Get decoder
    let decoder_mutex = unsafe { &*(handle as *const Mutex<OpusDecoder>) };
    let mut decoder = match decoder_mutex.lock() {
        Ok(d) => d,
        Err(_) => return std::ptr::null_mut(),
    };

    // Convert JByteArray to Vec<u8>
    let opus_bytes = match env.convert_byte_array(opus_data) {
        Ok(bytes) => bytes,
        Err(_) => return std::ptr::null_mut(),
    };

    // Decode with FEC flag = true (limit to FRAME_SIZE for consistent 20ms frames)
    // This extracts the redundant copy of frame N from packet N+1
    let mut pcm_samples = vec![0i16; FRAME_SIZE];
    match decoder.decode(&opus_bytes, &mut pcm_samples, true) {
        Ok(size) => {
            // CRITICAL FIX: Limit to FRAME_SIZE for consistent timing (same as regular decode)
            let actual_size = size.min(FRAME_SIZE);
            pcm_samples.truncate(actual_size);

            // Convert i16 samples to bytes
            let mut pcm_bytes = Vec::with_capacity(pcm_samples.len() * 2);
            for sample in pcm_samples {
                pcm_bytes.extend_from_slice(&sample.to_le_bytes());
            }

            match env.byte_array_from_slice(&pcm_bytes) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            log::error!("Opus FEC decode error: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

// External C function from libopus
extern "C" {
    fn opus_get_version_string() -> *const std::os::raw::c_char;
}

/// Get Opus library version string
/// Returns string like "libopus 1.4" or "libopus 1.6"
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_getOpusVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    unsafe {
        let version_ptr = opus_get_version_string();
        if version_ptr.is_null() {
            return std::ptr::null_mut();
        }

        let version_cstr = CStr::from_ptr(version_ptr);
        let version_str = match version_cstr.to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };

        log::info!("Opus version: {}", version_str);

        match env.new_string(version_str) {
            Ok(jstr) => jstr.into_raw(),
            Err(_) => std::ptr::null_mut(),
        }
    }
}
