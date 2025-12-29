use jni::JNIEnv;
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};
use opus::{Application, Channels, Encoder as OpusEncoder, Decoder as OpusDecoder};
use std::sync::Mutex;

// Sample rate: 48kHz (Opus native rate)
const SAMPLE_RATE: u32 = 48000;
// Frame size: 20ms at 48kHz = 960 samples
const FRAME_SIZE: usize = 960;
// Channels: Mono
const CHANNELS: Channels = Channels::Mono;

/// Create Opus encoder
/// Returns encoder handle (pointer) or -1 on error
#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_opusEncoderCreate(
    _env: JNIEnv,
    _class: JClass,
    bitrate: jint,
) -> jlong {
    match OpusEncoder::new(SAMPLE_RATE, CHANNELS, Application::Voip) {
        Ok(mut encoder) => {
            // Set bitrate (default: 24kbps for voice)
            let target_bitrate = if bitrate > 0 { bitrate } else { 24000 };
            if let Err(e) = encoder.set_bitrate(opus::Bitrate::Bits(target_bitrate)) {
                log::error!("Failed to set Opus bitrate: {:?}", e);
                return -1;
            }

            log::info!("Opus encoder initialized: {}kbps (VOIP mode)", target_bitrate / 1000);

            // Convert to raw pointer and return as jlong
            let boxed = Box::new(Mutex::new(encoder));
            Box::into_raw(boxed) as jlong
        }
        Err(e) => {
            log::error!("Failed to create Opus encoder: {:?}", e);
            -1
        }
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
            let _ = Box::from_raw(handle as *mut Mutex<OpusEncoder>);
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

    // Get encoder
    let encoder_mutex = unsafe { &*(handle as *const Mutex<OpusEncoder>) };
    let mut encoder = match encoder_mutex.lock() {
        Ok(e) => e,
        Err(_) => return std::ptr::null_mut(),
    };

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

    // Encode
    let mut output = vec![0u8; 4000]; // Max Opus frame size
    match encoder.encode(&pcm_samples, &mut output) {
        Ok(size) => {
            output.truncate(size);
            match env.byte_array_from_slice(&output) {
                Ok(arr) => arr.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(e) => {
            log::error!("Opus encode error: {:?}", e);
            std::ptr::null_mut()
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
    match OpusDecoder::new(SAMPLE_RATE, CHANNELS) {
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

    // Decode
    let mut pcm_samples = vec![0i16; FRAME_SIZE * 6]; // Max size for potential FEC
    match decoder.decode(&opus_bytes, &mut pcm_samples, false) {
        Ok(size) => {
            pcm_samples.truncate(size);

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

    // Decode with FEC flag = true
    // This extracts the redundant copy of frame N from packet N+1
    let mut pcm_samples = vec![0i16; FRAME_SIZE * 6]; // Max size for potential FEC
    match decoder.decode(&opus_bytes, &mut pcm_samples, true) {
        Ok(size) => {
            pcm_samples.truncate(size);

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
