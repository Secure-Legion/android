//! Bounded Android bindings for the portable forward-secret own-device engine.
//! The caller must enforce the current signed roster before and after each call.

use jni::{objects::{JByteArray, JClass}, sys::{jbyteArray, jlong}, JNIEnv};
use std::ptr;
use zeroize::Zeroizing;

const MAX_REQUEST: usize = 1024 * 1024;

fn read_key(env: &mut JNIEnv, key: JByteArray) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let bytes = Zeroizing::new(env.convert_byte_array(key).map_err(|_| "invalid key")?);
    let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "invalid key length")?;
    Ok(Zeroizing::new(key))
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_syncFsNew(
    mut env: JNIEnv,
    _class: JClass,
    account: JByteArray,
    device_ed_seed: JByteArray,
    device_x_secret: JByteArray,
) -> jlong {
    let result = (|| {
        let account = read_key(&mut env, account)?;
        let ed = read_key(&mut env, device_ed_seed)?;
        let x = read_key(&mut env, device_x_secret)?;
        let handle = unsafe {
            secure_sync_fs::ffi::sl_sync_fs_new(account.as_ptr(), ed.as_ptr(), x.as_ptr())
        };
        if handle == 0 { Err("engine unavailable") } else { Ok(handle as jlong) }
    })();
    match result {
        Ok(handle) => handle,
        Err(reason) => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", reason);
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_syncFsCall(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    request: JByteArray,
) -> jbyteArray {
    if handle <= 0 {
        let _ = env.throw_new("java/lang/IllegalArgumentException", "invalid engine handle");
        return ptr::null_mut();
    }
    let request = match env.convert_byte_array(request) {
        Ok(value) if !value.is_empty() && value.len() <= MAX_REQUEST => Zeroizing::new(value),
        _ => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "invalid sync request");
            return ptr::null_mut();
        }
    };
    let mut output = Zeroizing::new(vec![0u8; MAX_REQUEST]);
    let mut output_len = output.len() as u32;
    let status = unsafe {
        secure_sync_fs::ffi::sl_sync_fs_call(
            handle as u64, request.as_ptr(), request.len() as u32,
            output.as_mut_ptr(), &mut output_len,
        )
    };
    if status != 0 {
        let _ = env.throw_new("java/lang/IllegalArgumentException", format!("sync rejected ({status})"));
        return ptr::null_mut();
    }
    match env.byte_array_from_slice(&output[..output_len as usize]) {
        Ok(bytes) => bytes.into_raw(),
        Err(_) => {
            let _ = env.throw_new("java/lang/IllegalStateException", "sync output failed");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_syncFsFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle > 0 {
        secure_sync_fs::ffi::sl_sync_fs_free(handle as u64);
    }
}
