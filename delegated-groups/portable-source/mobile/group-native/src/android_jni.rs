use jni::{
    objects::{JByteArray, JObject},
    sys::jbyteArray,
    JNIEnv,
};
use secure_group_protocol::api::{MAX_API_LEN, MAX_RESULT_LEN};
use std::{panic::{catch_unwind, AssertUnwindSafe}, ptr};
use zeroize::Zeroizing;

const INITIAL_OUTPUT: usize = 64 * 1024;

fn fail(env: &mut JNIEnv, code: i32) -> jbyteArray {
    let _ = env.throw_new(
        "java/lang/IllegalStateException",
        format!("group protocol code {code}"),
    );
    ptr::null_mut()
}

fn optional_secret(env: &mut JNIEnv, value: JByteArray) -> Result<Option<Zeroizing<[u8; 32]>>, i32> {
    if value.is_null() {
        return Ok(None);
    }
    if env.get_array_length(&value).map_err(|_| -1)? != 32 {
        return Err(-1);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    let mut signed = Zeroizing::new([0i8; 32]);
    env.get_byte_array_region(&value, 0, &mut signed[..]).map_err(|_| -1)?;
    for (dst, src) in bytes.iter_mut().zip(signed.iter()) {
        *dst = *src as u8;
    }
    Ok(Some(bytes))
}

fn execute(
    env: &mut JNIEnv,
    request: JByteArray,
    signing_seed: JByteArray,
    group_key: JByteArray,
) -> Result<jbyteArray, i32> {
    if request.is_null() {
        return Err(-1);
    }
    let request_len = env.get_array_length(&request).map_err(|_| -1)? as usize;
    if request_len == 0 || request_len > MAX_API_LEN {
        return Err(-31);
    }
    let mut request_bytes = Zeroizing::new(env.convert_byte_array(&request).map_err(|_| -1)?);
    // The normal device adapter never acts as an account-root ratification oracle.
    let request_json: serde_json::Value = serde_json::from_slice(&request_bytes).map_err(|_| -30)?;
    if request_json.get("operation").and_then(serde_json::Value::as_str) == Some("ratify") {
        return Err(-32);
    }
    let seed = optional_secret(env, signing_seed)?;
    let key = optional_secret(env, group_key)?;
    let mut output = Zeroizing::new(vec![0u8; INITIAL_OUTPUT]);
    let mut output_len = output.len() as u32;
    let mut code = unsafe {
        super::group_ffi::sl_desktop_group_protocol(
            request_bytes.as_ptr(), request_bytes.len() as u32,
            seed.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            if seed.is_some() { 32 } else { 0 },
            key.as_ref().map_or(ptr::null(), |k| k.as_ptr()),
            if key.is_some() { 32 } else { 0 },
            output.as_mut_ptr(), &mut output_len,
        )
    };
    if code == -2 {
        if output_len as usize > MAX_RESULT_LEN || output_len == 0 {
            return Err(-31);
        }
        output.resize(output_len as usize, 0);
        code = unsafe {
            super::group_ffi::sl_desktop_group_protocol(
                request_bytes.as_ptr(), request_bytes.len() as u32,
                seed.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                if seed.is_some() { 32 } else { 0 },
                key.as_ref().map_or(ptr::null(), |k| k.as_ptr()),
                if key.is_some() { 32 } else { 0 },
                output.as_mut_ptr(), &mut output_len,
            )
        };
    }
    if code != 0 {
        return Err(code);
    }
    if output_len as usize > output.len() || output_len as usize > MAX_RESULT_LEN {
        return Err(-31);
    }
    request_bytes.fill(0);
    let result = env.byte_array_from_slice(&output[..output_len as usize]).map_err(|_| -1)?;
    Ok(result.into_raw())
}

#[no_mangle]
pub extern "system" fn Java_com_securelegion_crypto_DeviceGroupProtocolBridge_executeNative(
    mut env: JNIEnv,
    _object: JObject,
    request: JByteArray,
    signing_seed: JByteArray,
    group_key: JByteArray,
) -> jbyteArray {
    match catch_unwind(AssertUnwindSafe(|| execute(&mut env, request, signing_seed, group_key))) {
        Ok(Ok(result)) => result,
        Ok(Err(code)) => fail(&mut env, code),
        Err(_) => fail(&mut env, -1),
    }
}
