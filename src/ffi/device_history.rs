//! Canonical build-48 history identity. Output is digest[32] || event_id[32]
//! || canonical delta; the caller persists only after roster authorization.
use jni::{objects::{JByteArray, JClass, JString}, sys::{jbyteArray, jlong}, JNIEnv};
use std::{panic::{catch_unwind, AssertUnwindSafe}, ptr};

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_deviceHistoryIdentity(
    mut env: JNIEnv,
    _class: JClass,
    delta: JByteArray,
    topic: JString,
    object_id: JString,
    event_ts: jlong,
) -> jbyteArray {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let length = env.get_array_length(&delta).map_err(|_| ())? as usize;
        if length == 0 || length > secure_device_protocol::history::MAX_GROUP_DELTA {
            return Err(());
        }
        let delta = env.convert_byte_array(delta).map_err(|_| ())?;
        let topic: String = env.get_string(&topic).map_err(|_| ())?.into();
        let object_id: String = env.get_string(&object_id).map_err(|_| ())?.into();
        let result = secure_device_protocol::history::identity(
            &delta, &topic, &object_id, event_ts.try_into().map_err(|_| ())?,
        ).map_err(|_| ())?;
        let mut output = Vec::with_capacity(64 + result.canonical_delta.len());
        output.extend_from_slice(&result.digest);
        output.extend_from_slice(&result.event_id);
        output.extend_from_slice(&result.canonical_delta);
        env.byte_array_from_slice(&output).map(|array| array.into_raw()).map_err(|_| ())
    }));
    match result {
        Ok(Ok(bytes)) => bytes,
        _ => {
            let _ = env.throw_new("java/lang/IllegalArgumentException", "Invalid device history event");
            ptr::null_mut()
        }
    }
}
