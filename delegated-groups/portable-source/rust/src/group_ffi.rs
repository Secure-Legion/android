//! Stateless group validation/signing binding. No network, global group cache,
//! database writes, or installation of trust. The host owns committed state.
use secure_group_protocol::api::{execute, ApiError, MAX_API_LEN};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};
use zeroize::Zeroizing;

unsafe fn optional_secret(pointer: *const u8, len: u32) -> Option<Zeroizing<[u8; 32]>> {
    if len == 0 {
        return None;
    }
    let mut secret = Zeroizing::new([0; 32]);
    secret.copy_from_slice(slice::from_raw_parts(pointer, 32));
    Some(secret)
}
fn valid_secret(pointer: *const u8, len: u32) -> bool {
    (len == 0 && pointer.is_null()) || (len == 32 && !pointer.is_null())
}

/// Return 0 on success; -1 invalid buffer/panic; -2 insufficient capacity;
/// -30 malformed request; -31 limit; -32 authority; -33 invalid operation;
/// -34 missing dependency; -35 conflict; -36 group key rotation required.
/// Only -2 updates out_len on error. No error writes a partial response.
///
/// # Safety
/// Caller must provide accessible buffers for their declared lengths; out_len
/// points to output capacity and must not overlap request/secrets/output.
/// Seed means device seed for create/attest and account-root seed for ratify.
/// The host must permit ratify only for an exact previously approved committed
/// hash, with a fresh primary role. Never expose this as a network signing RPC.
/// Requests/responses can contain membership secrets: do not log their JSON.
#[no_mangle]
pub unsafe extern "C" fn sl_desktop_group_protocol(
    request: *const u8,
    request_len: u32,
    signing_seed: *const u8,
    signing_seed_len: u32,
    group_key: *const u8,
    group_key_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if request.is_null()
        || request_len == 0
        || request_len as usize > MAX_API_LEN
        || out.is_null()
        || out_len.is_null()
        || !valid_secret(signing_seed, signing_seed_len)
        || !valid_secret(group_key, group_key_len)
    {
        return -1;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let seed = optional_secret(signing_seed, signing_seed_len);
        let key = optional_secret(group_key, group_key_len);
        let result = match execute(
            slice::from_raw_parts(request, request_len as usize),
            seed.as_deref(),
            key.as_deref(),
        ) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(error) => {
                return match error {
                    ApiError::Malformed => -30,
                    ApiError::Limit => -31,
                    ApiError::Authority => -32,
                    ApiError::InvalidOperation => -33,
                    ApiError::Dependency => -34,
                    ApiError::Conflict => -35,
                    ApiError::RekeyRequired => -36,
                }
            }
        };
        if result.len() > *out_len as usize {
            *out_len = result.len() as u32;
            return -2;
        }
        ptr::copy_nonoverlapping(result.as_ptr(), out, result.len());
        *out_len = result.len() as u32;
        0
    }))
    .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_buffers_secret_modes_and_requests_without_partial_output() {
        let request = br#"{"operation":"inspect","encoded":""}"#;
        let mut out = [0xa5; 64];
        let mut len = 64;
        let seed = [1; 32];
        unsafe {
            assert_eq!(
                sl_desktop_group_protocol(
                    ptr::null(),
                    1,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    &mut len
                ),
                -1
            );
            assert_eq!(
                sl_desktop_group_protocol(
                    request.as_ptr(),
                    u32::MAX,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    &mut len
                ),
                -1
            );
            assert_eq!(
                sl_desktop_group_protocol(
                    request.as_ptr(),
                    request.len() as u32,
                    ptr::null(),
                    32,
                    ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    &mut len
                ),
                -1
            );
            assert_eq!(
                sl_desktop_group_protocol(
                    request.as_ptr(),
                    request.len() as u32,
                    ptr::null(),
                    0,
                    seed.as_ptr(),
                    0,
                    out.as_mut_ptr(),
                    &mut len
                ),
                -1
            );
            assert_eq!(
                sl_desktop_group_protocol(
                    request.as_ptr(),
                    request.len() as u32,
                    seed.as_ptr(),
                    32,
                    ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    &mut len
                ),
                -30
            );
            assert_eq!(
                sl_desktop_group_protocol(
                    request.as_ptr(),
                    request.len() as u32,
                    ptr::null(),
                    0,
                    seed.as_ptr(),
                    32,
                    out.as_mut_ptr(),
                    &mut len
                ),
                -30
            );
        }
        assert_eq!(out, [0xa5; 64]);
        assert_eq!(len, 64);
    }

    #[test]
    fn output_capacity_retry_is_stateless_and_never_writes_a_partial_response() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        use securelegion::crdt::{
            ids::{DeviceID, GroupID},
            ops::{GroupCreatePayload, OpEnvelope, OpType},
        };
        let seed = [1; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let op = OpEnvelope::create_signed(
            GroupID::new(&DeviceID::from_pubkey(&public), &[5; 32]),
            OpType::GroupCreate,
            &GroupCreatePayload {
                group_name: "Synthetic".into(),
                encrypted_group_secret: vec![9; 32],
            },
            1,
            1,
            public,
            &seed,
        )
        .unwrap();
        let request=serde_json::to_vec(&serde_json::json!({"operation":"inspect","encoded":B64.encode(op.to_bytes().unwrap())})).unwrap();
        let mut small = [0xa5; 2];
        let mut len = 2;
        unsafe {
            assert_eq!(
                sl_desktop_group_protocol(
                    request.as_ptr(),
                    request.len() as u32,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    small.as_mut_ptr(),
                    &mut len
                ),
                -2
            );
            assert_eq!(small, [0xa5; 2]);
            assert!(len > 2);
            let mut out = vec![0; len as usize];
            assert_eq!(
                sl_desktop_group_protocol(
                    request.as_ptr(),
                    request.len() as u32,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    &mut len
                ),
                0
            );
            let value: serde_json::Value = serde_json::from_slice(&out[..len as usize]).unwrap();
            assert_eq!(value["op_type"], "GroupCreate");
            assert!(value.get("payload").is_none());
        }
    }
}
