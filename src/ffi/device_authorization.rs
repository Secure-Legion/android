//! iOS binding for the portable independent-device authorization protocol.
//!
//! Trust state stays in the encrypted application database. This entry point
//! only validates or issues bounded public protocol objects against an explicit
//! pinned account key and optional account signing seed.

use secure_device_protocol::{
    api::{execute, MAX_API_LEN},
    AuthorizationError,
};
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};
use zeroize::Zeroizing;

/// Executes a bounded UTF-8 JSON authorization request.
///
/// Returns 0 on success, -1 for invalid buffers, -2 when the output buffer is
/// too small, and -10 through -21 for protocol validation failures. Signing
/// requests receive a separate 32-byte account seed; verification requests
/// must pass no seed. No partial output is written on failure.
#[no_mangle]
pub unsafe extern "C" fn securelegion_device_authorization(
    request: *const u8,
    request_len: u32,
    account_seed: *const u8,
    account_seed_len: u32,
    out: *mut u8,
    out_len: *mut u32,
) -> i32 {
    if request.is_null()
        || request_len == 0
        || request_len as usize > MAX_API_LEN
        || out.is_null()
        || out_len.is_null()
        || !matches!(account_seed_len, 0 | 32)
        || (account_seed_len == 32 && account_seed.is_null())
        || (account_seed_len == 0 && !account_seed.is_null())
    {
        return -1;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let seed = if account_seed_len == 32 {
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(slice::from_raw_parts(account_seed, 32));
            Some(seed)
        } else {
            None
        };
        let request = slice::from_raw_parts(request, request_len as usize);
        let result = match execute(request, seed.as_deref()) {
            Ok(result) => result,
            Err(error) => {
                return match error {
                    AuthorizationError::Malformed => -10,
                    AuthorizationError::InvalidKey => -11,
                    AuthorizationError::WrongAccount => -12,
                    AuthorizationError::Signature => -13,
                    AuthorizationError::Onion => -14,
                    AuthorizationError::Lifetime => -15,
                    AuthorizationError::Inactive => -16,
                    AuthorizationError::Unauthorized => -17,
                    AuthorizationError::Rollback => -18,
                    AuthorizationError::Fork => -19,
                    AuthorizationError::Order => -20,
                    AuthorizationError::Limit => -21,
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
    fn invalid_requests_never_write_partial_output() {
        let request = b"{}";
        let mut output = [0xa5; 64];
        let mut output_len = output.len() as u32;

        let result = unsafe {
            securelegion_device_authorization(
                request.as_ptr(),
                request.len() as u32,
                ptr::null(),
                0,
                output.as_mut_ptr(),
                &mut output_len,
            )
        };

        assert_eq!(result, -10);
        assert_eq!(output, [0xa5; 64]);
        assert_eq!(output_len, 64);
    }
}
