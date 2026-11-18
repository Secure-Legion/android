//! Own-device group-link policy. A SQL label or enclosing topic is not proof
//! that an operation is connection metadata; inspect each signed envelope.
use jni::{objects::{JByteArray, JClass}, sys::{jboolean, JNI_FALSE, JNI_TRUE}, JNIEnv};
use std::panic::{catch_unwind, AssertUnwindSafe};
use crate::crdt::ops::{OpEnvelope, OpType};

const MAX_PACKED_BYTES: usize = 8 * 1024 * 1024;
const MAX_OP_BYTES: usize = 65_536;
const MAX_OPS: usize = 256;

fn safe_group_link_ops(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > MAX_PACKED_BYTES { return false; }
    let mut offset = 0usize;
    let mut count = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 || count >= MAX_OPS { return false; }
        let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        if len == 0 || len > MAX_OP_BYTES || len > bytes.len() - offset { return false; }
        let op = match OpEnvelope::from_bytes(&bytes[offset..offset + len]) {
            Ok(op) => op,
            Err(_) => return false,
        };
        if !matches!(op.op_type,
            OpType::GroupCreate | OpType::GroupDelete | OpType::MemberInvite |
            OpType::MemberAccept | OpType::MemberRemove | OpType::MemberUnban |
            OpType::MetadataSet | OpType::RoleSet
        ) || !matches!(op.verify(), Ok(true)) { return false; }
        offset += len;
        count += 1;
    }
    count != 0
}

#[no_mangle]
pub extern "C" fn Java_com_securelegion_crypto_RustBridge_validateDeviceGroupLinkOps(
    env: JNIEnv, _class: JClass, packed: JByteArray,
) -> jboolean {
    let safe = catch_unwind(AssertUnwindSafe(|| {
        let length = env.get_array_length(&packed).ok()? as usize;
        if length == 0 || length > MAX_PACKED_BYTES { return Some(false); }
        let bytes = env.convert_byte_array(packed).ok()?;
        Some(safe_group_link_ops(&bytes))
    })).ok().flatten().unwrap_or(false);
    if safe { JNI_TRUE } else { JNI_FALSE }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::ids::GroupID;
    use crate::crypto::signing::generate_keypair;

    fn packed(op_type: OpType) -> Vec<u8> {
        let (public, secret) = generate_keypair();
        let op = OpEnvelope::create_signed(GroupID([7; 32]), op_type,
            &"opaque payload", 1, 9, public, &secret).unwrap();
        let bytes = op.to_bytes().unwrap();
        let mut packed = (bytes.len() as u32).to_be_bytes().to_vec();
        packed.extend_from_slice(&bytes);
        packed
    }

    #[test]
    fn invalid_or_trailing_frames_fail_closed() {
        assert!(!safe_group_link_ops(&[]));
        assert!(!safe_group_link_ops(&[0, 0, 0, 0]));
        assert!(!safe_group_link_ops(&[0, 0, 0, 1, 0]));
        assert!(!safe_group_link_ops(&[0, 0, 0, 1, 0, 0]));
    }

    #[test]
    fn signed_connection_types_only() {
        assert!(safe_group_link_ops(&packed(OpType::MemberInvite)));
        assert!(safe_group_link_ops(&packed(OpType::GroupDelete)));
        assert!(!safe_group_link_ops(&packed(OpType::MsgAdd)));
        assert!(!safe_group_link_ops(&packed(OpType::MsgEdit)));
        assert!(!safe_group_link_ops(&packed(OpType::ReactionSet)));
        let mut tampered = packed(OpType::MetadataSet);
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(!safe_group_link_ops(&tampered));
    }
}
