//! Mobile link target for the canonical, stateless group protocol.
//! This shares the exact Desktop FFI implementation and its boundary tests.
#[path = "../../../rust/src/group_ffi.rs"]
mod group_ffi;

#[cfg(target_os = "android")]
mod android_jni;
