//! Portable, strict codecs for independent linked-device authorization.
//!
//! These types do not install trust: callers must pin the account public key,
//! persist the highest accepted roster epoch atomically, and consult that roster
//! before accepting a new device operation. A certificate alone is insufficient.
//! Existing PAIR_V2, friend-request schema 5 and SYNC_V1 remain separate protocols.

mod account_identity;
pub mod api;
mod authorization;

pub use account_identity::*;
pub use authorization::*;
