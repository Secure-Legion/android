//! Portable delivery acknowledgements shared by every client adapter.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::Zeroize;

use crate::crypto::key_exchange::derive_shared_secret;
use crate::crypto::{decrypt_message, encrypt_message};

pub const DELIVERY_ACK_WIRE_TYPE: u8 = 0x06;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeliveryAck {
    pub item_id: String,
    pub ack_type: String,
    pub timestamp: i64,
    pub sender_ed25519_signing_pubkey: [u8; 32],
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl DeliveryAck {
    pub const ACK_TYPE_PING: &'static str = "PING_ACK";
    pub const ACK_TYPE_MESSAGE: &'static str = "MESSAGE_ACK";
    pub const ACK_TYPE_TAP: &'static str = "TAP_ACK";

    pub fn new(item_id: &str, ack_type: &str, signing_key: &SigningKey) -> Result<Self, String> {
        if item_id.is_empty()
            || !matches!(
                ack_type,
                Self::ACK_TYPE_PING | Self::ACK_TYPE_MESSAGE | Self::ACK_TYPE_TAP
            )
        {
            return Err("invalid ACK identity or type".to_string());
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock predates Unix epoch".to_string())?
            .as_secs() as i64;

        let mut ack = Self {
            item_id: item_id.to_owned(),
            ack_type: ack_type.to_owned(),
            timestamp,
            sender_ed25519_signing_pubkey: signing_key.verifying_key().to_bytes(),
            signature: [0u8; 64],
        };
        ack.signature = signing_key.sign(&ack.signable_bytes()).to_bytes();
        Ok(ack)
    }

    pub fn verify(&self, signer_pubkey: &VerifyingKey) -> Result<bool, String> {
        Ok(signer_pubkey
            .verify(
                &self.signable_bytes(),
                &Signature::from_bytes(&self.signature),
            )
            .is_ok())
    }

    fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.item_id.len() + self.ack_type.len() + 8 + 32);
        bytes.extend_from_slice(self.item_id.as_bytes());
        bytes.extend_from_slice(self.ack_type.as_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.sender_ed25519_signing_pubkey);
        bytes
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|error| format!("ACK serialization failed: {error}"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|error| format!("ACK deserialization failed: {error}"))
    }
}

pub fn create_delivery_ack_wire(
    item_id: &str,
    ack_type: &str,
    ed25519_seed: &[u8; 32],
    sender_x25519_private: &[u8; 32],
    sender_x25519_public: &[u8; 32],
    recipient_x25519_public: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let signing_key = SigningKey::from_bytes(ed25519_seed);
    let ack = DeliveryAck::new(item_id, ack_type, &signing_key)?;
    let mut ack_bytes = ack.to_bytes()?;
    let mut shared = derive_shared_secret(sender_x25519_private, recipient_x25519_public)
        .map_err(|error| format!("ACK key agreement failed: {error}"))?;
    let encrypted = encrypt_message(&ack_bytes, &shared)
        .map_err(|error| format!("ACK encryption failed: {error}"))?;
    ack_bytes.zeroize();
    shared.zeroize();

    let mut wire = Vec::with_capacity(1 + 32 + encrypted.len());
    wire.push(DELIVERY_ACK_WIRE_TYPE);
    wire.extend_from_slice(sender_x25519_public);
    wire.extend_from_slice(&encrypted);
    Ok(wire)
}

pub fn decrypt_and_verify_delivery_ack(
    wire: &[u8],
    recipient_x25519_private: &[u8; 32],
) -> Result<DeliveryAck, String> {
    if wire.len() < 1 + 32 + 24 + 16 || wire[0] != DELIVERY_ACK_WIRE_TYPE {
        return Err("invalid ACK wire frame".to_string());
    }

    let sender_x25519_public: [u8; 32] = wire[1..33]
        .try_into()
        .map_err(|_| "invalid ACK sender key".to_string())?;
    let mut shared = derive_shared_secret(recipient_x25519_private, &sender_x25519_public)
        .map_err(|error| format!("ACK key agreement failed: {error}"))?;
    let mut ack_bytes = decrypt_message(&wire[33..], &shared)
        .map_err(|error| format!("ACK decryption failed: {error}"))?;
    shared.zeroize();

    let ack = DeliveryAck::from_bytes(&ack_bytes)?;
    ack_bytes.zeroize();
    let verifying_key = VerifyingKey::from_bytes(&ack.sender_ed25519_signing_pubkey)
        .map_err(|error| format!("invalid ACK signer key: {error}"))?;
    if !ack.verify(&verifying_key)? {
        return Err("ACK signature invalid".to_string());
    }
    Ok(ack)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::key_exchange::derive_public_key;

    #[test]
    fn delivery_ack_round_trip_preserves_mobile_wire_format() {
        let sender_signing = [0x31; 32];
        let sender_x_private = [0x41; 32];
        let sender_x_public = derive_public_key(&sender_x_private).unwrap();
        let recipient_x_private = [0x51; 32];
        let recipient_x_public = derive_public_key(&recipient_x_private).unwrap();

        let wire = create_delivery_ack_wire(
            "message-id-1",
            DeliveryAck::ACK_TYPE_MESSAGE,
            &sender_signing,
            &sender_x_private,
            &sender_x_public,
            &recipient_x_public,
        )
        .unwrap();

        assert_eq!(wire[0], DELIVERY_ACK_WIRE_TYPE);
        assert_eq!(&wire[1..33], &sender_x_public);
        let ack = decrypt_and_verify_delivery_ack(&wire, &recipient_x_private).unwrap();
        assert_eq!(ack.item_id, "message-id-1");
        assert_eq!(ack.ack_type, DeliveryAck::ACK_TYPE_MESSAGE);
    }
}
