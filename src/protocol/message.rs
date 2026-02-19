use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Text,
    SystemNotification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub sender_public_key: Vec<u8>,
    pub recipient_public_key: Vec<u8>,
    pub encrypted_content: Vec<u8>,
    pub signature: Vec<u8>,
    pub timestamp: i64,
    pub message_type: MessageType,
    pub nonce: Vec<u8>,
}

impl Message {
    pub fn new(
        sender_public_key: Vec<u8>,
        recipient_public_key: Vec<u8>,
        encrypted_content: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        use chrono::Utc;

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            sender_public_key,
            recipient_public_key,
            encrypted_content,
            signature,
            timestamp: Utc::now().timestamp(),
            message_type: MessageType::Text,
            nonce: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingToken {
    pub protocol_version: u8,
    pub sender_pubkey: [u8; 32], // Ed25519 signing public key
    pub recipient_pubkey: [u8; 32], // Ed25519 signing public key
    pub sender_x25519_pubkey: [u8; 32], // X25519 encryption public key
    pub recipient_x25519_pubkey: [u8; 32], // X25519 encryption public key
    pub nonce: [u8; 24],
    pub timestamp: i64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl PingToken {
    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    pub fn serialize_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.protocol_version);
        data.extend_from_slice(&self.sender_pubkey);
        data.extend_from_slice(&self.recipient_pubkey);
        data.extend_from_slice(&self.sender_x25519_pubkey);
        data.extend_from_slice(&self.recipient_x25519_pubkey);
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongToken {
    pub protocol_version: u8,
    pub ping_nonce: [u8; 24],
    pub pong_nonce: [u8; 24],
    pub timestamp: i64,
    pub authenticated: bool,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}

impl PongToken {
    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    pub fn serialize_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.protocol_version);
        data.extend_from_slice(&self.ping_nonce);
        data.extend_from_slice(&self.pong_nonce);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.push(if self.authenticated { 1 } else { 0 });
        data
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryConfirmationToken {
    pub message_id: String, // ID of the message being confirmed
    pub recipient_pubkey: [u8; 32], // Recipient's signing public key
    pub timestamp: i64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64], // Signature over message_id + timestamp
}

impl DeliveryConfirmationToken {
    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    pub fn serialize_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.message_id.as_bytes());
        data.extend_from_slice(&self.recipient_pubkey);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

/// TAP_ACK: Confirms that TAP (check-in request) was received by sender
/// Recipient sent TAP to ask "Do I have messages waiting?"
/// Sender responds with TAP_ACK to confirm "I got your check-in"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapAckToken {
    pub tap_nonce: [u8; 24], // Nonce from the TAP being acknowledged
    pub recipient_pubkey: [u8; 32], // Recipient's signing public key
    pub timestamp: i64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64], // Signature over tap_nonce + timestamp
}

impl TapAckToken {
    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    pub fn serialize_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.tap_nonce);
        data.extend_from_slice(&self.recipient_pubkey);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

/// PONG_ACK: Confirms that PONG (encrypted message payload) landed on recipient device
/// Gap: Phone could crash between PONG_ACK and MESSAGE_ACK
/// - PONG_ACK = "Encrypted bytes arrived on my device"
/// - MESSAGE_ACK = "Decrypted, verified, and saved to database"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongAckToken {
    pub pong_nonce: [u8; 24], // Nonce from the PONG being acknowledged
    pub recipient_pubkey: [u8; 32], // Recipient's signing public key
    pub timestamp: i64,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64], // Signature over pong_nonce + timestamp
}

impl PongAckToken {
    pub fn serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(data)
    }

    pub fn serialize_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.pong_nonce);
        data.extend_from_slice(&self.recipient_pubkey);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = Message::new(
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        );

        let serialized = msg.serialize().unwrap();
        let deserialized = Message::deserialize(&serialized).unwrap();

        assert_eq!(msg.id, deserialized.id);
        assert_eq!(msg.sender_public_key, deserialized.sender_public_key);
    }

    #[test]
    fn test_message_json() {
        let msg = Message::new(
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            vec![10, 11, 12],
        );

        let json = msg.to_json().unwrap();
        let deserialized = Message::from_json(&json).unwrap();

        assert_eq!(msg.id, deserialized.id);
    }
}
