use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactCard {
    pub public_key: Vec<u8>,
    pub solana_address: String,
    pub handle: String,
    pub onion_address: Option<String>,
    pub relay_preferences: RelayPreferences,
    pub timestamp: i64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayPreferences {
    pub accepts_relay_messages: bool,
    pub preferred_relays: Vec<String>,
}

impl ContactCard {
    pub fn new(
        public_key: Vec<u8>,
        solana_address: String,
        handle: String,
        onion_address: Option<String>,
    ) -> Self {
        use chrono::Utc;

        Self {
            public_key,
            solana_address,
            handle,
            onion_address,
            relay_preferences: RelayPreferences {
                accepts_relay_messages: true,
                preferred_relays: Vec::new(),
            },
            timestamp: Utc::now().timestamp(),
            signature: Vec::new(),
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

    pub fn serialize_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.public_key);
        data.extend_from_slice(self.solana_address.as_bytes());
        data.extend_from_slice(self.handle.as_bytes());
        if let Some(ref onion) = self.onion_address {
            data.extend_from_slice(onion.as_bytes());
        }
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_card_serialization() {
        let card = ContactCard::new(
            vec![1, 2, 3, 4],
            "SoL1234...".to_string(),
            "user1".to_string(),
            Some("abc123.onion".to_string()),
        );

        let serialized = card.serialize().unwrap();
        let deserialized = ContactCard::deserialize(&serialized).unwrap();

        assert_eq!(card.handle, deserialized.handle);
        assert_eq!(card.solana_address, deserialized.solana_address);
    }

    #[test]
    fn test_contact_card_json() {
        let card = ContactCard::new(
            vec![1, 2, 3, 4],
            "SoL1234...".to_string(),
            "user2".to_string(),
            None,
        );

        let json = card.to_json().unwrap();
        let deserialized = ContactCard::from_json(&json).unwrap();

        assert_eq!(card.handle, deserialized.handle);
    }
}
