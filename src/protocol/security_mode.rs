use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityMode {
    Direct,
    Relay,
    Auto,
}

impl SecurityMode {
    pub fn from_string(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "DIRECT" => SecurityMode::Direct,
            "RELAY" => SecurityMode::Relay,
            "AUTO" => SecurityMode::Auto,
            _ => SecurityMode::Auto,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            SecurityMode::Direct => "DIRECT".to_string(),
            SecurityMode::Relay => "RELAY".to_string(),
            SecurityMode::Auto => "AUTO".to_string(),
        }
    }
}

impl Default for SecurityMode {
    fn default() -> Self {
        SecurityMode::Auto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityTier {
    HighRisk,
    Normal,
    Bulk,
}

impl SecurityTier {
    pub fn from_string(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "HIGH_RISK" => SecurityTier::HighRisk,
            "NORMAL" => SecurityTier::Normal,
            "BULK" => SecurityTier::Bulk,
            _ => SecurityTier::Normal,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            SecurityTier::HighRisk => "HIGH_RISK".to_string(),
            SecurityTier::Normal => "NORMAL".to_string(),
            SecurityTier::Bulk => "BULK".to_string(),
        }
    }
}

impl Default for SecurityTier {
    fn default() -> Self {
        SecurityTier::Normal
    }
}
