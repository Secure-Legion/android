//! Private key versions and explicit exposure coverage. Membership and event
//! signatures are checked by the group state adapter before invoking this type.
use crate::epoch::EpochOperation;
use securelegion::crdt::ids::{DeviceID, OpID};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyStateError {
    Dependency,
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::EpochHeader;
    use ed25519_dalek::SigningKey;
    use secure_device_protocol::{
        onion_from_public_key, DeviceCertificate, DeviceClaims, CAP_GROUPS,
    };
    use securelegion::crdt::ids::GroupID;

    fn epoch(previous: [u8; 32], clock: u64, frontier: Vec<OpID>, key: u8) -> EpochOperation {
        let root = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let leaf = SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes();
        let onion = onion_from_public_key(&leaf).unwrap();
        let cert = DeviceCertificate::issue(
            DeviceClaims {
                account_ed: root,
                device_ed: leaf,
                device_x: [3; 32],
                ml_kem_public_hash: [4; 32],
                onion: onion
                    .strip_suffix(".onion")
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                issued_at_ms: 1000,
                expires_at_ms: 100000,
                capabilities: CAP_GROUPS,
            },
            &[1; 32],
        )
        .unwrap();
        EpochOperation::create(
            cert,
            &[11; 32],
            EpochHeader {
                group_id: GroupID::from_bytes([1; 32]),
                op_id: OpID::new(DeviceID::from_pubkey(&leaf), clock, clock),
                timestamp_ms: 2000,
                parent_heads: vec![],
                removal_frontier: frontier,
                previous_epoch: previous,
                membership_digest: [5; 32],
            },
            [key; 32],
        )
        .unwrap()
    }

    #[test]
    fn bounded_rotation_deltas_retain_all_prior_exposure_coverage() {
        let mut keys = GroupKeys::default();
        keys.set_genesis(
            [1; 32],
            OpID::new(DeviceID::from_bytes([1; 16]), 1, 1),
            [1; 32],
        )
        .unwrap();
        let mut events = BTreeMap::new();
        for n in 0u16..130 {
            let mut raw = [0; 16];
            raw[..2].copy_from_slice(&n.to_be_bytes());
            let account = DeviceID::from_bytes(raw);
            let event = OpID::new(account, u64::from(n) + 2, 1);
            keys.expose(account, event).unwrap();
            events.insert(event, account);
        }
        assert!(keys.needs_rekey());
        let first = epoch([1; 32], 200, keys.frontier(), 2);
        assert_eq!(first.header().removal_frontier.len(), 128);
        keys.install(
            &first,
            first
                .header()
                .removal_frontier
                .iter()
                .map(|id| (events[id], *id))
                .collect(),
            true,
        )
        .unwrap();
        assert!(keys.needs_rekey());
        assert_eq!(keys.frontier().len(), 2);
        let second = epoch(first.hash(), 201, keys.frontier(), 3);
        keys.install(
            &second,
            second
                .header()
                .removal_frontier
                .iter()
                .map(|id| (events[id], *id))
                .collect(),
            true,
        )
        .unwrap();
        assert!(!keys.needs_rekey());
        assert!(keys.frontier().is_empty());
        assert_eq!(keys.current().unwrap().coverage.len(), 130);
        assert!(!keys.ready(&first.hash()));
        assert!(keys.ready(&second.hash()));
        let hash = keys.state_hash([6; 32]);
        keys.versions.get_mut(&second.hash()).unwrap().eligible = false;
        assert_ne!(hash, keys.state_hash([6; 32]));
        assert!(keys.needs_rekey());
    }
}

#[derive(Clone)]
pub(crate) struct KeyVersion {
    pub id: [u8; 32],
    pub op_id: OpID,
    pub key: Zeroizing<[u8; 32]>,
    pub coverage: BTreeMap<DeviceID, OpID>,
    pub eligible: bool,
}
#[derive(Clone, Default)]
pub(crate) struct GroupKeys {
    genesis: Option<[u8; 32]>,
    versions: BTreeMap<[u8; 32], KeyVersion>,
    requirements: BTreeMap<DeviceID, OpID>,
}
impl GroupKeys {
    pub fn set_genesis(
        &mut self,
        id: [u8; 32],
        op_id: OpID,
        key: [u8; 32],
    ) -> Result<(), KeyStateError> {
        if self.genesis.is_some() {
            return Err(KeyStateError::Invalid);
        }
        self.versions.insert(
            id,
            KeyVersion {
                id,
                op_id,
                key: Zeroizing::new(key),
                coverage: BTreeMap::new(),
                eligible: true,
            },
        );
        self.genesis = Some(id);
        Ok(())
    }
    pub fn expose(&mut self, account: DeviceID, event: OpID) -> Result<(), KeyStateError> {
        self.requirements
            .entry(account)
            .and_modify(|id| *id = (*id).max(event))
            .or_insert(event);
        Ok(())
    }
    pub fn install(
        &mut self,
        epoch: &EpochOperation,
        coverage: BTreeMap<DeviceID, OpID>,
        eligible: bool,
    ) -> Result<(), KeyStateError> {
        let previous = self
            .versions
            .get(&epoch.header().previous_epoch)
            .ok_or(KeyStateError::Dependency)?;
        let mut refs: Vec<_> = coverage.values().copied().collect();
        refs.sort();
        if refs != epoch.header().removal_frontier
            || self.versions.contains_key(&epoch.hash())
            || self
                .versions
                .values()
                .any(|version| crate::group_key_eq(&version.key, epoch.key()))
        {
            return Err(KeyStateError::Invalid);
        }
        let mut inherited = previous.coverage.clone();
        for (account, event) in coverage {
            inherited
                .entry(account)
                .and_modify(|id| *id = (*id).max(event))
                .or_insert(event);
        }
        self.versions.insert(
            epoch.hash(),
            KeyVersion {
                id: epoch.hash(),
                op_id: epoch.header().op_id,
                key: Zeroizing::new(*epoch.key()),
                coverage: inherited,
                eligible,
            },
        );
        Ok(())
    }
    fn covers(&self, version: &KeyVersion) -> bool {
        version.eligible
            && self.requirements.iter().all(|(account, required)| {
                version
                    .coverage
                    .get(account)
                    .is_some_and(|event| event >= required)
            })
    }
    pub fn current(&self) -> Option<&KeyVersion> {
        self.versions
            .values()
            .filter(|version| self.covers(version))
            .max_by_key(|version| version.op_id)
            .or_else(|| {
                self.versions
                    .values()
                    .filter(|version| version.eligible)
                    .max_by_key(|version| version.op_id)
            })
    }
    pub fn genesis(&self) -> Option<[u8; 32]> {
        self.genesis
    }
    pub fn get(&self, id: &[u8; 32]) -> Option<&KeyVersion> {
        self.versions.get(id)
    }
    pub fn ready(&self, id: &[u8; 32]) -> bool {
        self.versions
            .get(id)
            .is_some_and(|version| self.covers(version))
    }
    pub fn needs_rekey(&self) -> bool {
        self.current().is_some_and(|version| !self.covers(version))
    }
    pub fn frontier(&self) -> Vec<OpID> {
        let current = self.current();
        let mut frontier: Vec<_> = self
            .requirements
            .iter()
            .filter(|(account, event)| {
                current.is_none_or(|version| {
                    version
                        .coverage
                        .get(account)
                        .is_none_or(|covered| covered < *event)
                })
            })
            .map(|(_, event)| *event)
            .collect();
        frontier.sort();
        // A rotation carries a bounded delta; subsequent rotations inherit
        // coverage and finish any larger merge without dropping removals.
        frontier.truncate(crate::epoch::MAX_EXPOSURES);
        frontier
    }
    pub fn versions(&self) -> impl Iterator<Item = &KeyVersion> {
        self.versions.values()
    }
    pub fn state_hash(&self, core: [u8; 32]) -> [u8; 32] {
        // Preserve the pinned legacy hash until an explicit epoch is present.
        if self.versions.len() < 2 {
            return core;
        }
        let mut hash = Sha256::new();
        hash.update(b"secure-legion-group-key-state-v1\0");
        hash.update(core);
        if let Some(current) = self.current() {
            hash.update(current.id);
        }
        for version in self.versions.values() {
            hash.update(version.id);
            hash.update([u8::from(version.eligible)]);
            hash.update((version.coverage.len() as u32).to_be_bytes());
            for (account, event) in &version.coverage {
                hash.update(account.as_bytes());
                hash.update(event.author.as_bytes());
                hash.update(event.lamport.to_be_bytes());
                hash.update(event.nonce.to_be_bytes());
            }
        }
        for (account, event) in &self.requirements {
            hash.update(account.as_bytes());
            hash.update(event.author.as_bytes());
            hash.update(event.lamport.to_be_bytes());
            hash.update(event.nonce.to_be_bytes());
        }
        hash.finalize().into()
    }
}
