//! Structural delivery selection over an already validated committed log.
//! This grants no account, group or signing authority. Hosts authorize the
//! local origin/recipient and persist exact encrypted packets before sending.
//! Terminal delivery must never expand to later history or key epochs.
use crate::state::GroupOperation;
use securelegion::crdt::{
    ids::OpID,
    ops::{MemberAcceptPayload, OpType},
};
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SelectionError {
    #[error("delivery dependency is unavailable")]
    Dependency,
    #[error("delivery log has conflicting identities")]
    Conflict,
    #[error("delivery selection exceeds its bound")]
    Limit,
}

pub struct DeliverySelection<'a> {
    pub operations: Vec<&'a GroupOperation>,
    pub complete: bool,
}

struct IndexedLog<'a> {
    by_id: BTreeMap<OpID, &'a GroupOperation>,
    by_hash: HashMap<[u8; 32], &'a GroupOperation>,
    founding: OpID,
}

impl<'a> IndexedLog<'a> {
    fn new(committed: &'a [GroupOperation]) -> Result<Self, SelectionError> {
        let mut by_id: BTreeMap<OpID, &'a GroupOperation> = BTreeMap::new();
        let mut by_hash = HashMap::new();
        let mut founding = None;
        let mut group = None;
        let mut bytes = 0usize;
        for op in committed {
            bytes = bytes
                .checked_add(op.encoded().len() + 4)
                .ok_or(SelectionError::Limit)?;
            if bytes > 24 * 1024 * 1024 {
                return Err(SelectionError::Limit);
            }
            let header = op.operation();
            if group
                .replace(header.group_id)
                .is_some_and(|old| old != header.group_id)
            {
                return Err(SelectionError::Conflict);
            }
            if by_id
                .insert(header.op_id, op)
                .is_some_and(|old| old.hash() != op.hash())
            {
                return Err(SelectionError::Conflict);
            }
            by_hash.insert(op.hash(), op);
            if op
                .core_operation()
                .is_some_and(|inner| inner.op_type == OpType::GroupCreate)
                && founding
                    .replace(header.op_id)
                    .is_some_and(|old| old != header.op_id)
            {
                return Err(SelectionError::Conflict);
            }
        }
        Ok(Self {
            by_id,
            by_hash,
            founding: founding.ok_or(SelectionError::Dependency)?,
        })
    }

    fn known(&self, hashes: &HashSet<[u8; 32]>) -> Result<Vec<OpID>, SelectionError> {
        hashes
            .iter()
            .map(|hash| {
                self.by_hash
                    .get(hash)
                    .map(|op| op.operation().op_id)
                    .ok_or(SelectionError::Conflict)
            })
            .collect()
    }

    fn dependencies(&self, op: &GroupOperation) -> Result<Vec<OpID>, SelectionError> {
        let mut dependencies = op.operation().parent_heads.to_vec();
        if let Some(epoch) = op.epoch() {
            let previous = self
                .by_hash
                .get(&epoch.header().previous_epoch)
                .ok_or(SelectionError::Dependency)?;
            dependencies.push(previous.operation().op_id);
            dependencies.extend(&epoch.header().removal_frontier);
        }
        if let Some(inner) = op
            .core_operation()
            .filter(|inner| inner.op_type == OpType::MemberAccept)
        {
            let payload: MemberAcceptPayload = inner
                .decode_payload()
                .map_err(|_| SelectionError::Conflict)?;
            dependencies.push(payload.invite_op_id);
        }
        for id in &dependencies {
            if self
                .by_id
                .get(id)
                .ok_or(SelectionError::Dependency)?
                .operation()
                .lamport
                >= op.operation().lamport
            {
                return Err(SelectionError::Conflict);
            }
        }
        Ok(dependencies)
    }

    /// Iterative even for long histories. No inferred author-counter prefixes.
    fn walk(
        &self,
        mut pending: Vec<OpID>,
        upper: Option<u64>,
    ) -> Result<BTreeMap<OpID, &'a GroupOperation>, SelectionError> {
        let mut selected = BTreeMap::new();
        while let Some(id) = pending.pop() {
            if selected.contains_key(&id) {
                continue;
            }
            let op = *self.by_id.get(&id).ok_or(SelectionError::Dependency)?;
            if upper.is_some_and(|max| op.operation().lamport > max) {
                return Err(SelectionError::Conflict);
            }
            pending.extend(self.dependencies(op)?);
            selected.insert(id, op);
        }
        Ok(selected)
    }

    fn acknowledged_closure(
        &self,
        known: &HashSet<[u8; 32]>,
    ) -> Result<HashSet<[u8; 32]>, SelectionError> {
        let mut roots = self.known(known)?;
        if !roots.is_empty() {
            roots.push(self.founding);
        }
        Ok(self
            .walk(roots, None)?
            .into_values()
            .map(GroupOperation::hash)
            .collect())
    }
}

/// Hashes must come ONLY from committed, verified complete-bundle ACKs for this
/// exact group/account/installation. Native acceptance guarantees the exact
/// operation's causal dependencies were committed too, including after later
/// supersession. The host may therefore retain causal checkpoints instead of
/// a growing list of every acknowledged ancestor. This is not account transfer.
pub fn select<'a>(
    committed: &'a [GroupOperation],
    origin: OpID,
    acknowledged: &HashSet<[u8; 32]>,
    maximum: usize,
) -> Result<DeliverySelection<'a>, SelectionError> {
    if maximum == 0 || maximum > 1000 {
        return Err(SelectionError::Limit);
    }
    let log = IndexedLog::new(committed)?;
    let known = log.acknowledged_closure(acknowledged)?;
    let last = log.by_id.get(&origin).ok_or(SelectionError::Dependency)?;
    if known.contains(&last.hash()) {
        return Ok(DeliverySelection {
            operations: vec![],
            complete: true,
        });
    }
    let mut ordered: Vec<_> = log
        .walk(vec![origin, log.founding], Some(last.operation().lamport))?
        .into_values()
        .filter(|op| !known.contains(&op.hash()))
        .collect();
    ordered.sort_by_key(|op| (op.operation().lamport, op.operation().op_id));
    let complete = ordered.len() <= maximum;
    ordered.truncate(maximum);
    Ok(DeliverySelection {
        operations: ordered,
        complete,
    })
}

/// Remove only checkpoints whose exact causal coverage is carried by another
/// verified checkpoint. Concurrent lower-clock operations remain independent.
pub fn compact_acknowledgements(
    committed: &[GroupOperation],
    acknowledged: &HashSet<[u8; 32]>,
) -> Result<HashSet<[u8; 32]>, SelectionError> {
    let log = IndexedLog::new(committed)?;
    let roots = log.known(acknowledged)?;
    let mut dependencies = Vec::new();
    for id in roots {
        dependencies.extend(log.dependencies(log.by_id[&id])?);
        if id != log.founding {
            dependencies.push(log.founding);
        }
    }
    let covered: HashSet<_> = log
        .walk(dependencies, None)?
        .into_values()
        .map(GroupOperation::hash)
        .collect();
    Ok(acknowledged.difference(&covered).copied().collect())
}
