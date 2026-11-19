use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::SigningKey;
use secure_device_protocol::{
    onion_from_public_key, DeviceCertificate, DeviceClaims, DeviceRoster, RosterEntry,
    ALL_CAPABILITIES, CAP_GROUPS, CAP_SYNC, ML_KEM_PUBLIC_LEN,
};
use secure_group_protocol::{
    api::{execute, pack, unpack, ApiError},
    history::HistoryReceipt,
    state::GroupOperation,
    DelegatedOperation,
};
use securelegion::crdt::{
    ids::{DeviceID, GroupID},
    ops::*,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const KEY: [u8; 32] = [9; 32];
fn public(n: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes()
}
fn entry(root: u8, leaf: u8, caps: u32) -> RosterEntry {
    let ed = public(leaf);
    let kem = [leaf; ML_KEM_PUBLIC_LEN];
    let onion = onion_from_public_key(&ed).unwrap();
    let cert = DeviceCertificate::issue(
        DeviceClaims {
            account_ed: public(root),
            device_ed: ed,
            device_x: PublicKey::from(&StaticSecret::from([leaf + 30; 32])).to_bytes(),
            ml_kem_public_hash: Sha256::digest(kem).into(),
            onion: onion
                .strip_suffix(".onion")
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
            issued_at_ms: 1000,
            expires_at_ms: 1_000_000,
            capabilities: caps,
        },
        &[root; 32],
    )
    .unwrap();
    RosterEntry::new(cert, kem, format!("Synthetic {leaf}")).unwrap()
}
fn roster(root: u8, epoch: u64, leaves: &[(u8, u32)]) -> DeviceRoster {
    let entries = leaves
        .iter()
        .map(|(n, c)| entry(root, *n, *c))
        .collect::<Vec<_>>();
    DeviceRoster::issue(
        &[root; 32],
        epoch,
        1000 + epoch,
        entries[0].certificate().claims().device_id_bytes(),
        entries,
    )
    .unwrap()
}
fn full(root: u8) -> DeviceRoster {
    roster(
        root,
        1,
        &[
            (10 + root, ALL_CAPABILITIES),
            (20 + root, CAP_GROUPS | CAP_SYNC),
        ],
    )
}

#[test]
fn missing_history_authority_names_exact_unratified_revoked_records_without_mutating_history() {
    let old = vec![founding()];
    let current = [roster(1, 2, &[(21, ALL_CAPABILITIES)])];
    let request =
        |state| json!({"operation":"missing_history_authority","state":state,"limit":128});
    let missing = call(request(state(1, &old, &current)), None, true).unwrap();
    assert_eq!(
        missing["missing"],
        json!([{"account_public":B64.encode(public(1)),
        "hash":hex::encode(old[0].hash())}])
    );
    assert_eq!(missing["has_more"], false);
    let read = call(
        json!({"operation":"read_state","state":state(1,&old,&current)}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(missing["state_hash"], read["state_hash"]);
    assert_eq!(missing["op_count"], read["op_count"]);
    for limit in [0, 129] {
        assert!(matches!(
            call(
                json!({"operation":"missing_history_authority",
            "state":state(1,&old,&current),"limit":limit}),
                None,
                true
            ),
            Err(ApiError::Limit)
        ));
    }
    let mut repaired = state(1, &old, &current);
    let proof = call(
        json!({"operation":"ratify","encoded":B64.encode(old[0].encoded()),
        "approved_hash":hex::encode(old[0].hash())}),
        Some(1),
        false,
    )
    .unwrap();
    repaired["ratifications"] = json!([proof["ratification"]]);
    assert_eq!(
        call(request(repaired), None, true).unwrap()["missing"],
        json!([])
    );
    assert_eq!(
        call(request(state(1, &old, &[full(1)])), None, true).unwrap()["missing"],
        json!([])
    );
    assert!(matches!(
        call(request(state(1, &old, &current)), Some(21), true),
        Err(ApiError::Malformed)
    ));
}
fn group() -> GroupID {
    GroupID::new(&DeviceID::from_pubkey(&public(1)), &[5; 32])
}
fn state(root: u8, old: &[GroupOperation], rosters: &[DeviceRoster]) -> Value {
    json!({"group_id":group().to_hex(),"account_public":B64.encode(public(root)),
        "existing_local":B64.encode(pack(old).unwrap()),"now_ms":2000,
        "rosters":rosters.iter().map(|r|json!({"account_public":B64.encode(r.account_ed()),"encoded":B64.encode(r.encoded())})).collect::<Vec<_>>(),"ratifications":[]})
}
fn call(value: Value, seed: Option<u8>, key: bool) -> Result<Value, ApiError> {
    let seed = seed.map(|n| [n; 32]);
    execute(
        &serde_json::to_vec(&value).unwrap(),
        seed.as_ref(),
        key.then_some(&KEY),
    )
    .map(|v| serde_json::from_slice(&v).unwrap())
}
fn create(
    root: u8,
    leaf: u8,
    old: &[GroupOperation],
    rosters: &[DeviceRoster],
    mutation: Value,
) -> GroupOperation {
    let result=call(json!({"operation":"create_operation","state":state(root,old,rosters),
        "certificate":B64.encode(entry(root,leaf,if leaf==10+root {ALL_CAPABILITIES}else{CAP_GROUPS|CAP_SYNC}).certificate().encoded()),"mutation":mutation}),Some(leaf),true).unwrap();
    GroupOperation::decode(&B64.decode(result["encoded"].as_str().unwrap()).unwrap()).unwrap()
}
fn direct<P: Serialize>(
    root: u8,
    leaf: u8,
    kind: OpType,
    payload: &P,
    clock: u64,
) -> GroupOperation {
    GroupOperation::from_device(
        DelegatedOperation::create(
            entry(root, leaf, ALL_CAPABILITIES).certificate().clone(),
            &[leaf; 32],
            group(),
            kind,
            payload,
            vec![],
            clock,
            clock,
            2000,
        )
        .unwrap(),
    )
}
fn founding() -> GroupOperation {
    direct(
        1,
        11,
        OpType::GroupCreate,
        &GroupCreatePayload {
            group_name: "Synthetic group".into(),
            encrypted_group_secret: KEY.to_vec(),
        },
        1,
    )
}
fn message(leaf: u8, clock: u64, id: u8) -> GroupOperation {
    direct(
        1,
        leaf,
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [id; 32],
            ciphertext: vec![id; 32],
            nonce: [id; 24],
        },
        clock,
    )
}

#[test]
fn leaf_only_creation_mirrors_account_messages_and_supports_restart_pagination() {
    let rosters = [full(1)];
    let mut old = vec![create(
        1,
        21,
        &[],
        &rosters,
        json!({"kind":"group_create","name":"Synthetic group"}),
    )];
    for n in 1..=3 {
        let op = create(
            1,
            if n % 2 == 0 { 11 } else { 21 },
            &old,
            &rosters,
            json!({"kind":"msg_add","ciphertext":B64.encode([n;32]),"nonce":B64.encode([n;24])}),
        );
        assert_eq!(op.operation().author_pubkey, public(1));
        assert_eq!(op.operation().lamport, u64::from(n) + 1);
        old.push(op);
    }
    let first = call(
        json!({"operation":"read_messages","state":state(1,&old,&rosters),"after":null,"limit":2}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(first["messages"].as_array().unwrap().len(), 2);
    assert_eq!(first["has_more"], true);
    let second=call(json!({"operation":"read_messages","state":state(1,&old,&rosters),"after":first["next"],"limit":2}),None,true).unwrap();
    assert_eq!(second["messages"].as_array().unwrap().len(), 1);
    assert_eq!(second["has_more"], false);
    let recent = call(
        json!({"operation":"read_messages","state":state(1,&old,&rosters),
            "after":null,"limit":2,"recent":true}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(recent["messages"].as_array().unwrap().len(), 2);
    assert_eq!(recent["has_more"], true);
    assert_eq!(recent["messages"][1]["msg_id"], second["messages"][0]["msg_id"]);
    let id = first["messages"][0]["msg_id"].clone();
    old.push(create(1,11,&old,&rosters,json!({"kind":"msg_edit","msg_id":id,"ciphertext":B64.encode([42;32]),"nonce":B64.encode([42;24])})));
    let edited = call(
        json!({"operation":"read_messages","state":state(1,&old,&rosters),"after":null,"limit":2}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(
        edited["messages"][0]["ciphertext_b64"],
        B64.encode([42; 32])
    );
    let inspect = call(
        json!({"operation":"inspect","encoded":B64.encode(old[0].encoded())}),
        None,
        false,
    )
    .unwrap();
    assert_eq!(
        inspect["installation_id"],
        DeviceID::from_pubkey(&public(21)).to_hex()
    );
    assert!(inspect.get("payload").is_none());
    assert!(inspect.get("encrypted_group_secret").is_none());
}

#[test]
fn strict_dtos_secret_modes_and_packed_framing_fail_closed() {
    let op = founding();
    let inspect = json!({"operation":"inspect","encoded":B64.encode(op.encoded())});
    assert!(matches!(
        call(inspect.clone(), Some(11), false),
        Err(ApiError::Malformed)
    ));
    assert!(matches!(
        call(inspect.clone(), None, true),
        Err(ApiError::Malformed)
    ));
    let mut unknown = inspect;
    unknown["trusted"] = json!(true);
    assert!(matches!(
        call(unknown, None, false),
        Err(ApiError::Malformed)
    ));
    let mut bad = pack(&[op]).unwrap();
    bad.push(0);
    assert!(unpack(&bad).is_err());
    assert!(unpack(&[0, 0, 0, 0]).is_err());
    let bad = call(
        json!({"operation":"create_operation","state":state(1,&[],&[full(1)]),
        "certificate":B64.encode(entry(1,21,CAP_GROUPS|CAP_SYNC).certificate().encoded()),
        "mutation":{"kind":"group_create","name":"Synthetic","private_key":"forbidden"}}),
        Some(21),
        true,
    );
    assert!(matches!(bad, Err(ApiError::Malformed)));
    let mut fork = state(1, &[founding()], &[full(1)]);
    fork["rosters"][0]["account_public"] = json!(B64.encode(public(2)));
    assert!(matches!(
        call(
            json!({"operation":"read_messages","state":fork,"after":null,"limit":1}),
            None,
            true
        ),
        Err(ApiError::Authority)
    ));
}

#[test]
fn own_history_receipt_preserves_revoked_device_history_without_reviving_live_authority() {
    let old = vec![founding()];
    let unseen = message(21, 2, 7);
    let bytes = pack(std::slice::from_ref(&unseen)).unwrap();
    let revoked = roster(1, 2, &[(11, ALL_CAPABILITIES)]);
    let live = json!({"operation":"preview_live","state":state(1,&old,std::slice::from_ref(&revoked)),"incoming":B64.encode(&bytes)});
    assert!(matches!(call(live, None, true), Err(ApiError::Authority)));
    let receipt = HistoryReceipt::issue(
        entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
        &[11; 32],
        group(),
        &bytes,
    )
    .unwrap();
    let request = json!({"operation":"preview_history","state":state(1,&old,&[revoked]),"incoming":B64.encode(&bytes),"receipt":B64.encode(receipt.encoded())});
    let result = call(request.clone(), None, true).unwrap();
    assert_eq!(result["op_count"], 2);
    assert_eq!(result["members"].as_array().unwrap().len(), 1);
    let mut wrong = request.clone();
    wrong["incoming"] = json!(B64.encode(pack(&[message(21, 3, 8)]).unwrap()));
    assert!(matches!(call(wrong, None, true), Err(ApiError::Authority)));
    let mut expired = request.clone();
    expired["state"]["now_ms"] = json!(1_000_001);
    assert!(matches!(
        call(expired, None, true),
        Err(ApiError::Authority)
    ));
    let mut foreign = request;
    let proof = HistoryReceipt::issue(
        entry(2, 12, ALL_CAPABILITIES).certificate().clone(),
        &[12; 32],
        group(),
        &bytes,
    )
    .unwrap();
    foreign["receipt"] = json!(B64.encode(proof.encoded()));
    assert!(matches!(
        call(foreign, None, true),
        Err(ApiError::Authority)
    ));
}

#[test]
fn foreign_live_packets_cannot_backdate_into_a_removed_group_permission() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let demote = direct(
        1,
        11,
        OpType::RoleSet,
        &RoleSetPayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            new_role: Role::ReadOnly,
            admin_rights: None,
            custom_title: None,
        },
        5,
    );
    let old = vec![founding(), invite, accept, demote];
    let backdated = direct(
        2,
        12,
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [7; 32],
            ciphertext: vec![7; 32],
            nonce: [7; 24],
        },
        4,
    );
    let request = json!({"operation":"preview_live","state":state(1,&old,&rosters),"incoming":B64.encode(pack(&[backdated]).unwrap())});
    assert!(matches!(
        call(request, None, true),
        Err(ApiError::Authority)
    ));
    // A read-only query still rebuilds the original committed state unchanged.
    let messages = call(
        json!({"operation":"read_messages","state":state(1,&old,&rosters),"after":null,"limit":5}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(messages["messages"], json!([]));
}

#[test]
fn invitation_requires_bound_foreign_receipt_current_source_and_our_pending_membership() {
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let bytes = pack(&[founding(), invite]).unwrap();
    let receipt = HistoryReceipt::issue(
        entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
        &[11; 32],
        group(),
        &bytes,
    )
    .unwrap();
    let request = json!({"operation":"preview_invite","state":state(2,&[],&[full(1),full(2)]),"incoming":B64.encode(&bytes),"source_account":B64.encode(public(1)),"receipt":B64.encode(receipt.encoded())});
    let result = call(request.clone(), None, true).unwrap();
    assert_eq!(result["pending_invite"], true);
    let mut wrong = request.clone();
    wrong["state"]["account_public"] = json!(B64.encode(public(3)));
    assert!(matches!(call(wrong, None, true), Err(ApiError::Authority)));
    let mut stale = request;
    stale["state"]["rosters"] =
        state(2, &[], &[roster(1, 2, &[(21, ALL_CAPABILITIES)]), full(2)])["rosters"].clone();
    assert!(matches!(call(stale, None, true), Err(ApiError::Authority)));
}

#[test]
fn exact_large_invitation_retry_preserves_accepted_membership_and_rejects_unseen_history() {
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        1004,
    );
    let mut initial = vec![founding(), invite];
    initial.extend((3..1004).map(|n| message(11, n, 7)));
    let mut committed = initial.clone();
    committed.push(accept);
    let request = |incoming: &[GroupOperation]| {
        let bytes = pack(incoming).unwrap();
        let receipt = HistoryReceipt::issue(
            entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
            &[11; 32],
            group(),
            &bytes,
        )
        .unwrap();
        json!({"operation":"preview_invite","state":state(2,&committed,&[full(1),full(2)]),
            "incoming":B64.encode(bytes),"source_account":B64.encode(public(1)),"receipt":B64.encode(receipt.encoded())})
    };
    let result = call(request(&initial), None, true).unwrap();
    assert_eq!(result["pending_invite"], false);
    assert_eq!(result["op_count"], committed.len());
    initial.push(message(11, 1005, 8));
    assert!(matches!(
        call(request(&initial), None, true),
        Err(ApiError::Conflict)
    ));
}

#[test]
fn concurrent_leave_and_previously_accepted_content_converge_without_reviving_group_authority() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let leave = direct(
        2,
        22,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Leave,
            ban: false,
        },
        4,
    );
    let message = |clock| {
        direct(
            2,
            12,
            OpType::MsgAdd,
            &MsgAddPayload {
                msg_id: [8; 32],
                ciphertext: vec![8; 32],
                nonce: [8; 24],
            },
            clock,
        )
    };
    let old = vec![founding(), invite, accept, message(10)];
    let live = call(
        json!({"operation":"preview_live","state":state(1,&old,&rosters),
        "incoming":B64.encode(pack(&[leave.clone()]).unwrap())}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(live["op_count"], 5);
    assert_eq!(live["last_message"], Value::Null);
    assert_eq!(live["superseded"].as_array().unwrap().len(), 1);
    let mut left = old[..3].to_vec();
    left.push(leave);
    let bytes = pack(&old).unwrap();
    let receipt = HistoryReceipt::issue(
        entry(2, 12, ALL_CAPABILITIES).certificate().clone(),
        &[12; 32],
        group(),
        &bytes,
    )
    .unwrap();
    let synced = call(
        json!({"operation":"preview_history","state":state(2,&left,&rosters),
        "incoming":B64.encode(bytes),"receipt":B64.encode(receipt.encoded())}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(synced["our_role"], "Removed");
    assert_eq!(synced["state_hash"], live["state_hash"]);
    assert_eq!(synced["needs_rekey"], true);
    let mut committed = old.clone();
    committed.push(left.last().unwrap().clone());
    let normal = call(
        json!({"operation":"read_messages","state":state(2,&committed,&rosters),
        "after":null,"limit":1}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(normal["messages"], json!([]));
    let own = call(
        json!({"operation":"read_messages","state":state(2,&committed,&rosters),
        "after":null,"limit":1,"include_local_dispositions":true}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(own["messages"][0]["local_disposition"], "not_delivered");
    assert_eq!(own["messages"][0]["msg_id"], hex::encode([8; 32]));
    assert_eq!(own["messages"][0]["ciphertext_b64"], B64.encode([8; 32]));
    let other = call(
        json!({"operation":"read_messages","state":state(1,&committed,&rosters),
        "after":null,"limit":1,"include_local_dispositions":true}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(other["messages"], json!([]));
    let next = call(
        json!({"operation":"read_messages","state":state(2,&committed,&rosters),
        "after":own["next"],"limit":1,"include_local_dispositions":true}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(next["messages"], json!([]));
    let deleted = direct(
        2,
        12,
        OpType::MsgDelete,
        &MsgDeletePayload { msg_id: [8; 32] },
        11,
    );
    committed.push(deleted);
    let hidden = call(
        json!({"operation":"read_messages","state":state(2,&committed,&rosters),
        "after":null,"limit":1,"include_local_dispositions":true}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(hidden["messages"][0]["deleted"], true);
    assert!(matches!(
        call(
            json!({"operation":"preview_live","state":state(2,&left,&rosters),
        "incoming":B64.encode(pack(&[message(11)]).unwrap())}),
            None,
            true
        ),
        Err(ApiError::Authority)
    ));
}

#[test]
fn known_writes_superseded_by_demotion_or_deletion_do_not_block_control_or_restart() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let msg = direct(
        2,
        22,
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [9; 32],
            ciphertext: vec![9; 32],
            nonce: [9; 24],
        },
        10,
    );
    let old = vec![founding(), invite, accept, msg];
    let demote = direct(
        1,
        11,
        OpType::RoleSet,
        &RoleSetPayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            new_role: Role::ReadOnly,
            admin_rights: None,
            custom_title: None,
        },
        4,
    );
    let delete = direct(
        1,
        11,
        OpType::GroupDelete,
        &GroupDeletePayload { reason: None },
        4,
    );
    for control in [demote, delete] {
        let result = call(
            json!({"operation":"preview_live","state":state(1,&old,&rosters),
            "incoming":B64.encode(pack(&[control.clone()]).unwrap())}),
            None,
            true,
        )
        .unwrap();
        assert_eq!(result["superseded"].as_array().unwrap().len(), 1);
        assert_eq!(result["last_message"], Value::Null);
        let mut complete = old.clone();
        complete.push(control);
        let restarted = call(
            json!({"operation":"read_state","state":state(1,&complete,&rosters)}),
            None,
            true,
        )
        .unwrap();
        assert_eq!(restarted["state_hash"], result["state_hash"]);
        assert_eq!(restarted["op_count"], 5);
    }
    // Historical privilege cannot soften a second creator or immutable Owner.
    let takeover = direct(
        2,
        12,
        OpType::GroupCreate,
        &GroupCreatePayload {
            group_name: "Takeover".into(),
            encrypted_group_secret: KEY.to_vec(),
        },
        1,
    );
    let mut invalid = old.clone();
    invalid.push(takeover);
    assert!(call(
        json!({"operation":"read_state","state":state(1,&invalid,&rosters)}),
        None,
        true
    )
    .is_err());
    invalid = old;
    invalid.push(direct(
        1,
        11,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(1)),
            reason: RemoveReason::Leave,
            ban: false,
        },
        11,
    ));
    assert!(call(
        json!({"operation":"read_state","state":state(1,&invalid,&rosters)}),
        None,
        true
    )
    .is_err());
}

#[test]
fn pending_non_owner_can_decline_without_accepting_or_removing_anyone_else() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::ReadOnly,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let old = vec![founding(), invite];
    let declined = create(
        2,
        22,
        &old,
        &rosters,
        json!({"kind":"member_remove", "account_public":B64.encode(public(2)),"reason":"Leave","ban":false}),
    );
    let mut complete = old;
    complete.push(declined);
    let result = call(
        json!({"operation":"read_state","state":state(2,&complete,&rosters)}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(result["our_role"], "Removed");
    assert_eq!(result["pending_invite"], false);
    assert_eq!(result["needs_rekey"], true);
    assert_eq!(result["superseded"], json!([]));
}

#[test]
fn leaving_a_group_preserves_valid_pre_leave_message_history_for_every_account_device() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let message = direct(
        2,
        22,
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [9; 32],
            ciphertext: vec![9; 32],
            nonce: [9; 24],
        },
        4,
    );
    let leave = direct(
        2,
        12,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Leave,
            ban: false,
        },
        5,
    );
    let old = vec![founding(), invite, accept, message, leave];
    for account in [1, 2] {
        let result=call(json!({"operation":"read_messages","state":state(account,&old,&rosters),"after":null,"limit":10}),None,true).unwrap();
        assert_eq!(result["messages"].as_array().unwrap().len(), 1);
        let state = call(
            json!({"operation":"read_state","state":state(account,&old,&rosters)}),
            None,
            true,
        )
        .unwrap();
        assert_eq!(state["last_message"]["msg_id"], hex::encode([9; 32]));
        assert_eq!(state["superseded"], json!([]));
    }
}

#[test]
fn two_installations_accepting_and_leaving_the_same_membership_do_not_deadlock_sync() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = |leaf| {
        direct(
            2,
            leaf,
            OpType::MemberAccept,
            &MemberAcceptPayload {
                invite_op_id: invite.operation().op_id,
            },
            3,
        )
    };
    let leave = |leaf| {
        direct(
            2,
            leaf,
            OpType::MemberRemove,
            &MemberRemovePayload {
                target_device_id: DeviceID::from_pubkey(&public(2)),
                reason: RemoveReason::Leave,
                ban: false,
            },
            4,
        )
    };
    let mut old = vec![founding(), invite.clone(), accept(12)];
    let result = call(
        json!({"operation":"preview_live","state":state(1,&old,&rosters),
        "incoming":B64.encode(pack(&[accept(22)]).unwrap())}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(result["op_count"], 4);
    old.extend([accept(22), leave(12)]);
    let result = call(
        json!({"operation":"preview_live","state":state(1,&old,&rosters),
        "incoming":B64.encode(pack(&[leave(22)]).unwrap())}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(result["op_count"], 6);
    assert_eq!(result["superseded"].as_array().unwrap().len(), 2);
    old.push(leave(22));
    let restarted = call(
        json!({"operation":"read_state","state":state(2,&old,&rosters)}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(restarted["state_hash"], result["state_hash"]);
    assert_eq!(restarted["our_role"], "Removed");
}

#[test]
fn a_concurrently_invalidated_invitation_becomes_a_private_archive_without_fake_membership() {
    let rosters = [full(1), full(2), full(3)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let promote = direct(
        1,
        11,
        OpType::RoleSet,
        &RoleSetPayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            new_role: Role::Admin,
            admin_rights: Some(AdminRights::all_true()),
            custom_title: None,
        },
        4,
    );
    let late = direct(
        2,
        12,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(3)),
            invited_pubkey: public(3),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        10,
    );
    let accepted = direct(
        3,
        13,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: late.operation().op_id,
        },
        11,
    );
    let leave = direct(
        2,
        22,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Leave,
            ban: false,
        },
        5,
    );
    let mut old = vec![founding(), invite, accept, promote, late, accepted];
    let merged = call(
        json!({"operation":"preview_live","state":state(3,&old,&rosters),
        "incoming":B64.encode(pack(&[leave.clone()]).unwrap())}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(merged["our_role"], "Removed");
    assert_eq!(merged["archived"], true);
    assert_eq!(merged["pending_invite"], false);
    assert_eq!(merged["members"].as_array().unwrap().len(), 2);
    assert_eq!(merged["superseded"].as_array().unwrap().len(), 2);
    old.push(leave);
    let restarted = call(
        json!({"operation":"read_state","state":state(3,&old,&rosters)}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(restarted["state_hash"], merged["state_hash"]);
    let new = direct(
        1,
        11,
        OpType::MetadataSet,
        &MetadataSetPayload {
            key: MetadataKey::Name,
            value: b"Late".to_vec(),
        },
        12,
    );
    assert!(matches!(
        call(
            json!({"operation":"preview_live","state":state(3,&old,&rosters),
        "incoming":B64.encode(pack(&[new]).unwrap())}),
            None,
            true
        ),
        Err(ApiError::Authority)
    ));
    // A new foreign invitation cannot use the private archive fallback to
    // bootstrap an account absent from the validated membership.
    let bytes = pack(&old).unwrap();
    let receipt = HistoryReceipt::issue(
        entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
        &[11; 32],
        group(),
        &bytes,
    )
    .unwrap();
    assert!(call(json!({"operation":"preview_invite","state":state(3,&[],&rosters),
        "incoming":B64.encode(bytes),"source_account":B64.encode(public(1)),"receipt":B64.encode(receipt.encoded())}),None,true).is_err());

    // A real subsequent invite can carry these no-effect records, but EVERY
    // previously unseen historical leaf still needs current authority/proof.
    let rosters = [full(1), full(2), full(3), full(4)];
    let (epoch, key, _) = epoch_create(&old, 11, &rosters, &KEY);
    old.push(epoch);
    let fresh = keyed(json!({"operation":"create_operation", "state":state(1,&old,&rosters),
        "certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),
        "mutation":{"kind":"member_invite","account_public":B64.encode(public(4)),"role":"Member"}}),Some(11),&key).unwrap();
    old.push(
        GroupOperation::decode(&B64.decode(fresh["encoded"].as_str().unwrap()).unwrap()).unwrap(),
    );
    let bytes = pack(&old).unwrap();
    let receipt = HistoryReceipt::issue(
        entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
        &[11; 32],
        group(),
        &bytes,
    )
    .unwrap();
    let request = |s| {
        json!({"operation":"preview_invite","state":s,"incoming":B64.encode(&bytes),
        "source_account":B64.encode(public(1)),"receipt":B64.encode(receipt.encoded()),"incoming_key":B64.encode(key)})
    };
    let invited = keyed(request(state(4, &[], &rosters)), None, &key).unwrap();
    assert_eq!(invited["pending_invite"], true);
    assert!(invited["historical_principals"]
        .as_array()
        .unwrap()
        .contains(&json!(hex::encode(public(3)))));
    let revoked = [
        full(1),
        full(2),
        roster(3, 2, &[(23, ALL_CAPABILITIES)]),
        full(4),
    ];
    assert!(matches!(
        keyed(request(state(4, &[], &revoked)), None, &key),
        Err(ApiError::Authority)
    ));
    let accepted = old
        .iter()
        .find(|op| op.operation().author_pubkey == public(3))
        .unwrap();
    let proof = call(
        json!({"operation":"ratify","encoded":B64.encode(accepted.encoded()),
        "approved_hash":hex::encode(accepted.hash())}),
        Some(3),
        false,
    )
    .unwrap();
    let mut approved = state(4, &[], &revoked);
    approved["ratifications"] = json!([proof["ratification"]]);
    assert_eq!(
        keyed(request(approved), None, &key).unwrap()["state_hash"],
        invited["state_hash"]
    );
}

#[test]
fn missing_causal_parents_defer_atomic_batches_and_inspection_exposes_repair_ids() {
    let rosters = [full(1)];
    let old = vec![founding()];
    let parent = message(11, 2, 6);
    let child = GroupOperation::from_device(
        DelegatedOperation::create(
            entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
            &[11; 32],
            group(),
            OpType::MsgAdd,
            &MsgAddPayload {
                msg_id: [7; 32],
                ciphertext: vec![7; 32],
                nonce: [7; 24],
            },
            vec![parent.operation().op_id],
            3,
            3,
            2000,
        )
        .unwrap(),
    );
    let inspected = call(
        json!({"operation":"inspect","encoded":B64.encode(child.encoded())}),
        None,
        false,
    )
    .unwrap();
    assert_eq!(
        inspected["parent_heads"],
        json!([parent.operation().op_id.to_hex()])
    );
    assert_eq!(inspected["message_target"], hex::encode([7; 32]));
    let preview = |ops: &[GroupOperation]| {
        call(
            json!({"operation":"preview_live","state":state(1,&old,&rosters),
        "incoming":B64.encode(pack(ops).unwrap())}),
            None,
            true,
        )
    };
    assert!(matches!(
        preview(&[child.clone()]),
        Err(ApiError::Dependency)
    ));
    assert!(matches!(
        preview(&[child.clone(), parent.clone()]),
        Err(ApiError::Dependency)
    ));
    assert_eq!(
        preview(&[parent.clone(), child.clone()]).unwrap()["op_count"],
        3
    );
    let authority = secure_group_protocol::state::Authority {
        rosters: &rosters,
        ratifications: &[],
        now_ms: 2000,
    };
    let mut current =
        secure_group_protocol::state::AccountGroupState::rebuild(group(), &old, &[], &authority)
            .unwrap();
    assert!(current.apply_batch(&[child, parent], &authority).is_err());
    assert_eq!(current.core().op_count, 1);
}

#[test]
fn acceptance_exposes_and_requires_the_exact_invitation_dependency() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accepted = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let inspected = call(
        json!({"operation":"inspect","encoded":B64.encode(accepted.encoded())}),
        None,
        false,
    )
    .unwrap();
    assert_eq!(
        inspected["invitation_dependency"],
        invite.operation().op_id.to_hex()
    );
    assert!(matches!(
        call(
            json!({"operation":"preview_live","state":state(1,&[founding()],&rosters),
        "incoming":B64.encode(pack(&[accepted.clone()]).unwrap())}),
            None,
            true
        ),
        Err(ApiError::Dependency)
    ));
    let applied = call(
        json!({"operation":"preview_live","state":state(1,&[founding(),invite],&rosters),
        "incoming":B64.encode(pack(&[accepted]).unwrap())}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(applied["op_count"], 3);
}

#[test]
fn bounded_parent_window_keeps_the_senders_predecessor_among_many_concurrent_heads() {
    let rosters = [full(1)];
    let (own, other) = if DeviceID::from_pubkey(&public(11)) < DeviceID::from_pubkey(&public(21)) {
        (11, 21)
    } else {
        (21, 11)
    };
    let founding = founding();
    let predecessor = message(own, 2, 99);
    let mut old = vec![founding.clone(), predecessor.clone()];
    for n in 0..66u8 {
        old.push(GroupOperation::from_device(
            DelegatedOperation::create(
                entry(1, other, ALL_CAPABILITIES).certificate().clone(),
                &[other; 32],
                group(),
                OpType::MsgAdd,
                &MsgAddPayload {
                    msg_id: [n; 32],
                    ciphertext: vec![n; 32],
                    nonce: [n; 24],
                },
                vec![founding.operation().op_id],
                2,
                u64::from(n) + 100,
                2000,
            )
            .unwrap(),
        ));
    }
    let next = create(
        1,
        own,
        &old,
        &rosters,
        json!({"kind":"msg_add","ciphertext":B64.encode([8;32]),"nonce":B64.encode([8;24])}),
    );
    assert_eq!(next.operation().parent_heads.len(), 64);
    assert!(next
        .operation()
        .parent_heads
        .contains(&predecessor.operation().op_id));
    assert!(next
        .operation()
        .parent_heads
        .windows(2)
        .all(|w| w[0] < w[1]));
}

#[test]
fn terminal_dependency_repair_can_record_an_accept_after_decline_without_rejoining() {
    let rosters = [full(1), full(2), full(3)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let decline = direct(
        2,
        22,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Leave,
            ban: false,
        },
        3,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let left = GroupOperation::from_device(
        DelegatedOperation::create(
            entry(2, 12, ALL_CAPABILITIES).certificate().clone(),
            &[12; 32],
            group(),
            OpType::MemberRemove,
            &MemberRemovePayload {
                target_device_id: DeviceID::from_pubkey(&public(2)),
                reason: RemoveReason::Leave,
                ban: false,
            },
            vec![accept.operation().op_id],
            4,
            4,
            2000,
        )
        .unwrap(),
    );
    let mut old = vec![founding(), invite.clone(), decline];
    let preview = |old: &[GroupOperation], incoming: &[GroupOperation]| {
        call(
            json!({"operation":"preview_live","state":state(1,old,&rosters),
        "incoming":B64.encode(pack(incoming).unwrap())}),
            None,
            true,
        )
    };
    assert!(matches!(
        preview(&old, &[left.clone()]),
        Err(ApiError::Dependency)
    ));
    preview(&old, &[accept.clone()]).unwrap();
    old.push(accept);
    let done = preview(&old, &[left]).unwrap();
    assert!(done["members"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["pubkey_hex"] == hex::encode(public(2)) && m["removed"] == true));
    let foreign = direct(
        3,
        13,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        4,
    );
    assert!(preview(&old, &[foreign]).is_err());
}

fn keyed(value: Value, seed: Option<u8>, key: &[u8; 32]) -> Result<Value, ApiError> {
    let seed = seed.map(|n| [n; 32]);
    execute(
        &serde_json::to_vec(&value).unwrap(),
        seed.as_ref(),
        Some(key),
    )
    .map(|encoded| serde_json::from_slice(&encoded).unwrap())
}
fn epoch_create(
    old: &[GroupOperation],
    leaf: u8,
    rosters: &[DeviceRoster],
    key: &[u8; 32],
) -> (GroupOperation, [u8; 32], Value) {
    let cert = rosters
        .iter()
        .flat_map(|r| r.entries())
        .find(|e| e.certificate().claims().device_ed == public(leaf))
        .unwrap()
        .certificate();
    let result = keyed(
        json!({"operation":"create_operation","state":state(1,old,rosters),
        "certificate":B64.encode(cert.encoded()),"mutation":{"kind":"group_rekey"}}),
        Some(leaf),
        key,
    )
    .unwrap();
    let op =
        GroupOperation::decode(&B64.decode(result["encoded"].as_str().unwrap()).unwrap()).unwrap();
    let next = B64
        .decode(result["summary"]["group_secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (op, next, result["summary"].clone())
}

#[test]
fn explicit_leaf_epoch_rotates_after_removal_and_is_exactly_root_ratifiable() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let kick = direct(
        1,
        11,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Kick,
            ban: false,
        },
        4,
    );
    let mut old = vec![founding(), invite, accept, kick];
    let (epoch, next, summary) = epoch_create(&old, 21, &rosters, &KEY);
    assert_ne!(next, KEY);
    assert_eq!(epoch.type_name(), "GroupKeyEpoch");
    assert_eq!(summary["needs_rekey"], false);
    assert_eq!(summary["keyring"].as_array().unwrap().len(), 2);
    assert!(summary["members"]
        .as_array()
        .unwrap()
        .iter()
        .all(|m| m["rekey_required"] == false));
    // The removed account cannot accept a fresh key even though its leaf is
    // still globally certified. Account authorization is not group membership.
    assert!(matches!(
        keyed(
            json!({"operation":"preview_live","state":state(2,&old,&rosters),
        "incoming":B64.encode(pack(&[epoch.clone()]).unwrap())}),
            None,
            &KEY
        ),
        Err(ApiError::Authority)
    ));
    let proof=call(json!({"operation":"ratify","encoded":B64.encode(epoch.encoded()),"approved_hash":hex::encode(epoch.hash())}),Some(1),false).unwrap();
    assert!(call(json!({"operation":"ratify","encoded":B64.encode(epoch.encoded()),"approved_hash":hex::encode(epoch.hash())}),Some(2),false).is_err());
    old.push(epoch.clone());
    let mut restored = state(1, &old, &[roster(1, 2, &[(11, ALL_CAPABILITIES)]), full(2)]);
    let current = keyed(
        json!({"operation":"read_state","state":restored}),
        None,
        &next,
    )
    .unwrap();
    assert_eq!(current["state_hash"], summary["state_hash"]);
    assert!(current.get("keyring").is_none());
    assert!(current.get("group_secret").is_none());
    // A new foreign import needs current leaf authority or an exact Root proof.
    restored = state(
        1,
        &old[..4],
        &[roster(1, 2, &[(11, ALL_CAPABILITIES)]), full(2)],
    );
    assert!(matches!(
        keyed(
            json!({"operation":"preview_live","state":restored,"incoming":B64.encode(pack(&[epoch.clone()]).unwrap())}),
            None,
            &KEY
        ),
        Err(ApiError::Authority)
    ));
    restored["ratifications"] = json!([proof["ratification"]]);
    let allowed=keyed(json!({"operation":"preview_live","state":restored,"incoming":B64.encode(pack(&[epoch]).unwrap())}),None,&KEY).unwrap();
    assert_eq!(allowed["group_secret"], B64.encode(next));
}

#[test]
fn explicit_reinvitation_preserves_old_history_and_validates_changed_keys_without_implicit_rejoin()
{
    let rosters = [full(1), full(2)];
    let invitation = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invitation.operation().op_id,
        },
        3,
    );
    let leave = direct(
        2,
        22,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Leave,
            ban: false,
        },
        4,
    );
    let previous = vec![founding(), invitation, accept, leave];
    let mut incoming = previous.clone();
    let (epoch, key, _) = epoch_create(&incoming, 11, &rosters, &KEY);
    incoming.push(epoch);
    let fresh = keyed(json!({"operation":"create_operation","state":state(1,&incoming,&rosters),
        "certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),
        "mutation":{"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}}),Some(11),&key).unwrap();
    incoming.push(
        GroupOperation::decode(&B64.decode(fresh["encoded"].as_str().unwrap()).unwrap()).unwrap(),
    );
    let bytes = pack(&incoming).unwrap();
    let receipt = HistoryReceipt::issue(
        entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
        &[11; 32],
        group(),
        &bytes,
    )
    .unwrap();
    let request = |operation, old: &[GroupOperation], proposed| {
        json!({"operation":operation,"state":state(2,old,&rosters),
        "incoming":B64.encode(&bytes),"receipt":B64.encode(receipt.encoded()),"source_account":B64.encode(public(1)),"incoming_key":proposed})
    };
    assert!(matches!(
        keyed(
            request("preview_invite", &previous, B64.encode(key)),
            None,
            &KEY
        ),
        Err(ApiError::Conflict)
    ));
    let result = keyed(
        request("preview_reinvite", &previous, B64.encode(key)),
        None,
        &KEY,
    )
    .unwrap();
    assert_eq!(result["pending_invite"], true);
    assert_eq!(result["group_secret"], B64.encode(key));
    assert_eq!(result["op_count"], 6);
    assert_ne!(
        result["invite_op_id"],
        previous[1].operation().op_id.to_hex()
    );
    assert!(matches!(
        keyed(
            request("preview_reinvite", &previous, B64.encode(KEY)),
            None,
            &KEY
        ),
        Err(ApiError::InvalidOperation)
    ));
    let missed_leave = keyed(
        request("preview_reinvite", &previous[..3], B64.encode(key)),
        None,
        &KEY,
    )
    .unwrap();
    assert_eq!(missed_leave["state_hash"], result["state_hash"]);
    assert_eq!(missed_leave["pending_invite"], true);
    // Current authority still applies to the unseen closing proof. A revoked
    // sibling cannot turn the phone's active membership into a new invitation.
    let mut revoked = request("preview_reinvite", &previous[..3], B64.encode(key));
    revoked["state"] = state(
        2,
        &previous[..3],
        &[full(1), roster(2, 2, &[(12, ALL_CAPABILITIES)])],
    );
    assert!(matches!(
        keyed(revoked, None, &KEY),
        Err(ApiError::Authority)
    ));
    let mut omitted = incoming.clone();
    omitted.retain(|op| op.hash() != previous[3].hash());
    let packed = pack(&omitted).unwrap();
    let signed = HistoryReceipt::issue(
        entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
        &[11; 32],
        group(),
        &packed,
    )
    .unwrap();
    let missing = json!({"operation":"preview_reinvite","state":state(2,&previous[..3],&rosters),
      "incoming":B64.encode(packed),"receipt":B64.encode(signed.encoded()),"source_account":B64.encode(public(1)),"incoming_key":B64.encode(key)});
    assert!(matches!(
        keyed(missing, None, &KEY),
        Err(ApiError::Authority)
    ));
    let repeated = keyed(
        request("preview_reinvite", &incoming, B64.encode(key)),
        None,
        &key,
    )
    .unwrap();
    assert_eq!(repeated["state_hash"], result["state_hash"]);
    let deleted = direct(
        1,
        11,
        OpType::GroupDelete,
        &GroupDeletePayload { reason: None },
        5,
    );
    let mut terminal = previous.clone();
    terminal.push(deleted);
    assert!(matches!(
        keyed(
            request("preview_reinvite", &terminal, B64.encode(key)),
            None,
            &KEY
        ),
        Err(ApiError::Conflict)
    ));
}

#[test]
fn prepared_invitation_uses_a_genuine_pending_snapshot_and_not_a_later_accepted_key() {
    let rosters = [full(1), full(2)];
    let mut old = vec![founding()];
    let invite = create(
        1,
        11,
        &old,
        &rosters,
        json!({"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}),
    );
    old.push(invite.clone());
    let (epoch, key, _) = epoch_create(&old, 11, &rosters, &KEY);
    old.push(epoch);
    let request = |old: &[GroupOperation]| {
        json!({"operation":"prepare_invitation","state":state(1,old,&rosters),
        "certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),
        "origin_op_id":invite.operation().op_id.to_hex(),"recipient_account":B64.encode(public(2))})
    };
    let pending = keyed(request(&old), Some(11), &key).unwrap();
    assert_eq!(pending["reinvitation"], false);
    assert_eq!(pending["group_secret"], B64.encode(key));
    let receive = |prepared: &Value| {
        json!({"operation":"preview_invite","state":state(2,&[],&rosters),
        "incoming":prepared["packed_ops"],"source_account":B64.encode(public(1)),
        "receipt":prepared["receipt"],"incoming_key":prepared["group_secret"]})
    };
    assert_eq!(
        keyed(receive(&pending), None, &key).unwrap()["pending_invite"],
        true
    );
    let accepted = keyed(
        json!({"operation":"create_operation","state":state(2,&old,&rosters),
        "certificate":B64.encode(entry(2,12,ALL_CAPABILITIES).certificate().encoded()),
        "mutation":{"kind":"member_accept","invite_op_id":invite.operation().op_id.to_hex()}}),
        Some(12),
        &key,
    )
    .unwrap();
    let accepted =
        GroupOperation::decode(&B64.decode(accepted["encoded"].as_str().unwrap()).unwrap())
            .unwrap();
    old.push(accepted.clone());
    let (later, later_key, _) = epoch_create(&old, 11, &rosters, &key);
    old.push(later.clone());
    let prepared = keyed(request(&old), Some(11), &later_key).unwrap();
    let snapshot = unpack(
        &B64.decode(prepared["packed_ops"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(prepared["group_secret"], B64.encode(key));
    assert_eq!(snapshot.len(), 3);
    assert!(snapshot
        .iter()
        .all(|op| op.hash() != accepted.hash() && op.hash() != later.hash()));
    assert_eq!(
        keyed(receive(&prepared), None, &key).unwrap()["pending_invite"],
        true
    );
}

#[test]
fn invitation_preparation_rejects_obsolete_lifecycles_and_another_installations_origin() {
    let rosters = [full(1), full(2)];
    let mut old = vec![founding()];
    let invite = create(
        1,
        11,
        &old,
        &rosters,
        json!({"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}),
    );
    old.push(invite.clone());
    old.push(create(
        2,
        12,
        &old,
        &rosters,
        json!({"kind":"member_accept","invite_op_id":invite.operation().op_id.to_hex()}),
    ));
    old.push(create(1,11,&old,&rosters,json!({"kind":"member_remove","account_public":B64.encode(public(2)),"reason":"Kick","ban":false})));
    let request = |old: &[GroupOperation], origin: &GroupOperation, leaf| {
        json!({"operation":"prepare_invitation","state":state(1,old,&rosters),
        "certificate":B64.encode(entry(1,leaf,if leaf==11{ALL_CAPABILITIES}else{CAP_GROUPS|CAP_SYNC}).certificate().encoded()),
        "origin_op_id":origin.operation().op_id.to_hex(),"recipient_account":B64.encode(public(2))})
    };
    assert!(matches!(
        keyed(request(&old, &invite, 11), Some(11), &KEY),
        Err(ApiError::Authority)
    ));
    let (epoch, key, _) = epoch_create(&old, 11, &rosters, &KEY);
    old.push(epoch);
    let result=keyed(json!({"operation":"create_operation","state":state(1,&old,&rosters),
        "certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),
        "mutation":{"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}}),Some(11),&key).unwrap();
    let fresh =
        GroupOperation::decode(&B64.decode(result["encoded"].as_str().unwrap()).unwrap()).unwrap();
    old.push(fresh.clone());
    assert!(matches!(
        keyed(request(&old, &invite, 11), Some(11), &key),
        Err(ApiError::Authority)
    ));
    assert!(matches!(
        keyed(request(&old, &fresh, 21), Some(21), &key),
        Err(ApiError::Authority)
    ));
    let prepared = keyed(request(&old, &fresh, 11), Some(11), &key).unwrap();
    assert_eq!(prepared["reinvitation"], true);
    assert_eq!(prepared["group_secret"], B64.encode(key));
    assert!(prepared.get("group_id").is_none());
}

#[test]
fn rejoin_delivery_does_not_require_offline_messages_from_the_departed_lifecycle() {
    use secure_group_protocol::delivery::select;
    use std::collections::HashSet;
    let rosters = [full(1), full(2)];
    let mut shared = vec![founding()];
    let invitation = create(
        1,
        11,
        &shared,
        &rosters,
        json!({"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}),
    );
    shared.push(invitation.clone());
    shared.push(create(
        2,
        12,
        &shared,
        &rosters,
        json!({"kind":"member_accept","invite_op_id":invitation.operation().op_id.to_hex()}),
    ));
    let mut offline = shared.clone();
    for n in 4..=8 {
        offline.push(create(
            2,
            12,
            &offline,
            &rosters,
            json!({"kind":"msg_add","ciphertext":B64.encode([n;32]),"nonce":B64.encode([n;24])}),
        ));
    }
    let old_messages = offline[shared.len()..].to_vec();
    let mut owner = shared.clone();
    owner.push(create(
        1,
        11,
        &owner,
        &rosters,
        json!({"kind":"metadata_set","key":"Name","value":B64.encode("Synthetic changed group")}),
    ));
    owner.push(create(2, 22, &owner, &rosters,
        json!({"kind":"member_remove","account_public":B64.encode(public(2)),"reason":"Leave","ban":false})));
    let terminal = &owner[shared.len()..];
    keyed(
        json!({"operation":"preview_live","state":state(2,&offline,&rosters),
        "incoming":B64.encode(pack(terminal).unwrap())}),
        None,
        &KEY,
    )
    .unwrap();
    offline.extend_from_slice(terminal);
    let (epoch, key, _) = epoch_create(&owner, 11, &rosters, &KEY);
    owner.push(epoch.clone());
    let fresh = keyed(json!({"operation":"create_operation","state":state(1,&owner,&rosters),
        "certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),
        "mutation":{"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}}), Some(11), &key).unwrap();
    let fresh =
        GroupOperation::decode(&B64.decode(fresh["encoded"].as_str().unwrap()).unwrap()).unwrap();
    owner.push(fresh.clone());
    let packed = pack(&owner).unwrap();
    let receipt = HistoryReceipt::issue(
        entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
        &[11; 32],
        group(),
        &packed,
    )
    .unwrap();
    let merged = keyed(
        json!({"operation":"preview_reinvite","state":state(2,&offline,&rosters),
        "incoming":B64.encode(packed),"source_account":B64.encode(public(1)),
        "receipt":B64.encode(receipt.encoded()),"incoming_key":B64.encode(key)}),
        None,
        &KEY,
    )
    .unwrap();
    assert_eq!(merged["pending_invite"], true);
    offline.extend([epoch, fresh.clone()]);
    let before = keyed(
        json!({"operation":"read_messages","state":state(2,&offline,&rosters),
        "after":null,"limit":100}),
        None,
        &key,
    )
    .unwrap();
    let accepted = keyed(
        json!({"operation":"create_operation","state":state(2,&offline,&rosters),
        "certificate":B64.encode(entry(2,12,ALL_CAPABILITIES).certificate().encoded()),
        "mutation":{"kind":"member_accept","invite_op_id":fresh.operation().op_id.to_hex()}}),
        Some(12),
        &key,
    )
    .unwrap();
    let accepted =
        GroupOperation::decode(&B64.decode(accepted["encoded"].as_str().unwrap()).unwrap())
            .unwrap();
    assert_eq!(accepted.operation().lamport, 9);
    offline.push(accepted.clone());
    let known: HashSet<_> = owner.iter().map(GroupOperation::hash).collect();
    let selected = select(&offline, accepted.operation().op_id, &known, 1000).unwrap();
    assert!(selected.complete);
    assert!(selected.operations.iter().all(|op| !old_messages.iter().any(|old| old.hash()==op.hash())),
        "new acceptance must not force old-lifecycle message delivery to a currently pending account");
    let selected: Vec<_> = selected.operations.iter().map(|op| (*op).clone()).collect();
    let result = keyed(
        json!({"operation":"preview_live","state":state(1,&owner,&rosters),
        "incoming":B64.encode(pack(&selected).unwrap())}),
        None,
        &key,
    )
    .unwrap();
    let member = result["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["pubkey_hex"] == hex::encode(public(2)))
        .unwrap();
    assert_eq!(member["accepted"], true);
    // The sender's old committed history remains available for its own account.
    let history = keyed(
        json!({"operation":"read_messages","state":state(2,&offline,&rosters),
        "after":null,"limit":100}),
        None,
        &key,
    )
    .unwrap();
    assert!(!before["messages"].as_array().unwrap().is_empty());
    assert_eq!(history["messages"], before["messages"]);
}

#[test]
fn accepted_reactions_to_a_superseded_message_do_not_deadlock_history_recovery() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let demote = direct(
        1,
        11,
        OpType::RoleSet,
        &RoleSetPayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            new_role: Role::ReadOnly,
            admin_rights: None,
            custom_title: None,
        },
        4,
    );
    let message = direct(
        2,
        12,
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [7; 32],
            ciphertext: vec![7; 32],
            nonce: [7; 24],
        },
        5,
    );
    let reaction = |clock| {
        direct(
            1,
            11,
            OpType::ReactionSet,
            &ReactionSetPayload {
                msg_id: [7; 32],
                emoji: "+1".into(),
                present: true,
            },
            clock,
        )
    };
    let old = vec![founding(), invite, accept, demote, message, reaction(6)];
    let recovered = call(
        json!({"operation":"read_state","state":state(1,&old,&rosters)}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(recovered["op_count"], 6);
    assert_eq!(recovered["last_message"], Value::Null);
    assert_eq!(recovered["superseded"].as_array().unwrap().len(), 2);
    assert!(matches!(
        call(
            json!({"operation":"preview_live","state":state(1,&old,&rosters),
        "incoming":B64.encode(pack(&[reaction(7)]).unwrap())}),
            None,
            true
        ),
        Err(ApiError::Dependency)
    ));
}

#[test]
fn target_membership_dependencies_survive_a_full_parent_window_and_can_be_repaired() {
    use secure_group_protocol::delivery::select;
    use std::collections::HashSet;
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        21,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accepted = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let promotion = direct(
        1,
        21,
        OpType::RoleSet,
        &RoleSetPayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            new_role: Role::Admin,
            admin_rights: Some(AdminRights::all_true()),
            custom_title: None,
        },
        4,
    );
    let mut old = vec![
        founding(),
        invite.clone(),
        accepted.clone(),
        promotion.clone(),
    ];
    for n in 0..66u8 {
        old.push(GroupOperation::from_device(
            DelegatedOperation::create(
                entry(1, 21, ALL_CAPABILITIES).certificate().clone(),
                &[21; 32],
                group(),
                OpType::MsgAdd,
                &MsgAddPayload {
                    msg_id: [n; 32],
                    ciphertext: vec![n; 32],
                    nonce: [n; 24],
                },
                vec![],
                5,
                100 + u64::from(n),
                2000,
            )
            .unwrap(),
        ));
    }
    let kick = create(
        1,
        11,
        &old,
        &rosters,
        json!({"kind":"member_remove","account_public":B64.encode(public(2)),"reason":"Kick","ban":false}),
    );
    assert_eq!(kick.operation().parent_heads.len(), 64);
    for dependency in [
        invite.operation().op_id,
        accepted.operation().op_id,
        promotion.operation().op_id,
    ] {
        assert!(kick.operation().parent_heads.contains(&dependency));
    }
    old.push(kick.clone());
    let selected = select(&old, kick.operation().op_id, &HashSet::new(), 1000).unwrap();
    let operations: Vec<_> = selected.operations.iter().map(|op| (*op).clone()).collect();
    let applied = call(
        json!({"operation":"preview_live","state":state(1,&[founding()],&rosters),
        "incoming":B64.encode(pack(&operations).unwrap())}),
        None,
        true,
    )
    .unwrap();
    let target = applied["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["pubkey_hex"] == hex::encode(public(2)))
        .unwrap();
    assert_eq!(target["removed"], true);
    assert_eq!(target["role"], "Admin");
}

#[test]
fn terminal_delivery_closure_stops_before_new_keys_and_acknowledged_batches_make_progress() {
    use secure_group_protocol::delivery::{select, SelectionError};
    use std::collections::HashSet;
    let rosters = [full(1), full(2)];
    let mut old = vec![founding()];
    let invite = create(
        1,
        21,
        &old,
        &rosters,
        json!({"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}),
    );
    old.push(invite.clone());
    let accepted = create(
        2,
        22,
        &old,
        &rosters,
        json!({"kind":"member_accept","invite_op_id":invite.operation().op_id.to_hex()}),
    );
    old.push(accepted);
    let kick = create(
        1,
        11,
        &old,
        &rosters,
        json!({"kind":"member_remove","account_public":B64.encode(public(2)),"reason":"Kick","ban":false}),
    );
    old.push(kick.clone());
    let (epoch, key, _) = epoch_create(&old, 11, &rosters, &KEY);
    old.push(epoch.clone());
    let later = keyed(
        json!({"operation":"create_operation","state":state(1,&old,&rosters),
        "certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),
        "mutation":{"kind":"msg_add","ciphertext":B64.encode([7;32]),"nonce":B64.encode([7;24])}}),
        Some(11),
        &key,
    )
    .unwrap();
    let message =
        GroupOperation::decode(&B64.decode(later["encoded"].as_str().unwrap()).unwrap()).unwrap();
    old.push(message.clone());
    let request = |leaf, known: Vec<String>| {
        json!({"operation":"select_delivery","state":state(1,&old,&rosters),
        "certificate":B64.encode(entry(1,leaf,if leaf==11 {ALL_CAPABILITIES}else{CAP_GROUPS|CAP_SYNC}).certificate().encoded()),
        "origin_op_id":kick.operation().op_id.to_hex(),"acknowledged":known,"limit":1})
    };
    let first = keyed(request(11, vec![]), None, &key).unwrap();
    assert_eq!(first["complete"], false);
    assert_eq!(
        first["operation_hashes"],
        json!([hex::encode(old[0].hash())])
    );
    assert!(first.get("group_secret").is_none());
    let next = keyed(request(11, vec![hex::encode(old[0].hash())]), None, &key).unwrap();
    assert_eq!(
        next["operation_hashes"],
        json!([hex::encode(invite.hash())])
    );
    assert!(matches!(
        keyed(request(21, vec![]), None, &key),
        Err(ApiError::Authority)
    ));
    assert!(matches!(
        keyed(request(11, vec![hex::encode([0; 32])]), None, &key),
        Err(ApiError::Conflict)
    ));
    assert!(matches!(
        keyed(
            request(
                11,
                vec![hex::encode(old[0].hash()), hex::encode(old[0].hash())]
            ),
            None,
            &key
        ),
        Err(ApiError::Malformed)
    ));
    let mut acknowledged = HashSet::new();
    let closed = select(&old, kick.operation().op_id, &acknowledged, 1000).unwrap();
    assert!(closed.complete);
    assert_eq!(closed.operations.len(), 4);
    assert!(!closed
        .operations
        .iter()
        .any(|op| op.hash() == epoch.hash() || op.hash() == message.hash()));
    let mut delivered = Vec::new();
    loop {
        let selected = select(&old, kick.operation().op_id, &acknowledged, 1).unwrap();
        assert_eq!(selected.operations.len(), 1);
        let hash = selected.operations[0].hash();
        assert!(acknowledged.insert(hash));
        delivered.push(hash);
        if selected.complete {
            break;
        }
    }
    assert_eq!(
        delivered,
        closed
            .operations
            .iter()
            .map(|op| op.hash())
            .collect::<Vec<_>>()
    );
    assert!(select(&old, kick.operation().op_id, &acknowledged, 1)
        .unwrap()
        .operations
        .is_empty());
    let missing: Vec<_> = old
        .iter()
        .filter(|op| op.hash() != invite.hash())
        .cloned()
        .collect();
    assert!(matches!(
        select(&missing, kick.operation().op_id, &HashSet::new(), 1000),
        Err(SelectionError::Dependency)
    ));
    assert!(matches!(
        select(
            &old,
            kick.operation().op_id,
            &HashSet::from([[0; 32]]),
            1000
        ),
        Err(SelectionError::Conflict)
    ));
}

#[test]
fn terminal_recipient_validation_allows_owned_leave_and_pending_delete_without_later_key_disclosure(
) {
    let rosters = [full(1), full(2)];
    let mut old = vec![founding()];
    let invite = create(
        1,
        11,
        &old,
        &rosters,
        json!({"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}),
    );
    old.push(invite.clone());
    let request = |root, leaf, old: &[GroupOperation], origin: &GroupOperation, target| {
        json!({
        "operation":"select_delivery","state":state(root,old,&rosters),
        "certificate":B64.encode(entry(root,leaf,ALL_CAPABILITIES).certificate().encoded()),
        "origin_op_id":origin.operation().op_id.to_hex(),"acknowledged":[],"limit":1000,
        "terminal_recipient":B64.encode(public(target))})
    };
    let deleted = create(
        1,
        11,
        &old,
        &rosters,
        json!({"kind":"group_delete","reason":"Synthetic pending cancellation"}),
    );
    let mut terminal = old.clone();
    terminal.push(deleted.clone());
    assert_eq!(
        call(request(1, 11, &terminal, &deleted, 2), None, true).unwrap()["complete"],
        true
    );
    assert!(matches!(
        call(request(1, 11, &terminal, &deleted, 3), None, true),
        Err(ApiError::Authority)
    ));
    assert!(matches!(
        call(request(1, 11, &old, &invite, 2), None, true),
        Err(ApiError::Malformed)
    ));
    old.push(create(
        2,
        12,
        &old,
        &rosters,
        json!({"kind":"member_accept","invite_op_id":invite.operation().op_id.to_hex()}),
    ));
    let leave = create(
        2,
        12,
        &old,
        &rosters,
        json!({"kind":"member_remove","account_public":B64.encode(public(2)),"reason":"Leave","ban":false}),
    );
    old.push(leave.clone());
    let prepared = call(request(2, 12, &old, &leave, 1), None, true).unwrap();
    assert_eq!(prepared["complete"], true);
    assert!(prepared.get("group_secret").is_none());
    assert!(matches!(
        call(request(2, 12, &old, &leave, 2), None, true),
        Err(ApiError::Authority)
    ));
    assert!(matches!(
        call(request(2, 12, &old, &leave, 1), Some(12), true),
        Err(ApiError::Malformed)
    ));
    let (epoch, key, _) = epoch_create(&old, 11, &rosters, &KEY);
    old.push(epoch.clone());
    let after = keyed(request(2, 12, &old, &leave, 1), None, &key).unwrap();
    let selected = unpack(&B64.decode(after["packed_ops"].as_str().unwrap()).unwrap()).unwrap();
    assert!(selected.iter().all(|op| op.hash() != epoch.hash()));
}

#[test]
fn verified_ack_checkpoints_cover_exact_ancestors_without_skipping_concurrent_branches() {
    use secure_group_protocol::delivery::{compact_acknowledgements, select};
    use std::collections::HashSet;
    let make = |clock: u64, leaf: u8, mut parents: Vec<_>, id: u8| {
        parents.sort();
        GroupOperation::from_device(
            DelegatedOperation::create(
                entry(
                    1,
                    leaf,
                    if leaf == 11 {
                        ALL_CAPABILITIES
                    } else {
                        CAP_GROUPS | CAP_SYNC
                    },
                )
                .certificate()
                .clone(),
                &[leaf; 32],
                group(),
                OpType::MsgAdd,
                &MsgAddPayload {
                    msg_id: [id; 32],
                    ciphertext: vec![id; 32],
                    nonce: [id; 24],
                },
                parents,
                clock,
                clock,
                2000,
            )
            .unwrap(),
        )
    };
    let first = founding();
    let a = make(2, 11, vec![first.operation().op_id], 1);
    let b = make(3, 11, vec![a.operation().op_id], 2);
    let c = make(4, 11, vec![b.operation().op_id], 3);
    let concurrent = make(3, 21, vec![first.operation().op_id], 4);
    let merged = make(
        5,
        11,
        vec![c.operation().op_id, concurrent.operation().op_id],
        5,
    );
    let unrelated = make(6, 21, vec![first.operation().op_id], 6);
    let old = vec![
        first.clone(),
        a,
        b,
        c.clone(),
        concurrent.clone(),
        merged.clone(),
        unrelated.clone(),
    ];
    let mut known = HashSet::from([c.hash()]);
    let next = select(&old, merged.operation().op_id, &known, 1).unwrap();
    assert!(!next.complete);
    assert_eq!(next.operations[0].hash(), concurrent.hash());
    known.insert(concurrent.hash());
    let frontier = compact_acknowledgements(&old, &known).unwrap();
    assert_eq!(frontier, known);
    let next = select(&old, merged.operation().op_id, &frontier, 1).unwrap();
    assert!(next.complete);
    assert_eq!(next.operations[0].hash(), merged.hash());
    known.extend([first.hash(), merged.hash()]);
    let compact = compact_acknowledgements(&old, &known).unwrap();
    assert_eq!(compact, HashSet::from([merged.hash()]));
    let next = select(&old, unrelated.operation().op_id, &compact, 1).unwrap();
    assert_eq!(next.operations[0].hash(), unrelated.hash());
    assert!(select(&old, c.operation().op_id, &compact, 1)
        .unwrap()
        .operations
        .is_empty());

    let request = |hashes| {
        json!({"operation":"compact_delivery_acknowledgements",
        "state":state(1,&old,&[full(1)]),
        "certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),
        "acknowledged":hashes})
    };
    let result = call(
        request(known.iter().map(hex::encode).collect::<Vec<_>>()),
        None,
        true,
    )
    .unwrap();
    assert_eq!(result, json!({"acknowledged":[hex::encode(merged.hash())]}));
    assert!(matches!(
        call(request(vec![hex::encode([0; 32])]), None, true),
        Err(ApiError::Conflict)
    ));
    assert!(matches!(
        call(request(vec![hex::encode(c.hash()); 2]), None, true),
        Err(ApiError::Malformed)
    ));
    assert!(matches!(
        call(request(Vec::<String>::new()), Some(11), true),
        Err(ApiError::Malformed)
    ));
}

#[test]
fn compact_checkpoints_make_progress_across_a_long_batched_dependency_chain() {
    use secure_group_protocol::delivery::{compact_acknowledgements, select};
    use std::collections::HashSet;
    let mut old = vec![founding()];
    for clock in 2u64..=1201 {
        let id: [u8; 32] = Sha256::digest(clock.to_be_bytes()).into();
        old.push(GroupOperation::from_device(
            DelegatedOperation::create(
                entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
                &[11; 32],
                group(),
                OpType::MsgAdd,
                &MsgAddPayload {
                    msg_id: id,
                    ciphertext: vec![7; 32],
                    nonce: [7; 24],
                },
                vec![old.last().unwrap().operation().op_id],
                clock,
                clock,
                2000,
            )
            .unwrap(),
        ));
    }
    let last = old.last().unwrap();
    let mut known = HashSet::new();
    let mut delivered = HashSet::new();
    let mut batches = 0;
    loop {
        let selected = select(&old, last.operation().op_id, &known, 1000).unwrap();
        assert!(!selected.operations.is_empty());
        for op in &selected.operations {
            assert!(
                delivered.insert(op.hash()),
                "acknowledged dependency was selected again"
            );
            known.insert(op.hash());
        }
        known = compact_acknowledgements(&old, &known).unwrap();
        assert_eq!(known.len(), 1);
        batches += 1;
        if selected.complete {
            break;
        }
        assert!(batches < 3);
    }
    assert_eq!(batches, 2);
    assert_eq!(delivered.len(), old.len());
    assert_eq!(known, HashSet::from([last.hash()]));
}

#[test]
fn terminal_membership_noops_are_bounded_per_leaf_and_invitation() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let acceptance = |leaf, clock| {
        direct(
            2,
            leaf,
            OpType::MemberAccept,
            &MemberAcceptPayload {
                invite_op_id: invite.operation().op_id,
            },
            clock,
        )
    };
    let mut old = vec![founding(), invite.clone(), acceptance(12, 3)];
    let preview = |old: &[GroupOperation], op: GroupOperation| {
        call(
            json!({"operation":"preview_live",
        "state":state(1,old,&rosters),"incoming":B64.encode(pack(&[op]).unwrap())}),
            None,
            true,
        )
    };
    assert!(matches!(
        preview(&old, acceptance(12, 4)),
        Err(ApiError::Limit)
    ));
    let other = acceptance(22, 4);
    preview(&old, other.clone()).unwrap();
    old.push(other);
    let leave = |leaf, clock| {
        direct(
            2,
            leaf,
            OpType::MemberRemove,
            &MemberRemovePayload {
                target_device_id: DeviceID::from_pubkey(&public(2)),
                reason: RemoveReason::Leave,
                ban: false,
            },
            clock,
        )
    };
    let first = leave(12, 5);
    preview(&old, first.clone()).unwrap();
    old.push(first);
    assert!(matches!(preview(&old, leave(12, 6)), Err(ApiError::Limit)));
    preview(&old, leave(22, 6)).unwrap();
}

#[test]
fn concurrent_last_slot_invitations_merge_without_exceeding_capacity_or_losing_the_log() {
    let rosters = [full(1)];
    let mut base = vec![founding()];
    for root in 2..20 {
        let op = create(
            1,
            11,
            &base,
            &rosters,
            json!({"kind":"member_invite","account_public":B64.encode(public(root)),"role":"Member"}),
        );
        base.push(op);
    }
    let a = create(
        1,
        11,
        &base,
        &rosters,
        json!({"kind":"member_invite","account_public":B64.encode(public(20)),"role":"Member"}),
    );
    let b = create(
        1,
        21,
        &base,
        &rosters,
        json!({"kind":"member_invite","account_public":B64.encode(public(21)),"role":"Member"}),
    );
    let mut hashes = vec![];
    for (left, right) in [(a.clone(), b.clone()), (b, a)] {
        let mut old = base.clone();
        old.push(left);
        let mut incoming = base.clone();
        incoming.push(right);
        let bytes = pack(&incoming).unwrap();
        let receipt = HistoryReceipt::issue(
            entry(1, 21, CAP_GROUPS | CAP_SYNC).certificate().clone(),
            &[21; 32],
            group(),
            &bytes,
        )
        .unwrap();
        let merged = call(json!({"operation":"preview_history","state":state(1,&old,&rosters),
            "incoming":B64.encode(bytes),"receipt":B64.encode(receipt.encoded()),"incoming_key":B64.encode(KEY)}),None,true).unwrap();
        assert_eq!(merged["op_count"], 21);
        assert_eq!(merged["members"].as_array().unwrap().len(), 20);
        assert_eq!(merged["superseded"].as_array().unwrap().len(), 1);
        assert_eq!(merged["needs_rekey"], true);
        hashes.push(merged["state_hash"].clone());
    }
    assert_eq!(hashes[0], hashes[1]);
}

#[test]
fn a_concurrent_leave_cannot_discard_an_authorized_ban_or_reinvite_its_target() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let base = vec![founding(), invite, accept];
    let leave = direct(
        2,
        22,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Leave,
            ban: false,
        },
        4,
    );
    let ban = direct(
        1,
        11,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Kick,
            ban: true,
        },
        5,
    );
    let mut hashes = Vec::new();
    for (first, second) in [(leave.clone(), ban.clone()), (ban, leave)] {
        let mut old = base.clone();
        old.push(first);
        let merged = call(
            json!({"operation":"preview_live", "state":state(1,&old,&rosters),
            "incoming":B64.encode(pack(&[second.clone()]).unwrap())}),
            None,
            true,
        )
        .unwrap();
        let target = merged["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["pubkey_hex"] == hex::encode(public(2)))
            .unwrap();
        assert_eq!(target["banned"], true);
        assert_eq!(target["removed"], true);
        hashes.push(merged["state_hash"].clone());
        old.push(second);
        assert!(call(json!({"operation":"create_operation", "state":state(1,&old,&rosters),
            "certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),
            "mutation":{"kind":"member_invite","account_public":B64.encode(public(2)),"role":"Member"}}),Some(11),true).is_err());
        let unban = create(
            1,
            11,
            &old,
            &rosters,
            json!({"kind":"member_unban", "account_public":B64.encode(public(2))}),
        );
        old.push(unban);
        let unbanned = call(
            json!({"operation":"read_state", "state":state(1,&old,&rosters)}),
            None,
            true,
        )
        .unwrap();
        let target = unbanned["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["pubkey_hex"] == hex::encode(public(2)))
            .unwrap();
        assert_eq!(target["banned"], false);
        assert_eq!(target["removed"], true);
        create(
            1,
            11,
            &old,
            &rosters,
            json!({"kind":"member_invite", "account_public":B64.encode(public(2)), "role":"Member"}),
        );
    }
    assert_eq!(hashes[0], hashes[1]);
}

#[test]
fn concurrent_epoch_branches_merge_with_independent_local_and_source_key_checks() {
    let rosters = [full(1)];
    let initial = vec![founding()];
    let (a, key_a, _) = epoch_create(&initial, 11, &rosters, &KEY);
    let (b, key_b, _) = epoch_create(&initial, 21, &rosters, &KEY);
    let mut branch_a = initial.clone();
    branch_a.push(a.clone());
    let mut branch_b = initial;
    branch_b.push(b.clone());
    let merge = keyed(
        json!({"operation":"preview_live","state":state(1,&branch_a,&rosters),
        "incoming":B64.encode(pack(&[b]).unwrap())}),
        None,
        &key_a,
    )
    .unwrap();
    let reverse = keyed(
        json!({"operation":"preview_live","state":state(1,&branch_b,&rosters),
        "incoming":B64.encode(pack(&[a]).unwrap())}),
        None,
        &key_b,
    )
    .unwrap();
    assert_eq!(merge["state_hash"], reverse["state_hash"]);
    assert_eq!(merge["group_secret"], reverse["group_secret"]);
    assert_eq!(merge["keyring"].as_array().unwrap().len(), 3);
    let bytes = pack(&branch_a).unwrap();
    let receipt = HistoryReceipt::issue(
        entry(1, 11, ALL_CAPABILITIES).certificate().clone(),
        &[11; 32],
        group(),
        &bytes,
    )
    .unwrap();
    let request = json!({"operation":"preview_history","state":state(1,&branch_b,&rosters),
        "incoming":B64.encode(bytes),"receipt":B64.encode(receipt.encoded()),"incoming_key":B64.encode(key_a)});
    let synced = keyed(request.clone(), None, &key_b).unwrap();
    assert_eq!(synced["state_hash"], merge["state_hash"]);
    let mut wrong = request;
    wrong["incoming_key"] = json!(B64.encode(KEY));
    assert!(matches!(
        keyed(wrong, None, &key_b),
        Err(ApiError::InvalidOperation)
    ));
}

#[test]
fn late_rotation_without_the_latest_removal_cannot_clear_rekey_requirements() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let mut shared = vec![founding(), invite, accept];
    let (first, key_first, _) = epoch_create(&shared, 11, &rosters, &KEY);
    shared.push(first);
    let (late, _, _) = epoch_create(&shared, 21, &rosters, &key_first);
    let leave = direct(
        2,
        12,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Leave,
            ban: false,
        },
        5,
    );
    let mut current = shared;
    current.push(leave);
    let accepted = keyed(
        json!({"operation":"preview_live","state":state(1,&current,&rosters),
        "incoming":B64.encode(pack(&[late.clone()]).unwrap())}),
        None,
        &key_first,
    )
    .unwrap();
    assert_eq!(accepted["needs_rekey"], true);
    let retained_key = B64
        .decode(accepted["group_secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    current.push(late);
    let (_, _, fresh) = epoch_create(&current, 11, &rosters, &retained_key);
    assert_eq!(fresh["needs_rekey"], false);
}

#[test]
fn message_cipher_epochs_preserve_old_history_and_edit_with_the_current_key() {
    let rosters = [full(1)];
    let mut old = vec![founding(), message(11, 2, 7)];
    let (epoch, key, summary) = epoch_create(&old, 21, &rosters, &KEY);
    old.push(epoch.clone());
    let result = keyed(
        json!({"operation":"create_operation","state":state(1,&old,&rosters),
        "certificate":B64.encode(entry(1,21,CAP_GROUPS|CAP_SYNC).certificate().encoded()),
        "mutation":{"kind":"msg_add","ciphertext":B64.encode([8;32]),"nonce":B64.encode([8;24])}}),
        Some(21),
        &key,
    )
    .unwrap();
    let added =
        GroupOperation::decode(&B64.decode(result["encoded"].as_str().unwrap()).unwrap()).unwrap();
    let payload: MsgAddPayload = added.core_operation().unwrap().decode_payload().unwrap();
    assert_eq!(&payload.ciphertext[..6], b"SLGM01");
    assert_eq!(&payload.ciphertext[6..38], epoch.hash());
    assert!(added
        .operation()
        .parent_heads
        .contains(&epoch.operation().op_id));
    old.push(added);
    let read = keyed(
        json!({"operation":"read_messages","state":state(1,&old,&rosters),"after":null,"limit":10}),
        None,
        &key,
    )
    .unwrap();
    assert_eq!(read["messages"][0]["ciphertext_b64"], B64.encode([7; 32]));
    assert_eq!(read["messages"][1]["ciphertext_b64"], B64.encode([8; 32]));
    assert_eq!(
        read["messages"][1]["cipher_epoch"],
        summary["current_epoch"]
    );
    let edit=keyed(json!({"operation":"create_operation","state":state(1,&old,&rosters),
        "certificate":B64.encode(entry(1,21,CAP_GROUPS|CAP_SYNC).certificate().encoded()),
        "mutation":{"kind":"msg_edit","msg_id":hex::encode([7;32]),"ciphertext":B64.encode([9;32]),"nonce":B64.encode([9;24])}}),Some(21),&key).unwrap();
    old.push(
        GroupOperation::decode(&B64.decode(edit["encoded"].as_str().unwrap()).unwrap()).unwrap(),
    );
    let read = keyed(
        json!({"operation":"read_messages","state":state(1,&old,&rosters),"after":null,"limit":10}),
        None,
        &key,
    )
    .unwrap();
    assert_eq!(read["messages"][0]["ciphertext_b64"], B64.encode([9; 32]));
    assert_eq!(
        read["messages"][0]["cipher_epoch"],
        summary["current_epoch"]
    );
}

#[test]
fn unknown_cipher_epoch_defers_without_guessing_the_current_key() {
    let rosters = [full(1)];
    let old = vec![founding()];
    let ciphertext = [b"SLGM01".as_slice(), &[99; 32], &[7; 32]].concat();
    let unknown = direct(
        1,
        11,
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [7; 32],
            ciphertext,
            nonce: [7; 24],
        },
        2,
    );
    assert!(matches!(
        keyed(
            json!({"operation":"preview_live","state":state(1,&old,&rosters),
        "incoming":B64.encode(pack(&[unknown]).unwrap())}),
            None,
            &KEY
        ),
        Err(ApiError::Dependency)
    ));
}

#[test]
fn root_ratification_is_exact_and_read_only_requests_never_sign() {
    let op = message(21, 2, 7);
    let request = json!({"operation":"ratify","encoded":B64.encode(op.encoded()),"approved_hash":hex::encode(op.hash())});
    assert!(matches!(
        call(request.clone(), Some(2), false),
        Err(ApiError::Authority)
    ));
    assert!(call(request.clone(), Some(1), false).is_ok());
    let mut wrong = request;
    wrong["approved_hash"] = json!(hex::encode([0; 32]));
    assert!(matches!(
        call(wrong, Some(1), false),
        Err(ApiError::Conflict)
    ));
    let request = json!({"operation":"attest_history","state":state(1,&[founding()],&[full(1)]),"certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded())});
    assert!(call(request, Some(11), true).is_ok());
}

#[test]
fn key_mismatch_and_kick_rekey_safeguard_block_new_content() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let kick = direct(
        1,
        11,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Kick,
            ban: false,
        },
        4,
    );
    let old = vec![founding(), invite, accept, kick];
    let request = json!({"operation":"create_operation","state":state(1,&old,&rosters),"certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),"mutation":{"kind":"msg_add","ciphertext":B64.encode([4;32]),"nonce":B64.encode([4;24])}});
    assert!(matches!(
        call(request, Some(11), true),
        Err(ApiError::RekeyRequired)
    ));
    let request = serde_json::to_vec(
        &json!({"operation":"read_messages","state":state(1,&old,&rosters),"after":null,"limit":1}),
    )
    .unwrap();
    assert!(matches!(
        execute(&request, None, Some(&[8; 32])),
        Err(ApiError::InvalidOperation)
    ));
}

#[test]
fn delegated_payloads_reject_unknown_fields_alias_membership_and_privileged_invites() {
    #[derive(Serialize)]
    struct Extra {
        group_name: String,
        encrypted_group_secret: Vec<u8>,
        ignored: bool,
    }
    let cert = entry(1, 11, ALL_CAPABILITIES).certificate().clone();
    assert!(DelegatedOperation::create(
        cert.clone(),
        &[11; 32],
        group(),
        OpType::GroupCreate,
        &Extra {
            group_name: "Synthetic".into(),
            encrypted_group_secret: KEY.to_vec(),
            ignored: true
        },
        vec![],
        1,
        1,
        2000
    )
    .is_err());
    for (id, role) in [
        (DeviceID::from_pubkey(&public(3)), Role::Member),
        (DeviceID::from_pubkey(&public(2)), Role::Owner),
    ] {
        assert!(DelegatedOperation::create(
            cert.clone(),
            &[11; 32],
            group(),
            OpType::MemberInvite,
            &MemberInvitePayload {
                invited_device_id: id,
                invited_pubkey: public(2),
                role,
                encrypted_group_secret: KEY.to_vec()
            },
            vec![],
            2,
            2,
            2000
        )
        .is_err());
    }
}

#[test]
fn admin_rights_cannot_be_used_to_grant_ownership_or_rewrite_owner_permissions() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let promote = direct(
        1,
        11,
        OpType::RoleSet,
        &RoleSetPayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            new_role: Role::Admin,
            admin_rights: Some(AdminRights::all_true()),
            custom_title: None,
        },
        4,
    );
    let old = vec![founding(), invite, accept, promote];
    let escalate = direct(
        2,
        12,
        OpType::RoleSet,
        &RoleSetPayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            new_role: Role::Owner,
            admin_rights: None,
            custom_title: None,
        },
        5,
    );
    let permissions = direct(
        2,
        12,
        OpType::MetadataSet,
        &MetadataSetPayload {
            key: MetadataKey::AllowMemberInvites,
            value: vec![1],
        },
        5,
    );
    for op in [escalate, permissions] {
        let request = json!({"operation":"preview_live","state":state(1,&old,&rosters),"incoming":B64.encode(pack(&[op]).unwrap())});
        assert!(matches!(
            call(request, None, true),
            Err(ApiError::Authority)
        ));
    }
}

#[test]
fn a_groups_only_device_can_attest_an_invitation_but_not_own_sync_history() {
    let roster = roster(1, 1, &[(11, ALL_CAPABILITIES), (21, CAP_GROUPS)]);
    let old = [founding()];
    let state = state(1, &old, &[roster]);
    let cert = B64.encode(entry(1, 21, CAP_GROUPS).certificate().encoded());
    let invitation = call(
        json!({"operation":"attest_invitation","state":state,"certificate":cert}),
        Some(21),
        true,
    )
    .unwrap();
    assert!(matches!(
        call(
            json!({"operation":"attest_history","state":state,"certificate":cert}),
            Some(21),
            true
        ),
        Err(ApiError::Authority)
    ));
    assert!(matches!(
        call(
            json!({"operation":"preview_history","state":state,"incoming":B64.encode(pack(&old).unwrap()),"receipt":invitation["receipt"]}),
            None,
            true
        ),
        Err(ApiError::Authority)
    ));
    let read = call(json!({"operation":"read_state","state":state}), None, true).unwrap();
    assert_eq!(read["op_count"], 1);
    assert!(read.get("last_message").is_some());
}

#[test]
fn legacy_live_frames_cannot_bypass_a_pending_kick_rotation_but_committed_history_remains_readable()
{
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let kick = direct(
        1,
        11,
        OpType::MemberRemove,
        &MemberRemovePayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            reason: RemoveReason::Kick,
            ban: false,
        },
        4,
    );
    let mut old = vec![founding(), invite, accept, kick];
    let legacy = OpEnvelope::create_signed(
        group(),
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [7; 32],
            ciphertext: vec![7; 32],
            nonce: [7; 24],
        },
        5,
        5,
        public(1),
        &[1; 32],
    )
    .unwrap();
    let legacy = GroupOperation::decode(&legacy.to_bytes().unwrap()).unwrap();
    assert!(matches!(
        call(
            json!({"operation":"preview_live","state":state(1,&old,&rosters),"incoming":B64.encode(pack(std::slice::from_ref(&legacy)).unwrap())}),
            None,
            true
        ),
        Err(ApiError::RekeyRequired)
    ));
    old.push(legacy);
    let read = call(
        json!({"operation":"read_state","state":state(1,&old,&rosters)}),
        None,
        true,
    )
    .unwrap();
    assert_eq!(read["op_count"], 5);
    assert_eq!(read["needs_rekey"], true);
}

#[test]
fn read_only_members_cannot_issue_or_relay_first_invitation_history() {
    let rosters = [full(1), full(2), full(3)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::ReadOnly,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let target = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(3)),
            invited_pubkey: public(3),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        4,
    );
    let old = vec![founding(), invite, accept, target];
    assert!(matches!(
        call(
            json!({"operation":"attest_invitation","state":state(2,&old,&rosters),"certificate":B64.encode(entry(2,12,ALL_CAPABILITIES).certificate().encoded())}),
            Some(12),
            true
        ),
        Err(ApiError::Authority)
    ));
    let bytes = pack(&old).unwrap();
    let receipt = HistoryReceipt::issue(
        entry(2, 12, ALL_CAPABILITIES).certificate().clone(),
        &[12; 32],
        group(),
        &bytes,
    )
    .unwrap();
    assert!(matches!(
        call(
            json!({"operation":"preview_invite","state":state(3,&[],&rosters),"incoming":B64.encode(bytes),"source_account":B64.encode(public(2)),"receipt":B64.encode(receipt.encoded())}),
            None,
            true
        ),
        Err(ApiError::Authority)
    ));
}

#[test]
fn members_can_leave_only_themselves_and_removed_recipients_reject_new_foreign_state() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::ReadOnly,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let mut old = vec![founding(), invite, accept];
    let cert = B64.encode(entry(2, 12, ALL_CAPABILITIES).certificate().encoded());
    assert!(matches!(
        call(
            json!({"operation":"create_operation","state":state(2,&old,&rosters),"certificate":cert,"mutation":{"kind":"member_remove","account_public":B64.encode(public(1)),"reason":"Kick","ban":false}}),
            Some(12),
            true
        ),
        Err(ApiError::Authority)
    ));
    let result=call(json!({"operation":"create_operation","state":state(2,&old,&rosters),"certificate":cert,"mutation":{"kind":"member_remove","account_public":B64.encode(public(2)),"reason":"Leave","ban":false}}),Some(12),true).unwrap();
    assert_eq!(result["summary"]["our_role"], "Removed");
    assert_eq!(result["summary"]["needs_rekey"], true);
    old.push(
        GroupOperation::decode(&B64.decode(result["encoded"].as_str().unwrap()).unwrap()).unwrap(),
    );
    let update = direct(
        1,
        11,
        OpType::MetadataSet,
        &MetadataSetPayload {
            key: MetadataKey::Name,
            value: b"New name".to_vec(),
        },
        5,
    );
    assert!(matches!(
        call(
            json!({"operation":"preview_live","state":state(2,&old,&rosters),"incoming":B64.encode(pack(&[update]).unwrap())}),
            None,
            true
        ),
        Err(ApiError::Authority)
    ));
    // An exact previously accepted bundle can still be acknowledged after a
    // removal without introducing new data or reactivating the group.
    assert!(call(json!({"operation":"preview_live","state":state(2,&old,&rosters),"incoming":B64.encode(pack(&[old[0].clone()]).unwrap())}),None,true).is_ok());
    assert!(matches!(
        call(
            json!({"operation":"create_operation","state":state(1,&old,&rosters),"certificate":B64.encode(entry(1,11,ALL_CAPABILITIES).certificate().encoded()),"mutation":{"kind":"msg_add","ciphertext":B64.encode([7;32]),"nonce":B64.encode([7;24])}}),
            Some(11),
            true
        ),
        Err(ApiError::RekeyRequired)
    ));
}

#[test]
fn legacy_root_signatures_cannot_bypass_the_wrappers_role_or_identity_guards() {
    let rosters = [full(1), full(2)];
    let invite = direct(
        1,
        11,
        OpType::MemberInvite,
        &MemberInvitePayload {
            invited_device_id: DeviceID::from_pubkey(&public(2)),
            invited_pubkey: public(2),
            role: Role::Member,
            encrypted_group_secret: KEY.to_vec(),
        },
        2,
    );
    let accept = direct(
        2,
        12,
        OpType::MemberAccept,
        &MemberAcceptPayload {
            invite_op_id: invite.operation().op_id,
        },
        3,
    );
    let promote = direct(
        1,
        11,
        OpType::RoleSet,
        &RoleSetPayload {
            target_device_id: DeviceID::from_pubkey(&public(2)),
            new_role: Role::Admin,
            admin_rights: Some(AdminRights::all_true()),
            custom_title: None,
        },
        4,
    );
    let old = vec![founding(), invite, accept, promote];
    fn legacy<P: Serialize>(kind: OpType, payload: &P) -> GroupOperation {
        GroupOperation::decode(
            &OpEnvelope::create_signed(group(), kind, payload, 5, 5, public(2), &[2; 32])
                .unwrap()
                .to_bytes()
                .unwrap(),
        )
        .unwrap()
    }
    let attacks = [
        legacy(
            OpType::RoleSet,
            &RoleSetPayload {
                target_device_id: DeviceID::from_pubkey(&public(2)),
                new_role: Role::Owner,
                admin_rights: None,
                custom_title: None,
            },
        ),
        legacy(
            OpType::MemberInvite,
            &MemberInvitePayload {
                invited_device_id: DeviceID::from_pubkey(&public(3)),
                invited_pubkey: public(3),
                role: Role::Owner,
                encrypted_group_secret: KEY.to_vec(),
            },
        ),
        legacy(
            OpType::MemberInvite,
            &MemberInvitePayload {
                invited_device_id: DeviceID::from_pubkey(&public(4)),
                invited_pubkey: public(3),
                role: Role::Member,
                encrypted_group_secret: KEY.to_vec(),
            },
        ),
        legacy(
            OpType::MetadataSet,
            &MetadataSetPayload {
                key: MetadataKey::AllowMemberInvites,
                value: vec![1],
            },
        ),
    ];
    for attack in attacks {
        assert!(call(json!({"operation":"preview_live","state":state(1,&old,&rosters),"incoming":B64.encode(pack(std::slice::from_ref(&attack)).unwrap())}),None,true).is_err());
        let mut unsafe_old = old.clone();
        unsafe_old.push(attack);
        assert!(call(
            json!({"operation":"read_state","state":state(1,&unsafe_old,&rosters)}),
            None,
            true
        )
        .is_err());
    }
}

#[test]
fn signed_giant_clocks_and_legacy_overflow_cannot_poison_group_progress() {
    let rosters = [full(1)];
    let old = vec![founding()];
    let delegated = message(21, 1_000_000_000, 7);
    let legacy = OpEnvelope::create_signed(
        group(),
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [7; 32],
            ciphertext: vec![7; 32],
            nonce: [7; 24],
        },
        1_000_000_000,
        5,
        public(1),
        &[1; 32],
    )
    .unwrap();
    let legacy = GroupOperation::decode(&legacy.to_bytes().unwrap()).unwrap();
    for attack in [delegated, legacy] {
        assert!(matches!(
            call(
                json!({"operation":"preview_live","state":state(1,&old,&rosters),"incoming":B64.encode(pack(&[attack]).unwrap())}),
                None,
                true
            ),
            Err(ApiError::Dependency)
        ));
    }
    let overflow = OpEnvelope::create_signed(
        group(),
        OpType::MsgAdd,
        &MsgAddPayload {
            msg_id: [7; 32],
            ciphertext: vec![7; 32],
            nonce: [7; 24],
        },
        u64::MAX,
        5,
        public(1),
        &[1; 32],
    )
    .unwrap();
    assert!(GroupOperation::decode(&overflow.to_bytes().unwrap()).is_err());
    let next = create(
        1,
        21,
        &old,
        &rosters,
        json!({"kind":"msg_add","ciphertext":B64.encode([7;32]),"nonce":B64.encode([7;24])}),
    );
    assert_eq!(next.operation().lamport, 2);
}
