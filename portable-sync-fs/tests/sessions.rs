use secure_sync_fs::{device_id, Engine, Error, Peer, DATA, HANDSHAKE, MAX_PLAIN};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey,StaticSecret};

fn make(seed:u8)->(Engine,Peer) {
    let ed=SigningKey::from_bytes(&[seed;32]).verifying_key().to_bytes();
    let x=PublicKey::from(&StaticSecret::from([seed+10;32])).to_bytes();
    (Engine::new([9;32],[seed;32],[seed+10;32]),Peer{id:device_id(&ed,&x),ed:B64.encode(ed),x:B64.encode(x)})
}
fn pair()->(Engine,Peer,Engine,Peer) {let(a,pa)=make(1);let(b,pb)=make(2);(a,pa,b,pb)}
fn handshake(a:&mut Engine,pa:&Peer,b:&mut Engine,pb:&Peer)->Vec<(bool,Vec<u8>)> {
    let mut pending=std::collections::VecDeque::new();let mut captured=vec![];
    for w in a.ensure(pb,100000).unwrap().outgoing{pending.push_back((true,w));}
    for _ in 0..20 {
        let Some((to_b,w))=pending.pop_front()else{break};captured.push((to_b,w.clone()));
        let result=if to_b{b.receive(pa,&w,100000)}else{a.receive(pb,&w,100000)}.unwrap();
        for reply in result.outgoing{pending.push_back((!to_b,reply));}
    }
    assert!(pending.is_empty());assert!(a.ready(pb,100000));assert!(b.ready(pa,100000));captured
}
#[test]fn no_application_payload_before_mutual_key_confirmation(){
    let(mut a,pa,mut b,pb)=pair();
    let early=a.seal(&pb,b"private history",100000).unwrap();assert!(!early.ready);
    assert!(early.outgoing.iter().all(|w|w[0]==HANDSHAKE));
    let packets=handshake(&mut a,&pa,&mut b,&pb);
    assert!(packets.iter().all(|(_,w)|!w.windows(15).any(|s|s==b"private history")));
    let wire=a.seal(&pb,b"private history",100001).unwrap().outgoing.remove(0);
    assert_eq!(wire[0],DATA);assert_eq!(b.receive(&pa,&wire,100001).unwrap().message.unwrap().as_slice(),b"private history");
}
#[test]fn both_directions_and_out_of_order_packets_work_without_reusing_nonces(){
    let(mut a,pa,mut b,pb)=pair();handshake(&mut a,&pa,&mut b,&pb);
    let first=a.seal(&pb,b"same",100001).unwrap().outgoing.remove(0);
    let second=a.seal(&pb,b"same",100001).unwrap().outgoing.remove(0);assert_ne!(first,second);
    assert!(b.receive(&pa,&second,100001).unwrap().message.is_some());
    assert!(b.receive(&pa,&first,100001).unwrap().message.is_some());
    assert!(matches!(b.receive(&pa,&first,100001),Err(Error::Replay)));
    let back=b.seal(&pa,b"receipt",100001).unwrap().outgoing.remove(0);
    assert_eq!(a.receive(&pb,&back,100001).unwrap().message.unwrap().as_slice(),b"receipt");
}
#[test]fn malformed_ciphertext_does_not_consume_the_valid_packet_nonce(){
    let(mut a,pa,mut b,pb)=pair();handshake(&mut a,&pa,&mut b,&pb);
    let wire=a.seal(&pb,b"fixture",100001).unwrap().outgoing.remove(0);let mut bad=wire.clone();
    *bad.last_mut().unwrap()^=1;assert!(b.receive(&pa,&bad,100001).is_err());
    assert!(b.receive(&pa,&wire,100001).unwrap().message.is_some());
}
#[test]fn large_messages_are_bounded_and_all_fragments_must_authenticate(){
    let(mut a,pa,mut b,pb)=pair();handshake(&mut a,&pa,&mut b,&pb);
    let plain=vec![7;MAX_PLAIN];let wire=a.seal(&pb,&plain,100001).unwrap().outgoing.remove(0);
    let mut truncated=wire[..wire.len()-3].to_vec();let len=(truncated.len()-5)as u32;truncated[1..5].copy_from_slice(&len.to_be_bytes());
    assert!(b.receive(&pa,&truncated,100001).is_err());
    assert_eq!(b.receive(&pa,&wire,100001).unwrap().message.unwrap().as_slice(),plain);
    assert!(a.seal(&pb,&vec![8;MAX_PLAIN+1],100001).is_err());
}
#[test]fn session_account_recipient_and_public_keys_are_bound(){
    let(mut a,pa,mut b,pb)=pair();handshake(&mut a,&pa,&mut b,&pb);
    let wire=a.seal(&pb,b"fixture",100001).unwrap().outgoing.remove(0);
    let(mut c,_)=make(3);assert!(c.receive(&pa,&wire,100001).is_err());
    let mut wrong=pa.clone();wrong.x=B64.encode([0;32]);assert!(b.receive(&wrong,&wire,100001).is_err());
    let mut other_account=Engine::new([8;32],[2;32],[12;32]);assert!(other_account.receive(&pa,&wire,100001).is_err());
}
#[test]fn old_ciphertext_cannot_be_recovered_by_reconstructing_only_long_term_keys(){
    let(mut a,pa,mut b,pb)=pair();let captured=handshake(&mut a,&pa,&mut b,&pb);
    let wire=a.seal(&pb,b"older secret",100001).unwrap().outgoing.remove(0);
    let(mut replacement,_)=make(2);
    assert!(replacement.receive(&pa,&wire,100001).is_err());
    // Replaying the captured signed handshake starts a fresh random exchange;
    // captured later handshake messages cannot finish that different exchange.
    for (to_b,w) in captured {
        if to_b{let _=replacement.receive(&pa,&w,100001);}
    }
    assert!(!replacement.ready(&pa,100001));assert!(replacement.receive(&pa,&wire,100001).is_err());
}
#[test]fn duplicate_handshake_messages_resend_cached_ciphertext_and_recover_lost_confirmations(){
    let(mut a,pa,mut b,pb)=pair();let captured=handshake(&mut a,&pa,&mut b,&pb);
    for (to_b,w) in captured.iter().filter(|(_,w)|w[0]==HANDSHAKE){
        let result=if *to_b{b.receive(&pa,w,100001)}else{a.receive(&pb,w,100001)}.unwrap();
        assert!(!result.outgoing.is_empty());
    }
    let packet=a.seal(&pb,b"still valid",100001).unwrap().outgoing.remove(0);
    assert!(b.receive(&pa,&packet,100001).unwrap().message.is_some());
}
#[test]fn expiry_and_peer_removal_require_a_new_handshake(){
    let(mut a,pa,mut b,pb)=pair();handshake(&mut a,&pa,&mut b,&pb);
    let wire=a.seal(&pb,b"fixture",100001).unwrap().outgoing.remove(0);
    assert!(!a.ready(&pb,1300000));assert!(b.receive(&pa,&wire,1300000).is_err());
    b.forget(&pa.id);assert!(!b.ready(&pa,100001));assert!(b.receive(&pa,&wire,100001).is_err());
}
#[test]fn overflowing_nonce_is_rejected_without_panicking(){
    let(mut a,pa,mut b,pb)=pair();handshake(&mut a,&pa,&mut b,&pb);
    let mut wire=a.seal(&pb,b"fixture",100001).unwrap().outgoing.remove(0);
    wire[124..132].copy_from_slice(&u64::MAX.to_be_bytes());assert!(b.receive(&pa,&wire,100001).is_err());
}
