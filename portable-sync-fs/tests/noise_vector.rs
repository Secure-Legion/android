// Known-answer XX vector shipped by upstream snow (cacophony interoperability vectors).
use secure_sync_fs::PROTOCOL;
fn hex(s:&str)->Vec<u8>{(0..s.len()).step_by(2).map(|n|u8::from_str_radix(&s[n..n+2],16).unwrap()).collect()}
#[test]fn vendored_noise_matches_the_upstream_xx_known_answer(){
    let v:serde_json::Value=serde_json::from_str(include_str!("noise-xx-vector.json")).unwrap();
    let get=|key:&str|hex(v[key].as_str().unwrap());
    let isp=get("init_static");let ie=get("init_ephemeral");let ip=get("init_prologue");
    let rsp=get("resp_static");let re=get("resp_ephemeral");let rp=get("resp_prologue");
    let mut a=snow::Builder::new(PROTOCOL.parse().unwrap()).local_private_key(&isp).unwrap()
        .fixed_ephemeral_key_for_testing_only(&ie).prologue(&ip).unwrap().build_initiator().unwrap();
    let mut b=snow::Builder::new(PROTOCOL.parse().unwrap()).local_private_key(&rsp).unwrap()
        .fixed_ephemeral_key_for_testing_only(&re).prologue(&rp).unwrap().build_responder().unwrap();
    let messages=v["messages"].as_array().unwrap();
    for (i,m) in messages[..3].iter().enumerate(){
        let plain=hex(m["payload"].as_str().unwrap());let expected=hex(m["ciphertext"].as_str().unwrap());
        let mut out=[0u8;65535];let mut received=[0u8;65535];
        let(writer,reader)=if i%2==0{(&mut a,&mut b)}else{(&mut b,&mut a)};
        let n=writer.write_message(&plain,&mut out).unwrap();assert_eq!(&out[..n],expected);
        let n=reader.read_message(&out[..n],&mut received).unwrap();assert_eq!(&received[..n],plain);
    }
    assert_eq!(a.get_handshake_hash(),get("handshake_hash"));
    let mut a=a.into_transport_mode().unwrap();let mut b=b.into_transport_mode().unwrap();
    for (i,m) in messages[3..].iter().enumerate(){
        let plain=hex(m["payload"].as_str().unwrap());let expected=hex(m["ciphertext"].as_str().unwrap());
        let mut out=[0u8;65535];let mut received=[0u8;65535];
        let(writer,reader)=if i%2==1{(&mut a,&mut b)}else{(&mut b,&mut a)};
        let n=writer.write_message(&plain,&mut out).unwrap();assert_eq!(&out[..n],expected);
        let n=reader.read_message(&out[..n],&mut received).unwrap();assert_eq!(&received[..n],plain);
    }
}
