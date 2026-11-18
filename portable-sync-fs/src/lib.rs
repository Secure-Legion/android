//! Authenticated, ephemeral Noise XX sessions for own-device history sync.
//! Trust decisions and durable application acknowledgements remain with hosts.
pub const PROTOCOL: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
pub mod ffi;

use base64::{engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use zeroize::{Zeroize, Zeroizing};

pub const HANDSHAKE: u8 = 0xB6;
pub const DATA: u8 = 0xB7;
pub const MAX_WIRE: usize = 512 * 1024;
pub const MAX_PLAIN: usize = 384 * 1024;
const CHUNK: usize = 60000;
const PREFIX: usize = 15;
const MAX_NONCE: u64 = 1_000_000;
const SESSION_MS: u64 = 20 * 60 * 1000;
const HANDSHAKE_MS: u64 = 120000;
const REPLAY_WINDOW: u64 = 4096;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid forward-secret sync packet")] Invalid,
    #[error("forward-secret sync authentication failed")] Authentication,
    #[error("forward-secret sync session is not ready")] NotReady,
    #[error("forward-secret sync replay rejected")] Replay,
    #[error("forward-secret sync limit reached")] Limit,
}
type Result<T> = std::result::Result<T, Error>;

pub fn device_id(ed: &[u8;32], x: &[u8;32]) -> String {
    let mut h=Sha256::new(); h.update(b"secure-legion-device-v1"); h.update(ed); h.update(x);
    URL_SAFE_NO_PAD.encode(h.finalize())
}
fn decode<const N:usize>(s:&str) -> Result<[u8;N]> {
    let b=B64.decode(s).map_err(|_|Error::Invalid)?;
    if B64.encode(&b)!=s { return Err(Error::Invalid); }
    b.try_into().map_err(|_|Error::Invalid)
}
fn token() -> [u8;32] { let mut b=[0;32]; OsRng.fill_bytes(&mut b); b }

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer { pub id:String, pub ed:String, pub x:String }
impl Peer {
    fn keys(&self) -> Result<([u8;32],[u8;32])> {
        let ed=decode(&self.ed)?; let x=decode(&self.x)?;
        if self.id!=device_id(&ed,&x) || x==[0;32] || VerifyingKey::from_bytes(&ed).is_err() { return Err(Error::Authentication); }
        Ok((ed,x))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
    v:u8, from:String, to:String, account:String, session:String, step:u8, ts:u64, noise:String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Signed { header:Header, signature:String }
fn signed_bytes(h:&Header)->Result<Vec<u8>> {
    let mut b=b"secure-sync-fs-v2-handshake\0".to_vec();
    b.extend(serde_json::to_vec(h).map_err(|_|Error::Invalid)?); Ok(b)
}
fn frame(kind:u8, body:&[u8])->Result<Vec<u8>> {
    if body.len()+5>MAX_WIRE { return Err(Error::Limit); }
    let mut v=Vec::with_capacity(body.len()+5); v.push(kind);v.extend((body.len() as u32).to_be_bytes());v.extend(body);Ok(v)
}
fn body(wire:&[u8], kind:u8)->Result<&[u8]> {
    if wire.len()<5 || wire.len()>MAX_WIRE || wire[0]!=kind ||
        u32::from_be_bytes(wire[1..5].try_into().unwrap()) as usize!=wire.len()-5 { return Err(Error::Invalid); }
    Ok(&wire[5..])
}

#[derive(Default)]
pub struct Outcome { pub outgoing:Vec<Vec<u8>>, pub message:Option<Zeroizing<Vec<u8>>>, pub ready:bool }
struct Session {
    id:[u8;32], created:u64, initiator:bool, ready:bool,
    handshake:Option<HandshakeState>, transport:Option<StatelessTransportState>,
    next:u64, highest:Option<u64>, seen:BTreeSet<u64>,
    incoming:BTreeMap<u8,[u8;32]>, replies:BTreeMap<u8,Vec<u8>>, last:Vec<u8>,
}
impl Session {
    fn expired(&self, now:u64)->bool {
        now<self.created || now-self.created>=if self.ready {SESSION_MS}else{HANDSHAKE_MS} || self.next>=MAX_NONCE-16
    }
    fn finish(&mut self, expected:&[u8;32])->Result<()> {
        let h=self.handshake.take().ok_or(Error::Invalid)?;
        if !h.is_handshake_finished() || h.get_remote_static()!=Some(expected.as_slice()) { return Err(Error::Authentication); }
        self.transport=Some(h.into_stateless_transport_mode().map_err(|_|Error::Authentication)?);
        Ok(()) // Noise drops/zeroizes the ephemeral handshake keys here.
    }
}
struct PeerState { config:Peer, session:Option<Session>, request:Option<Vec<u8>>, requests:VecDeque<[u8;32]>, retired:VecDeque<[u8;32]> }
pub struct Engine {
    account:[u8;32], signing:SigningKey, x:Zeroizing<[u8;32]>, pub id:String,
    peers:BTreeMap<String,PeerState>,
}
impl Engine {
    pub fn new(account:[u8;32], mut signing:[u8;32], mut x:[u8;32])->Self {
        let key=SigningKey::from_bytes(&signing);signing.zeroize();
        let public=x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(x)).to_bytes();
        let id=device_id(&key.verifying_key().to_bytes(),&public);
        let secret=Zeroizing::new(x);x.zeroize();
        Self{account,signing:key,x:secret,id,peers:BTreeMap::new()}
    }
    fn take_peer(&mut self,p:&Peer)->Result<PeerState> {
        p.keys()?;
        if p.id==self.id {return Err(Error::Authentication);}
        if let Some(old)=self.peers.remove(&p.id) {
            if old.config==*p {return Ok(old);}
            // Same installation ID cannot acquire different keys.
            return Err(Error::Authentication);
        }
        if self.peers.len()>=64 {return Err(Error::Limit);}
        Ok(PeerState{config:p.clone(),session:None,request:None,requests:VecDeque::new(),retired:VecDeque::new()})
    }
    fn packet(&self,p:&Peer,id:[u8;32],step:u8,noise:&[u8],now:u64)->Result<Vec<u8>> {
        let header=Header{v:2,from:self.id.clone(),to:p.id.clone(),account:B64.encode(self.account),
            session:B64.encode(id),step,ts:now,noise:B64.encode(noise)};
        let signature=B64.encode(self.signing.sign(&signed_bytes(&header)?).to_bytes());
        frame(HANDSHAKE,&serde_json::to_vec(&Signed{header,signature}).map_err(|_|Error::Invalid)?)
    }
    fn new_session(&self,p:&Peer,id:[u8;32],initiator:bool,now:u64)->Result<Session> {
        let (a,b)=if initiator {(&self.id,&p.id)}else{(&p.id,&self.id)};
        let mut prologue=b"secure-sync-fs-v2\0".to_vec();prologue.extend(self.account);prologue.extend(a.as_bytes());prologue.extend(b.as_bytes());prologue.extend(id);
        let builder=Builder::new(PROTOCOL.parse().map_err(|_|Error::Invalid)?)
            .prologue(&prologue).map_err(|_|Error::Invalid)?.local_private_key(&self.x[..]).map_err(|_|Error::Invalid)?;
        let handshake=if initiator {builder.build_initiator()}else{builder.build_responder()}.map_err(|_|Error::Authentication)?;
        Ok(Session{id,created:now,initiator,ready:false,handshake:Some(handshake),transport:None,next:0,highest:None,
            seen:BTreeSet::new(),incoming:BTreeMap::new(),replies:BTreeMap::new(),last:vec![]})
    }
    fn retire(state:&mut PeerState) {
        if let Some(s)=state.session.take(){state.retired.push_back(s.id);if state.retired.len()>32 {state.retired.pop_front();}}
    }
    fn ensure_state(&self,state:&mut PeerState,now:u64, restart:bool)->Result<Outcome> {
        if state.session.as_ref().is_some_and(|s|s.expired(now)) {Self::retire(state);}
        if restart && state.session.as_ref().is_some_and(|s|s.ready) {Self::retire(state);}
        if let Some(s)=&state.session {return Ok(Outcome{outgoing:if s.ready {vec![]}else{vec![s.last.clone()]},ready:s.ready,..Default::default()});}
        if self.id<state.config.id {
            let mut s=self.new_session(&state.config,token(),true,now)?;
            let mut out=[0u8;512];let n=s.handshake.as_mut().unwrap().write_message(&[],&mut out).map_err(|_|Error::Authentication)?;
            s.last=self.packet(&state.config,s.id,1,&out[..n],now)?;
            let outgoing=vec![s.last.clone()];state.session=Some(s);state.request=None;
            Ok(Outcome{outgoing,..Default::default()})
        } else {
            // Reconciliation requests are authenticated control only, never history.
            let request=match &state.request {Some(w)=>w.clone(),None=>self.packet(&state.config,token(),0,&[],now)?};
            // Cached requests have a bounded lifetime, just like handshakes.
            let parsed:Signed=serde_json::from_slice(body(&request,HANDSHAKE)?).map_err(|_|Error::Invalid)?;
            let request=if now<parsed.header.ts || now-parsed.header.ts>=HANDSHAKE_MS {self.packet(&state.config,token(),0,&[],now)?}else{request};
            state.request=Some(request.clone());Ok(Outcome{outgoing:vec![request],..Default::default()})
        }
    }
    pub fn ensure(&mut self,p:&Peer,now:u64)->Result<Outcome> {
        let mut state=self.take_peer(p)?;let result=self.ensure_state(&mut state,now,false);self.peers.insert(p.id.clone(),state);result
    }
    pub fn ready(&self,p:&Peer,now:u64)->bool {self.peers.get(&p.id).is_some_and(|s|s.config==*p && s.session.as_ref().is_some_and(|s|s.ready&&!s.expired(now)))}
    pub fn forget(&mut self,id:&str){self.peers.remove(id);}
    pub fn receive(&mut self,p:&Peer,wire:&[u8],now:u64)->Result<Outcome> {
        let mut state=self.take_peer(p)?;
        let result=match wire.first() {Some(&HANDSHAKE)=>self.handshake(&mut state,wire,now),Some(&DATA)=>self.open(&mut state,wire,now),_=>Err(Error::Invalid)};
        self.peers.insert(p.id.clone(),state);result
    }
    fn handshake(&self,state:&mut PeerState,wire:&[u8],now:u64)->Result<Outcome> {
        if wire.len()>8192 {return Err(Error::Limit);}
        let signed:Signed=serde_json::from_slice(body(wire,HANDSHAKE)?).map_err(|_|Error::Invalid)?;
        let h=signed.header;
        if h.v!=2 || h.from!=state.config.id || h.to!=self.id || h.account!=B64.encode(self.account) || h.ts>now.saturating_add(30000) || now>h.ts.saturating_add(HANDSHAKE_MS) || h.step>3 {return Err(Error::Invalid);}
        let (ed,x)=state.config.keys()?;let sig=Signature::from_bytes(&decode::<64>(&signed.signature)?);
        VerifyingKey::from_bytes(&ed).map_err(|_|Error::Authentication)?.verify_strict(&signed_bytes(&h)?,&sig).map_err(|_|Error::Authentication)?;
        let id=decode(&h.session)?;
        let noise=B64.decode(&h.noise).map_err(|_|Error::Invalid)?;
        if noise.len()>512 || B64.encode(&noise)!=h.noise {return Err(Error::Invalid);}
        if h.step==0 {
            if self.id>state.config.id || !noise.is_empty() {return Err(Error::Invalid);}
            let duplicate=state.requests.contains(&id);
            if !duplicate {state.requests.push_back(id);if state.requests.len()>32 {state.requests.pop_front();}}
            return self.ensure_state(state,now,!duplicate);
        }
        if state.session.as_ref().is_some_and(|s|s.expired(now)){Self::retire(state);}
        if h.step==1 && self.id>state.config.id {
            if state.retired.contains(&id){return Err(Error::Replay);}
            if state.session.as_ref().is_none_or(|s|s.id!=id) {
                // Only the deterministic leader may initiate; no crossed key states.
                Self::retire(state);state.session=Some(self.new_session(&state.config,id,false,now)?);state.request=None;
            }
        }
        let session=state.session.as_mut().ok_or(Error::NotReady)?;
        if session.id!=id {return Err(Error::NotReady);}
        let digest: [u8;32]=Sha256::digest(wire).into();
        if let Some(old)=session.incoming.get(&h.step) {
            if *old!=digest {return Err(Error::Authentication);}
            return Ok(Outcome{outgoing:session.replies.get(&h.step).cloned().into_iter().collect(),ready:session.ready,..Default::default()});
        }
        if (session.initiator && h.step!=2)||(!session.initiator && h.step!=1 && h.step!=3) {return Err(Error::Invalid);}
        let hs=session.handshake.as_mut().ok_or(Error::Invalid)?;
        let mut payload=Zeroizing::new([0u8;512]);
        if hs.read_message(&noise,&mut payload[..]).map_err(|_|Error::Authentication)?!=0 {return Err(Error::Invalid);}
        let reply=if h.step<3 {
            let mut output=[0;512];let n=hs.write_message(&[],&mut output).map_err(|_|Error::Authentication)?;
            let wire=self.packet(&state.config,id,h.step+1,&output[..n],now)?;
            if h.step==2 {session.finish(&x)?;}
            wire
        } else {
            session.finish(&x)?;session.ready=true;
            self.seal_session(&state.config,session,0,b"secure-sync-fs-ready-v2")?
        };
        session.incoming.insert(h.step,digest);session.replies.insert(h.step,reply.clone());session.last=reply.clone();
        Ok(Outcome{outgoing:vec![reply],ready:session.ready,..Default::default()})
    }
    pub fn seal(&mut self,p:&Peer,message:&[u8],now:u64)->Result<Outcome> {
        let mut state=self.take_peer(p)?;
        let result=(||{
            if !state.session.as_ref().is_some_and(|s|s.ready&&!s.expired(now)){return self.ensure_state(&mut state,now,false);}
            let session=state.session.as_mut().unwrap();
            Ok(Outcome{outgoing:vec![self.seal_session(p,session,1,message)?],ready:true,..Default::default()})
        })();
        self.peers.insert(p.id.clone(),state);result
    }
    fn seal_session(&self,p:&Peer,s:&mut Session,kind:u8,message:&[u8])->Result<Vec<u8>> {
        if message.is_empty() || message.len()>MAX_PLAIN {return Err(Error::Limit);}
        let count=message.len().div_ceil(CHUNK);let first=s.next;
        if count>8 || first+count as u64>=MAX_NONCE {return Err(Error::Limit);}
        let transport=s.transport.as_ref().ok_or(Error::NotReady)?;
        // Reserve nonces before encryption; any error burns the entire range.
        s.next+=count as u64;
        let mut out=vec![2];out.extend(s.id);out.extend(self.id.as_bytes());out.extend(p.id.as_bytes());out.extend(first.to_be_bytes());out.push(count as u8);
        for (index,part) in message.chunks(CHUNK).enumerate() {
            let mut plain=Zeroizing::new(Vec::with_capacity(PREFIX+part.len()));
            plain.extend(first.to_be_bytes());plain.push(index as u8);plain.push(count as u8);plain.extend((message.len() as u32).to_be_bytes());plain.push(kind);plain.extend(part);
            let mut cipher=vec![0;plain.len()+16];let n=transport.write_message(first+index as u64,&plain,&mut cipher).map_err(|_|Error::Authentication)?;
            out.extend((n as u16).to_be_bytes());out.extend(&cipher[..n]);
        }
        frame(DATA,&out)
    }
    fn open(&self,state:&mut PeerState,wire:&[u8],now:u64)->Result<Outcome> {
        let b=body(wire,DATA)?;
        if b.len()<128 || b[0]!=2 || &b[33..76]!=state.config.id.as_bytes() || &b[76..119]!=self.id.as_bytes() {return Err(Error::Invalid);}
        let s=state.session.as_mut().ok_or(Error::NotReady)?;
        if s.expired(now)||b[1..33]!=s.id {return Err(Error::NotReady);}
        let first=u64::from_be_bytes(b[119..127].try_into().unwrap());let count=b[127] as usize;
        if count==0 || count>8 || first>=MAX_NONCE || first+count as u64>=MAX_NONCE {return Err(Error::Limit);}
        if (first..first+count as u64).any(|n|s.seen.contains(&n)) || s.highest.is_some_and(|h|first.saturating_add(REPLAY_WINDOW)<=h){return Err(Error::Replay);}
        let transport=s.transport.as_ref().ok_or(Error::NotReady)?;
        let mut output=Zeroizing::new(Vec::new());let mut at=128;let mut total=None;let mut kind=None;
        for index in 0..count {
            if at+2>b.len(){return Err(Error::Invalid);}
            let n=u16::from_be_bytes(b[at..at+2].try_into().unwrap()) as usize;at+=2;
            if n<PREFIX+17 || at+n>b.len(){return Err(Error::Invalid);}
            let mut part=Zeroizing::new(vec![0;n]);let len=transport.read_message(first+index as u64,&b[at..at+n],&mut part).map_err(|_|Error::Authentication)?;at+=n;
            if len<PREFIX || part[..8]!=first.to_be_bytes() || part[8]!=index as u8 || part[9]!=count as u8 {return Err(Error::Authentication);}
            let size=u32::from_be_bytes(part[10..14].try_into().unwrap()) as usize;
            if size==0 || size>MAX_PLAIN || total.is_some_and(|t|t!=size) || kind.is_some_and(|k|k!=part[14]) || output.len()+len-PREFIX>size {return Err(Error::Limit);}
            total=Some(size);kind=Some(part[14]);output.extend(&part[PREFIX..len]);
        }
        if at!=b.len() || total!=Some(output.len()) {return Err(Error::Invalid);}
        match kind {
            Some(0) if s.initiator && output.as_slice()==b"secure-sync-fs-ready-v2" => {s.ready=true;}
            Some(1) if s.ready => {},
            _=>return Err(Error::NotReady),
        }
        let highest=first+count as u64-1;s.highest=Some(s.highest.map_or(highest,|h|h.max(highest)));
        for n in first..first+count as u64{s.seen.insert(n);}
        let floor=s.highest.unwrap().saturating_sub(REPLAY_WINDOW-1);s.seen=s.seen.split_off(&floor);
        Ok(Outcome{ready:s.ready,message:if kind==Some(1){Some(output)}else{None},..Default::default()})
    }
}
