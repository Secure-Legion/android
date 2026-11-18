//! Opaque memory-only engines shared by Desktop and the iOS app.
use crate::{Engine, Error, Peer, MAX_PLAIN, MAX_WIRE};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::Deserialize;
use std::{collections::BTreeMap, panic::{catch_unwind,AssertUnwindSafe}, ptr, slice,
    sync::{Mutex, OnceLock, atomic::{AtomicU64,Ordering}}};
use zeroize::Zeroizing;

static ENGINES: OnceLock<Mutex<BTreeMap<u64,Engine>>> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(1);
fn engines()-> &'static Mutex<BTreeMap<u64,Engine>> {ENGINES.get_or_init(||Mutex::new(BTreeMap::new()))}
fn locked()->std::sync::MutexGuard<'static,BTreeMap<u64,Engine>> {
    match engines().lock() {
        Ok(map)=>map,
        Err(poisoned)=>{let mut map=poisoned.into_inner();map.clear();engines().clear_poison();map}
    }
}

/// # Safety
/// Each input points to 32 accessible bytes. Never accepts account signing seeds.
#[no_mangle]
pub unsafe extern "C" fn sl_sync_fs_new(account:*const u8, ed:*const u8, x:*const u8)->u64 {
    if account.is_null()||ed.is_null()||x.is_null(){return 0;}
    catch_unwind(AssertUnwindSafe(||{
        let mut a=[0;32];a.copy_from_slice(slice::from_raw_parts(account,32));
        let mut e=Zeroizing::new([0;32]);e.copy_from_slice(slice::from_raw_parts(ed,32));
        let mut k=Zeroizing::new([0;32]);k.copy_from_slice(slice::from_raw_parts(x,32));
        let mut map=locked();
        if map.len()>=64{return 0;}
        let id=NEXT.fetch_add(1,Ordering::Relaxed);if id==0{return 0;}
        map.insert(id,Engine::new(a,*e,*k));id
    })).unwrap_or(0)
}
#[no_mangle]
pub extern "C" fn sl_sync_fs_free(handle:u64) {
    let _=catch_unwind(AssertUnwindSafe(||{locked().remove(&handle);}));
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {op:String, peer:Peer, now:u64, wire:Option<String>, message:Option<String>}
fn execute(handle:u64,input:&[u8])->Result<Zeroizing<Vec<u8>>,Error> {
    let r:Request=serde_json::from_slice(input).map_err(|_|Error::Invalid)?;
    if r.now==0||r.now>9_007_199_254_740_991{return Err(Error::Invalid);}
    let mut map=locked();let engine=map.get_mut(&handle).ok_or(Error::NotReady)?;
    let before=engine.ready(&r.peer,r.now);
    let result=match r.op.as_str(){
        "ensure" if r.wire.is_none()&&r.message.is_none()=>engine.ensure(&r.peer,r.now)?,
        "seal" if r.wire.is_none()=>{
            let text=r.message.ok_or(Error::Invalid)?;if text.len()>MAX_PLAIN.div_ceil(3)*4{return Err(Error::Limit);}
            let bytes=Zeroizing::new(B64.decode(&text).map_err(|_|Error::Invalid)?);engine.seal(&r.peer,&bytes,r.now)?
        },
        "receive" if r.message.is_none()=>{
            let text=r.wire.ok_or(Error::Invalid)?;if text.len()>MAX_WIRE.div_ceil(3)*4{return Err(Error::Limit);}
            let bytes=B64.decode(text).map_err(|_|Error::Invalid)?;engine.receive(&r.peer,&bytes,r.now)?
        },
        "forget" if r.wire.is_none()&&r.message.is_none()=>{engine.forget(&r.peer.id);crate::Outcome::default()},
        _=>return Err(Error::Invalid),
    };
    let value=serde_json::json!({"ready":result.ready,"became_ready":!before&&result.ready,
        "outgoing":result.outgoing.iter().map(|w|B64.encode(w)).collect::<Vec<_>>(),
        "message":result.message.as_ref().map(|m|B64.encode(m.as_slice()))});
    Ok(Zeroizing::new(serde_json::to_vec(&value).map_err(|_|Error::Invalid)?))
}
/// # Safety
/// Buffers must have their stated accessible sizes. Output is written atomically
/// after successful processing; caller supplies at least 1 MiB output capacity.
#[no_mangle]
pub unsafe extern "C" fn sl_sync_fs_call(handle:u64,input:*const u8,len:u32,out:*mut u8,out_len:*mut u32)->i32 {
    if input.is_null()||out.is_null()||out_len.is_null()||len==0||len>1024*1024||*out_len<1024*1024||*out_len>2*1024*1024{return -1;}
    catch_unwind(AssertUnwindSafe(||{
        let input=Zeroizing::new(slice::from_raw_parts(input,len as usize).to_vec());
        let result=match execute(handle,&input){Ok(r)=>r,Err(e)=>return match e{Error::Invalid=>-10,Error::Authentication=>-11,Error::NotReady=>-12,Error::Replay=>-13,Error::Limit=>-14}};
        if result.len()>*out_len as usize{return -2;}
        ptr::copy_nonoverlapping(result.as_ptr(),out,result.len());*out_len=result.len() as u32;0
    })).unwrap_or(-1)
}
