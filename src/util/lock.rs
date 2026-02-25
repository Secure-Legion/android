use std::sync::{Mutex, MutexGuard};

#[inline]
pub fn lock_recover<'a, T>(m: &'a Mutex<T>) -> MutexGuard<'a, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}
