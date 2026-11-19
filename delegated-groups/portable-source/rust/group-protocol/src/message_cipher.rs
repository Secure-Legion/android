//! Explicit epoch binding inside the signed group ciphertext payload. Old raw
//! values remain genesis-key history; the key itself never appears here.
pub(crate) const MAGIC: &[u8; 6] = b"SLGM01";
pub(crate) fn wrap(epoch: [u8; 32], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(38 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&epoch);
    out.extend_from_slice(ciphertext);
    out
}
pub(crate) fn split<'a>(
    ciphertext: &'a [u8],
    genesis: [u8; 32],
    legacy: bool,
) -> Result<([u8; 32], &'a [u8], bool), ()> {
    if !legacy && ciphertext.starts_with(MAGIC) {
        if ciphertext.len() < 38 + 16 {
            return Err(());
        }
        Ok((
            ciphertext[6..38].try_into().map_err(|_| ())?,
            &ciphertext[38..],
            true,
        ))
    } else {
        Ok((genesis, ciphertext, false))
    }
}
