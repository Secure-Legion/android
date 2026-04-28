//! Bloom filter for HELLO digest.
//!
//! Step 6 of the Phase 6 build. Skeleton only.
//!
//! Planned shape:
//! - Configurable size + hash function count, sized per group head count
//!   (target ~1% false-positive rate at 250K ops → ~512 byte filter, k=5).
//! - BLAKE3-keyed double hashing (Kirsch-Mitzenmacher) — two BLAKE3 derivations,
//!   k indexes computed as `(h1 + i * h2) % m`. Same algorithm on both peers,
//!   so false-positives are deterministic given the same set, which simplifies
//!   reasoning about gap detection.
//! - Item type: `OpID` (encoded as `(author_bytes, lamport, nonce)`).
//! - `Bloom::new(estimated_n)` chooses `m` and `k`; `Bloom::insert(op_id)`;
//!   `Bloom::contains(op_id) -> bool`.
//! - Empty filter = sentinel for "no bloom in use" (responder ships everything
//!   above lamport heads).
