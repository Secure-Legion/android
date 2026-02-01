use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand::thread_rng;

/// Generate a Bulletproof range proof for a given amount.
///
/// Proves that `amount` is in range [0, 2^bit_length) without revealing the amount.
/// Used by ShadowWire for internal transfers where amounts must be hidden.
///
/// Returns (proof_bytes, commitment_bytes, blinding_factor_bytes) on success.
/// - proof_bytes: ~672 bytes (variable), the serialized range proof
/// - commitment_bytes: 32 bytes, the Pedersen commitment to the amount
/// - blinding_factor_bytes: 32 bytes, the blinding factor (needed for verification)
pub fn generate_range_proof(
    amount: u64,
    bit_length: usize,
) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), String> {
    if bit_length != 8 && bit_length != 16 && bit_length != 32 && bit_length != 64 {
        return Err(format!(
            "bit_length must be 8, 16, 32, or 64, got {}",
            bit_length
        ));
    }

    // Check amount fits in bit_length
    if bit_length < 64 && amount >= (1u64 << bit_length) {
        return Err(format!(
            "amount {} exceeds range for {}-bit proof (max {})",
            amount,
            bit_length,
            (1u64 << bit_length) - 1
        ));
    }

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(bit_length, 1);

    let mut rng = thread_rng();
    let blinding = Scalar::random(&mut rng);

    let (proof, commitment) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut Transcript::new(b"ShadowWire_RangeProof"),
        amount,
        &blinding,
        bit_length,
    )
    .map_err(|e| format!("Range proof generation failed: {:?}", e))?;

    let proof_bytes = proof.to_bytes();
    let commitment_bytes: [u8; 32] = commitment.to_bytes();
    let blinding_bytes: [u8; 32] = blinding.to_bytes();

    Ok((proof_bytes, commitment_bytes, blinding_bytes))
}

/// Verify a Bulletproof range proof.
///
/// Checks that the commitment opens to a value in range [0, 2^bit_length).
pub fn verify_range_proof(
    proof_bytes: &[u8],
    commitment_bytes: &[u8; 32],
    bit_length: usize,
) -> Result<bool, String> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(bit_length, 1);

    let proof = RangeProof::from_bytes(proof_bytes)
        .map_err(|e| format!("Invalid proof bytes: {:?}", e))?;

    let commitment = CompressedRistretto::from_slice(commitment_bytes)
        .map_err(|e| format!("Invalid commitment bytes: {:?}", e))?;

    proof
        .verify_single(
            &bp_gens,
            &pc_gens,
            &mut Transcript::new(b"ShadowWire_RangeProof"),
            &commitment,
            bit_length,
        )
        .map(|_| true)
        .map_err(|e| format!("Proof verification failed: {:?}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof_roundtrip() {
        let amount = 1_000_000u64; // 0.001 SOL in lamports
        let (proof_bytes, commitment, blinding) =
            generate_range_proof(amount, 64).expect("proof generation failed");

        assert!(!proof_bytes.is_empty(), "proof should not be empty");
        assert_ne!(commitment, [0u8; 32], "commitment should not be zero");
        assert_ne!(blinding, [0u8; 32], "blinding should not be zero");

        // Verify
        let valid =
            verify_range_proof(&proof_bytes, &commitment, 64).expect("verification failed");
        assert!(valid, "proof should be valid");
    }

    #[test]
    fn test_range_proof_invalid_bit_length() {
        let result = generate_range_proof(100, 12);
        assert!(result.is_err());
    }
}
