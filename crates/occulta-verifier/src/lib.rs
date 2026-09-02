//! Stateless Groth16 proof verification over BLS12-381 and BN254.
//!
//! This crate implements the Groth16 pairing check:
//!
//! ```text
//! e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1
//! ```
//!
//! where `vk_x = ic[0] + Σ ic[i+1]·signal[i]` is computed via `g1_msm` (never a loop of
//! `g1_mul` — the cost difference is significant). All four pairs are assembled into a single
//! `pairing_check` call, per the advice in `docs/PLATFORM.md`.
//!
//! ## No fixtures caveat
//!
//! A real `circom`/`snarkjs`-produced proof fixture does not exist in `fixtures/vote/` yet
//! (`circom` was not available in this environment). The implementation is built from the
//! specification and verified SDK bindings; every non-trivial path is exercised with synthetic
//! tests using `soroban-sdk`'s testutils `Env`. The first thing a new contributor should do is
//! run `scripts/gen-fixtures.sh` (needs `circom` + `snarkjs`) and replace those tests with
//! ones backed by real snarkjs artefacts.
//!
//! ## Encoding
//!
//! All point encoding follows `docs/ENCODING.md` and the verified bindings in
//! `docs/PLATFORM.md`. The most important: G2 coordinate order is **c1 before c0** in both
//! BLS12-381 and BN254 (opposite to snarkjs JSON order) — `occulta_types::swap_fp2_limbs`
//! must be applied before constructing a `VerificationKey` or `Proof` from snarkjs output.
#![no_std]

mod error;
mod verify_bls12;
mod verify_bn254;

pub use error::VerifierError;

use occulta_types::{Curve, Proof, VerificationKey};
use soroban_sdk::{Env, Vec, U256};

/// Stateless Groth16 verification.
///
/// Returns `Ok(true)` if the proof is valid, `Ok(false)` if the pairing check fails,
/// and `Err(e)` if the inputs are structurally invalid (wrong byte lengths, out-of-range
/// scalars, wrong public signal count, etc.).
///
/// Security Invariant #5: this function enforces `public_signals.len() + 1 == vk.ic.len()`.
/// A mismatch means the caller is verifying against the wrong circuit — this is a hard error,
/// not a soft false.
pub fn verify(
    env: &Env,
    vk: &VerificationKey,
    proof: &Proof,
    public_signals: &Vec<U256>,
) -> Result<bool, VerifierError> {
    // Structural checks first — quick and cheap before touching any crypto.
    vk.validate_shape().map_err(|_| VerifierError::MalformedVerificationKey)?;
    proof.validate_shape().map_err(|_| VerifierError::MalformedVerificationKey)?;

    if vk.curve != proof.curve {
        return Err(VerifierError::MalformedVerificationKey);
    }

    // Security Invariant #5: public signal count must match exactly.
    let expected = vk.expected_public_signal_count();
    if public_signals.len() != expected {
        return Err(VerifierError::PublicSignalCountMismatch);
    }

    // Range-check every public signal against the field modulus.
    let modulus = vk.curve.fr_modulus_be();
    for signal in public_signals.iter() {
        let bytes = u256_to_be32(&signal);
        if !occulta_types::scalar_in_range(&bytes, modulus) {
            return Err(VerifierError::ScalarOutOfRange);
        }
    }

    match vk.curve {
        Curve::Bls12_381 => verify_bls12::verify(env, vk, proof, public_signals),
        Curve::Bn254 => verify_bn254::verify(env, vk, proof, public_signals),
    }
}

/// Convert a `U256` to a 32-byte big-endian array for range checking.
pub(crate) fn u256_to_be32(v: &U256) -> [u8; 32] {
    let bytes = v.to_be_bytes();
    let mut arr = [0u8; 32];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = bytes.get_unchecked(i as u32);
    }
    arr
}

#[cfg(test)]
mod tests;

