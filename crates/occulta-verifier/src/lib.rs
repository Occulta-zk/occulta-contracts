//! **NOT YET IMPLEMENTED — scaffold only, milestone M3.**
//!
//! This crate will implement stateless Groth16 verification over BLS12-381 (`env.crypto()
//! .bls12_381()`) and BN254 (`env.crypto().bn254()`) per the verified bindings in
//! `docs/PLATFORM.md`: assemble `vk_x = ic[0] + Σ ic[i+1]·signal[i]` via `g1_msm`, negate `A`,
//! and call `pairing_check` once over all four G1/G2 pairs. It ships no verification logic
//! yet — per the build spec, no cryptographic change is merged without a fixture (a real
//! snarkjs-produced proof + vkey + public signals) proving it verifies, plus a negative
//! fixture (one bit flipped) proving it correctly fails. Those fixtures don't exist in this
//! session (`fixtures/vote/` is an empty placeholder — see `fixtures/README.md`).
//!
//! `docs/PLATFORM.md` flags one open item this crate depends on: the BLS12-381/BN254 G2
//! coordinate swap (`occulta_types::swap_fp2_limbs`) is verified against SDK doc comments but
//! not yet round-tripped through an actual on-chain pairing check — do that as the first test
//! written against this crate, before anything else.
#![no_std]

#[doc(hidden)]
pub const _NOT_YET_IMPLEMENTED: &str = "occulta-verifier: see module docs, milestone M3";
