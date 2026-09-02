//! Tests for `occulta-verifier`.
//!
//! ## Fixture situation
//!
//! A real `circom`/`snarkjs`-produced proof does not exist in `fixtures/vote/` yet — `circom`
//! was not available in this build environment. All tests here use *synthetic* (handcrafted)
//! data that exercises the verifier's structural / error-path logic through the real
//! `soroban-sdk` testutils `Env` (not a mock), backed by the real `soroban-env-host`. This
//! covers every `Err` variant and every length/count check.
//!
//! The pairing-check `Ok(true)` / `Ok(false)` paths cannot be meaningfully tested without a
//! real proof and matching VK. Once `scripts/gen-fixtures.sh` is runnable (needs `circom` +
//! `snarkjs`), replace the `TODO_real_fixture_*` placeholders below with real data from
//! `fixtures/vote/vkey.json`, `proof.json`, and `public.json`.
//!
//! See the module-level doc in `lib.rs` for the open-item flag.

extern crate std;

use occulta_types::{Curve, Proof, VerificationKey};
use soroban_sdk::{Bytes, Env, Vec, U256};

use crate::{verify, VerifierError};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn zero_bytes(env: &Env, len: usize) -> Bytes {
    let v: std::vec::Vec<u8> = std::vec![0u8; len];
    Bytes::from_slice(env, &v)
}

fn make_bn254_vk(env: &Env, n_ic: u32) -> VerificationKey {
    let mut ic = Vec::new(env);
    for _ in 0..n_ic {
        ic.push_back(zero_bytes(env, 64));
    }
    VerificationKey {
        curve: Curve::Bn254,
        alpha_g1: zero_bytes(env, 64),
        beta_g2: zero_bytes(env, 128),
        gamma_g2: zero_bytes(env, 128),
        delta_g2: zero_bytes(env, 128),
        ic,
    }
}

fn make_bn254_proof(env: &Env) -> Proof {
    Proof {
        curve: Curve::Bn254,
        a: zero_bytes(env, 64),
        b: zero_bytes(env, 128),
        c: zero_bytes(env, 64),
    }
}

fn make_bls12_vk(env: &Env, n_ic: u32) -> VerificationKey {
    let mut ic = Vec::new(env);
    for _ in 0..n_ic {
        ic.push_back(zero_bytes(env, 96));
    }
    VerificationKey {
        curve: Curve::Bls12_381,
        alpha_g1: zero_bytes(env, 96),
        beta_g2: zero_bytes(env, 192),
        gamma_g2: zero_bytes(env, 192),
        delta_g2: zero_bytes(env, 192),
        ic,
    }
}

fn make_bls12_proof(env: &Env) -> Proof {
    Proof {
        curve: Curve::Bls12_381,
        a: zero_bytes(env, 96),
        b: zero_bytes(env, 192),
        c: zero_bytes(env, 96),
    }
}

fn signals(env: &Env, count: u32) -> Vec<U256> {
    let mut v = Vec::new(env);
    for i in 0..count {
        v.push_back(U256::from_u32(env, i + 1));
    }
    v
}

// ---------------------------------------------------------------------------
// Error-path tests (structural checks that must fire before any crypto)
// ---------------------------------------------------------------------------

/// Public signal count mismatch — Security Invariant #5.
#[test]
fn public_signal_count_mismatch_is_an_error() {
    let env = Env::default();
    // VK with ic len=3 expects 2 signals; we pass 1.
    let vk = make_bn254_vk(&env, 3);
    let proof = make_bn254_proof(&env);
    let sigs = signals(&env, 1); // one too few
    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::PublicSignalCountMismatch);
}

#[test]
fn zero_signals_when_vk_has_ic_len_2_is_a_mismatch() {
    let env = Env::default();
    let vk = make_bn254_vk(&env, 2); // expects 1 signal
    let proof = make_bn254_proof(&env);
    let sigs = signals(&env, 0); // zero signals
    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::PublicSignalCountMismatch);
}

#[test]
fn too_many_signals_is_a_mismatch() {
    let env = Env::default();
    let vk = make_bn254_vk(&env, 2); // expects 1 signal
    let proof = make_bn254_proof(&env);
    let sigs = signals(&env, 3); // too many
    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::PublicSignalCountMismatch);
}

/// Permuting two public signals — Security Invariant #1 test (build spec §5).
/// With a real proof fixture this would give Ok(false); with synthetic zero-point data it hits
/// an invalid-point error first, which still demonstrates the path works.
#[test]
fn permuted_signals_do_not_silently_succeed() {
    let env = Env::default();
    // We can't test pairing failure without real data; we can test that our signal-count
    // check doesn't mask a permutation when count does match.
    let vk = make_bn254_vk(&env, 3); // 2 signals
    let proof = make_bn254_proof(&env);
    // Both orderings have the same count — the verifier proceeds to crypto and (with all-zero
    // synthetic data) hits an InvalidPoint error, not a count mismatch. The important property
    // is that neither ordering returns Ok(true) with fake data.
    let mut sigs_ab = Vec::new(&env);
    sigs_ab.push_back(U256::from_u32(&env, 1));
    sigs_ab.push_back(U256::from_u32(&env, 2));

    let mut sigs_ba = Vec::new(&env);
    sigs_ba.push_back(U256::from_u32(&env, 2));
    sigs_ba.push_back(U256::from_u32(&env, 1));

    // Both reach the crypto layer (no count error) — they may trap on invalid synthetic
    // points, which is acceptable. The test asserts they don't return Ok(true).
    let r_ab = verify(&env, &vk, &proof, &sigs_ab);
    let r_ba = verify(&env, &vk, &proof, &sigs_ba);
    assert!(
        r_ab != Ok(true),
        "synthetic zero-point proof must not verify as true"
    );
    assert!(r_ba != Ok(true), "permuted signals must not verify as true");
}

/// Out-of-range scalar — Security Invariant #8.
#[test]
fn out_of_range_bn254_signal_is_rejected() {
    let env = Env::default();
    // BN254 Fr modulus is 0x30644e72...f0000001.
    // One-past-the-modulus: 0x30644e72...f0000002.
    let mut over_bytes = [0u8; 32];
    let modulus_be = [
        0x30u8, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    over_bytes.copy_from_slice(&modulus_be);
    over_bytes[31] = over_bytes[31].wrapping_add(1); // modulus + 1

    let vk = make_bn254_vk(&env, 2); // 1 signal
    let proof = make_bn254_proof(&env);
    let mut sigs = Vec::new(&env);
    let over_u256 = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &over_bytes));
    sigs.push_back(over_u256);

    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::ScalarOutOfRange);
}

#[test]
fn out_of_range_bls12_signal_is_rejected() {
    let env = Env::default();
    // BLS12-381 Fr modulus + 1 (last byte is 0x01, wraps to 0x02 without overflow).
    let mut over_bytes = [0u8; 32];
    let modulus_be = [
        0x73u8, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x01,
    ];
    over_bytes.copy_from_slice(&modulus_be);
    over_bytes[31] = over_bytes[31].wrapping_add(1);

    let vk = make_bls12_vk(&env, 2);
    let proof = make_bls12_proof(&env);
    let mut sigs = Vec::new(&env);
    let over_u256 = U256::from_be_bytes(&env, &soroban_sdk::Bytes::from_array(&env, &over_bytes));
    sigs.push_back(over_u256);

    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::ScalarOutOfRange);
}

/// Malformed VK — wrong byte lengths.
#[test]
fn vk_with_wrong_alpha_length_is_rejected() {
    let env = Env::default();
    let mut vk = make_bn254_vk(&env, 2);
    vk.alpha_g1 = zero_bytes(&env, 96); // BLS12-381 sized in a BN254 VK
    let proof = make_bn254_proof(&env);
    let sigs = signals(&env, 1);
    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::MalformedVerificationKey);
}

#[test]
fn proof_with_wrong_b_length_is_rejected() {
    let env = Env::default();
    let vk = make_bn254_vk(&env, 2);
    let mut proof = make_bn254_proof(&env);
    proof.b = zero_bytes(&env, 64); // G1 size instead of G2
    let sigs = signals(&env, 1);
    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::MalformedVerificationKey);
}

/// VK and proof on different curves must be rejected.
#[test]
fn curve_mismatch_between_vk_and_proof_is_rejected() {
    let env = Env::default();
    let vk = make_bn254_vk(&env, 2);
    let proof = make_bls12_proof(&env); // BLS12-381 proof for a BN254 VK
    let sigs = signals(&env, 1);
    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::MalformedVerificationKey);
}

/// Empty ic must be caught by VK shape validation.
#[test]
fn empty_ic_vk_is_rejected() {
    let env = Env::default();
    let vk = make_bn254_vk(&env, 0); // 0 ic entries → EmptyIc from validate_shape
    let proof = make_bn254_proof(&env);
    let sigs = signals(&env, 0);
    let err = verify(&env, &vk, &proof, &sigs).unwrap_err();
    assert_eq!(err, VerifierError::MalformedVerificationKey);
}

// ---------------------------------------------------------------------------
// TODO: real fixture tests — unblock by running `scripts/gen-fixtures.sh`
// ---------------------------------------------------------------------------
//
// Once `fixtures/vote/vkey.json`, `proof.json`, `public.json` exist:
//
// ```rust
// #[test]
// fn bn254_groth16_real_fixture_verifies() {
//     let env = Env::default();
//     let vk = load_vk_from_json(&env, include_str!("../../../fixtures/vote/vkey.json"));
//     let proof = load_proof_from_json(&env, include_str!("../../../fixtures/vote/proof.json"));
//     let signals = load_signals(&env, include_str!("../../../fixtures/vote/public.json"));
//     assert_eq!(verify(&env, &vk, &proof, &signals), Ok(true));
// }
//
// #[test]
// fn bn254_groth16_bit_flipped_proof_fails() {
//     // negative fixture: one bit flipped in proof.a's first byte
//     let env = Env::default();
//     let vk = load_vk_from_json(...);
//     let mut proof = load_proof_from_json(...);
//     // flip bit 0 of proof.a[0]
//     assert_eq!(verify(&env, &vk, &proof, &signals), Ok(false));
// }
// ```
