//! Tests for `occulta-verifier`.
//!
//! Two groups:
//!
//! - **snarkjs fixture tests** (`fixture::*`): a real Groth16 proof over BN254, produced by
//!   circom 2.2.3 + snarkjs 0.7.5 from `circuits/private_vote.circom` and accepted by
//!   `snarkjs groth16 verify` before it was committed (see `fixtures/README.md` and
//!   `scripts/gen-fixtures.sh`). These are the only tests that exercise the `Ok(true)` path,
//!   and the only ones that would catch a `verify()` that always returns `Ok(false)`.
//! - **structural tests**: synthetic all-zero inputs that exercise every `Err` path before
//!   any host crypto is reached.
//!
//! All tests run against the real `soroban-env-host` via the testutils `Env`, not a mock.

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
// snarkjs fixture tests — fixtures/vote/, BN254, public signals [root, nullifier, choice, poll_id]
// ---------------------------------------------------------------------------

mod fixture {
    extern crate std;

    use occulta_types::snarkjs::{proof_from_json, public_signals_from_json, vk_from_json};
    use occulta_types::{swap_fp2_limbs, Proof, VerificationKey};
    use soroban_sdk::crypto::bn254::Bn254G1Affine;
    use soroban_sdk::{Bytes, BytesN, Env, Vec, U256};

    use crate::verify;

    const VKEY: &str = include_str!("../../../fixtures/vote/vkey.json");
    const PROOF: &str = include_str!("../../../fixtures/vote/proof.json");
    const PROOF_NEGATIVE: &str = include_str!("../../../fixtures/vote/proof_negative.json");
    const PUBLIC: &str = include_str!("../../../fixtures/vote/public.json");

    /// Recorded cost plus 10%. See `docs/BUDGET.md`.
    const BN254_VERIFY_CPU_THRESHOLD: u64 = 29_830_000;

    pub(super) fn load(env: &Env) -> (VerificationKey, Proof, Vec<U256>) {
        (
            vk_from_json(env, VKEY).unwrap(),
            proof_from_json(env, PROOF).unwrap(),
            public_signals_from_json(env, PUBLIC).unwrap(),
        )
    }

    /// Re-applies the Fp2 limb swap to both coordinates of a BN254 G2 point, turning the
    /// host order `c1 || c0` back into snarkjs's native `c0 || c1`.
    fn to_snarkjs_g2_order(env: &Env, g2: &Bytes) -> Bytes {
        let host: std::vec::Vec<u8> = g2.iter().collect();
        let mut out = [0u8; 128];
        swap_fp2_limbs(&host[..64], 32, &mut out[..64]);
        swap_fp2_limbs(&host[64..], 32, &mut out[64..]);
        Bytes::from_array(env, &out)
    }

    /// The point of the whole crate: a real snarkjs proof verifies on-chain.
    #[test]
    fn fixture_proof_verifies() {
        let env = Env::default();
        let (vk, proof, signals) = load(&env);
        assert_eq!(signals.len(), 4);
        assert_eq!(verify(&env, &vk, &proof, &signals), Ok(true));
    }

    /// Budget probe for `docs/BUDGET.md`: cost of `verify()` alone on the fixture (4 public
    /// signals), measured the same way as the Poseidon numbers there. Fails if the cost
    /// regresses more than 10% past the recorded figure.
    #[test]
    fn fixture_verify_budget() {
        let env = Env::default();
        let (vk, proof, signals) = load(&env);
        env.cost_estimate().budget().reset_unlimited();
        assert_eq!(verify(&env, &vk, &proof, &signals), Ok(true));
        let cpu = env.cost_estimate().budget().cpu_instruction_cost();
        std::println!("verify(BN254, 4 signals) cpu_instruction_cost = {cpu}");
        assert!(
            cpu < BN254_VERIFY_CPU_THRESHOLD,
            "verify cost regressed: {cpu}"
        );
    }

    /// Swapping `root` and `nullifier` keeps every value in range and the count correct —
    /// the only thing wrong is the order, and that must be enough to fail.
    #[test]
    fn fixture_permuted_signals_do_not_verify() {
        let env = Env::default();
        let (vk, proof, signals) = load(&env);
        let mut permuted = signals.clone();
        permuted.set(0, signals.get_unchecked(1));
        permuted.set(1, signals.get_unchecked(0));
        assert_eq!(verify(&env, &vk, &proof, &permuted), Ok(false));
    }

    /// Security Invariant #1: `choice` is bound into the proof. A proof copied from the
    /// mempool cannot be resubmitted with the other choice.
    #[test]
    fn fixture_proof_rejects_a_different_choice() {
        let env = Env::default();
        let (vk, proof, mut signals) = load(&env);
        assert_eq!(signals.get_unchecked(2), U256::from_u32(&env, 1));
        signals.set(2, U256::from_u32(&env, 0));
        assert_eq!(verify(&env, &vk, &proof, &signals), Ok(false));
    }

    /// Security Invariant #6: the proof is bound to its `poll_id`; it cannot be replayed in
    /// another poll.
    #[test]
    fn fixture_proof_rejects_a_different_poll_id() {
        let env = Env::default();
        let (vk, proof, mut signals) = load(&env);
        assert_eq!(signals.get_unchecked(3), U256::from_u32(&env, 42));
        signals.set(3, U256::from_u32(&env, 43));
        assert_eq!(verify(&env, &vk, &proof, &signals), Ok(false));
    }

    /// An on-curve but wrong proof (`A` replaced by `-A`) reaches the pairing and fails it.
    #[test]
    fn fixture_proof_with_negated_a_returns_false() {
        let env = Env::default();
        let (vk, mut proof, signals) = load(&env);
        let a = Bn254G1Affine::from_bytes(BytesN::<64>::try_from(proof.a.clone()).unwrap());
        proof.a = (-a).to_bytes().into();
        assert_eq!(verify(&env, &vk, &proof, &signals), Ok(false));
    }

    /// `fixtures/vote/proof_negative.json` flips the lowest bit of `pi_a.x`, which snarkjs
    /// rejects as "Proof commitments are not valid". The resulting `A` is not on the curve,
    /// and the host does not return `false` for that: it traps the invocation. That is the
    /// correct outcome (a malformed proof aborts the transaction), and it means a contract
    /// cannot catch it and continue.
    #[test]
    #[should_panic(expected = "bn254 G1: point not on curve")]
    fn fixture_negative_proof_traps_in_the_host() {
        let env = Env::default();
        let (vk, _, signals) = load(&env);
        let proof = proof_from_json(&env, PROOF_NEGATIVE).unwrap();
        let _ = verify(&env, &vk, &proof, &signals);
    }

    /// Evidence for `docs/ENCODING.md` rule 3. Feeding the host snarkjs's native G2 limb
    /// order (`c0 || c1`) instead of `c1 || c0` does not verify: the host traps because the
    /// bytes do not decode to a point on the curve. Paired with `fixture_proof_verifies`, this
    /// pins down the order empirically rather than from documentation alone.
    #[test]
    #[should_panic(expected = "bn254 G2: point not on curve")]
    fn fixture_snarkjs_native_g2_order_is_rejected_by_the_host() {
        let env = Env::default();
        let (mut vk, mut proof, signals) = load(&env);
        proof.b = to_snarkjs_g2_order(&env, &proof.b);
        vk.beta_g2 = to_snarkjs_g2_order(&env, &vk.beta_g2);
        vk.gamma_g2 = to_snarkjs_g2_order(&env, &vk.gamma_g2);
        vk.delta_g2 = to_snarkjs_g2_order(&env, &vk.delta_g2);
        let _ = verify(&env, &vk, &proof, &signals);
    }
}
