//! Differential tests: these values are not invented here -- every one is copied
//! mechanically (via scripts/poseidon-gen/gen_tests.mjs, GENERATED FILE, do not hand-edit
//! this file) from `fixtures/poseidon/{bn254,bls12_381}.json`, which were themselves
//! computed by `scripts/poseidon-gen/` (see that directory's README for exact provenance:
//! real `circomlibjs` for BN254, `soroban-env-host`'s own conformance vectors for
//! BLS12-381). Each test here calls the REAL host implementation through `soroban-sdk`'s
//! `Env` (which wraps the actual `soroban-env-host` under `testutils` -- not a mock) and
//! asserts the result matches the independently-computed fixture. This is the actual
//! "differential test against a reference implementation" `CONTRIBUTING.md` requires, not
//! just a compile check.

extern crate std;

use occulta_types::Curve;
use soroban_sdk::{Bytes, Env, Vec, U256};

use crate::{Poseidon, PoseidonError};

fn hex_to_u256(env: &Env, hex_no_prefix: &str) -> U256 {
    assert_eq!(hex_no_prefix.len(), 64, "fixture hex must be exactly 32 bytes");
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_no_prefix[i * 2..i * 2 + 2], 16).unwrap();
    }
    U256::from_be_bytes(env, &Bytes::from_array(env, &bytes))
}

fn u32_input(env: &Env, n: u32) -> U256 {
    U256::from_u32(env, n)
}

// --- BN254: real circomlib constants (see fixtures/poseidon/bn254.json) ---

#[test]
fn bn254_hash2_fixture_0() {
    let env = Env::default();
    let left = u32_input(&env, 0);
    let right = u32_input(&env, 0);
    let got = Poseidon::hash2(&env, Curve::Bn254, &left, &right).unwrap();
    let expected = hex_to_u256(&env, "2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864");
    assert_eq!(got, expected, "inputs: 0, 0");
}

#[test]
fn bn254_hash2_fixture_1() {
    let env = Env::default();
    let left = u32_input(&env, 0);
    let right = u32_input(&env, 1);
    let got = Poseidon::hash2(&env, Curve::Bn254, &left, &right).unwrap();
    let expected = hex_to_u256(&env, "1bd20834f5de9830c643778a2e88a3a1363c8b9ac083d36d75bf87c49953e65e");
    assert_eq!(got, expected, "inputs: 0, 1");
}

#[test]
fn bn254_hash2_fixture_2() {
    let env = Env::default();
    let left = u32_input(&env, 1);
    let right = u32_input(&env, 2);
    let got = Poseidon::hash2(&env, Curve::Bn254, &left, &right).unwrap();
    let expected = hex_to_u256(&env, "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
    assert_eq!(got, expected, "inputs: 1, 2");
}

#[test]
fn bn254_hash2_fixture_3() {
    let env = Env::default();
    let left = hex_to_u256(&env, "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000");
    let right = u32_input(&env, 1);
    let got = Poseidon::hash2(&env, Curve::Bn254, &left, &right).unwrap();
    let expected = hex_to_u256(&env, "241af30a65318c4636803d8133f87ce755ed485f10695563caff5ed186bccf7d");
    assert_eq!(got, expected, "inputs: 21888242871839275222246405745257275088548364400416034343698204186575808495616, 1");
}

#[test]
fn bn254_hash_n_fixture_0() {
    let env = Env::default();
    let mut inputs: Vec<U256> = Vec::new(&env);
    inputs.push_back(u32_input(&env, 1));
    let got = Poseidon::hash_n(&env, Curve::Bn254, &inputs).unwrap();
    let expected = hex_to_u256(&env, "29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133");
    assert_eq!(got, expected, "inputs: 1");
}

#[test]
fn bn254_hash_n_fixture_1() {
    let env = Env::default();
    let mut inputs: Vec<U256> = Vec::new(&env);
    inputs.push_back(u32_input(&env, 1));
    inputs.push_back(u32_input(&env, 2));
    inputs.push_back(u32_input(&env, 3));
    let got = Poseidon::hash_n(&env, Curve::Bn254, &inputs).unwrap();
    let expected = hex_to_u256(&env, "0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732");
    assert_eq!(got, expected, "inputs: 1, 2, 3");
}

// --- BLS12-381: soroban-env-host's own CAP-75 conformance vectors (see
// fixtures/poseidon/bls12_381.json and this crate's module doc for what this table does
// and does not claim compatibility with) ---

#[test]
fn bls12_381_hash_n_fixture_0() {
    let env = Env::default();
    let mut inputs: Vec<U256> = Vec::new(&env);
    inputs.push_back(u32_input(&env, 1));
    let got = Poseidon::hash_n(&env, Curve::Bls12_381, &inputs).unwrap();
    let expected = hex_to_u256(&env, "1dc37ce34aeee058292bb73bff9acffce73a8a92f3d6d1daa8b77d9516b5c837");
    assert_eq!(got, expected, "inputs: 1");
}

#[test]
fn bls12_381_hash2_fixture_1() {
    let env = Env::default();
    let left = u32_input(&env, 1);
    let right = u32_input(&env, 2);
    let got = Poseidon::hash2(&env, Curve::Bls12_381, &left, &right).unwrap();
    let expected = hex_to_u256(&env, "200e6982ac00df8fa65cef1fde9f21373fdbbfd98f2df1eb5fa04f3302ab0397");
    assert_eq!(got, expected, "inputs: 1, 2");
}

#[test]
fn bls12_381_hash2_fixture_2() {
    let env = Env::default();
    let left = u32_input(&env, 0);
    let right = u32_input(&env, 0);
    let got = Poseidon::hash2(&env, Curve::Bls12_381, &left, &right).unwrap();
    let expected = hex_to_u256(&env, "60351d345576275c676667b0b05fe317ac89f7f5d827b4c94f137be8f65fb2e9");
    assert_eq!(got, expected, "inputs: 0, 0");
}

#[test]
fn bls12_381_hash_n_fixture_3() {
    let env = Env::default();
    let mut inputs: Vec<U256> = Vec::new(&env);
    inputs.push_back(u32_input(&env, 1));
    inputs.push_back(u32_input(&env, 2));
    inputs.push_back(u32_input(&env, 3));
    let got = Poseidon::hash_n(&env, Curve::Bls12_381, &inputs).unwrap();
    let expected = hex_to_u256(&env, "3ee96c25cccd2d4ce9423040834a34e61fccbd98d1820ee60d31098867511dc3");
    assert_eq!(got, expected, "inputs: 1, 2, 3");
}

// --- Negative / error-path tests (not fixture-derived; exercise this crate's own logic) ---

#[test]
fn hash2_is_order_sensitive() {
    let env = Env::default();
    let a = u32_input(&env, 1);
    let b = u32_input(&env, 2);
    let ab = Poseidon::hash2(&env, Curve::Bn254, &a, &b).unwrap();
    let ba = Poseidon::hash2(&env, Curve::Bn254, &b, &a).unwrap();
    assert_ne!(ab, ba, "hash2(a,b) must not equal hash2(b,a) -- Merkle tree soundness depends on left/right order mattering");
}

#[test]
fn hash_n_rejects_zero_inputs() {
    let env = Env::default();
    let inputs: Vec<U256> = Vec::new(&env);
    let err = Poseidon::hash_n(&env, Curve::Bn254, &inputs).unwrap_err();
    assert_eq!(err, PoseidonError::InvalidInputCount);
}

#[test]
fn hash_n_rejects_unsupported_arity() {
    let env = Env::default();
    let mut inputs: Vec<U256> = Vec::new(&env);
    for i in 0..10u32 {
        inputs.push_back(u32_input(&env, i));
    }
    let err = Poseidon::hash_n(&env, Curve::Bn254, &inputs).unwrap_err();
    assert_eq!(err, PoseidonError::UnsupportedArity);
}

#[test]
fn hash2_rejects_out_of_range_scalar() {
    let env = Env::default();
    // BN254 field modulus itself is out of range (valid range is [0, modulus)).
    let out_of_range = hex_to_u256(&env, "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    let one = u32_input(&env, 1);
    let err = Poseidon::hash2(&env, Curve::Bn254, &out_of_range, &one).unwrap_err();
    assert_eq!(err, PoseidonError::ScalarOutOfRange);
}

#[test]
fn different_curves_are_not_verified_against_each_others_params() {
    // Same numeric inputs, different curve -> different (and independently verified) params
    // -> different output. Not a fixture value, just a sanity check that curve dispatch
    // actually changes which table is used.
    let env = Env::default();
    let a = u32_input(&env, 1);
    let b = u32_input(&env, 2);
    let bn = Poseidon::hash2(&env, Curve::Bn254, &a, &b).unwrap();
    let bls = Poseidon::hash2(&env, Curve::Bls12_381, &a, &b).unwrap();
    assert_ne!(bn, bls);
}

// --- Budget probe (informational; see docs/BUDGET.md for the recorded measurement) ---

#[test]
fn budget_probe_hash2_bn254() {
    let env = Env::default();
    #[allow(deprecated)]
    let mut budget = env.budget();
    budget.reset_unlimited();
    let a = u32_input(&env, 1);
    let b = u32_input(&env, 2);
    let _ = Poseidon::hash2(&env, Curve::Bn254, &a, &b).unwrap();
    std::println!("hash2(BN254) cpu_instruction_cost = {}", budget.cpu_instruction_cost());
}
