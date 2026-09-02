// Generates crates/occulta-poseidon/src/tests.rs from the committed fixture JSON files.
// Mechanical generation, on purpose: hand-typing 64-hex-char fixture values into a Rust test
// file is exactly the kind of transcription-error surface this whole repo is trying to
// avoid (and this script exists because a hand-typed draft attempt in this session had
// exactly that kind of bug, caught before it was ever committed).
import fs from "node:fs";

const bn = JSON.parse(fs.readFileSync("../../fixtures/poseidon/bn254.json", "utf8"));
const bls = JSON.parse(fs.readFileSync("../../fixtures/poseidon/bls12_381.json", "utf8"));

// Computed, not hand-typed: BN254 Fr modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
let bn254ModulusHex = BN254_R.toString(16);
while (bn254ModulusHex.length < 64) bn254ModulusHex = "0" + bn254ModulusHex;

function assertHex64(h) {
  const hex = h.startsWith("0x") ? h.slice(2) : h;
  if (hex.length !== 64) throw new Error(`expected 64 hex chars, got ${hex.length}: ${h}`);
  return hex;
}

function inputExpr(envVar, decimalStr) {
  // Small literal inputs (fits u32) use U256::from_u32; the one large (r-1) fixture input
  // is emitted as an explicit big-endian byte literal instead of parsed from decimal at
  // runtime (no bignum-from-decimal parser is worth pulling in for one test constant).
  const n = BigInt(decimalStr);
  if (n < 0x100000000n) {
    return `u32_input(&${envVar}, ${n.toString()})`;
  }
  let hex = n.toString(16);
  while (hex.length < 64) hex = "0" + hex;
  return `hex_to_u256(&${envVar}, "${hex}")`;
}

let out = `//! Differential tests: these values are not invented here -- every one is copied
//! mechanically (via scripts/poseidon-gen/gen_tests.mjs, GENERATED FILE, do not hand-edit
//! this file) from \`fixtures/poseidon/{bn254,bls12_381}.json\`, which were themselves
//! computed by \`scripts/poseidon-gen/\` (see that directory's README for exact provenance:
//! real \`circomlibjs\` for BN254, \`soroban-env-host\`'s own conformance vectors for
//! BLS12-381). Each test here calls the REAL host implementation through \`soroban-sdk\`'s
//! \`Env\` (which wraps the actual \`soroban-env-host\` under \`testutils\` -- not a mock) and
//! asserts the result matches the independently-computed fixture. This is the actual
//! "differential test against a reference implementation" \`CONTRIBUTING.md\` requires, not
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
`;

bn.hash2.forEach((v, i) => {
  const hex = assertHex64(v.output);
  out += `
#[test]
fn bn254_hash2_fixture_${i}() {
    let env = Env::default();
    let left = ${inputExpr("env", v.inputs[0])};
    let right = ${inputExpr("env", v.inputs[1])};
    let got = Poseidon::hash2(&env, Curve::Bn254, &left, &right).unwrap();
    let expected = hex_to_u256(&env, "${hex}");
    assert_eq!(got, expected, "inputs: ${v.inputs.join(", ")}");
}
`;
});

bn.hash_n.forEach((v, i) => {
  const hex = assertHex64(v.output);
  out += `
#[test]
fn bn254_hash_n_fixture_${i}() {
    let env = Env::default();
    let mut inputs: Vec<U256> = Vec::new(&env);
${v.inputs.map((inp) => `    inputs.push_back(${inputExpr("env", inp)});`).join("\n")}
    let got = Poseidon::hash_n(&env, Curve::Bn254, &inputs).unwrap();
    let expected = hex_to_u256(&env, "${hex}");
    assert_eq!(got, expected, "inputs: ${v.inputs.join(", ")}");
}
`;
});

out += `
// --- BLS12-381: soroban-env-host's own CAP-75 conformance vectors (see
// fixtures/poseidon/bls12_381.json and this crate's module doc for what this table does
// and does not claim compatibility with) ---
`;

const tToFn = { t2: "hash_n_1", t3: "hash2_or_hash_n_2", t4: "hash_n_3" };
let blsIdx = 0;
for (const tKey of Object.keys(bls)) {
  for (const v of bls[tKey]) {
    const hex = assertHex64(v.output);
    if (v.inputs.length === 2) {
      out += `
#[test]
fn bls12_381_hash2_fixture_${blsIdx}() {
    let env = Env::default();
    let left = ${inputExpr("env", v.inputs[0])};
    let right = ${inputExpr("env", v.inputs[1])};
    let got = Poseidon::hash2(&env, Curve::Bls12_381, &left, &right).unwrap();
    let expected = hex_to_u256(&env, "${hex}");
    assert_eq!(got, expected, "inputs: ${v.inputs.join(", ")}");
}
`;
    } else {
      out += `
#[test]
fn bls12_381_hash_n_fixture_${blsIdx}() {
    let env = Env::default();
    let mut inputs: Vec<U256> = Vec::new(&env);
${v.inputs.map((inp) => `    inputs.push_back(${inputExpr("env", inp)});`).join("\n")}
    let got = Poseidon::hash_n(&env, Curve::Bls12_381, &inputs).unwrap();
    let expected = hex_to_u256(&env, "${hex}");
    assert_eq!(got, expected, "inputs: ${v.inputs.join(", ")}");
}
`;
    }
    blsIdx++;
  }
}

out += `
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
    let out_of_range = hex_to_u256(&env, "${bn254ModulusHex}");
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
`;

fs.writeFileSync("../../crates/occulta-poseidon/src/tests.rs", out);
console.log("wrote crates/occulta-poseidon/src/tests.rs");
