//! snarkjs JSON -> `VerificationKey` / `Proof` / public signals (feature `snarkjs`).
//!
//! Off-chain and test-time only: it needs `std` and `serde_json`, so it is behind a feature
//! and never compiled into a contract wasm. It applies every rule in `docs/ENCODING.md`:
//!
//! - decimal strings -> fixed-width big-endian field elements (32 bytes BN254, 48 BLS12-381)
//! - G1 `[x, y, "1"]` -> `x || y` (the projective `z` must be `"1"`)
//! - G2 `[[x_c0, x_c1], [y_c0, y_c1], ["1", "0"]]` -> `x_c1 || x_c0 || y_c1 || y_c0`
//!
//! The G2 limb order is not a guess: `occulta-verifier`'s fixture tests verify a real
//! snarkjs proof with this order and show the snarkjs-native order does not verify. See
//! `docs/ENCODING.md` rule 3 for the evidence.

extern crate std;

use std::string::{String, ToString};
use std::vec::Vec as StdVec;

use serde_json::Value;
use soroban_sdk::{Bytes, Env, Vec, U256};

use crate::{swap_fp2_limbs, Curve, Proof, VerificationKey};

/// Why a snarkjs JSON document could not be converted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnarkjsError {
    /// Not valid JSON, or a required field is missing / has the wrong JSON type.
    Json(String),
    /// `curve` / `protocol` is not something this crate supports.
    Unsupported(String),
    /// A decimal field element was malformed or too large for the curve's field width.
    BadFieldElement(String),
    /// A point was not in normalised projective form (`z != 1`).
    NotAffine,
}

fn field_width(curve: Curve) -> usize {
    match curve {
        Curve::Bn254 => 32,
        Curve::Bls12_381 => 48,
    }
}

/// Parses snarkjs's `curve` string (`"bn128"` or `"bls12381"`).
pub fn curve_from_name(name: &str) -> Result<Curve, SnarkjsError> {
    match name {
        "bn128" | "bn254" => Ok(Curve::Bn254),
        "bls12381" | "bls12_381" => Ok(Curve::Bls12_381),
        other => Err(SnarkjsError::Unsupported(other.to_string())),
    }
}

/// Decimal string -> `width`-byte big-endian integer. Rejects anything that doesn't fit.
pub fn decimal_to_be(s: &str, width: usize) -> Result<StdVec<u8>, SnarkjsError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SnarkjsError::BadFieldElement(s.to_string()));
    }
    let mut out = std::vec![0u8; width];
    for digit in s.bytes().map(|b| (b - b'0') as u32) {
        // out = out * 10 + digit
        let mut carry = digit;
        for byte in out.iter_mut().rev() {
            let v = (*byte as u32) * 10 + carry;
            *byte = v as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err(SnarkjsError::BadFieldElement(s.to_string()));
        }
    }
    Ok(out)
}

fn as_str(v: &Value) -> Result<&str, SnarkjsError> {
    v.as_str()
        .ok_or_else(|| SnarkjsError::Json(std::format!("expected string, got {v}")))
}

fn as_array(v: &Value) -> Result<&[Value], SnarkjsError> {
    v.as_array()
        .map(|a| a.as_slice())
        .ok_or_else(|| SnarkjsError::Json(std::format!("expected array, got {v}")))
}

fn field(obj: &Value, key: &str) -> Result<Value, SnarkjsError> {
    obj.get(key)
        .cloned()
        .ok_or_else(|| SnarkjsError::Json(std::format!("missing field `{key}`")))
}

/// snarkjs G1 `[x, y, "1"]` -> `x || y`.
fn g1(env: &Env, curve: Curve, v: &Value) -> Result<Bytes, SnarkjsError> {
    let p = as_array(v)?;
    if p.len() != 3 || as_str(&p[2])? != "1" {
        return Err(SnarkjsError::NotAffine);
    }
    let w = field_width(curve);
    let mut out = decimal_to_be(as_str(&p[0])?, w)?;
    out.extend(decimal_to_be(as_str(&p[1])?, w)?);
    Ok(Bytes::from_slice(env, &out))
}

/// snarkjs G2 `[[x_c0, x_c1], [y_c0, y_c1], ["1", "0"]]` -> `x_c1 || x_c0 || y_c1 || y_c0`.
fn g2(env: &Env, curve: Curve, v: &Value) -> Result<Bytes, SnarkjsError> {
    let p = as_array(v)?;
    if p.len() != 3 {
        return Err(SnarkjsError::NotAffine);
    }
    let z = as_array(&p[2])?;
    if z.len() != 2 || as_str(&z[0])? != "1" || as_str(&z[1])? != "0" {
        return Err(SnarkjsError::NotAffine);
    }
    let w = field_width(curve);
    let mut out = StdVec::with_capacity(4 * w);
    for coord in &p[..2] {
        let limbs = as_array(coord)?;
        if limbs.len() != 2 {
            return Err(SnarkjsError::Json(std::format!(
                "Fp2 must have 2 limbs: {coord}"
            )));
        }
        // snarkjs order: c0 || c1. The host wants c1 || c0.
        let mut snarkjs_order = decimal_to_be(as_str(&limbs[0])?, w)?;
        snarkjs_order.extend(decimal_to_be(as_str(&limbs[1])?, w)?);
        let mut host_order = std::vec![0u8; 2 * w];
        swap_fp2_limbs(&snarkjs_order, w, &mut host_order);
        out.extend(host_order);
    }
    Ok(Bytes::from_slice(env, &out))
}

fn parse(json: &str) -> Result<Value, SnarkjsError> {
    serde_json::from_str(json).map_err(|e| SnarkjsError::Json(e.to_string()))
}

fn groth16_curve(doc: &Value) -> Result<Curve, SnarkjsError> {
    let protocol = as_str(&field(doc, "protocol")?)?.to_string();
    if protocol != "groth16" {
        return Err(SnarkjsError::Unsupported(protocol));
    }
    curve_from_name(as_str(&field(doc, "curve")?)?)
}

/// `snarkjs zkey export verificationkey` output -> `VerificationKey`.
pub fn vk_from_json(env: &Env, json: &str) -> Result<VerificationKey, SnarkjsError> {
    let doc = parse(json)?;
    let curve = groth16_curve(&doc)?;
    let mut ic = Vec::new(env);
    for point in as_array(&field(&doc, "IC")?)? {
        ic.push_back(g1(env, curve, point)?);
    }
    Ok(VerificationKey {
        curve,
        alpha_g1: g1(env, curve, &field(&doc, "vk_alpha_1")?)?,
        beta_g2: g2(env, curve, &field(&doc, "vk_beta_2")?)?,
        gamma_g2: g2(env, curve, &field(&doc, "vk_gamma_2")?)?,
        delta_g2: g2(env, curve, &field(&doc, "vk_delta_2")?)?,
        ic,
    })
}

/// `snarkjs groth16 prove` `proof.json` -> `Proof`.
pub fn proof_from_json(env: &Env, json: &str) -> Result<Proof, SnarkjsError> {
    let doc = parse(json)?;
    let curve = groth16_curve(&doc)?;
    Ok(Proof {
        curve,
        a: g1(env, curve, &field(&doc, "pi_a")?)?,
        b: g2(env, curve, &field(&doc, "pi_b")?)?,
        c: g1(env, curve, &field(&doc, "pi_c")?)?,
    })
}

/// `snarkjs groth16 prove` `public.json` (array of decimal strings) -> `Vec<U256>`.
pub fn public_signals_from_json(env: &Env, json: &str) -> Result<Vec<U256>, SnarkjsError> {
    let doc = parse(json)?;
    let mut out = Vec::new(env);
    for s in as_array(&doc)? {
        let be = decimal_to_be(as_str(s)?, 32)?;
        out.push_back(U256::from_be_bytes(env, &Bytes::from_slice(env, &be)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_to_be_small_values() {
        assert_eq!(decimal_to_be("0", 4).unwrap(), [0, 0, 0, 0]);
        assert_eq!(decimal_to_be("42", 4).unwrap(), [0, 0, 0, 42]);
        assert_eq!(decimal_to_be("65536", 4).unwrap(), [0, 1, 0, 0]);
    }

    #[test]
    fn decimal_to_be_matches_bn254_fr_modulus() {
        let r = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
        assert_eq!(
            decimal_to_be(r, 32).unwrap(),
            crate::curve::BN254_FR_MODULUS_BE
        );
    }

    #[test]
    fn decimal_to_be_rejects_overflow_and_garbage() {
        assert!(decimal_to_be("4294967296", 4).is_err()); // 2^32 does not fit in 4 bytes
        assert!(decimal_to_be("12a", 4).is_err());
        assert!(decimal_to_be("", 4).is_err());
        assert!(decimal_to_be("-1", 4).is_err());
    }

    #[test]
    fn g2_is_emitted_c1_first() {
        let env = Env::default();
        let v: Value = serde_json::from_str(r#"[["1","2"],["3","4"],["1","0"]]"#).unwrap();
        let b = g2(&env, Curve::Bn254, &v).unwrap();
        let mut expected = [0u8; 128];
        expected[31] = 2; // x_c1
        expected[63] = 1; // x_c0
        expected[95] = 4; // y_c1
        expected[127] = 3; // y_c0
        assert_eq!(b, Bytes::from_array(&env, &expected));
    }

    #[test]
    fn non_normalised_points_are_rejected() {
        let env = Env::default();
        let v: Value = serde_json::from_str(r#"["1","2","3"]"#).unwrap();
        assert_eq!(g1(&env, Curve::Bn254, &v), Err(SnarkjsError::NotAffine));
    }

    #[test]
    fn non_groth16_vkey_is_rejected() {
        let env = Env::default();
        let json = r#"{"protocol":"plonk","curve":"bn128"}"#;
        assert!(matches!(
            vk_from_json(&env, json),
            Err(SnarkjsError::Unsupported(_))
        ));
    }
}
