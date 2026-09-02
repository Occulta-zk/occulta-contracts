//! Verified parameter table lookup: `(Curve, t)` -> the exact `d`/`rounds_f`/`rounds_p` plus
//! MDS matrix and round-constant matrix the CAP-75 host function requires as explicit call
//! parameters (see `docs/PLATFORM.md`'s "Poseidon parameters are caller-supplied, not
//! host-embedded" finding). Every byte in `params_bn254.rs`/`params_bls12.rs` was produced by
//! `scripts/poseidon-gen/` — extracted or computed mechanically, never hand-typed — see that
//! directory's README and the module docs on `params_bn254`/`params_bls12` for exact
//! provenance and citations.

use occulta_types::Curve;
use soroban_sdk::{Bytes, Env, Vec, U256};

use crate::{params_bls12, params_bn254};

/// One verified `(curve, t)` parameter set, in raw byte form (converted to `U256`/`Vec` only
/// when actually used, so looking a set up costs nothing until you call `permute`/`hash2`).
pub struct ParamSet {
    pub t: u32,
    pub d: u32,
    pub rounds_f: u32,
    pub rounds_p: u32,
    mds: &'static [[u8; 32]],
    round_constants: &'static [[u8; 32]],
}

impl ParamSet {
    pub(crate) fn mds_vec(&self, env: &Env) -> Vec<Vec<U256>> {
        bytes_rows_to_vec(env, self.mds, self.t as usize)
    }

    pub(crate) fn round_constants_vec(&self, env: &Env) -> Vec<Vec<U256>> {
        // `round_constants` is sized to exactly `(rounds_f + rounds_p) * t` entries at
        // codegen time (see scripts/poseidon-gen) — no truncation needed here.
        bytes_rows_to_vec(env, self.round_constants, self.t as usize)
    }
}

fn bytes_rows_to_vec(env: &Env, flat: &[[u8; 32]], width: usize) -> Vec<Vec<U256>> {
    let mut rows: Vec<Vec<U256>> = Vec::new(env);
    let mut i = 0;
    while i < flat.len() {
        let mut row: Vec<U256> = Vec::new(env);
        for j in 0..width {
            let b = Bytes::from_array(env, &flat[i + j]);
            row.push_back(U256::from_be_bytes(env, &b));
        }
        rows.push_back(row);
        i += width;
    }
    rows
}

/// Look up the verified parameter set for `(curve, t)`. Returns `None` for any `t` this
/// milestone hasn't shipped a verified table for (see `docs/PLATFORM.md` — currently
/// BN254 t∈{2,3,4} against real circomlib constants, BLS12-381 t∈{2,3,4} against
/// soroban-env-host's own CAP-75 conformance vectors). Widening this is a mechanical
/// `scripts/poseidon-gen/` re-run, not a design change — see that directory's README.
pub fn lookup(curve: Curve, t: u32) -> Option<ParamSet> {
    match (curve, t) {
        (Curve::Bn254, 2) => Some(ParamSet {
            t: 2,
            d: 5,
            rounds_f: params_bn254::BN254_T2_ROUNDS_F,
            rounds_p: params_bn254::BN254_T2_ROUNDS_P,
            mds: &params_bn254::BN254_T2_MDS,
            round_constants: &params_bn254::BN254_T2_RC,
        }),
        (Curve::Bn254, 3) => Some(ParamSet {
            t: 3,
            d: 5,
            rounds_f: params_bn254::BN254_T3_ROUNDS_F,
            rounds_p: params_bn254::BN254_T3_ROUNDS_P,
            mds: &params_bn254::BN254_T3_MDS,
            round_constants: &params_bn254::BN254_T3_RC,
        }),
        (Curve::Bn254, 4) => Some(ParamSet {
            t: 4,
            d: 5,
            rounds_f: params_bn254::BN254_T4_ROUNDS_F,
            rounds_p: params_bn254::BN254_T4_ROUNDS_P,
            mds: &params_bn254::BN254_T4_MDS,
            round_constants: &params_bn254::BN254_T4_RC,
        }),
        (Curve::Bls12_381, 2) => Some(ParamSet {
            t: 2,
            d: 5,
            rounds_f: params_bls12::BLS12_381_T2_ROUNDS_F,
            rounds_p: params_bls12::BLS12_381_T2_ROUNDS_P,
            mds: &params_bls12::BLS12_381_T2_MDS,
            round_constants: &params_bls12::BLS12_381_T2_RC,
        }),
        (Curve::Bls12_381, 3) => Some(ParamSet {
            t: 3,
            d: 5,
            rounds_f: params_bls12::BLS12_381_T3_ROUNDS_F,
            rounds_p: params_bls12::BLS12_381_T3_ROUNDS_P,
            mds: &params_bls12::BLS12_381_T3_MDS,
            round_constants: &params_bls12::BLS12_381_T3_RC,
        }),
        (Curve::Bls12_381, 4) => Some(ParamSet {
            t: 4,
            d: 5,
            rounds_f: params_bls12::BLS12_381_T4_ROUNDS_F,
            rounds_p: params_bls12::BLS12_381_T4_ROUNDS_P,
            mds: &params_bls12::BLS12_381_T4_MDS,
            round_constants: &params_bls12::BLS12_381_T4_RC,
        }),
        _ => None,
    }
}
