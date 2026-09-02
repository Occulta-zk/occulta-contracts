//! Turns CAP-75's raw `poseidon_permutation` host function (gated behind soroban-sdk's
//! `hazmat-crypto` feature, accessed via `env.crypto_hazmat()` — see `docs/PLATFORM.md`) into
//! a usable hash: a verified parameter table (`params`) plus a one-shot sponge construction
//! (`sponge`) matching circomlib's own convention for BN254, and matching the Soroban host's
//! own CAP-75 conformance vectors for BLS12-381 (which has no native circomlib parameters to
//! match — see `docs/PLATFORM.md`).
//!
//! **Coverage as of this milestone**: BN254 and BLS12-381, `t ∈ {2, 3, 4}` (1–3 inputs).
//! `hash2` (2 inputs, `t=3`) is fully covered on both curves — the Merkle-tree critical path.
//! Wider coverage (more inputs, or Poseidon2) is a mechanical `scripts/poseidon-gen/` re-run,
//! not a design change; see that directory's README.
//!
//! Every constant in `params_bn254.rs`/`params_bls12.rs` was generated, not hand-typed — see
//! `scripts/poseidon-gen/README.md` for exact provenance, and `fixtures/poseidon/` plus this
//! crate's own tests for the differential checks against those sources.
#![no_std]

mod error;
mod params;
mod params_bls12;
mod params_bn254;
mod sponge;

pub use error::PoseidonError;
pub use params::lookup as lookup_params;

use occulta_types::Curve;
use soroban_sdk::{Env, Symbol, Vec, U256};

pub struct Poseidon;

impl Poseidon {
    /// 2-to-1 compression — the Merkle node hash. `t = 3` (arity 2 + one capacity element).
    pub fn hash2(
        env: &Env,
        curve: Curve,
        left: &U256,
        right: &U256,
    ) -> Result<U256, PoseidonError> {
        sponge::hash2(env, curve, left, right)
    }

    /// Sponge over `1..=3` inputs — see this crate's module doc for why the upper bound is 3
    /// rather than the originally-scoped 16, and how to widen it.
    pub fn hash_n(env: &Env, curve: Curve, inputs: &Vec<U256>) -> Result<U256, PoseidonError> {
        sponge::hash_n(env, curve, inputs)
    }

    /// Escape hatch: raw permutation with explicit, caller-supplied parameters, for circuits
    /// using non-standard parameter sets. See `sponge::permute_raw`'s doc comment — no
    /// differential testing is performed on the caller's behalf here.
    #[allow(clippy::too_many_arguments)]
    pub fn permute(
        env: &Env,
        field: Symbol,
        t: u32,
        d: u32,
        rounds_f: u32,
        rounds_p: u32,
        mds: &Vec<Vec<U256>>,
        round_constants: &Vec<Vec<U256>>,
        state: &Vec<U256>,
    ) -> Vec<U256> {
        sponge::permute_raw(
            env,
            field,
            t,
            d,
            rounds_f,
            rounds_p,
            mds,
            round_constants,
            state,
        )
    }
}

#[cfg(test)]
mod tests;
