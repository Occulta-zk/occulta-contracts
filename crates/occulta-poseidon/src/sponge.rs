//! The sponge construction CAP-75 deliberately leaves to guest code (see `docs/PLATFORM.md`
//! quoting the host's own doc comment: "The sponge construction is a simple state machine
//! that can be efficiently implemented in the SDK guest code").
//!
//! Convention used here — chosen to match circomlib's own `poseidon_reference.js` (the exact
//! algorithm read and replicated in `scripts/poseidon-gen/gen.mjs`, see that file): for `n`
//! inputs, `t = n + 1`, the permutation's initial state is `[0, input_0, ..., input_{n-1}]`
//! (a single zero "capacity" element prepended, no domain separation tag), and the output is
//! `state[0]` after the permutation. This is a one-shot construction, not an iterated sponge
//! with multiple absorb/squeeze rounds — matching circomlib's own Poseidon (non-2), which
//! only ever calls the permutation once per hash. It is NOT validated against a per-field
//! multi-block sponge standard; if a circuit needs one, it isn't this.

use occulta_types::{scalar_in_range, Curve};
use soroban_sdk::Env;
use soroban_sdk::{Symbol, Vec, U256};

use crate::{error::PoseidonError, params};

fn field_symbol(env: &Env, curve: Curve) -> Symbol {
    match curve {
        Curve::Bls12_381 => Symbol::new(env, "BLS12_381"),
        Curve::Bn254 => Symbol::new(env, "BN254"),
    }
}

fn u256_to_be_bytes(v: &U256) -> [u8; 32] {
    let bytes = v.to_be_bytes();
    let mut arr = [0u8; 32];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = bytes.get_unchecked(i as u32);
    }
    arr
}

fn check_range(curve: Curve, inputs: &Vec<U256>) -> Result<(), PoseidonError> {
    let modulus = curve.fr_modulus_be();
    for input in inputs.iter() {
        let arr = u256_to_be_bytes(&input);
        if !scalar_in_range(&arr, modulus) {
            return Err(PoseidonError::ScalarOutOfRange);
        }
    }
    Ok(())
}

/// Sponge over `1..=3` inputs (the range this milestone has a verified parameter table for —
/// see `params::lookup`). `t = inputs.len() + 1` selects the parameter set.
pub fn hash_n(env: &Env, curve: Curve, inputs: &Vec<U256>) -> Result<U256, PoseidonError> {
    let n = inputs.len();
    if n == 0 {
        return Err(PoseidonError::InvalidInputCount);
    }
    let t = n + 1;
    let param_set = params::lookup(curve, t).ok_or(PoseidonError::UnsupportedArity)?;

    check_range(curve, inputs)?;

    let mut state: Vec<U256> = Vec::new(env);
    state.push_back(U256::from_u32(env, 0));
    for input in inputs.iter() {
        state.push_back(input);
    }

    let mds = param_set.mds_vec(env);
    let round_constants = param_set.round_constants_vec(env);
    let symbol = field_symbol(env, curve);

    let out = env.crypto_hazmat().poseidon_permutation(
        &state,
        symbol,
        param_set.t,
        param_set.d,
        param_set.rounds_f,
        param_set.rounds_p,
        &mds,
        &round_constants,
    );
    Ok(out.get_unchecked(0))
}

/// 2-to-1 compression — the Merkle node hash (`t = 3`). Hot path for `occulta-merkle::insert`
/// (M4) — see `docs/BUDGET.md` for measured cost once that lands.
pub fn hash2(env: &Env, curve: Curve, left: &U256, right: &U256) -> Result<U256, PoseidonError> {
    let mut inputs: Vec<U256> = Vec::new(env);
    inputs.push_back(left.clone());
    inputs.push_back(right.clone());
    hash_n(env, curve, &inputs)
}

/// Escape hatch: call the raw host permutation with explicit, caller-supplied parameters —
/// for circuits using parameter sets outside this crate's verified table. **Callers are
/// responsible for the differential-testing rule this crate itself follows for its own
/// table**: an unverified parameter set here is exactly the "demo of a bug" the build spec
/// warns against. No range-checking is performed here (the caller's parameter set may not
/// even be over one of `occulta_types::Curve`'s two fields) — this function is a thin,
/// unopinionated wrapper over the host call, nothing more.
#[allow(clippy::too_many_arguments)]
pub fn permute_raw(
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
    env.crypto_hazmat().poseidon_permutation(
        state,
        field,
        t,
        d,
        rounds_f,
        rounds_p,
        mds,
        round_constants,
    )
}
