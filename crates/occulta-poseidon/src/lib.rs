//! **NOT YET IMPLEMENTED — scaffold only, milestone M2.**
//!
//! This crate will turn CAP-75's raw `poseidon_permutation`/`poseidon2_permutation` host
//! functions (gated behind soroban-sdk's `hazmat-crypto` feature — see `docs/PLATFORM.md`)
//! into a circomlib-compatible sponge hash. It intentionally ships no hashing logic yet:
//! per the build spec's operating rules, no cryptographic primitive is merged without a
//! differential fixture proving byte-identical output against circomlib, and those fixtures
//! (`fixtures/poseidon/`) have not been generated in this session — that requires either
//! installing `circom` or vendoring circomlib's `poseidon_constants.circom` (cited by source
//! file + commit hash, not hand-transcribed) plus the round-constant/MDS matrices the host
//! function requires as explicit call parameters (see the "Poseidon parameters are caller-
//! supplied, not host-embedded" finding in `docs/PLATFORM.md`).
//!
//! `docs/PLATFORM.md` records a live decision point that must be resolved before writing
//! real code here: whether to depend on SDF's own `soroban-poseidon` crate
//! (`stellar/rs-soroban-poseidon`) for its parameter tables rather than re-deriving them.
#![no_std]

/// Placeholder so this crate compiles and participates in `cargo test --workspace` before
/// M2 lands. Deliberately not part of the public API surface described in the build spec.
#[doc(hidden)]
pub const _NOT_YET_IMPLEMENTED: &str = "occulta-poseidon: see module docs, milestone M2";
