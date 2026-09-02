use soroban_sdk::contracterror;

#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PoseidonError {
    /// No verified parameter set exists for this `(curve, t)` — see `params::lookup`'s doc
    /// comment for exactly which `t` values are covered as of this milestone.
    UnsupportedArity = 1,
    /// `hash_n` was called with zero inputs, or more inputs than any verified parameter set
    /// supports (currently up to 3 — `t=4` is the largest verified table entry).
    InvalidInputCount = 2,
    /// An input scalar was `>=` the curve's field modulus — see
    /// `occulta_types::scalar_in_range` and Security Invariant #8.
    ScalarOutOfRange = 3,
}
