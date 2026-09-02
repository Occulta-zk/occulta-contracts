use soroban_sdk::contracterror;

/// Errors raised while decoding/validating a `Proof` or `VerificationKey`.
///
/// Kept separate from `occulta-verifier::VerifierError` (which additionally covers
/// pairing-check failure modes) so that a pure encoding failure is distinguishable from a
/// cryptographic verification failure by any caller matching on error codes.
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum TypesError {
    /// A G1/G2 byte string's length didn't match what `curve` requires.
    WrongPointLength = 1,
    /// A scalar (Fr element) was >= the field modulus.
    ScalarOutOfRange = 2,
    /// `VerificationKey.ic` was empty — every VK needs at least `ic[0]` (the constant term).
    EmptyIc = 3,
}
