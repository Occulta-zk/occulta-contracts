use soroban_sdk::contracterror;

/// Errors returned by `occulta_verifier::verify`.
///
/// These are distinct from `occulta_types::TypesError` (pure encoding errors) — a caller
/// matching error codes can distinguish "the proof bytes were the wrong length" from "the
/// pairing check was called but the proof count didn't match the VK".
#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifierError {
    /// A point's byte length was wrong, a G2 point byte length was wrong, `ic` was empty, or
    /// the `proof.curve` != `vk.curve`.
    MalformedVerificationKey = 1,
    /// `public_signals.len() + 1 != vk.ic.len()` — Security Invariant #5.
    ///
    /// This mismatch means the caller is verifying a proof against the wrong circuit's VK.
    /// It is a hard error, not a false result, because silently returning false could mask
    /// a circuit-swap attack.
    PublicSignalCountMismatch = 2,
    /// A public signal scalar was >= the field modulus — Security Invariant #8.
    ScalarOutOfRange = 3,
    /// A G1/G2 point was not on the curve, or was not in the correct subgroup. Only raised
    /// when explicit subgroup checks are needed (see `docs/PLATFORM.md` — the host traps on
    /// genuinely off-curve bytes, so this variant fires on subgroup-membership failures
    /// detected via `is_in_subgroup()`, not on malformed byte lengths).
    InvalidPoint = 4,
    /// The `vk.curve` field is a variant this verifier doesn't recognise. Should not occur
    /// in practice — kept for forward-compatibility if new curve variants are added.
    UnsupportedCurve = 5,
}
