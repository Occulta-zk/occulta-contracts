//! Groth16 verification over BLS12-381.
//!
//! SDK bindings used (all verified against `soroban-sdk 26.1.1` — see `docs/PLATFORM.md`):
//! - `env.crypto().bls12_381()` → `Bls12_381`
//! - `bls12_381.g1_msm(points, scalars)` — multi-scalar multiplication for `vk_x`
//! - `bls12_381.g1_is_in_subgroup(p)` — explicit subgroup check for externally-supplied points
//! - `bls12_381.pairing_check(g1_vec, g2_vec)` — single call for all four pairs
//!
//! G1 point encoding: `BytesN<96>`, `be(X) || be(Y)`, each 48 bytes.
//! G2 point encoding: `BytesN<192>`, `be(X_c1) || be(X_c0) || be(Y_c1) || be(Y_c0)`.
//! Note: c1 before c0 — opposite of snarkjs JSON order. See `docs/ENCODING.md` rule 3.
//!
//! Negation of A: `A_neg = (x, p - y)` where `p` is the BLS12-381 base field prime (Fp, not Fr).
//! Infinity edge case: if `y == 0` the point is infinity and negation is identity — but a valid
//! Groth16 proof `A` should never be infinity, so we treat `y == 0` as invalid and error out
//! to catch encoding bugs early.

use occulta_types::{is_zero_bytes, Proof, VerificationKey};
use soroban_sdk::{Bytes, BytesN, Env, Vec, U256};

use crate::VerifierError;

/// BLS12-381 base field prime `p` (Fp, 48 bytes, big-endian).
///
/// p = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
/// Source: https://github.com/zcash/librustzcash/blob/main/pairing/src/bls12_381/README.md
/// and cross-checked with the `ark-bls12-381` crate constant `Fq::MODULUS`.
const BLS12_381_FP_MODULUS_BE: [u8; 48] = [
    0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
    0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
    0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
];

/// Negate a BLS12-381 G1 affine point by flipping its Y coordinate: `(x, y) → (x, p - y)`.
///
/// An uncompressed affine G1 point is 96 bytes: `[x: 48 bytes][y: 48 bytes]`.
/// Returns `Err(InvalidPoint)` if `y == 0` (the point is at infinity or malformed — a valid
/// Groth16 proof `A` should never be infinity; callers relying on negation of an infinity
/// point should not reach this function).
fn negate_g1(env: &Env, point_bytes: &Bytes) -> Result<BytesN<96>, VerifierError> {
    // Split into x (bytes 0..48) and y (bytes 48..96).
    let x = point_bytes.slice(0..48);
    let y = point_bytes.slice(48..96);

    // Collect y into a fixed array for arithmetic.
    let mut y_arr = [0u8; 48];
    for i in 0..48u32 {
        y_arr[i as usize] = y.get_unchecked(i);
    }

    if is_zero_bytes(&y_arr) {
        // y == 0 means the point is at infinity (or a degenerate coordinate). A valid
        // Groth16 proof's A component must not be infinity — treat as invalid.
        return Err(VerifierError::InvalidPoint);
    }

    // Compute p - y by big-endian subtraction with borrow.
    let mut neg_y = [0u8; 48];
    let mut borrow: u16 = 0;
    for i in (0..48).rev() {
        let sub = (BLS12_381_FP_MODULUS_BE[i] as u16)
            .wrapping_sub(y_arr[i] as u16)
            .wrapping_sub(borrow);
        neg_y[i] = sub as u8;
        borrow = if sub > 0xff { 1 } else { 0 };
    }
    // If borrow is non-zero, y was not in [0, p) — the point is not a valid curve point.
    if borrow != 0 {
        return Err(VerifierError::InvalidPoint);
    }

    // Reassemble x || neg_y into a 96-byte array.
    let mut out = [0u8; 96];
    for i in 0..48u32 {
        out[i as usize] = x.get_unchecked(i);
    }
    out[48..].copy_from_slice(&neg_y);
    Ok(BytesN::from_array(env, &out))
}

/// Compute `vk_x = ic[0] + Σ_{i} ic[i+1] * signal[i]` using `g1_msm`.
///
/// `g1_msm` takes a `Vec<Bls12381G1Affine>` and a `Vec<Bls12381Fr>`, so we extract
/// `ic[1..]` as the base points and `public_signals` as the scalars, call msm, then add
/// `ic[0]`. The MSM does all the scalar multiplications and the additions between them in
/// one host call — far cheaper than calling `g1_mul` + `g1_add` in a loop.
fn compute_vk_x_bls12(
    env: &Env,
    vk: &VerificationKey,
    public_signals: &Vec<U256>,
) -> Result<soroban_sdk::crypto::bls12_381::Bls12381G1Affine, VerifierError> {
    use soroban_sdk::crypto::bls12_381::{Bls12381Fr, Bls12381G1Affine};

    let bls = env.crypto().bls12_381();

    // ic[0] is the constant term (no associated signal).
    let ic0_bytes: BytesN<96> = bytes_to_fixed(env, &vk.ic.get_unchecked(0))?;
    let ic0 = Bls12381G1Affine::from_bytes(ic0_bytes);

    // Collect ic[1..] as G1 points and public_signals as Fr scalars.
    let n = public_signals.len();
    let mut points: Vec<Bls12381G1Affine> = Vec::new(env);
    let mut scalars: Vec<Bls12381Fr> = Vec::new(env);

    for i in 0..n {
        let ic_bytes: BytesN<96> = bytes_to_fixed(env, &vk.ic.get_unchecked(i + 1))?;
        points.push_back(Bls12381G1Affine::from_bytes(ic_bytes));

        let sig = public_signals.get_unchecked(i);
        let sig_bytes = u256_to_bytes32(env, &sig);
        scalars.push_back(Bls12381Fr::from_bytes(sig_bytes));
    }

    // Compute Σ ic[i+1] * signal[i] via MSM.
    let sum = bls.g1_msm(points, scalars);

    // Add ic[0]: vk_x = ic[0] + sum.
    Ok(bls.g1_add(&ic0, &sum))
}

/// Main BLS12-381 Groth16 verification.
///
/// Verification equation (Groth16):
/// `e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1`
///
/// Assembled as one `pairing_check` call with four (G1, G2) pairs:
/// - `(-A, B)` — proof A negated, proof B
/// - `(α, β)` — vk alpha_g1, vk beta_g2
/// - `(vk_x, γ)` — computed linear combination, vk gamma_g2
/// - `(C, δ)` — proof C, vk delta_g2
pub fn verify(
    env: &Env,
    vk: &VerificationKey,
    proof: &Proof,
    public_signals: &Vec<U256>,
) -> Result<bool, VerifierError> {
    use soroban_sdk::crypto::bls12_381::{Bls12381G1Affine, Bls12381G2Affine};

    let bls = env.crypto().bls12_381();

    // --- Negate A (for -A in the first pairing pair). ---
    let neg_a_bytes = negate_g1(env, &proof.a)?;
    let neg_a = Bls12381G1Affine::from_bytes(neg_a_bytes);

    // --- Subgroup checks on proof points. ---
    // Per docs/PLATFORM.md: from_bytes does NOT check subgroup membership; the host traps
    // on an off-curve point but NOT on an in-curve/wrong-subgroup point. We must call
    // is_in_subgroup() explicitly for externally-supplied points A, B, C.
    //
    // We check after constructing the SDK types so the check uses the same bytes that will
    // go into the pairing — no TOCTOU gap.
    let proof_a_raw = Bls12381G1Affine::from_bytes(bytes_to_fixed::<96>(env, &proof.a)?);
    if !bls.g1_is_in_subgroup(&proof_a_raw) {
        return Err(VerifierError::InvalidPoint);
    }
    let proof_b: Bls12381G2Affine =
        Bls12381G2Affine::from_bytes(bytes_to_fixed::<192>(env, &proof.b)?);
    // G2 subgroup check — BLS12-381 G2 has cofactor 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839126.
    if !bls.g2_is_in_subgroup(&proof_b) {
        return Err(VerifierError::InvalidPoint);
    }
    let proof_c: Bls12381G1Affine =
        Bls12381G1Affine::from_bytes(bytes_to_fixed::<96>(env, &proof.c)?);
    if !bls.g1_is_in_subgroup(&proof_c) {
        return Err(VerifierError::InvalidPoint);
    }

    // --- Build vk_x. ---
    let vk_x = compute_vk_x_bls12(env, vk, public_signals)?;

    // --- VK points. ---
    let alpha_g1: Bls12381G1Affine =
        Bls12381G1Affine::from_bytes(bytes_to_fixed::<96>(env, &vk.alpha_g1)?);
    let beta_g2: Bls12381G2Affine =
        Bls12381G2Affine::from_bytes(bytes_to_fixed::<192>(env, &vk.beta_g2)?);
    let gamma_g2: Bls12381G2Affine =
        Bls12381G2Affine::from_bytes(bytes_to_fixed::<192>(env, &vk.gamma_g2)?);
    let delta_g2: Bls12381G2Affine =
        Bls12381G2Affine::from_bytes(bytes_to_fixed::<192>(env, &vk.delta_g2)?);

    // --- Assemble the four pairs and call pairing_check once. ---
    let mut g1_vec: Vec<Bls12381G1Affine> = Vec::new(env);
    g1_vec.push_back(neg_a);
    g1_vec.push_back(alpha_g1);
    g1_vec.push_back(vk_x);
    g1_vec.push_back(proof_c);

    let mut g2_vec: Vec<Bls12381G2Affine> = Vec::new(env);
    g2_vec.push_back(proof_b);
    g2_vec.push_back(beta_g2);
    g2_vec.push_back(gamma_g2);
    g2_vec.push_back(delta_g2);

    Ok(bls.pairing_check(g1_vec, g2_vec))
}

// ---------------------------------------------------------------------------
// Byte-manipulation helpers (local to this module — no Env needed for most)
// ---------------------------------------------------------------------------

/// Convert a variable-length `Bytes` into a `BytesN<N>` — fails with `MalformedVerificationKey`
/// if the length is wrong. This handles the length mismatch case gracefully instead of panicking.
fn bytes_to_fixed<const N: usize>(env: &Env, b: &Bytes) -> Result<BytesN<N>, VerifierError> {
    if b.len() as usize != N {
        return Err(VerifierError::MalformedVerificationKey);
    }
    let mut arr = [0u8; N];
    for (i, byte) in arr.iter_mut().enumerate() {
        *byte = b.get_unchecked(i as u32);
    }
    Ok(BytesN::from_array(env, &arr))
}

/// Convert a `U256` to a `BytesN<32>` for constructing an `Fr` scalar.
fn u256_to_bytes32(env: &Env, v: &U256) -> BytesN<32> {
    let be = v.to_be_bytes();
    let mut arr = [0u8; 32];
    for (i, byte) in arr.iter_mut().enumerate() {
        *byte = be.get_unchecked(i as u32);
    }
    BytesN::from_array(env, &arr)
}
