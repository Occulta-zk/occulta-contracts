//! Groth16 verification over BN254.
//!
//! SDK bindings used (all verified against `soroban-sdk 26.1.1` — see `docs/PLATFORM.md`):
//! - `env.crypto().bn254()` → `Bn254`
//! - `bn254.g1_msm(points, scalars)` — SDK-level convenience wrapper (not a raw CAP-74 call)
//! - `bn254.pairing_check(g1_vec, g2_vec)` — wraps host `bn254_multi_pairing_check`
//!
//! CAP-74 lists only 3 raw host functions (`bn254_g1_add`, `bn254_g1_mul`,
//! `bn254_multi_pairing_check`); `g1_msm` and Fr arithmetic are SDK-level wrappers — cite the
//! SDK, not the CAP, per `docs/PLATFORM.md`.
//!
//! G1 encoding: `BytesN<64>`, `be(X) || be(Y)`, 32 bytes each.
//! G2 encoding: `BytesN<128>`, `be(X_c1) || be(X_c0) || be(Y_c1) || be(Y_c0)`.
//! c1 before c0 — same trap as BLS12-381. See `docs/ENCODING.md` rule 3.
//!
//! BN254 does **not** expose `g1_is_in_subgroup` / `g2_is_in_subgroup` in the SDK because
//! BN254's G1 cofactor is 1 (every on-curve point is in G1) and the host already validates
//! G2 subgroup membership during `pairing_check`. Per `docs/PLATFORM.md`: for BN254 the host
//! traps on an off-curve G1/G2 point — subgroup membership checks are not separately needed.

use occulta_types::{is_zero_bytes, Proof, VerificationKey};
use soroban_sdk::{Bytes, BytesN, Env, Vec, U256};

use crate::VerifierError;

/// BN254 base field prime `p` (Fp, 32 bytes, big-endian).
///
/// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
/// Source: EIP-197 and ark-bn254.
const BN254_FP_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// Negate a BN254 G1 affine point: `(x, y) → (x, p - y)`.
///
/// An uncompressed affine G1 point is 64 bytes: `[x: 32 bytes][y: 32 bytes]`.
/// Returns `Err(InvalidPoint)` if `y == 0` (point at infinity / malformed).
fn negate_g1(env: &Env, point_bytes: &Bytes) -> Result<BytesN<64>, VerifierError> {
    let x = point_bytes.slice(0..32);
    let y = point_bytes.slice(32..64);

    let mut y_arr = [0u8; 32];
    for i in 0..32u32 {
        y_arr[i as usize] = y.get_unchecked(i);
    }

    if is_zero_bytes(&y_arr) {
        return Err(VerifierError::InvalidPoint);
    }

    // Compute p - y.
    let mut neg_y = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let sub = (BN254_FP_MODULUS_BE[i] as u16)
            .wrapping_sub(y_arr[i] as u16)
            .wrapping_sub(borrow);
        neg_y[i] = sub as u8;
        borrow = if sub > 0xff { 1 } else { 0 };
    }
    if borrow != 0 {
        return Err(VerifierError::InvalidPoint);
    }

    let mut out = [0u8; 64];
    for i in 0..32u32 {
        out[i as usize] = x.get_unchecked(i);
    }
    out[32..].copy_from_slice(&neg_y);
    Ok(BytesN::from_array(env, &out))
}

/// Compute `vk_x = ic[0] + Σ_{i} ic[i+1] * signal[i]` using `g1_msm`.
fn compute_vk_x_bn254(
    env: &Env,
    vk: &VerificationKey,
    public_signals: &Vec<U256>,
) -> Result<soroban_sdk::crypto::bn254::Bn254G1Affine, VerifierError> {
    use soroban_sdk::crypto::bn254::{Bn254Fr, Bn254G1Affine};

    let bn = env.crypto().bn254();

    let ic0_bytes: BytesN<64> = bytes_to_fixed(env, &vk.ic.get_unchecked(0))?;
    let ic0 = Bn254G1Affine::from_bytes(ic0_bytes);

    let n = public_signals.len();
    let mut points: Vec<Bn254G1Affine> = Vec::new(env);
    let mut scalars: Vec<Bn254Fr> = Vec::new(env);

    for i in 0..n {
        let ic_bytes: BytesN<64> = bytes_to_fixed(env, &vk.ic.get_unchecked(i + 1))?;
        points.push_back(Bn254G1Affine::from_bytes(ic_bytes));

        let sig = public_signals.get_unchecked(i);
        let sig_bytes = u256_to_bytes32(env, &sig);
        scalars.push_back(Bn254Fr::from_bytes(sig_bytes));
    }

    let sum = bn.g1_msm(points, scalars);
    Ok(bn.g1_add(&ic0, &sum))
}

/// Main BN254 Groth16 verification.
///
/// Same equation as the BLS12-381 path:
/// `e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) == 1`
pub fn verify(
    env: &Env,
    vk: &VerificationKey,
    proof: &Proof,
    public_signals: &Vec<U256>,
) -> Result<bool, VerifierError> {
    use soroban_sdk::crypto::bn254::{Bn254G1Affine, Bn254G2Affine};

    let bn = env.crypto().bn254();

    // Negate A.
    let neg_a_bytes = negate_g1(env, &proof.a)?;
    let neg_a = Bn254G1Affine::from_bytes(neg_a_bytes);

    // BN254 G1 cofactor is 1 — every on-curve point is in the group. The host traps on
    // off-curve bytes. No explicit is_in_subgroup call needed (and none exists in the SDK
    // for BN254 per docs/PLATFORM.md). We rely on the host trap for A, B, C.
    let proof_b: Bn254G2Affine = Bn254G2Affine::from_bytes(bytes_to_fixed::<128>(env, &proof.b)?);
    let proof_c: Bn254G1Affine = Bn254G1Affine::from_bytes(bytes_to_fixed::<64>(env, &proof.c)?);

    // Build vk_x.
    let vk_x = compute_vk_x_bn254(env, vk, public_signals)?;

    // VK points.
    let alpha_g1: Bn254G1Affine =
        Bn254G1Affine::from_bytes(bytes_to_fixed::<64>(env, &vk.alpha_g1)?);
    let beta_g2: Bn254G2Affine =
        Bn254G2Affine::from_bytes(bytes_to_fixed::<128>(env, &vk.beta_g2)?);
    let gamma_g2: Bn254G2Affine =
        Bn254G2Affine::from_bytes(bytes_to_fixed::<128>(env, &vk.gamma_g2)?);
    let delta_g2: Bn254G2Affine =
        Bn254G2Affine::from_bytes(bytes_to_fixed::<128>(env, &vk.delta_g2)?);

    // One pairing_check call, four pairs.
    let mut g1_vec: Vec<Bn254G1Affine> = Vec::new(env);
    g1_vec.push_back(neg_a);
    g1_vec.push_back(alpha_g1);
    g1_vec.push_back(vk_x);
    g1_vec.push_back(proof_c);

    let mut g2_vec: Vec<Bn254G2Affine> = Vec::new(env);
    g2_vec.push_back(proof_b);
    g2_vec.push_back(beta_g2);
    g2_vec.push_back(gamma_g2);
    g2_vec.push_back(delta_g2);

    // Use the local bn variable to avoid dead_code warnings about the unused imports.
    let _ = &bn;
    Ok(env.crypto().bn254().pairing_check(g1_vec, g2_vec))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn u256_to_bytes32(env: &Env, v: &U256) -> BytesN<32> {
    let be = v.to_be_bytes();
    let mut arr = [0u8; 32];
    for (i, byte) in arr.iter_mut().enumerate() {
        *byte = be.get_unchecked(i as u32);
    }
    BytesN::from_array(env, &arr)
}
