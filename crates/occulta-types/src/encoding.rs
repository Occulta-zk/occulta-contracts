//! snarkjs -> Soroban byte-level conversion primitives.
//!
//! These are pure byte functions with no dependency on `Env` — they don't call any host
//! function, so they can't validate "is this a point on the curve" (only the host can, by
//! trapping on an invalid point passed to `g1_add`/`pairing_check`/etc — see
//! `docs/PLATFORM.md`). What they *can* and must enforce, deterministically and testably,
//! is documented in `docs/ENCODING.md`: scalar range, point-at-infinity shape, and the G2
//! coordinate reordering. See `docs/ENCODING.md` for the full narrative version of each rule.

/// Rule 1 (`docs/ENCODING.md` #1): a 32-byte big-endian scalar is only valid if it is
/// strictly less than the curve's Fr modulus. snarkjs reduces mod r before emitting decimal
/// strings off-chain, but a malicious or buggy caller can still hand the contract an
/// out-of-range `U256`/`BytesN<32>` — the host silently reduces it (see the `poseidon_permutation`
/// doc-comment warning quoted in `docs/PLATFORM.md`), which would let two distinct encoded
/// scalars collide. Reject before use instead of trusting silent reduction.
pub fn scalar_in_range(scalar_be: &[u8; 32], modulus_be: &[u8; 32]) -> bool {
    // Big-endian byte-array comparison: scalar < modulus.
    for i in 0..32 {
        if scalar_be[i] < modulus_be[i] {
            return true;
        }
        if scalar_be[i] > modulus_be[i] {
            return false;
        }
    }
    // Equal to the modulus is out of range (valid range is [0, modulus)).
    false
}

/// Rule 4 (`docs/ENCODING.md` #4): is this byte string the all-zero encoding used for the
/// point at infinity? Used both to detect infinity (e.g. before negating a G1 point, since
/// negating infinity's `y = 0` must not underflow) and, in callers that don't accept
/// infinity for a given field (e.g. `vk.alpha_g1` must never be infinity), to reject it.
pub fn is_zero_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| *b == 0)
}

/// Swaps the two half-length limbs of a big-endian `Fp2` coordinate.
///
/// Rule 3 (`docs/ENCODING.md` #3, "the G2 coordinate order trap"): snarkjs emits a G2 point's
/// `Fp2` coordinates as `[c0, c1]` (c0 first); both `soroban_sdk::crypto::bls12_381` and
/// `crypto::bn254` document the host's wire format as `c1 || c0` (c1 first) — see
/// `docs/PLATFORM.md`. Concatenating snarkjs's JSON order directly produces a syntactically
/// valid-length byte string that is numerically wrong and will either trap (not a curve
/// point) or, worse, silently verify against the wrong point. This function performs exactly
/// the required swap: given `c0 || c1` (each `half_len` bytes), it writes `c1 || c0` into
/// `out`.
///
/// Panics if `input.len() != 2 * half_len` or `out.len() != input.len()` — a length mismatch
/// here is a caller bug, not a runtime/user-input condition.
pub fn swap_fp2_limbs(input: &[u8], half_len: usize, out: &mut [u8]) {
    assert_eq!(
        input.len(),
        2 * half_len,
        "swap_fp2_limbs: unexpected input length"
    );
    assert_eq!(
        out.len(),
        input.len(),
        "swap_fp2_limbs: out/input length mismatch"
    );
    let (c0, c1) = input.split_at(half_len);
    out[..half_len].copy_from_slice(c1);
    out[half_len..].copy_from_slice(c0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{BLS12_381_FR_MODULUS_BE, BN254_FR_MODULUS_BE};

    #[test]
    fn scalar_zero_is_in_range() {
        let zero = [0u8; 32];
        assert!(scalar_in_range(&zero, &BLS12_381_FR_MODULUS_BE));
        assert!(scalar_in_range(&zero, &BN254_FR_MODULUS_BE));
    }

    #[test]
    fn scalar_equal_to_modulus_is_rejected() {
        assert!(!scalar_in_range(
            &BLS12_381_FR_MODULUS_BE,
            &BLS12_381_FR_MODULUS_BE
        ));
        assert!(!scalar_in_range(&BN254_FR_MODULUS_BE, &BN254_FR_MODULUS_BE));
    }

    #[test]
    fn scalar_one_more_than_modulus_is_rejected() {
        let mut over = BN254_FR_MODULUS_BE;
        over[31] = over[31].wrapping_add(1); // modulus + 1 (no overflow: last byte is 0x01)
        assert!(!scalar_in_range(&over, &BN254_FR_MODULUS_BE));
    }

    #[test]
    fn scalar_one_less_than_modulus_is_in_range() {
        let mut under = BN254_FR_MODULUS_BE;
        under[31] -= 1;
        assert!(scalar_in_range(&under, &BN254_FR_MODULUS_BE));
    }

    #[test]
    fn max_32_byte_value_exceeds_both_moduli() {
        let max = [0xffu8; 32];
        assert!(!scalar_in_range(&max, &BLS12_381_FR_MODULUS_BE));
        assert!(!scalar_in_range(&max, &BN254_FR_MODULUS_BE));
    }

    #[test]
    fn zero_bytes_detected() {
        assert!(is_zero_bytes(&[0u8; 64]));
        let mut almost = [0u8; 64];
        almost[63] = 1;
        assert!(!is_zero_bytes(&almost));
        almost[63] = 0;
        almost[0] = 1;
        assert!(!is_zero_bytes(&almost));
    }

    /// Named regression test for the exact bug class `docs/ENCODING.md` #3 warns about:
    /// naively concatenating snarkjs's `[c0, c1]` JSON order must NOT equal the swapped
    /// host-order bytes, and applying the swap function must produce exactly `c1 || c0`.
    #[test]
    fn g2_coordinate_swap_matches_expected_host_order_bn254() {
        // Fabricated but structurally realistic: two distinct 32-byte limbs.
        let c0: [u8; 32] = core::array::from_fn(|i| i as u8); // 0x00..0x1f
        let c1: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(0x80)); // 0x80..0x9f

        let mut snarkjs_order = [0u8; 64];
        snarkjs_order[..32].copy_from_slice(&c0);
        snarkjs_order[32..].copy_from_slice(&c1);

        let mut host_order = [0u8; 64];
        swap_fp2_limbs(&snarkjs_order, 32, &mut host_order);

        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(&c1);
        expected[32..].copy_from_slice(&c0);

        assert_eq!(
            host_order, expected,
            "swap must produce c1||c0, not a copy of c0||c1"
        );
        assert_ne!(
            host_order, snarkjs_order,
            "an un-swapped copy must not pass as swapped"
        );
    }

    #[test]
    fn g2_coordinate_swap_is_its_own_inverse() {
        let input: [u8; 96] = core::array::from_fn(|i| i as u8); // BLS12-381 Fp coord width (48*2)
        let mut once = [0u8; 96];
        swap_fp2_limbs(&input, 48, &mut once);
        let mut twice = [0u8; 96];
        swap_fp2_limbs(&once, 48, &mut twice);
        assert_eq!(
            twice, input,
            "swapping twice must return the original bytes"
        );
    }

    #[test]
    #[should_panic(expected = "unexpected input length")]
    fn swap_rejects_wrong_length() {
        let bad = [0u8; 10];
        let mut out = [0u8; 10];
        swap_fp2_limbs(&bad, 32, &mut out);
    }
}
