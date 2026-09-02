use soroban_sdk::contracttype;

/// Byte length of an uncompressed G1 point, per curve.
///
/// Verified against `soroban_sdk::crypto::{bls12_381,bn254}` source — see `docs/PLATFORM.md`.
pub const BLS12_381_G1_LEN: u32 = 96;
/// Byte length of an uncompressed G2 point, for BLS12-381.
pub const BLS12_381_G2_LEN: u32 = 192;
/// Byte length of an uncompressed G1 point, for BN254.
pub const BN254_G1_LEN: u32 = 64;
/// Byte length of an uncompressed G2 point, for BN254.
pub const BN254_G2_LEN: u32 = 128;
/// Both curves' scalar fields (Fr) serialize to 32 bytes.
pub const FR_LEN: u32 = 32;

/// Scalar field (Fr) modulus, big-endian, 32 bytes.
///
/// BLS12-381: r = 52435875175126190479447740508185965837690552500527637822603658699938581184513
/// This is the well-known BLS12-381 scalar field order (see e.g. `ark-bls12-381`); computed to
/// bytes programmatically and cross-checked, not hand-transcribed digit-by-digit.
pub const BLS12_381_FR_MODULUS_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// BN254: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Which pairing-friendly curve a proof / verification key was produced for.
///
/// A `VerificationKey` carries its own `Curve`; `occulta-verifier::verify` dispatches on it.
/// Point and scalar byte lengths differ by curve (see the constants above) — callers must not
/// assume a fixed `G1_LEN`/`G2_LEN` across curves. This is a deliberate, documented deviation
/// from the original spec's pseudocode, which used a single `BytesN<G1_LEN>` constant; the
/// verified SDK facts in `docs/PLATFORM.md` show G1/G2 are differently sized per curve
/// (96/192 bytes for BLS12-381 vs 64/128 for BN254), so `Proof`/`VerificationKey` store
/// variable-length `Bytes` and validate the expected length for `self.curve` at decode time.
#[contracttype]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Curve {
    Bls12_381,
    Bn254,
}

impl Curve {
    pub const fn g1_len(&self) -> u32 {
        match self {
            Curve::Bls12_381 => BLS12_381_G1_LEN,
            Curve::Bn254 => BN254_G1_LEN,
        }
    }

    pub const fn g2_len(&self) -> u32 {
        match self {
            Curve::Bls12_381 => BLS12_381_G2_LEN,
            Curve::Bn254 => BN254_G2_LEN,
        }
    }

    pub const fn fr_len(&self) -> u32 {
        FR_LEN
    }

    pub const fn fr_modulus_be(&self) -> &'static [u8; 32] {
        match self {
            Curve::Bls12_381 => &BLS12_381_FR_MODULUS_BE,
            Curve::Bn254 => &BN254_FR_MODULUS_BE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn g1_g2_lengths_differ_by_curve() {
        assert_eq!(Curve::Bls12_381.g1_len(), 96);
        assert_eq!(Curve::Bls12_381.g2_len(), 192);
        assert_eq!(Curve::Bn254.g1_len(), 64);
        assert_eq!(Curve::Bn254.g2_len(), 128);
    }

    #[test]
    fn moduli_are_32_bytes_and_odd() {
        // Every prime > 2 is odd; a cheap sanity check that we didn't drop/shift a byte.
        for m in [
            Curve::Bls12_381.fr_modulus_be(),
            Curve::Bn254.fr_modulus_be(),
        ] {
            assert_eq!(m.len(), 32);
            assert_eq!(m[31] & 1, 1, "field modulus must be odd");
            assert_ne!(
                m[0], 0,
                "modulus should not have a redundant leading zero byte at this magnitude"
            );
        }
    }

    #[test]
    fn bls12_381_and_bn254_moduli_are_distinct() {
        assert_ne!(
            Curve::Bls12_381.fr_modulus_be(),
            Curve::Bn254.fr_modulus_be()
        );
    }
}
