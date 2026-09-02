use soroban_sdk::{contracttype, Bytes};

use crate::{Curve, TypesError};

/// A Groth16 proof: three curve points, `(A, B, C)` in the usual notation.
///
/// `a`/`c` are G1 points, `b` is a G2 point. Stored as variable-length `Bytes` rather than a
/// fixed `BytesN<N>` because the byte length depends on `curve` (see `Curve`'s doc comment for
/// why this deviates from the original spec's fixed-size pseudocode). Uncompressed
/// affine encoding, big-endian coordinates — see `docs/ENCODING.md`. This type performs no
/// curve-membership check (only a host function call can do that); `validate_shape` only
/// checks byte lengths.
#[contracttype]
#[derive(Clone)]
pub struct Proof {
    pub curve: Curve,
    pub a: Bytes,
    pub b: Bytes,
    pub c: Bytes,
}

impl Proof {
    /// Checks that `a`, `b`, `c` have the byte lengths `curve` requires. Does **not** check
    /// that the bytes decode to a point on the curve, in the correct subgroup, or not at
    /// infinity where that matters — those require an `Env` and a host call, and belong in
    /// `occulta-verifier`, not here.
    pub fn validate_shape(&self) -> Result<(), TypesError> {
        if self.a.len() != self.curve.g1_len() || self.c.len() != self.curve.g1_len() {
            return Err(TypesError::WrongPointLength);
        }
        if self.b.len() != self.curve.g2_len() {
            return Err(TypesError::WrongPointLength);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn zero_bytes<const N: usize>(env: &Env) -> Bytes {
        Bytes::from_array(env, &[0u8; N])
    }

    #[test]
    fn correctly_sized_bn254_proof_validates() {
        let env = Env::default();
        let p = Proof {
            curve: Curve::Bn254,
            a: zero_bytes::<64>(&env),
            b: zero_bytes::<128>(&env),
            c: zero_bytes::<64>(&env),
        };
        assert!(p.validate_shape().is_ok());
    }

    #[test]
    fn correctly_sized_bls12_381_proof_validates() {
        let env = Env::default();
        let p = Proof {
            curve: Curve::Bls12_381,
            a: zero_bytes::<96>(&env),
            b: zero_bytes::<192>(&env),
            c: zero_bytes::<96>(&env),
        };
        assert!(p.validate_shape().is_ok());
    }

    #[test]
    fn bn254_a_sized_for_bls12_381_is_rejected() {
        let env = Env::default();
        // Classic mistake: pass a BLS12-381-sized G1 point on a proof tagged Bn254.
        let p = Proof {
            curve: Curve::Bn254,
            a: zero_bytes::<96>(&env),
            b: zero_bytes::<128>(&env),
            c: zero_bytes::<64>(&env),
        };
        assert_eq!(p.validate_shape(), Err(TypesError::WrongPointLength));
    }

    #[test]
    fn wrong_length_b_is_rejected() {
        let env = Env::default();
        let p = Proof {
            curve: Curve::Bn254,
            a: zero_bytes::<64>(&env),
            b: zero_bytes::<64>(&env), // should be 128 for BN254 G2
            c: zero_bytes::<64>(&env),
        };
        assert_eq!(p.validate_shape(), Err(TypesError::WrongPointLength));
    }
}
