use soroban_sdk::{contracttype, Bytes, Vec};

use crate::{Curve, TypesError};

/// A Groth16 verification key.
///
/// `ic` (the "input commitments" / linear-combination basis) must have exactly
/// `n_public_signals + 1` entries — `ic[0]` is the constant term, `ic[1..]` pair one-to-one
/// with public signals. Enforcing `public_signals.len() + 1 == ic.len()` is
/// `occulta-verifier`'s job (Security Invariant #5) since it needs the signals vector too;
/// this type only enforces that `ic` is non-empty and every point is correctly sized.
#[contracttype]
#[derive(Clone)]
pub struct VerificationKey {
    pub curve: Curve,
    pub alpha_g1: Bytes,
    pub beta_g2: Bytes,
    pub gamma_g2: Bytes,
    pub delta_g2: Bytes,
    pub ic: Vec<Bytes>,
}

impl VerificationKey {
    pub fn validate_shape(&self) -> Result<(), TypesError> {
        if self.alpha_g1.len() != self.curve.g1_len() {
            return Err(TypesError::WrongPointLength);
        }
        if self.beta_g2.len() != self.curve.g2_len()
            || self.gamma_g2.len() != self.curve.g2_len()
            || self.delta_g2.len() != self.curve.g2_len()
        {
            return Err(TypesError::WrongPointLength);
        }
        if self.ic.is_empty() {
            return Err(TypesError::EmptyIc);
        }
        for point in self.ic.iter() {
            if point.len() != self.curve.g1_len() {
                return Err(TypesError::WrongPointLength);
            }
        }
        Ok(())
    }

    /// Number of public signals this VK expects: `ic.len() - 1`.
    ///
    /// Security Invariant #5: callers MUST compare this against
    /// `public_signals.len()` before verifying — see `occulta-verifier`.
    pub fn expected_public_signal_count(&self) -> u32 {
        self.ic.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn zero_bytes<const N: usize>(env: &Env) -> Bytes {
        Bytes::from_array(env, &[0u8; N])
    }

    fn valid_bn254_vk(env: &Env, n_ic: u32) -> VerificationKey {
        let mut ic = Vec::new(env);
        for _ in 0..n_ic {
            ic.push_back(zero_bytes::<64>(env));
        }
        VerificationKey {
            curve: Curve::Bn254,
            alpha_g1: zero_bytes::<64>(env),
            beta_g2: zero_bytes::<128>(env),
            gamma_g2: zero_bytes::<128>(env),
            delta_g2: zero_bytes::<128>(env),
            ic,
        }
    }

    #[test]
    fn well_formed_vk_validates() {
        let env = Env::default();
        let vk = valid_bn254_vk(&env, 3);
        assert!(vk.validate_shape().is_ok());
        assert_eq!(vk.expected_public_signal_count(), 2);
    }

    #[test]
    fn empty_ic_is_rejected() {
        let env = Env::default();
        let vk = valid_bn254_vk(&env, 0);
        assert_eq!(vk.validate_shape(), Err(TypesError::EmptyIc));
    }

    #[test]
    fn wrong_sized_ic_entry_is_rejected() {
        let env = Env::default();
        let mut vk = valid_bn254_vk(&env, 2);
        vk.ic.set(1, zero_bytes::<96>(&env)); // BLS12-381-sized point smuggled into a BN254 VK
        assert_eq!(vk.validate_shape(), Err(TypesError::WrongPointLength));
    }

    #[test]
    fn wrong_sized_beta_g2_is_rejected() {
        let env = Env::default();
        let mut vk = valid_bn254_vk(&env, 2);
        vk.beta_g2 = zero_bytes::<192>(&env);
        assert_eq!(vk.validate_shape(), Err(TypesError::WrongPointLength));
    }

    #[test]
    fn expected_public_signal_count_matches_ic_len_minus_one() {
        let env = Env::default();
        for n in [1u32, 2, 5, 10] {
            let vk = valid_bn254_vk(&env, n);
            assert_eq!(vk.expected_public_signal_count(), n - 1);
        }
    }
}
