//! Groth16 verification-key registry.
//!
//! One deployed instance holds verification keys for many circuits, keyed by a `Symbol`
//! circuit id. Other contracts call `verify(circuit_id, proof, public_signals)` instead of
//! bundling their own copy of a VK.
//!
//! ## Trust model
//!
//! While a circuit is unfrozen, the admin can replace its VK, and a VK the admin chose can
//! be built to accept proofs of anything. `freeze` removes that power for one circuit,
//! permanently: a frozen circuit rejects `register` from everyone, the admin included, and
//! there is no unfreeze (Security Invariant #7). An app that needs trustlessness should only
//! rely on frozen circuits; check with `is_frozen`.
//!
//! ## Storage
//!
//! Admin, VKs and frozen flags all live in `persistent()` storage; nothing security-relevant
//! uses `temporary()`, where an expired "frozen" flag would read as unfrozen. Writes extend
//! the entry's TTL. `verify` is read-only (no storage writes, no TTL bumps), so it is safe to
//! call cross-contract; anyone can keep a circuit's entries alive with `extend_ttl`.
#![no_std]

use occulta_types::{Proof, VerificationKey};
use occulta_verifier::VerifierError;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, Env, Symbol, Vec,
    U256,
};

/// ~5s ledgers: 17,280 per day.
const DAY_IN_LEDGERS: u32 = 17_280;
/// Entries are extended to this TTL on every write and on `extend_ttl`.
const TTL_EXTEND_TO: u32 = 120 * DAY_IN_LEDGERS;
/// Only extend when the remaining TTL has dropped below this.
const TTL_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Vk(Symbol),
    Frozen(Symbol),
}

#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RegistryError {
    /// No VK is registered under this circuit id.
    CircuitNotFound = 1,
    /// The circuit is frozen; its VK can never change again.
    CircuitFrozen = 2,
    /// `freeze` was called on an already-frozen circuit.
    AlreadyFrozen = 3,
    /// The VK has wrong point lengths or an empty `ic`.
    MalformedVerificationKey = 4,
    /// The proof's shape or curve does not match the circuit's VK.
    MalformedProof = 5,
    /// `public_signals.len() + 1 != vk.ic.len()` (Security Invariant #5).
    PublicSignalCountMismatch = 6,
    /// A public signal is `>=` the scalar field modulus (Security Invariant #8).
    ScalarOutOfRange = 7,
    /// A proof point failed a subgroup check.
    InvalidPoint = 8,
}

impl From<VerifierError> for RegistryError {
    fn from(e: VerifierError) -> Self {
        match e {
            VerifierError::MalformedVerificationKey | VerifierError::UnsupportedCurve => {
                RegistryError::MalformedProof
            }
            VerifierError::PublicSignalCountMismatch => RegistryError::PublicSignalCountMismatch,
            VerifierError::ScalarOutOfRange => RegistryError::ScalarOutOfRange,
            VerifierError::InvalidPoint => RegistryError::InvalidPoint,
        }
    }
}

#[contractevent(topics = ["occulta", "vk_registered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VkRegistered {
    #[topic]
    pub circuit_id: Symbol,
}

#[contractevent(topics = ["occulta", "circuit_frozen"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CircuitFrozen {
    #[topic]
    pub circuit_id: Symbol,
}

#[contractevent(topics = ["occulta", "admin_changed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChanged {
    pub new_admin: Address,
}

#[contract]
pub struct Registry;

fn admin(env: &Env) -> Address {
    // Set in the constructor, so always present while the contract is live.
    env.storage()
        .persistent()
        .get(&DataKey::Admin)
        .expect("admin is set in the constructor")
}

fn bump(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
}

fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
}

fn is_frozen(env: &Env, circuit_id: &Symbol) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Frozen(circuit_id.clone()))
        .unwrap_or(false)
}

fn load_vk(env: &Env, circuit_id: &Symbol) -> Result<VerificationKey, RegistryError> {
    env.storage()
        .persistent()
        .get(&DataKey::Vk(circuit_id.clone()))
        .ok_or(RegistryError::CircuitNotFound)
}

#[contractimpl]
impl Registry {
    pub fn __constructor(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
        bump(&env, &DataKey::Admin);
        bump_instance(&env);
    }

    /// Registers or replaces the VK for `circuit_id`. Admin only. Fails with
    /// `CircuitFrozen` once the circuit is frozen, whoever calls it.
    pub fn register(
        env: Env,
        circuit_id: Symbol,
        vk: VerificationKey,
    ) -> Result<(), RegistryError> {
        admin(&env).require_auth();
        if is_frozen(&env, &circuit_id) {
            return Err(RegistryError::CircuitFrozen);
        }
        vk.validate_shape()
            .map_err(|_| RegistryError::MalformedVerificationKey)?;

        let key = DataKey::Vk(circuit_id.clone());
        env.storage().persistent().set(&key, &vk);
        bump(&env, &key);
        bump_instance(&env);
        VkRegistered { circuit_id }.publish(&env);
        Ok(())
    }

    /// Permanently freezes `circuit_id`'s VK. Admin only. One-way: there is no unfreeze.
    pub fn freeze(env: Env, circuit_id: Symbol) -> Result<(), RegistryError> {
        admin(&env).require_auth();
        load_vk(&env, &circuit_id)?;
        if is_frozen(&env, &circuit_id) {
            return Err(RegistryError::AlreadyFrozen);
        }
        let key = DataKey::Frozen(circuit_id.clone());
        env.storage().persistent().set(&key, &true);
        bump(&env, &key);
        bump(&env, &DataKey::Vk(circuit_id.clone()));
        CircuitFrozen { circuit_id }.publish(&env);
        Ok(())
    }

    /// Transfers the admin role. Requires the current admin's authorization.
    pub fn set_admin(env: Env, new_admin: Address) {
        admin(&env).require_auth();
        env.storage().persistent().set(&DataKey::Admin, &new_admin);
        bump(&env, &DataKey::Admin);
        AdminChanged { new_admin }.publish(&env);
    }

    pub fn admin(env: Env) -> Address {
        admin(&env)
    }

    pub fn get_vk(env: Env, circuit_id: Symbol) -> Result<VerificationKey, RegistryError> {
        load_vk(&env, &circuit_id)
    }

    pub fn is_frozen(env: Env, circuit_id: Symbol) -> bool {
        is_frozen(&env, &circuit_id)
    }

    /// Verifies a Groth16 proof against `circuit_id`'s VK. Read-only.
    ///
    /// `Ok(true)`: valid proof. `Ok(false)`: well-formed but the pairing check failed.
    /// `Err`: unknown circuit or structurally invalid input. A point that is not on the
    /// curve makes the host trap the whole invocation rather than return `false`.
    pub fn verify(
        env: Env,
        circuit_id: Symbol,
        proof: Proof,
        public_signals: Vec<U256>,
    ) -> Result<bool, RegistryError> {
        let vk = load_vk(&env, &circuit_id)?;
        Ok(occulta_verifier::verify(
            &env,
            &vk,
            &proof,
            &public_signals,
        )?)
    }

    /// Extends the TTL of `circuit_id`'s entries, the admin entry and the contract instance.
    /// Permissionless: it changes nothing but expiry.
    pub fn extend_ttl(env: Env, circuit_id: Symbol) -> Result<(), RegistryError> {
        load_vk(&env, &circuit_id)?;
        bump(&env, &DataKey::Vk(circuit_id.clone()));
        let frozen = DataKey::Frozen(circuit_id);
        if env.storage().persistent().has(&frozen) {
            bump(&env, &frozen);
        }
        bump(&env, &DataKey::Admin);
        bump_instance(&env);
        Ok(())
    }
}

#[cfg(test)]
mod test;
