//! Persistent nullifier registry.
//!
//! Security Invariant #2: nullifiers are stored in `persistent()` storage, NEVER
//! `temporary()`. An expired temporary entry is an exploitable double-spend.
//!
//! This module provides two operations:
//! - `is_spent`: non-mutating check.
//! - `spend`: marks as spent, panics if already spent (Security Invariant #3).
//!
//! Callers (`contracts/shielded-pool::withdraw`) must call `spend` before any token transfer.

use soroban_sdk::{BytesN, Env};

use crate::{MerkleError, NULLIFIER_TTL};

/// Storage key: just the nullifier bytes themselves. Each nullifier is 32 bytes (a field
/// element from the circuit), stored as a `BytesN<32>`.
fn storage_key(nullifier: &BytesN<32>) -> BytesN<32> {
    nullifier.clone()
}

/// Check whether `nullifier` has been spent. Does not modify storage.
pub struct Nullifiers;

impl Nullifiers {
    /// Returns `true` if the nullifier has been spent, `false` if not.
    ///
    /// Storage: `persistent()` — a temporary entry could expire and read as `false`,
    /// re-opening a double-spend. This must never be changed to `temporary()`.
    pub fn is_spent(env: &Env, nullifier: &BytesN<32>) -> bool {
        // SECURITY: persistent() — see module doc. Do NOT change to temporary().
        env.storage()
            .persistent()
            .get::<BytesN<32>, bool>(&storage_key(nullifier))
            .unwrap_or(false)
    }

    /// Mark `nullifier` as spent. Panics if already spent.
    ///
    /// Panics (via `MerkleError::NullifierAlreadySpent`) rather than returning an error so
    /// that a double-spend attempt always aborts the transaction — never silently succeeds or
    /// is masked by a caller forgetting to check the return value (Security Invariant #9:
    /// every panic path is a test).
    ///
    /// Storage: `persistent()` — see `is_spent`.
    ///
    /// TTL: bumped to `NULLIFIER_TTL` ledgers on every write. An entry whose TTL expires
    /// gets archived; if it were then restored it would read as absent (false), opening a
    /// double-spend. The bump here keeps it alive well past any reasonable withdrawal window.
    pub fn spend(env: &Env, nullifier: &BytesN<32>) {
        let key = storage_key(nullifier);

        // SECURITY: persistent() — Do NOT change to temporary().
        let already = env
            .storage()
            .persistent()
            .get::<BytesN<32>, bool>(&key)
            .unwrap_or(false);

        if already {
            panic!("{}", MerkleError::NullifierAlreadySpent as u32);
        }

        // SECURITY: persistent() — Do NOT change to temporary().
        env.storage().persistent().set(&key, &true);

        // Bump TTL so the entry survives long enough to prevent double-spend.
        env.storage()
            .persistent()
            .extend_ttl(&key, NULLIFIER_TTL, NULLIFIER_TTL);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{contract, Env};

    /// Storage only works inside a registered contract's context; this bare marker
    /// contract exists solely so tests can enter that context via `env.as_contract()`.
    #[contract]
    struct TestContract;

    fn setup() -> (Env, soroban_sdk::Address) {
        let env = Env::default();
        let contract_id = env.register(TestContract, ());
        (env, contract_id)
    }

    fn nullifier(env: &Env, seed: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[0] = seed;
        BytesN::from_array(env, &arr)
    }

    #[test]
    fn fresh_nullifier_is_not_spent() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let n = nullifier(&env, 1);
            assert!(!Nullifiers::is_spent(&env, &n));
        });
    }

    #[test]
    fn spent_nullifier_is_spent() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let n = nullifier(&env, 2);
            Nullifiers::spend(&env, &n);
            assert!(Nullifiers::is_spent(&env, &n));
        });
    }

    #[test]
    #[should_panic]
    fn double_spend_panics() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let n = nullifier(&env, 3);
            Nullifiers::spend(&env, &n);
            Nullifiers::spend(&env, &n); // second call must panic
        });
    }

    #[test]
    fn different_nullifiers_are_independent() {
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let a = nullifier(&env, 10);
            let b = nullifier(&env, 20);
            Nullifiers::spend(&env, &a);
            assert!(Nullifiers::is_spent(&env, &a));
            assert!(!Nullifiers::is_spent(&env, &b));
        });
    }

    #[test]
    fn spending_uses_persistent_storage() {
        // Verify the entry is in persistent storage (not temporary).
        let (env, contract_id) = setup();
        env.as_contract(&contract_id, || {
            let n = nullifier(&env, 42);
            Nullifiers::spend(&env, &n);

            let in_persistent = env
                .storage()
                .persistent()
                .get::<BytesN<32>, bool>(&n)
                .unwrap_or(false);
            assert!(
                in_persistent,
                "nullifier must be in persistent storage, not temporary"
            );
        });
    }
}
