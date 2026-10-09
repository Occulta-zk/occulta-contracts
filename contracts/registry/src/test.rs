extern crate std;

use occulta_types::snarkjs::{proof_from_json, public_signals_from_json, vk_from_json};
use occulta_types::{Proof, VerificationKey};
use soroban_sdk::testutils::storage::Persistent as _;
use soroban_sdk::testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{symbol_short, Address, Bytes, Env, IntoVal, Symbol, Vec, U256};

use crate::{DataKey, Registry, RegistryClient, RegistryError, TTL_EXTEND_TO};

const VKEY: &str = include_str!("../../../fixtures/vote/vkey.json");
const PROOF: &str = include_str!("../../../fixtures/vote/proof.json");
const PROOF_NEGATIVE: &str = include_str!("../../../fixtures/vote/proof_negative.json");
const PUBLIC: &str = include_str!("../../../fixtures/vote/public.json");

const VOTE: Symbol = symbol_short!("vote_v1");

struct Setup {
    env: Env,
    id: Address,
    admin: Address,
    vk: VerificationKey,
    proof: Proof,
    signals: Vec<U256>,
}

impl Setup {
    fn client(&self) -> RegistryClient<'_> {
        RegistryClient::new(&self.env, &self.id)
    }
}

/// Deployed registry with every auth mocked. Tests that check authorization build their
/// own `Env` state via `mock_auths` instead.
fn setup() -> Setup {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let admin = Address::generate(&env);
    let id = env.register(Registry, (admin.clone(),));
    env.mock_all_auths();
    let vk = vk_from_json(&env, VKEY).unwrap();
    let proof = proof_from_json(&env, PROOF).unwrap();
    let signals = public_signals_from_json(&env, PUBLIC).unwrap();
    Setup {
        env,
        id,
        admin,
        vk,
        proof,
        signals,
    }
}

fn registered() -> Setup {
    let s = setup();
    s.client().register(&VOTE, &s.vk);
    s
}

/// Mock exactly one authorization: `who` signs `fn_name(args)` on the registry.
fn auth_as(
    s: &Setup,
    who: &Address,
    fn_name: &'static str,
    args: soroban_sdk::Vec<soroban_sdk::Val>,
) {
    s.env.mock_auths(&[MockAuth {
        address: who,
        invoke: &MockAuthInvoke {
            contract: &s.id,
            fn_name,
            args,
            sub_invokes: &[],
        },
    }]);
}

// --- constructor / admin ---------------------------------------------------------------

#[test]
fn constructor_sets_admin() {
    let s = setup();
    assert_eq!(s.client().admin(), s.admin);
}

#[test]
fn set_admin_hands_over_control() {
    let s = registered();
    let new_admin = Address::generate(&s.env);
    s.client().set_admin(&new_admin);
    assert_eq!(s.client().admin(), new_admin);

    // The old admin can no longer register; the new one can.
    auth_as(
        &s,
        &s.admin,
        "register",
        (VOTE, s.vk.clone()).into_val(&s.env),
    );
    assert!(s.client().try_register(&VOTE, &s.vk).is_err());
    auth_as(
        &s,
        &new_admin,
        "register",
        (VOTE, s.vk.clone()).into_val(&s.env),
    );
    s.client().register(&VOTE, &s.vk);
}

#[test]
fn set_admin_rejects_non_admin() {
    let s = setup();
    let attacker = Address::generate(&s.env);
    auth_as(
        &s,
        &attacker,
        "set_admin",
        (attacker.clone(),).into_val(&s.env),
    );
    assert!(s.client().try_set_admin(&attacker).is_err());
    assert_eq!(s.client().admin(), s.admin);
}

// --- register / get_vk -----------------------------------------------------------------

#[test]
fn register_stores_vk_and_requires_admin_auth() {
    let s = registered();
    let auths = s.env.auths();
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0].0, s.admin);
    let stored = s.client().get_vk(&VOTE);
    assert_eq!(stored.alpha_g1, s.vk.alpha_g1);
    assert_eq!(stored.ic, s.vk.ic);
    assert!(!s.client().is_frozen(&VOTE));
}

#[test]
fn register_rejects_unauthorised_caller() {
    let s = setup();
    let attacker = Address::generate(&s.env);
    auth_as(
        &s,
        &attacker,
        "register",
        (VOTE, s.vk.clone()).into_val(&s.env),
    );
    assert!(s.client().try_register(&VOTE, &s.vk).is_err());
    assert_eq!(
        s.client().try_get_vk(&VOTE).map(|_| ()),
        Err(Ok(RegistryError::CircuitNotFound))
    );
}

#[test]
fn register_rejects_malformed_vk() {
    let s = setup();
    let mut bad = s.vk.clone();
    bad.ic = Vec::new(&s.env);
    assert_eq!(
        s.client().try_register(&VOTE, &bad),
        Err(Ok(RegistryError::MalformedVerificationKey))
    );
}

#[test]
fn unfrozen_vk_can_be_replaced() {
    let s = registered();
    let mut other = s.vk.clone();
    other.ic.pop_back();
    other.ic.push_back(s.vk.ic.get_unchecked(0));
    s.client().register(&VOTE, &other);
    assert_eq!(s.client().get_vk(&VOTE).ic, other.ic);
}

#[test]
fn get_vk_unknown_circuit() {
    let s = setup();
    assert_eq!(
        s.client().try_get_vk(&VOTE).map(|_| ()),
        Err(Ok(RegistryError::CircuitNotFound))
    );
}

// --- freeze ----------------------------------------------------------------------------

#[test]
fn frozen_circuit_rejects_register_even_from_admin() {
    let s = registered();
    s.client().freeze(&VOTE);
    assert!(s.client().is_frozen(&VOTE));

    let mut swapped = s.vk.clone();
    swapped.alpha_g1 = s.vk.ic.get_unchecked(0);
    // mock_all_auths is still on: the admin's signature is present, and it is not enough.
    assert_eq!(
        s.client().try_register(&VOTE, &swapped),
        Err(Ok(RegistryError::CircuitFrozen))
    );
    assert_eq!(s.client().get_vk(&VOTE).alpha_g1, s.vk.alpha_g1);
}

#[test]
fn frozen_circuit_stays_frozen_after_admin_change() {
    let s = registered();
    s.client().freeze(&VOTE);
    let new_admin = Address::generate(&s.env);
    s.client().set_admin(&new_admin);
    assert_eq!(
        s.client().try_register(&VOTE, &s.vk),
        Err(Ok(RegistryError::CircuitFrozen))
    );
}

#[test]
fn freeze_twice_is_rejected() {
    let s = registered();
    s.client().freeze(&VOTE);
    assert_eq!(
        s.client().try_freeze(&VOTE),
        Err(Ok(RegistryError::AlreadyFrozen))
    );
    assert!(s.client().is_frozen(&VOTE));
}

#[test]
fn freeze_unknown_circuit() {
    let s = setup();
    assert_eq!(
        s.client().try_freeze(&VOTE),
        Err(Ok(RegistryError::CircuitNotFound))
    );
}

#[test]
fn freeze_rejects_unauthorised_caller() {
    let s = registered();
    let attacker = Address::generate(&s.env);
    auth_as(&s, &attacker, "freeze", (VOTE,).into_val(&s.env));
    assert!(s.client().try_freeze(&VOTE).is_err());
    assert!(!s.client().is_frozen(&VOTE));
}

// --- verify ----------------------------------------------------------------------------

#[test]
fn verify_accepts_the_snarkjs_fixture() {
    let s = registered();
    assert!(s.client().verify(&VOTE, &s.proof, &s.signals));
}

#[test]
fn verify_accepts_the_fixture_after_freeze() {
    let s = registered();
    s.client().freeze(&VOTE);
    assert!(s.client().verify(&VOTE, &s.proof, &s.signals));
}

#[test]
fn verify_needs_no_auth() {
    let s = registered();
    s.env.mock_auths(&[]);
    assert!(s.client().verify(&VOTE, &s.proof, &s.signals));
    assert!(s.env.auths().is_empty());
}

#[test]
fn verify_rejects_a_different_choice() {
    let s = registered();
    let mut signals = s.signals.clone();
    signals.set(2, U256::from_u32(&s.env, 0));
    assert!(!s.client().verify(&VOTE, &s.proof, &signals));
}

#[test]
fn verify_unknown_circuit() {
    let s = setup();
    assert_eq!(
        s.client().try_verify(&VOTE, &s.proof, &s.signals),
        Err(Ok(RegistryError::CircuitNotFound))
    );
}

#[test]
fn verify_signal_count_mismatch() {
    let s = registered();
    let mut signals = s.signals.clone();
    signals.pop_back();
    assert_eq!(
        s.client().try_verify(&VOTE, &s.proof, &signals),
        Err(Ok(RegistryError::PublicSignalCountMismatch))
    );
}

#[test]
fn verify_scalar_out_of_range() {
    let s = registered();
    let mut signals = s.signals.clone();
    let max = Bytes::from_array(&s.env, &[0xff; 32]);
    signals.set(3, U256::from_be_bytes(&s.env, &max));
    assert_eq!(
        s.client().try_verify(&VOTE, &s.proof, &signals),
        Err(Ok(RegistryError::ScalarOutOfRange))
    );
}

#[test]
fn verify_malformed_proof() {
    let s = registered();
    let mut proof = s.proof.clone();
    proof.b = proof.a.clone(); // G1-sized bytes where a G2 point belongs
    assert_eq!(
        s.client().try_verify(&VOTE, &proof, &s.signals),
        Err(Ok(RegistryError::MalformedProof))
    );
}

/// The bit-flipped fixture's `A` is off the curve: the host aborts the invocation instead of
/// returning `false`. Through the client that surfaces as an error, never `Ok(false)` and
/// never `Ok(true)`.
#[test]
fn verify_off_curve_proof_aborts() {
    let s = registered();
    let bad = proof_from_json(&s.env, PROOF_NEGATIVE).unwrap();
    let r = s.client().try_verify(&VOTE, &bad, &s.signals);
    assert!(matches!(r, Err(Err(_))), "expected host abort, got {r:?}");
}

/// `verify` must not write state: it does not even extend TTLs.
#[test]
fn verify_is_read_only() {
    let s = registered();
    let key = DataKey::Vk(VOTE);
    let ttl = |s: &Setup| {
        s.env
            .as_contract(&s.id, || s.env.storage().persistent().get_ttl(&key))
    };
    s.env.ledger().with_mut(|l| l.sequence_number += 1_000);
    let before = ttl(&s);
    assert!(s.client().verify(&VOTE, &s.proof, &s.signals));
    assert_eq!(ttl(&s), before);
}

// --- TTL -------------------------------------------------------------------------------

#[test]
fn register_extends_ttl_and_extend_ttl_renews_it() {
    let s = registered();
    let key = DataKey::Vk(VOTE);
    let ttl = |s: &Setup| {
        s.env
            .as_contract(&s.id, || s.env.storage().persistent().get_ttl(&key))
    };
    assert_eq!(ttl(&s), TTL_EXTEND_TO);

    // Age past the 30-day threshold, then renew, permissionlessly.
    s.env
        .ledger()
        .with_mut(|l| l.sequence_number += TTL_EXTEND_TO - 10 * 17_280);
    assert!(ttl(&s) < TTL_EXTEND_TO);
    s.env.mock_auths(&[]);
    s.client().extend_ttl(&VOTE);
    assert_eq!(ttl(&s), TTL_EXTEND_TO);
}

#[test]
fn extend_ttl_unknown_circuit() {
    let s = setup();
    assert_eq!(
        s.client().try_extend_ttl(&VOTE),
        Err(Ok(RegistryError::CircuitNotFound))
    );
}
