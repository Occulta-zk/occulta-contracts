# Security model

> **Testnet only. Unaudited. Not for real assets.** This document records the security
> invariants the system is designed around and how each one is enforced in code.
> It is not a security audit. See `SECURITY.md` for responsible-disclosure instructions.

---

## Invariants

These are the non-negotiable rules. Every deviation requires a flagged security review
before merge — a code comment alone is not sufficient.

1. **Everything the transaction acts on must be a public signal bound into the proof.**
   If the recipient address, vote choice, amount, fee, or relayer is not committed inside
   the proof, an observer can copy a valid proof from the mempool and redirect the outcome.
   SDF's Privacy Pools prototype shipped with exactly this gap.

2. **Nullifiers are persistent storage. Always.**
   A `temporary()` entry that expires re-opens a double-spend window. Every
   `storage().persistent()` call site in `occulta-merkle` carries a `// SECURITY: persistent()`
   comment and must not be changed without a security review.

3. **Effects before interactions.**
   The nullifier is marked spent *before* any token transfer. The token transfer is a
   cross-contract call; executing it first is a reentrancy hole. The mandatory ordering in
   `contracts/shielded-pool::withdraw` is:
   `is_known_root` → `!is_spent` → `verify` → `spend` → transfer.

4. **Root must be checked against the history buffer**, never only against the current root.
   The prover builds a Merkle path against a specific root. If a second depositor inserts a
   leaf before the first withdrawal lands, the current root changes and the proof becomes
   stale. `Tree::is_known_root` accepts any of the last `root_history_size` roots (default 30).

5. **Public signal count must equal `ic.len() - 1`**, enforced in the verifier.
   A mismatch means the caller is verifying a proof against the wrong circuit's VK — a hard
   error returned as `Err(PublicSignalCountMismatch)`, not a silent false.

6. **External nullifiers scope nullifiers to a context.**
   Without a domain separator (e.g. `poll_id`), a nullifier spent in one app blocks the same
   identity in every other app. Each application includes its own domain tag as a public signal.

7. **No admin key may silently change a VK an app depends on.**
   An admin who can swap a VK can mint proofs for any statement. `contracts/registry::freeze`
   makes a circuit's VK permanently immutable — after which no admin can change it.

8. **Scalars must be range-checked against the field modulus before use.**
   The Poseidon host silently reduces out-of-range inputs mod the field order, meaning two
   distinct-looking inputs can collide. `occulta_types::scalar_in_range` and
   `occulta-verifier::verify` both reject scalars `>= r` before any host call.

9. **Every panic path is a test.**
   Code that fails open is worse than code that fails closed. Every `panic!` branch in
   security-critical code has a test that exercises it.

---

## How each invariant is enforced

| # | Where enforced | Tests |
| --- | --- | --- |
| 1 | Each app contract binds all acted-upon values as public signals | Signal-permutation test per app |
| 2 | `occulta-merkle::Nullifiers` — `storage().persistent()` exclusively, `// SECURITY` comment at every call site | `spending_uses_persistent_storage` |
| 3 | `contracts/shielded-pool::withdraw` — mandatory five-step ordering | `withdraw_ordering_*` tests |
| 4 | `occulta-merkle::Tree::is_known_root` — ring buffer scan over last `root_history_size` roots | `root_history_keeps_last_n_roots` |
| 5 | `occulta-verifier::verify` — returns `Err(PublicSignalCountMismatch)` before any crypto | `public_signal_count_mismatch_is_an_error`, `zero_signals_*`, `too_many_signals_*` |
| 6 | Each app contract includes a domain-separator public signal | Per-app tests |
| 7 | `contracts/registry::freeze` — one-way flag, checked on every `register` call | `frozen_circuit_rejects_register_even_from_admin`, `frozen_circuit_stays_frozen_after_admin_change`, `freeze_twice_is_rejected` |
| 8 | `occulta_types::scalar_in_range` (called in poseidon sponge + verifier) | `scalar_equal_to_modulus_is_rejected` (×6), `out_of_range_bn254_signal_is_rejected`, `out_of_range_bls12_signal_is_rejected` |
| 9 | Every `panic!` / double-spend path | `double_spend_panics`, `hash_n_rejects_zero_inputs`, `hash_n_rejects_unsupported_arity`, `hash2_rejects_out_of_range_scalar` |

---

## TTL and archival

Soroban archives ledger entries whose TTL expires. Every write to persistent storage in
`occulta-merkle` is followed by a TTL extension:

```rust
env.storage().persistent().extend_ttl(&key, TREE_TTL, TREE_TTL);
// TREE_TTL = NULLIFIER_TTL = 6_000_000 ledgers ≈ 1 year at ~5 s/ledger
```

`NULLIFIER_TTL` is set equal to `TREE_TTL`. A nullifier whose TTL expires before the tree
entry would allow a double-spend if the nullifier entry were to be restored from archive
without its spent value. Keeping them equal eliminates that window.

Both constants are in `crates/occulta-merkle/src/lib.rs`.

---

## Budget and atomicity

A `withdraw` transaction that exhausts its instruction budget mid-way through the
checks-effects-interactions sequence — after `verify` but before `spend` — can be replayed.
The system is designed to keep the full path within the testnet's ~100M instruction budget:

| Component | Lower-bound estimate |
| --- | --- |
| `Poseidon::hash2` BN254 | 1,750,923 instructions (measured) |
| `Tree::insert` depth=20 | ~35M instructions (20 × hash2) |
| Groth16 `verify` BN254 | ~40M instructions (SDF reference measurement) |
| Full `withdraw` path | ~75–80M instructions |

See `docs/BUDGET.md` for measurement details.

---

## Scope of this document

This is a design record. It does not prove the cryptographic constructions are sound, verify
the Groth16 implementation is bug-free, or assess the Stellar/Soroban platform's security.
Any deployment holding real assets requires an independent security audit.
