# Instruction budget

All measurements use `soroban-sdk`'s `testutils` `Env` with `budget.reset_unlimited()`
called before the operation. This measures the `soroban-env-host` instruction model — it
excludes Wasm VM instantiation, ledger I/O, and XDR round-trips. Treat every number here as
a **lower bound**: on-chain costs in a deployed Wasm contract will be higher.

---

## Measured costs

| Operation | Measured instructions | 10% regression threshold |
| --- | --- | --- |
| `occulta-poseidon::Poseidon::hash2` — BN254, t=3 | **1,750,923** | 1,930,000 |

---

## `hash2` BN254 — detail

**1,750,923 CPU instructions** for one call to `Poseidon::hash2(env, Curve::Bn254, &a, &b)`.

Measurement source: `crates/occulta-poseidon/src/tests.rs`, test `budget_probe_hash2_bn254`.

```rust
let env = Env::default();
let mut budget = env.budget();
budget.reset_unlimited();
let a = U256::from_u32(&env, 1);
let b = U256::from_u32(&env, 2);
let _ = Poseidon::hash2(&env, Curve::Bn254, &a, &b).unwrap();
// prints: hash2(BN254) cpu_instruction_cost = 1750923
```

This covers the full cost of one `poseidon_permutation` host call with the BN254 t=3
parameter set, including construction of the MDS and round-constant `Vec<Vec<U256>>`
arguments from the compiled-in byte arrays. It does not include Wasm overhead.

---

## Budget context

`hash2` is the hot path for `occulta-merkle::Tree::insert`. A depth-20 tree insert requires
20 `hash2` calls, giving a lower-bound estimate of `20 × 1,750,923 ≈ 35M instructions` for
the Merkle hashing component alone.

SDF measured a full Groth16 verification at approximately **40 million instructions**
(~40% of the testnet per-transaction budget), documented in the SDF Privacy Pools prototype
writeup at stellar.org/blog/ecosystem/prototyping-privacy-pools-on-stellar. Combined, a
`shielded-pool::withdraw` — which runs verify + insert + token transfer — sits in the
**75–80M instruction range**, well within the ~100M testnet budget per transaction.

This is why the design constrains depth to 20–32 and one proof per transaction: the budget
is genuinely tight and these bounds keep the full withdraw path atomic.

---

## Measurement methodology

`soroban-sdk`'s testutils `Env` wraps the real `soroban-env-host` but omits:

- Wasm VM instantiation and bytecode parsing
- Ledger entry reads/writes
- XDR serialisation/deserialisation
- Contract-to-contract call overhead

These numbers are regression signals — a code change that doubles `hash2` cost will be
caught here. For a definitive "does this fit in one transaction" answer, use
`stellar contract invoke --cost` against a live testnet or local validator with a deployed
Wasm binary.
