# Fixtures

The differential-test backbone required by `CONTRIBUTING.md`: no cryptographic change is
merged without a fixture proving it matches a reference implementation.

## `fixtures/poseidon/` — done (M2)

`bn254.json` and `bls12_381.json`: input/output vectors, generated (never hand-typed) by
`scripts/poseidon-gen/` — see that directory's README for exact provenance (real `circomlibjs`
for BN254, `soroban-env-host`'s own CAP-75 conformance vectors for BLS12-381) and how to
reproduce every byte. Asserted against the real Soroban host implementation in
`crates/occulta-poseidon/src/tests.rs` (also generated, from these same JSON files, by
`scripts/poseidon-gen/gen_tests.mjs`).

## `fixtures/vote/` — not yet real (blocked on `circom`)

Planned: `circuit.r1cs` metadata, `vkey.json`, `proof.json`, `public.json` for
`apps/private-vote`'s circuit, produced by `snarkjs groth16 setup` / `snarkjs groth16 prove`,
plus a negative fixture (one bit flipped in `proof.a`) that must fail verification.

**Not done — `circom` is not installed in this environment**, and compiling a real circuit to
R1CS needs it (`npx snarkjs` alone isn't enough; snarkjs proves/verifies, it doesn't compile
circuits). `occulta-verifier`'s M3 fixture instead uses a **synthetic, algebraically valid
Groth16 instance** constructed directly from curve arithmetic (see
`crates/occulta-verifier/src/tests.rs` and its module doc for exactly how, and what this does
and does not prove) — it is not a substitute for a real snarkjs-produced proof and does not
close this gap. `scripts/gen-fixtures.sh` documents the exact commands to run once `circom`
is available.
