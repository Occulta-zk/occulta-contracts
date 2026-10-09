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

## `fixtures/vote/` — real Groth16 proof, BN254

A Groth16 proof for `circuits/private_vote.circom` (depth-8 Poseidon Merkle membership plus
a per-poll nullifier, 5,195 constraints). Public signals, in order:
`[root, nullifier, choice, poll_id]`; this fixture has `choice = 1`, `poll_id = 42`.

| File | What it is |
| --- | --- |
| `vkey.json` | `snarkjs zkey export verificationkey` output |
| `proof.json` | `snarkjs groth16 prove` output |
| `public.json` | the four public signals |
| `proof_negative.json` | `proof.json` with the lowest bit of `pi_a.x` flipped |

`snarkjs groth16 verify` accepted `proof.json` and rejected `proof_negative.json`
("Proof commitments are not valid") before these files were committed;
`scripts/gen-fixtures.sh` refuses to write them otherwise.

**Toolchain:** circom 2.2.3 (`cargo install --git https://github.com/iden3/circom.git circom`),
snarkjs 0.7.5, circomlib 2.0.5, circomlibjs 0.1.7 (pinned in `circuits/package.json`).

**Trusted setup:** phase 1 is the published PSE Perpetual Powers of Tau, contribution #80,
prepared for 2^14:

- URL: <https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_14.ptau>
- sha256: `3ca1149e9349b22b0ee0649399cfb787677129b7b1189d1899fc0d615d9583db`

Phase 2 is a single local contribution with random entropy. That is fine for a test fixture
and **not** acceptable for anything holding value. (The Hermez `powersOfTau28_hez_final_*`
files that most tutorials link to now return 403.)

**Asserted by:** `crates/occulta-verifier/src/tests.rs`, module `fixture`. `proof.json`
verifies as `Ok(true)`; permuted signals, a changed `choice`, a changed `poll_id`, and an
on-curve wrong proof (`-A`) return `Ok(false)`. `proof_negative.json` does **not** return
`Ok(false)`: its `A` is off the curve, so the host traps with `bn254 G1: point not on curve`,
and the test asserts that trap.

**Regenerate:** `scripts/gen-fixtures.sh`. Phase-2 entropy and proof blinding are random, so
a rerun produces a different vkey/proof pair with the same public signals; commit all four
files together.

## Not yet covered

- No BLS12-381 proof fixture (`circom --prime bls12381` plus a BLS12-381 ptau). The
  BLS12-381 verifier path has structural tests only.
