# Fixtures

**Empty as of this writing.** This directory is the differential-test backbone required by
`CONTRIBUTING.md`: no cryptographic change is merged without a fixture proving it matches a
reference implementation (circomlib / snarkjs).

Generating real fixtures requires `circom` and `snarkjs` (Node), neither of which is
installed in the environment this scaffold was built in — `npx snarkjs --version` works
(resolves the package on demand), `circom` does not (`cargo install circom` or a prebuilt
binary is needed). Installing and wiring up `circom` is tracked as a prerequisite for M2.

## Planned layout

- `fixtures/poseidon/` — circomlib input/output vectors, one file per `(field, t)` parameter
  set in `occulta-poseidon`'s table. Each vector: input field elements, expected output,
  and a comment citing the circomlib source file + commit hash the constants came from (see
  `docs/PLATFORM.md`'s note on the `soroban-poseidon` dependency decision — if that crate is
  used, cite it here as the source instead of re-deriving from circomlib directly).
- `fixtures/vote/` — `circuit.r1cs` metadata, `vkey.json`, `proof.json`, `public.json` for
  `apps/private-vote`'s circuit, produced by `snarkjs groth16 setup` / `snarkjs groth16
  prove`. Plus one negative fixture: the same proof with one bit flipped in `proof.a`,
  which must fail verification.

`scripts/gen-fixtures.sh` will regenerate all of this from source circuits once they exist;
it is currently a stub (see that file) documenting the exact commands it will run, so a
contributor with `circom`/`snarkjs` installed can reproduce every byte by hand in the
meantime.
