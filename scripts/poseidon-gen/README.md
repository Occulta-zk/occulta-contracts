# poseidon-gen

Generates `crates/occulta-poseidon/src/params_{bn254,bls12}.rs` and
`fixtures/poseidon/{bn254,bls12_381}.json`. Not hand-typed data anywhere — every constant is
either extracted by parsing a vendored source file's literal text, or computed via a modular
exponentiation replica of the exact permutation algorithm, and cross-checked against a
known-answer test before being trusted. See `docs/PLATFORM.md` for how this fits the bigger
verification picture.

## Regenerating

```sh
cd scripts/poseidon-gen
npm install
node gen.mjs          # BN254: pulls circomlibjs's real circomlib constants + computes fixtures
node extract_bls.mjs  # BLS12-381: parses bls12_source.rs, self-checks against a known answer
node gen_bls.mjs       # BLS12-381: writes params_bls12.rs + fixtures_bls12.json from the above
cp params_bn254.rs params_bls12.rs ../../crates/occulta-poseidon/src/
cp fixtures_bn254.json ../../fixtures/poseidon/bn254.json
cp fixtures_bls12.json ../../fixtures/poseidon/bls12_381.json
```

`bls12_source.rs` is a **vendored snapshot** of
`soroban-env-host-26.1.4/src/test/poseidon/poseidon_instance_bls12.rs` (from the local Cargo
registry cache after `cargo fetch`ing `soroban-sdk = "26.1.1"` with the `hazmat-crypto`
feature — see `docs/PLATFORM.md`'s verification method). It is not fetched over the network
by this script because that crate isn't designed to be pulled as an npm/JS dependency; if you
bump the `soroban-sdk` pin, re-copy the file from your own registry cache and re-run
`extract_bls.mjs` — it will refuse to proceed (its self-check `process.exit(1)`s) if the
extracted constants don't reproduce the host's own hardcoded `[0,1,2]` test vector.

`gen.mjs` needs `circomlibjs` (an actual npm dependency, fetched fresh, not vendored) — it is
iden3's official JS reference implementation of circomlib, used here purely as a source of
ground truth, never linked into any shipped contract.
