#!/usr/bin/env bash
# Regenerates fixtures/ from source circuits. Not yet functional — see fixtures/README.md.
#
# Prerequisites (none installed in the environment this scaffold was built in):
#   - node + npm (present)
#   - circom (NOT present — install via `cargo install --locked circom` or a prebuilt binary
#     from https://github.com/iden3/circom/releases)
#   - snarkjs (works via `npx snarkjs`, no global install needed)
#
# Intended flow, once circuits exist under a (not-yet-created) `circuits/` directory:
#   1. circom circuits/<name>.circom --r1cs --wasm --sym -o fixtures/<name>/
#   2. snarkjs groth16 setup fixtures/<name>/<name>.r1cs pot<k>_final.ptau fixtures/<name>/circuit_0000.zkey
#      (powers-of-tau ceremony file: use a public one, e.g. from the snarkjs "Perpetual Powers
#      of Tau" repo — do not generate a fresh untrusted-setup ceremony for anything but local dev)
#   3. snarkjs zkey export verificationkey fixtures/<name>/circuit_0000.zkey fixtures/<name>/vkey.json
#   4. node fixtures/<name>/<name>_js/generate_witness.js ... -> witness.wtns
#   5. snarkjs groth16 prove fixtures/<name>/circuit_0000.zkey witness.wtns fixtures/<name>/proof.json fixtures/<name>/public.json
#   6. snarkjs groth16 verify fixtures/<name>/vkey.json fixtures/<name>/public.json fixtures/<name>/proof.json
#      (must print OK before committing — an unverified proof fixture is worse than no fixture)
#   7. Flip one bit in a copy of proof.json -> fixtures/<name>/proof_negative.json, confirm
#      `snarkjs groth16 verify` rejects it, and commit that too.
#
# For fixtures/poseidon/: see docs/PLATFORM.md's note on depending on `soroban-poseidon`
# (stellar/rs-soroban-poseidon) rather than hand-deriving circomlib constants — resolve that
# question before writing this section.

set -euo pipefail
echo "gen-fixtures.sh: not yet implemented — circom is not installed in this environment." >&2
echo "See the comment block at the top of this script for the intended flow." >&2
exit 1
