#!/usr/bin/env bash
# Regenerates fixtures/vote/ from circuits/private_vote.circom.
#
# Prerequisites:
#   - circom 2.2.x   cargo install --git https://github.com/iden3/circom.git circom
#   - node 20+ / npm (snarkjs, circomlib and circomlibjs are pinned in circuits/package.json)
#
# The Powers of Tau file is a published ceremony, never generated here: PSE Perpetual Powers
# of Tau, contribution #80, prepared for 2^14 constraints. It is downloaded once into
# circuits/build/ and checked against a pinned sha256.
#
# Phase-2 contribution entropy and the proof's blinding factors are random, so every run
# produces a different (but equally valid) vkey/proof pair. The public signals are fixed by
# circuits/gen_input.mjs and do not change between runs.
#
# Nothing is written to fixtures/vote/ unless `snarkjs groth16 verify` accepts the proof AND
# rejects the bit-flipped negative fixture.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUITS="$ROOT/circuits"
BUILD="$CIRCUITS/build"
OUT="$ROOT/fixtures/vote"

PTAU_URL="https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_14.ptau"
PTAU_SHA256="3ca1149e9349b22b0ee0649399cfb787677129b7b1189d1899fc0d615d9583db"
PTAU="$BUILD/ppot_0080_14.ptau"

# snarkjs 0.7.5 exits 0 even when it logs [ERROR] (e.g. "circuit too big for this power of
# tau ceremony"), so exit codes alone cannot be trusted. Fail on any [ERROR] line instead.
snarkjs() {
  local log
  log="$(cd "$CIRCUITS" && npx --no-install snarkjs "$@" 2>&1)" || { echo "$log" >&2; return 1; }
  echo "$log"
  if grep -q '\[ERROR\]' <<<"$log"; then return 1; fi
}

# For `groth16 verify`, only the literal success line counts.
groth16_verifies() { snarkjs groth16 verify "$@" | grep -q 'snarkJS.*OK!'; }

command -v circom >/dev/null || { echo "circom not found; see the header of this script" >&2; exit 1; }
echo "circom: $(circom --version)"

mkdir -p "$BUILD"
(cd "$CIRCUITS" && npm ci --no-audit --no-fund --silent)

if [ ! -f "$PTAU" ]; then
  echo "downloading $PTAU_URL"
  curl -sSfL -o "$PTAU.part" "$PTAU_URL"
  mv "$PTAU.part" "$PTAU"
fi
echo "$PTAU_SHA256  $PTAU" | sha256sum -c -

# 1. Compile.
(cd "$CIRCUITS" && circom private_vote.circom --r1cs --wasm --sym -o build)
snarkjs r1cs info build/private_vote.r1cs

# 2. Phase-2 setup: one contribution on top of the published ceremony.
snarkjs groth16 setup build/private_vote.r1cs "$PTAU" build/vote_0000.zkey
snarkjs zkey contribute build/vote_0000.zkey build/vote_final.zkey \
  --name="occulta fixture" -e="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
snarkjs zkey verify build/private_vote.r1cs "$PTAU" build/vote_final.zkey
snarkjs zkey export verificationkey build/vote_final.zkey build/vkey.json

# 3. Witness + proof.
(cd "$CIRCUITS" && node gen_input.mjs build/input.json)
(cd "$CIRCUITS" && node build/private_vote_js/generate_witness.js \
  build/private_vote_js/private_vote.wasm build/input.json build/witness.wtns)
snarkjs groth16 prove build/vote_final.zkey build/witness.wtns build/proof.json build/public.json

# 4. The proof must verify.
groth16_verifies build/vkey.json build/public.json build/proof.json \
  || { echo "FATAL: snarkjs did not accept the proof" >&2; exit 1; }
echo "proof accepted by snarkjs"

# 5. Negative fixture: flip the lowest bit of proof.pi_a's x coordinate. snarkjs must reject.
node -e '
  const fs = require("fs");
  const p = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  p.pi_a[0] = (BigInt(p.pi_a[0]) ^ 1n).toString();
  fs.writeFileSync(process.argv[2], JSON.stringify(p, null, 1) + "\n");
' "$BUILD/proof.json" "$BUILD/proof_negative.json"
if groth16_verifies build/vkey.json build/public.json build/proof_negative.json; then
  echo "FATAL: snarkjs accepted the bit-flipped proof" >&2
  exit 1
fi
echo "negative fixture rejected, as required"

# 6. Only now publish.
mkdir -p "$OUT"
cp "$BUILD"/{vkey.json,proof.json,public.json,proof_negative.json} "$OUT/"
echo "wrote $OUT: $(ls "$OUT" | tr '\n' ' ')"
