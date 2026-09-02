// Generates Rust param tables + ground-truth fixtures for BLS12-381 Poseidon (t=2,3,4),
// using constants extracted (and cross-validated against soroban-env-host's own
// known-answer test) by extract_bls.mjs -- run that first, this reads bls12_extracted.json.
import fs from "node:fs";

const BLS_R = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const data = JSON.parse(fs.readFileSync("bls12_extracted.json", "utf8"));

function beHexToBig(hex) {
  return BigInt("0x" + hex);
}
function bigToBeHex(n) {
  n = ((n % BLS_R) + BLS_R) % BLS_R;
  let h = n.toString(16);
  while (h.length < 64) h = "0" + h;
  return h;
}
function powmod(base, exp, mod) {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}
const pow5 = (a) => powmod(a, 5n, BLS_R);

function permute(state, mds, rc, t, roundsFBeginning, roundsP) {
  let s = state.slice();
  const rounds = 2 * roundsFBeginning + roundsP;
  for (let r = 0; r < rounds; r++) {
    s = s.map((v, i) => (v + rc[r][i]) % BLS_R);
    if (r < roundsFBeginning || r >= roundsFBeginning + roundsP) {
      s = s.map((v) => pow5(v));
    } else {
      s[0] = pow5(s[0]);
    }
    s = s.map((_, i) => {
      let acc = 0n;
      for (let j = 0; j < t; j++) acc = (acc + mds[i][j] * s[j]) % BLS_R;
      return acc;
    });
  }
  return s;
}

function rustByteArray(hex) {
  const bytes = [];
  for (let i = 0; i < 64; i += 2) bytes.push("0x" + hex.slice(i, i + 2));
  return `[${bytes.join(", ")}]`;
}

let rustOut = `// GENERATED FILE. Do not hand-edit -- regenerate with scripts/poseidon-gen/gen_bls.mjs
// (which itself depends on extract_bls.mjs's output).
//
// Source: soroban-env-host v26.1.4, src/test/poseidon/poseidon_instance_bls12.rs -- these
// are the exact parameters SDF's own host implementation is tested against for CAP-75's
// BLS12-381 Poseidon path (t=2,3,4; t=8 also exists upstream but is out of scope here).
// mod.rs in that source tree cites the ultimate upstream source as HorizenLabs/poseidon2
// and hadeshash (https://extgit.iaik.tugraz.at/krypto/hadeshash), NOT circomlib -- circomlib
// itself has no native BLS12-381 Poseidon parameters (see docs/PLATFORM.md). Extraction was
// verified byte-for-byte against soroban-env-host's own hardcoded known-answer test for
// input [0,1,2] at t=3 -- see extract_bls.mjs.
//
// Field: BLS12-381 Fr. d = 5. rounds_f = 8 (4 beginning + 4 end) for every t below.


`;

const fixtures = {};
for (const t of [2, 3, 4]) {
  const mds = data[`MDS${t}`].map((row) => row.map(beHexToBig));
  const rc = data[`RC${t}`].map((row) => row.map(beHexToBig));
  const roundsP = 56;
  const roundsFBeginning = 4;

  rustOut += `\npub const BLS12_381_T${t}_ROUNDS_F: u32 = 8;\n`;
  rustOut += `pub const BLS12_381_T${t}_ROUNDS_P: u32 = ${roundsP};\n`;
  rustOut += `pub const BLS12_381_T${t}_MDS: [[u8; 32]; ${t * t}] = [\n`;
  for (let i = 0; i < t; i++)
    for (let j = 0; j < t; j++) rustOut += `    ${rustByteArray(bigToBeHex(mds[i][j]))}, // M[${i}][${j}]\n`;
  rustOut += `];\n`;

  rustOut += `pub const BLS12_381_T${t}_RC: [[u8; 32]; ${rc.length * t}] = [\n`;
  for (let r = 0; r < rc.length; r++)
    for (let c = 0; c < t; c++) rustOut += `    ${rustByteArray(bigToBeHex(rc[r][c]))},\n`;
  rustOut += `];\n`;

  // Fixture: our sponge convention, capacity=0 prepended, output=state[0].
  const nInputs = t - 1;
  const sampleSets = [];
  if (nInputs === 1) sampleSets.push([1n]);
  if (nInputs === 2) sampleSets.push([1n, 2n], [0n, 0n]);
  if (nInputs === 3) sampleSets.push([1n, 2n, 3n]);
  fixtures[`t${t}`] = sampleSets.map((inputs) => {
    const state = [0n, ...inputs];
    const out = permute(state, mds, rc, t, roundsFBeginning, roundsP);
    return { inputs: inputs.map((x) => x.toString()), output: "0x" + bigToBeHex(out[0]) };
  });
}

fs.writeFileSync("params_bls12.rs", rustOut);
fs.writeFileSync("fixtures_bls12.json", JSON.stringify(fixtures, null, 2));
console.log("wrote params_bls12.rs, fixtures_bls12.json");
console.log(JSON.stringify(fixtures, null, 2));
