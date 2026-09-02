// Extracts BLS12-381 Poseidon MDS/RC constants from soroban-env-host v26.1.4's own test
// fixture source (bls12_source.rs, a verbatim copy of
// src/test/poseidon/poseidon_instance_bls12.rs, cited in docs/PLATFORM.md), by parsing the
// literal `from_hex("0x...")` string constants out of the Rust source text -- no re-typing,
// no arithmetic, pure text extraction, so there is no transcription-error surface. Then
// replicates soroban-env-host's own `Poseidon::permutation` algorithm (read directly from
// src/crypto/poseidon/poseidon.rs, cited below) in JS to compute an independent output for
// the exact input the host's own unit test uses ([0,1,2], t=3), and asserts it matches that
// test's hardcoded expected output byte-for-byte. A match proves both (a) the constants were
// extracted correctly and (b) this script's algorithm matches the real host implementation.
import fs from "node:fs";

const src = fs.readFileSync("bls12_source.rs", "utf8");
const BLS_R = 52435875175126190479447740508185965837690552500527637822603658699938581184513n;

function extractBlock(varName) {
  const re = new RegExp(`pub static ref ${varName}:[^=]*=\\s*vec!\\[([\\s\\S]*?)\\n    \\];`, "m");
  const m = src.match(re);
  if (!m) throw new Error(`block ${varName} not found`);
  const hexes = [...m[1].matchAll(/0x([0-9a-fA-F]{64})/g)].map((x) => x[1]);
  return hexes;
}

function toRows(flatHexes, width) {
  const rows = [];
  for (let i = 0; i < flatHexes.length; i += width) rows.push(flatHexes.slice(i, i + width));
  return rows;
}

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
function pow5(a) {
  return powmod(a, 5n, BLS_R);
}

// t=3 params, as shipped by soroban-env-host: t=3, d=5, rounds_f=8 (4 beginning + 4 end),
// rounds_p=56 -- these are the ACTUAL fields read from POSEIDON_BLS_3_PARAMS's constructor
// call in the source file (grep it below to confirm rather than trust this comment).
const ctorLine = src.match(/POSEIDON_BLS_3_PARAMS[\s\S]*?PoseidonParams::new_unchecked\(([\s\S]*?)\)\)/);
console.log("POSEIDON_BLS_3_PARAMS ctor:", ctorLine ? ctorLine[1].replace(/\s+/g, " ") : "NOT FOUND");

const MDS3 = toRows(extractBlock("MDS3"), 3).map((row) => row.map(beHexToBig));
const RC3 = toRows(extractBlock("RC3"), 3).map((row) => row.map(beHexToBig));
console.log("MDS3 rows:", MDS3.length, "RC3 rows:", RC3.length);

function permute(state, mds, rc, t, roundsFBeginning, roundsP) {
  let s = state.slice();
  const rounds = 2 * roundsFBeginning + roundsP;
  for (let r = 0; r < rounds; r++) {
    // add round constants
    s = s.map((v, i) => (v + rc[r][i]) % BLS_R);
    // sbox
    if (r < roundsFBeginning || r >= roundsFBeginning + roundsP) {
      s = s.map((v) => pow5(v));
    } else {
      s[0] = pow5(s[0]);
    }
    // MDS mix
    s = s.map((_, i) => {
      let acc = 0n;
      for (let j = 0; j < t; j++) acc = (acc + mds[i][j] * s[j]) % BLS_R;
      return acc;
    });
  }
  return s;
}

const out = permute([0n, 1n, 2n], MDS3, RC3, 3, 4, 56);
const outHex = out.map(bigToBeHex);
console.log("computed:", outHex);

const expected = [
  "200e6982ac00df8fa65cef1fde9f21373fdbbfd98f2df1eb5fa04f3302ab0397",
  "2233c9a40d91c1f643b700f836a1ac231c3f3a8d438ad1609355e1b7317a47e5",
  "2eae6736db3c086ad29938869dedbf969dd9804a58aa228ec467b7d5a08dc765",
];
const ok = JSON.stringify(outHex) === JSON.stringify(expected);
console.log(ok ? "MATCH -- extraction + algorithm both confirmed correct" : "MISMATCH -- do not proceed");
if (!ok) process.exit(1);

// Now extract t=2 and t=4 the same way, for our own parameter table.
const out2 = {
  MDS2: toRows(extractBlock("MDS2"), 2),
  RC2: toRows(extractBlock("RC2"), 2),
  MDS4: toRows(extractBlock("MDS4"), 4),
  RC4: toRows(extractBlock("RC4"), 4),
  MDS3: toRows(extractBlock("MDS3"), 3),
  RC3: toRows(extractBlock("RC3"), 3),
};
fs.writeFileSync("bls12_extracted.json", JSON.stringify(out2));
console.log("wrote bls12_extracted.json; row counts:",
  Object.fromEntries(Object.entries(out2).map(([k, v]) => [k, v.length])));
