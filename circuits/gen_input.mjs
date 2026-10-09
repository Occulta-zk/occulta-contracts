// Deterministic witness input for private_vote.circom (DEPTH = 8).
//
// Builds a depth-8 Poseidon Merkle tree over a handful of member leaves (empty slots are 0),
// takes member index 5 as the voter, and writes the circuit input JSON to argv[2].
// Every value is fixed so the fixture regenerates to the same public signals.
import { buildPoseidon } from "circomlibjs";
import { writeFileSync } from "node:fs";

const DEPTH = 8;
const VOTER_INDEX = 5;
const POLL_ID = 42n;
const CHOICE = 1n;

const poseidon = await buildPoseidon();
const F = poseidon.F;
const H = (a, b) => F.toObject(poseidon([a, b]));

// Member identities: (identity_nullifier, identity_trapdoor), fixed test values.
const members = Array.from({ length: 8 }, (_, i) => [1000n + BigInt(i), 2000n + BigInt(i)]);
const leaves = new Array(2 ** DEPTH).fill(0n);
members.forEach(([n, t], i) => { leaves[i] = H(n, t); });

let level = leaves;
const path_elements = [];
const path_indices = [];
let idx = VOTER_INDEX;
for (let d = 0; d < DEPTH; d++) {
  path_elements.push(level[idx ^ 1]);
  path_indices.push(idx & 1);
  const next = [];
  for (let i = 0; i < level.length; i += 2) next.push(H(level[i], level[i + 1]));
  level = next;
  idx >>= 1;
}
const root = level[0];

const [identity_nullifier, identity_trapdoor] = members[VOTER_INDEX];
const input = {
  root,
  nullifier: H(identity_nullifier, POLL_ID),
  choice: CHOICE,
  poll_id: POLL_ID,
  identity_nullifier,
  identity_trapdoor,
  path_elements,
  path_indices,
};
writeFileSync(process.argv[2], JSON.stringify(input, (_, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
