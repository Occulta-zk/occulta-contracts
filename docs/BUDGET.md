# Instruction budget

**Placeholder — no numbers in this repo have been independently measured yet.** The build
spec cites an SDF-measured figure of ~40M instructions for a Groth16 verification
(~40% of testnet's per-transaction instruction budget); that number is attributed to an SDF
blog post, not reproduced here, and must not be repeated elsewhere in this repo as if it were
this project's own measurement until it is.

This file will carry, once each is implemented and measured against a real Soroban test
environment (`soroban-sdk`'s `testutils`, which exposes a budget/cost tracker):

| Operation | Measured instructions | Threshold (CI fails if regressed >10%) | Milestone |
| --- | --- | --- | --- |
| `occulta-poseidon::hash2` | not yet measured | TBD | M2 |
| `occulta-verifier::verify` (per public-signal count) | not yet measured | TBD | M3 |
| `occulta-merkle::Tree::insert` (per depth) | not yet measured | TBD | M4 |
| `verify` + `insert` + token transfer in one transaction (the `shielded-pool::withdraw` path) | not yet measured | TBD | M5+ |

Until real numbers land here, treat every budget claim about this repo's own contracts as
unverified.
