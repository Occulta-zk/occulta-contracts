# Security model

Status: testnet only, unaudited. This document records the invariants this repo is designed
around and is not itself an audit. See the root `README.md` status banner.

## Invariants

These are copied verbatim from the build spec (§6) that this repo is built against. Every
deviation from one of these requires flagging before merge, not just a code comment.

1. **Everything the transaction acts on must be a public signal bound into the proof.** If
   the recipient address is not in the proof, an observer copies a valid proof out of the
   mempool and redirects the payout. SDF's Privacy Pools prototype shipped with exactly this
   gap and documented it as unfinished. Applies equally to `choice`, `amount`, `fee`, and
   `relayer`.
2. **Nullifiers are persistent storage. Always.**
3. **Effects before interactions.** Nullifier marked spent before any token transfer.
4. **Root must be checked against the history buffer**, never only against the current root.
5. **Public signal count must equal `ic.len() - 1`,** enforced in the verifier, not the app.
6. **External nullifiers scope nullifiers to a context.** Without a `poll_id`-style domain
   separator, one nullifier spent in app A blocks the same identity in app B.
7. **No admin key may silently change a VK an app depends on.** Apps requiring trustlessness
   must reference a frozen circuit.
8. **Scalars must be range-checked** against the field modulus before use.
9. **Every panic path is a test.** An app that fails open is worse than one that fails.

## Implementation status against each invariant

| # | Status |
| --- | --- |
| 1 | Not yet applicable — no app contracts exist yet (M6/M7). Each app's README will carry the public-signal table required by build-spec §5 when it lands. |
| 2 | Not yet applicable — `occulta-merkle`'s `Nullifiers` module is unimplemented (M4). When written, the persistent-storage requirement will be enforced with a comment at the storage call site per the build spec, and a test that a nullifier survives a simulated TTL-expiry window that would kill a `temporary()` entry. |
| 3 | Not yet applicable — `contracts/shielded-pool::withdraw`'s five-step ordering is unimplemented (M5+). |
| 4 | Not yet applicable — `occulta-merkle::Tree`'s root-history ring buffer is unimplemented (M4). |
| 5 | Not yet applicable — enforced by `occulta-verifier::verify` (M3); `occulta_types::VerificationKey::expected_public_signal_count()` exists today as the building block a future `verify()` will compare against `public_signals.len()`. |
| 6 | Not yet applicable — `poll_id`-style external nullifiers land with `apps/private-vote` (M6). |
| 7 | Not yet applicable — `contracts/registry::freeze` is unimplemented (M5). |
| 8 | **Implemented today.** `occulta_types::scalar_in_range` — see `docs/ENCODING.md` rule 1 and `crates/occulta-types/src/encoding.rs` tests. |
| 9 | Ongoing discipline, not a single implementation — tracked per-milestone as each panic path lands. |

## TTL / archival

Soroban archives ledger entries whose TTL expires. Nullifier and Merkle-tree state must have
their TTL bumped on every write (build spec §4.4) — a contract whose state gets archived
mid-life is, per the build spec, "a usability failure at best and a soundness failure at
worst" (an archived nullifier that later gets restored must still read as spent). This is
called out here as a requirement to implement in M4, not yet implemented.

## Instruction budget as a security property

SDF measured a Groth16 verification at ~40M instructions (~40% of testnet's per-transaction
budget, per the build spec — not independently re-measured in this repo yet). A contract
whose `verify` + `insert` + transfer doesn't fit in one transaction isn't insecure in the
cryptographic sense, but a design that can't complete its checks-effects-interactions
sequence atomically because it runs out of budget partway through is a soundness risk in
practice. `docs/BUDGET.md` will carry real measured numbers starting at M3.
