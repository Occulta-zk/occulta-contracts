# Encoding — snarkjs → Soroban, byte for byte

Every rule here is enforced (or will be, once the crate that needs it exists) somewhere in
code, with a named test. This document is the narrative version of `docs/PLATFORM.md`'s wire
formats — read that file for the verification method and source citations.

Status: rules 1 and 4 are implemented and tested today in `occulta-types` (`src/encoding.rs`,
`src/curve.rs`). Rules 2, 3 (the swap primitive itself is implemented and tested; its
end-to-end use against a real snarkjs proof is not yet wired up), and 5 depend on
`occulta-verifier` (M3) and real fixtures, which don't exist yet.

## 1. Field elements are 32-byte big-endian, reduced mod `r`

snarkjs emits public signals and scalars as decimal strings in JSON. The SDK layer
(`occulta-sdk`, out of scope for this repo) converts those to 32-byte big-endian on the way
into a transaction. **The contract must not trust that conversion was done correctly** — an
out-of-range scalar is silently reduced mod the field order by the Poseidon host function
(see the doc-comment warning quoted in `docs/PLATFORM.md`), which means two distinct-looking
inputs can collide. `occulta_types::scalar_in_range(scalar_be, modulus_be)` rejects anything
`>= r`. Implemented and tested: `crates/occulta-types/src/encoding.rs`.

## 2. G1 points: drop the Jacobian `z`, serialize `x || y`

snarkjs's `proof.json` gives G1 points as `[x, y, "1"]` — Jacobian coordinates where `z` is
always `"1"` for a normalized point. Soroban only accepts affine points, so: verify `z == 1`
(if it isn't, the point needs actual Jacobian-to-affine conversion, which shouldn't happen
for snarkjs's own output but must not be silently assumed), drop it, and concatenate
`be_bytes(x) || be_bytes(y)`, each coordinate zero-padded to the curve's field byte length —
**48 bytes for BLS12-381 (`Bls12381Fp`), 32 bytes for BN254 (`Bn254Fp`)** (verified in
`docs/PLATFORM.md`). This conversion happens off-chain in `occulta-sdk`; the contract-side
enforcement is `Proof::validate_shape()` / `VerificationKey::validate_shape()` checking the
resulting byte length matches `curve.g1_len()` (96 for BLS12-381, 64 for BN254).

## 3. G2 coordinate order is a trap — confirmed real, not hypothetical

snarkjs emits a G2 point as `[[x_c0, x_c1], [y_c0, y_c1], ["1", "0"]]` — `Fp2` coordinates
in `[c0, c1]` order, c0 first. **The Soroban host expects the opposite**: both
`Bls12381G2Affine` and `Bn254G2Affine`'s doc comments (quoted verbatim in
`docs/PLATFORM.md`) specify `be_bytes(X_c1) || be_bytes(X_c0) || be_bytes(Y_c1) ||
be_bytes(Y_c0)` — c1 first, within each of X and Y. Naively concatenating snarkjs's JSON
array order produces a byte string of the *correct length* that is *numerically the wrong
point* — the single most dangerous class of bug in this whole repo, because a malformed
length traps loudly but a swapped-limb point can pass a naive smoke test and only fail (or
worse, not fail) against a real fixture.

`occulta_types::swap_fp2_limbs(input, half_len, out)` performs exactly this swap:
`c0 || c1` (snarkjs order) → `c1 || c0` (host order). Tested for both round-trip
(`swap ∘ swap = identity`) and against a fabricated-but-structural known vector proving the
function doesn't degrade to a no-op copy. **Not yet tested against a real snarkjs-produced
proof point verified through an actual `pairing_check` call** — that end-to-end check is the
first thing `occulta-verifier` must do (flagged in that crate's module doc and in
`docs/PLATFORM.md`'s "Open items").

## 4. Point at infinity

Encoding: all-zero bytes for the coordinate portion, with the infinity flag bit set in the
first byte per the SDK's documented flag layout (top 3 bits of byte 0: compression,
infinity, sort — see `docs/PLATFORM.md`). `occulta_types::is_zero_bytes` detects the
all-zero payload; whether infinity is *accepted* is field-specific — e.g. `vk.alpha_g1`
should never legitimately be infinity for a real verification key, so `occulta-verifier`
(M3) must reject it there even though `is_zero_bytes` itself is a neutral predicate, not a
policy.

## 5. Reject invalid points / wrong subgroup — don't duplicate host work

Per `docs/PLATFORM.md`: `g1_add`'s SDK wrapper already re-validates subgroup membership of
its *result*, but a point built via `Bls12381G1Affine::from_bytes(...)` / passed straight
into `g1_msm`/`pairing_check` is not implicitly checked by construction — the host traps on
a genuinely invalid curve point, but subgroup membership needs an explicit
`is_in_subgroup()` call where the calling code path doesn't already get it for free. This is
an `occulta-verifier` (M3) concern, not `occulta-types`', since it requires an `Env` and a
host call; recorded here so the "which of rule 5's two checks is already free vs. must be
added" question isn't re-derived from scratch when M3 starts.
