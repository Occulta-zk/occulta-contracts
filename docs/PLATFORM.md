# Platform facts — verified

This file records the exact, verified `soroban-sdk` bindings this repo is built against.
**Every fact below was checked against the actual published crate source, not assumed.**
Verification method: `cargo fetch`'d `soroban-sdk = "26.1.1"` with `features = ["hazmat-crypto"]`
into a scratch crate and read the vendored source directly from the local Cargo registry
cache (`~/.cargo/registry/src/index.crates.io-*/soroban-sdk-26.1.1/src/crypto/`), cross-checked
against CAP-0059, CAP-0074 and CAP-0075 on `stellar/stellar-protocol`. Checked 2026-09-02.

Pin this exact version in the workspace `Cargo.toml`. If you bump it, re-run this
verification before trusting anything below — CAP-75 was only finalized 2025-10-08, this
API is young, and method names have already changed once (`multi_pairing_check` at the CAP
level is exposed as `pairing_check` at the SDK level — see below).

## soroban-sdk version

- **Pinned: `26.1.1`** (latest publish on crates.io as of verification date; `26.1.0` appears
  in some third-party writeups but is not what `cargo fetch` resolves — always trust the
  registry over blog posts).
- Requires the `hazmat-crypto` feature to reach Poseidon/Poseidon2 (see below). BLS12-381 and
  BN254 curve operations need no feature flag — they're on the plain `Crypto` struct.

## BLS12-381 (CAP-59, Protocol 22) — `soroban_sdk::crypto::bls12_381`

Accessed via `env.crypto().bls12_381()` → `Bls12_381`. No feature flag required.

| SDK method | Notes |
| --- | --- |
| `g1_add(&self, p0: &Bls12381G1Affine, p1: &Bls12381G1Affine) -> Bls12381G1Affine` | |
| `g1_mul(&self, p0: &Bls12381G1Affine, scalar: &Bls12381Fr) -> Bls12381G1Affine` | |
| `g1_msm(&self, vp: Vec<Bls12381G1Affine>, vs: Vec<Bls12381Fr>) -> Bls12381G1Affine` | use this for `vk_x`, not a loop of `g1_mul` |
| `g1_is_in_subgroup(&self, p: &Bls12381G1Affine) -> bool` | also on `Bls12381G1Affine::is_in_subgroup(&self)` |
| `map_fp_to_g1`, `hash_to_g1` | present; g2 equivalents (`g2_add`, `g2_mul`, `g2_msm`, `g2_is_in_subgroup`, `map_fp2_to_g2`, `hash_to_g2`) mirror the g1 API |
| `pairing_check(&self, vp1: Vec<Bls12381G1Affine>, vp2: Vec<Bls12381G2Affine>) -> bool` | **not** `multi_pairing_check` — that's the CAP-level/host export name only. Internally calls host fn `bls12_381_multi_pairing_check`. Wraps to true iff product of pairings == 1 in F_p12. |
| `fr_add`, `fr_sub`, `fr_mul`, `fr_pow(&self, lhs: &Fr, rhs: u64) -> Fr`, `fr_inv` | on `Bls12381Fr` |

**IMPORTANT — g1_add auto-validates subgroup membership of its *result*** (calls
`bls12_381_check_g1_is_in_subgroup` internally after add in the SDK wrapper) but a point
constructed via `Bls12381G1Affine::from_bytes(...)` and passed directly into `g1_msm` /
`pairing_check` is **not** implicitly checked by that constructor — `from_bytes` doc says
explicitly: *"does not validate the contents — it accepts any 96 bytes"*; invalid points
"cause the host call to trap, not construction." So: malformed points trap the whole
transaction (safe-by-panic), but subgroup membership of a proof's `A`/`B`/`C` points supplied
externally is **not guaranteed on construction** — `occulta-verifier` must call
`is_in_subgroup()` explicitly wherever the host call itself doesn't already trap on it. This
needs a targeted test per point (see `occulta-verifier` test plan) — do not assume.

### Encoding (verified from doc comments in `crypto/bls12_381.rs`)

- `Bls12381G1Affine`: `BytesN<96>`, uncompressed, `be_bytes(X) || be_bytes(Y)`, each Fp coord
  is 48 bytes. Top 3 bits of first byte are flags: compression (must be 0, only uncompressed
  supported), infinity, sort (must be 0). Infinity point: all-zero except infinity flag bit.
- `Bls12381G2Affine`: `BytesN<192>`, uncompressed, **`be_bytes(X_c1) || be_bytes(X_c0) ||
  be_bytes(Y_c1) || be_bytes(Y_c0)`** — c1 before c0. **snarkjs emits `[[x_c0,x_c1],[y_c0,y_c1]]`
  — c0 first.** This is the documented "G2 coordinate order trap" from the build spec,
  confirmed real: converting a snarkjs G2 point to SDK wire format requires **swapping c0/c1
  within each coordinate**, not just concatenating in JSON order. See `docs/ENCODING.md`.

## BN254 (CAP-74, Protocol 25) — `soroban_sdk::crypto::bn254`

Accessed via `env.crypto().bn254()` → `Bn254`. No feature flag required.

| SDK method | Notes |
| --- | --- |
| `g1_add`, `g1_mul`, `g1_msm` | same shape as BLS12-381 |
| `pairing_check(&self, vp1: Vec<Bn254G1Affine>, vp2: Vec<Bn254G2Affine>) -> bool` | wraps host `bn254_multi_pairing_check` |
| `fr_add`, `fr_sub`, `fr_mul`, `fr_pow`, `fr_inv` | on `Bn254Fr` |

### Encoding

- `Bn254G1Affine`: `BytesN<64>`, uncompressed, `be_bytes(X) || be_bytes(Y)`, 32-byte coords.
- `Bn254G2Affine`: `BytesN<128>`, uncompressed, each coordinate is `be_bytes(c1) || be_bytes(c0)`
  — same c1-before-c0 trap as BLS12-381. Aligns with EIP-197 convention, which is why circom's
  default BN254 output is close to but **not byte-identical** to what the host expects —
  the coordinate swap is still required. Confirm empirically against a known-good fixture
  before trusting this description in `verify()`.

**Note:** CAP-74 lists only 3 raw host functions (`bn254_g1_add`, `bn254_g1_mul`,
`bn254_multi_pairing_check`); the SDK additionally exposes `g1_msm` and Fr arithmetic as
convenience wrappers built from those primitives — this is an SDK-level, not CAP-level,
guarantee. Cite the SDK, not the CAP, when referring to `g1_msm`/`fr_*` for BN254.

## Poseidon / Poseidon2 (CAP-75, Protocol 25) — `soroban_sdk::crypto::CryptoHazmat`

**Gated behind the `hazmat-crypto` Cargo feature** on `soroban-sdk` (the struct and the `Env`
accessor `crypto_hazmat()` are both `pub(crate)` unless that feature — or `cfg(test)` — is
enabled; verified by reading `env.rs` line 350-364 and `crypto.rs`). Accessed via
`env.crypto_hazmat().poseidon_permutation(...)` / `.poseidon2_permutation(...)`.

```rust
pub fn poseidon_permutation(
    &self,
    input: &Vec<U256>,
    field: Symbol,          // "BLS12_381" or "BN254" — a Symbol, not an integer 0/1
    t: u32,
    d: u32,                 // 5 for BLS12-381 and BN254
    rounds_f: u32,
    rounds_p: u32,
    mds: &Vec<Vec<U256>>,               // t×t MDS matrix — CALLER SUPPLIES THIS
    round_constants: &Vec<Vec<U256>>,   // (rounds_f+rounds_p)×t — CALLER SUPPLIES THIS
) -> Vec<U256>

pub fn poseidon2_permutation(
    &self, input: &Vec<U256>, field: Symbol, t: u32, d: u32, rounds_f: u32, rounds_p: u32,
    mat_internal_diag_m_1: &Vec<U256>,  // length t — CALLER SUPPLIES THIS
    round_constants: &Vec<Vec<U256>>,
) -> Vec<U256>
```

**This corrects an assumption in the original build spec.** The spec described `field` as
taking numeric params `0`/`1`; it is actually a `Symbol` (`"BLS12_381"` / `"BN254"`). More
importantly, **the host does not embed circomlib's MDS matrix or round constants** — the
*caller* passes the full MDS matrix and round-constant matrix on every call. This means
`occulta-poseidon`'s parameter table is not just `(t, d, rounds_f, rounds_p)` scalars, it is
the **entire constant matrices**, sourced from circomlib, transcribed exactly. This is a
larger and higher-risk surface than the original spec anticipated. `t ∈ {2,3,4,8,12,16,20,24}`
is the supported set for Poseidon2 per the doc comment; Poseidon (non-2) doesn't state a
restricted set in the doc but should be tested per value actually used.

**Doc-comment warning worth repeating verbatim** (from `crypto.rs`): *"All `U256` values
(`input`, `mds`/`mat_internal_diag_m_1`, `round_constants`) are generic representations of
field elements... If a `U256` value exceeds the field modulus, it is silently reduced mod the
field order. Two distinct `U256` inputs that reduce to the same field element will produce
the same output... Callers must ensure inputs are already in the valid field range."` —
`occulta-poseidon` must range-check every input before calling the permutation; the host will
not catch an out-of-range scalar for you.

### Major finding: an official sponge implementation already exists

SDF publishes **`stellar/rs-soroban-poseidon`** (crate name `soroban-poseidon`, Apache-2.0,
not yet on crates.io as of verification — GitHub dependency only), which the SDK's own doc
comment on `poseidon_permutation` points to: *"For safe, user-friendly hash functions, use
`rs-soroban-poseidon` instead, which provides input validation and standard hash
constructions."* It ships parameter tables for:

- Poseidon: BN254 t=2..6 and BLS12-381 t=2..6 (1–5 inputs)
- Poseidon2: BN254 t=2..4 and BLS12-381 t=2..4

Its BN254 Poseidon parameters are stated to match circomlib directly. Its BLS12-381
parameters are **self-generated** (circomlib has no native BLS12-381 Poseidon params),
matching the `poseidon-bls12381-circom` project instead of circomlib proper.

**Decision needed before M2, flagged rather than decided silently:** `occulta-poseidon`
should most likely depend on `soroban-poseidon` for the constant tables and possibly the
sponge construction itself (citing it as the source, per the "do not vendor circomlib
constants without citing source" rule — citing an SDF-reviewed crate is materially safer
than a fresh hand-transcription), rather than re-deriving circomlib's round constants by
hand. This still requires our own differential fixture tests — depending on the crate does
not remove the "byte-identical to circomlib" verification requirement, it only removes the
transcription-error risk. This is a scope/dependency decision, not a cryptographic one, but
it changes `occulta-poseidon`'s Cargo.toml and is called out here for sign-off before M2
starts.

## Instruction budget

Not yet independently measured in this repo (`docs/BUDGET.md` is a placeholder until M3+
land real `verify()`/`hash2`/`insert` code against a local Soroban test environment). The
spec's cited figure (~40M instructions for a Groth16 verification, ~40% of testnet's
per-transaction budget) is attributed to an SDF blog post, not verified firsthand here —
treat it as a planning estimate until `docs/BUDGET.md` has measured numbers.

## Open items for the next session

1. Confirm exact G1/G2/Fr encoding for BN254 against a real snarkjs-produced proof fixture
   (the c1||c0 vs c0||c1 swap above is read from doc comments, not yet round-tripped through
   an actual pairing check — do that before shipping `occulta-verifier`).
2. Decide + record the `soroban-poseidon` dependency question above.
3. `stellar` CLI and `circom` are not installed in this environment yet; needed for
   `contract build` in CI and for `scripts/gen-fixtures.sh` respectively.
