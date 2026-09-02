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

**Resolved in M2, decided rather than left silent:** `occulta-poseidon` does **not** depend
on `soroban-poseidon` — it wasn't on crates.io at verification time (GitHub-only), and a
better option existed: sourcing constants mechanically rather than depending on a crate with
its own unverified provenance claims. See "How occulta-poseidon actually got its parameters"
below.

### How occulta-poseidon actually got its parameters (M2)

Two independent, mechanically-verified sources, not one crate trusted wholesale:

- **BN254**: real circomlib constants, extracted from the `circomlibjs` npm package (iden3's
  own JS reference implementation of circomlib) — `scripts/poseidon-gen/gen.mjs` reads
  `circomlibjs/src/poseidon_constants.json` directly and replicates
  `circomlibjs/src/poseidon_reference.js`'s exact algorithm to compute fixture outputs.
- **BLS12-381**: circomlib has no native BLS12-381 parameters (confirmed above), so
  `occulta-poseidon` instead uses **soroban-env-host's own CAP-75 conformance test
  vectors** (`soroban-env-host-26.1.4/src/test/poseidon/poseidon_instance_bls12.rs`, cited by
  that file's own `mod.rs` as sourced from HorizenLabs/poseidon2 and hadeshash) —
  `scripts/poseidon-gen/extract_bls.mjs` parses the literal hex constants out of that file's
  text (never hand-retyped) and self-checks its own algorithm replica against that file's
  hardcoded `[0,1,2]` known-answer test before anything downstream trusts it.

**A genuine discrepancy was found and is worth recording**: circomlib's own BN254 Poseidon
parameters for `t=3` (2 inputs) use `rounds_p=57`, while `soroban-env-host`'s own BN254 test
parameters for the same `t=3` use `rounds_p=56` — a real, load-bearing difference (different
round count means a different, incompatible permutation entirely), not a rounding artifact.
This means: **a circuit written against circomlib's actual Poseidon will not verify against
`poseidon_permutation` called with SDF's own `POSEIDON_BN_PARAMS`** — you need circomlib's
own constants (which is what `occulta-poseidon` uses for BN254). Always confirm which
"reference" a parameter set actually claims before trusting a name like "Poseidon params" —
see `crates/occulta-poseidon/src/params_bn254.rs`'s header comment for the full citation
chain, and `scripts/poseidon-gen/README.md` for how to reproduce this from scratch.

Every fixture value in `fixtures/poseidon/` was computed independently of the Rust
implementation it's tested against (JS reference algorithm, or extraction + a from-scratch JS
re-implementation of the round function) and then asserted against the **actual**
`soroban-env-host` (via `soroban-sdk`'s `testutils::Env`, not a mock) in
`crates/occulta-poseidon/src/tests.rs` — 16 tests, all green as of this writing. Coverage is
scoped to `t ∈ {2,3,4}` (1–3 inputs) on both curves; see that crate's module doc for how to
widen it.

## Instruction budget

`occulta-poseidon::hash2` (BN254, t=3) measured at **1,750,923 CPU instructions** via
`soroban-sdk` testutils. See `docs/BUDGET.md` for full details and methodology.
