# Encoding — snarkjs → Soroban, byte for byte

This document describes the byte-level conversion rules between snarkjs JSON output and the
Soroban host's wire formats. Each rule is enforced in code with a named test. The source of
truth for byte lengths and flag layouts is `docs/PLATFORM.md`, which records verified SDK
bindings from `soroban-sdk 26.1.1`.

---

## Rule 1 — Field elements: 32-byte big-endian, reduced mod `r`

snarkjs emits public signals and scalars as decimal strings. The off-chain SDK converts them
to 32-byte big-endian before building the transaction. Contracts must not trust that
conversion — the Poseidon host silently reduces out-of-range values mod the field order,
meaning two distinct-looking inputs can collide if either is `>= r`.

**Enforcement:** `occulta_types::scalar_in_range(scalar_be, modulus_be)` rejects any value
`>= r`. Called in `occulta-poseidon`'s sponge and in `occulta-verifier::verify` on every
public signal before any host call.

**Tests:** `scalar_zero_is_in_range`, `scalar_equal_to_modulus_is_rejected`,
`scalar_one_more_than_modulus_is_rejected`, `scalar_one_less_than_modulus_is_in_range`,
`max_32_byte_value_exceeds_both_moduli`, `out_of_range_bn254_signal_is_rejected`,
`out_of_range_bls12_signal_is_rejected`.

---

## Rule 2 — G1 points: drop the Jacobian `z`, serialize `x ‖ y`

snarkjs `proof.json` gives G1 points as `[x, y, "1"]` — Jacobian form with `z = 1` for a
normalized point. Soroban accepts affine points only. The `z` coordinate is dropped and the
point is serialized as `be_bytes(x) ‖ be_bytes(y)`, each coordinate zero-padded to the
curve's field byte length:

- **BLS12-381:** 48 bytes per coordinate → 96 bytes total (`Bls12381G1Affine: BytesN<96>`)
- **BN254:** 32 bytes per coordinate → 64 bytes total (`Bn254G1Affine: BytesN<64>`)

**Enforcement:** `Proof::validate_shape()` and `VerificationKey::validate_shape()` check
that the byte length matches `curve.g1_len()`.

**Tests:** `correctly_sized_bn254_proof_validates`, `correctly_sized_bls12_381_proof_validates`,
`bn254_a_sized_for_bls12_381_is_rejected`, `wrong_length_b_is_rejected`.

---

## Rule 3 — G2 coordinate order: c1 before c0

This is the single most dangerous encoding trap in the repo. snarkjs emits a G2 point as
`[[x_c0, x_c1], [y_c0, y_c1]]` — c0 first within each `Fp2` coordinate. The Soroban host
expects the **opposite**: `be_bytes(X_c1) ‖ be_bytes(X_c0) ‖ be_bytes(Y_c1) ‖ be_bytes(Y_c0)`.

Naively concatenating snarkjs's JSON order produces a byte string of the correct *length*
that encodes the *wrong point*.

### Evidence (BN254)

Measured against a real Groth16 proof (`fixtures/vote/`, circom 2.2.3 + snarkjs 0.7.5,
accepted by `snarkjs groth16 verify`), on `soroban-sdk 26.1.1`'s testutils host:

| G2 encoding fed to the host (proof `B`, VK `β`, `γ`, `δ`) | Result |
| --- | --- |
| `X_c1 ‖ X_c0 ‖ Y_c1 ‖ Y_c0` (swapped) | `verify` returns `Ok(true)` |
| `X_c0 ‖ X_c1 ‖ Y_c0 ‖ Y_c1` (snarkjs JSON order) | host traps: `Error(Crypto, InvalidInput)`, `bn254 G2: point not on curve` |

Tests: `fixture_proof_verifies`, `fixture_snarkjs_native_g2_order_is_rejected_by_the_host`
(`crates/occulta-verifier/src/tests.rs`). Swapping only the proof's `B` gives the same trap.

So on BN254 the wrong order fails loudly, not silently: the un-swapped bytes are not a point
on the twist, and the host checks that before pairing. Do not rely on that as a safety net —
it is a property of these particular points, not a guarantee — but it does mean a
mis-encoded verifier shows up the first time it sees a real proof.

BLS12-381 has no proof fixture yet. Its order (`c1` first) is taken from the
`soroban_sdk::crypto::bls12_381` documentation and is not yet confirmed empirically.

This affects both curves:

- **BLS12-381 G2:** `BytesN<192>`, each `Fp2` coordinate is 96 bytes (2 × 48)
- **BN254 G2:** `BytesN<128>`, each `Fp2` coordinate is 64 bytes (2 × 32)

**Enforcement:** `occulta_types::swap_fp2_limbs(input, half_len, out)` performs the swap
(`c0 ‖ c1` → `c1 ‖ c0`). `occulta_types::snarkjs` (feature `snarkjs`) applies it when
converting snarkjs JSON into `Proof` and `VerificationKey`.

**Tests:** `g2_coordinate_swap_matches_expected_host_order_bn254` (verifies the swap
produces the correct byte layout and is not a no-op copy),
`g2_coordinate_swap_is_its_own_inverse` (round-trip: swap twice = identity),
`swap_rejects_wrong_length`.

---

## Rule 4 — Point at infinity

The all-zero byte string encodes the point at infinity. `occulta_types::is_zero_bytes`
detects this. Whether infinity is *accepted* depends on context:

- `vk.alpha_g1` must never be infinity for a valid verification key
- `occulta-verifier` rejects a proof's `A` component with `y = 0` (infinity or degenerate)
  before negation, returning `Err(InvalidPoint)`

**Tests:** `zero_bytes_detected`.

---

## Rule 5 — Subgroup membership: don't duplicate host work

`Bls12381G1Affine::from_bytes(...)` accepts any 96 bytes without validation — the host
traps on a genuinely off-curve point when it is used in a host call, but does not check
subgroup membership on construction. `occulta-verifier` calls `bls12_381.g1_is_in_subgroup()`
and `bls12_381.g2_is_in_subgroup()` explicitly on the proof's `A`, `B`, and `C` points.

For BN254, G1's cofactor is 1 (every on-curve point is in the group) and the host validates
G2 subgroup membership during `pairing_check`. No separate subgroup check is needed or
available in the SDK for BN254.

This is documented in `docs/PLATFORM.md` under "g1_add auto-validates subgroup membership."
