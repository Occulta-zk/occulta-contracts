//! Shared contract types and snarkjs -> Soroban byte-level encoding rules for Occulta.
//!
//! This crate has no cryptography in it — no pairing, no field arithmetic, no hashing.
//! Its only job is to define the wire shapes (`Proof`, `VerificationKey`, `Curve`) shared by
//! `occulta-verifier` and every contract in `contracts/`, and to enforce the encoding rules
//! documented in `docs/ENCODING.md` (point-at-infinity handling, scalar range checks). See
//! `docs/ENCODING.md` for the human-readable version of every rule enforced here, and
//! `docs/PLATFORM.md` for the verified SDK facts (byte lengths, coordinate order) this module
//! is built against.
#![no_std]

mod curve;
mod encoding;
mod error;
mod proof;
mod vk;

pub use curve::Curve;
pub use encoding::{is_zero_bytes, scalar_in_range, swap_fp2_limbs};
pub use error::TypesError;
pub use proof::Proof;
pub use vk::VerificationKey;
