//! **NOT YET IMPLEMENTED — scaffold only, milestone M5.**
//!
//! Deployable verification-key registry (build spec §4.5): `register`/`freeze`/`get_vk`/
//! `verify`/`set_admin`. Depends on `occulta-verifier` (M3), which is not yet implemented —
//! see that crate. `freeze` is a one-way admin-can-never-touch-it-again operation
//! (Security Invariant #7) and needs its own dedicated test before this contract ships.
#![no_std]

#[doc(hidden)]
pub const _NOT_YET_IMPLEMENTED: &str = "registry: see module docs, milestone M5";
