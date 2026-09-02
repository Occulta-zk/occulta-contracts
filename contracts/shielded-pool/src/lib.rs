//! **NOT YET IMPLEMENTED — scaffold only, milestone M5+.**
//!
//! Deployable deposit/withdraw pool composing `occulta-merkle` + `contracts/registry` (build
//! spec §4.6). `withdraw`'s five-step ordering (known-root check, nullifier-unspent check,
//! proof verify, mark-nullifier-spent, *then* token transfer) is Security Invariant #3
//! (checks-effects-interactions) and is non-negotiable — do not implement the transfer before
//! the nullifier is marked spent, even temporarily during development.
#![no_std]

#[doc(hidden)]
pub const _NOT_YET_IMPLEMENTED: &str = "shielded-pool: see module docs, milestone M5+";
