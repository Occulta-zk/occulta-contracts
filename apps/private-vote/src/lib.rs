//! **NOT YET IMPLEMENTED — scaffold only, milestone M6.**
//!
//! Reference app: anonymous one-vote-per-member polling (build spec §4.7). `poll_id` is the
//! external nullifier that scopes a nullifier to this poll (Security Invariant #6) — without
//! it, a nullifier spent voting here blocks the same identity in every other app. `choice`
//! must be a public signal bound into the proof (Security Invariant #1) or a copied proof
//! from the mempool can be replayed with a different `choice`.
#![no_std]

#[doc(hidden)]
pub const _NOT_YET_IMPLEMENTED: &str = "private-vote: see module docs, milestone M6";
