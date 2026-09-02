//! **NOT YET IMPLEMENTED — scaffold only, milestone M4.**
//!
//! This crate will implement the incremental Merkle tree, root history ring buffer, and
//! persistent-storage nullifier registry described in the build spec (§4.4). It has a hard
//! dependency on `occulta-poseidon::hash2` for node hashing (M2), which is itself blocked on
//! circomlib fixture verification — see `crates/occulta-poseidon`. Building the tree before
//! Poseidon is verified would mean testing Merkle proofs against an unverified hash function,
//! which the build spec explicitly calls a "demo of a bug", not a milestone.
//!
//! Security Invariants #2–#4 (`docs/SECURITY-MODEL.md`) apply here: nullifiers must use
//! persistent storage (never `temporary()`), root history must accept any of the last
//! `root_history_size` roots (not just the current one), and every insertion must emit an
//! event carrying `(leaf_index, commitment, new_root)` so `occulta-sdk`'s indexer can
//! reconstruct the tree.
#![no_std]

#[doc(hidden)]
pub const _NOT_YET_IMPLEMENTED: &str = "occulta-merkle: see module docs, milestone M4";
