//! Incremental Merkle tree, root history ring buffer, and persistent nullifier registry.
//!
//! ## Security invariants enforced here
//!
//! - **Invariant #2 (Nullifiers are persistent storage. Always.)** — `Nullifiers::spend` and
//!   `Nullifiers::is_spent` only ever use `env.storage().persistent()`. Never
//!   `temporary()`. An expired temporary entry is an exploitable double-spend. This is called
//!   out with a comment at every storage call site below.
//!
//! - **Invariant #3 (Effects before interactions)** — `spend` *panics* on a double-spend
//!   immediately, before any cross-contract call is possible. The enforcing comment is at the
//!   call site in `contracts/shielded-pool`.
//!
//! - **Invariant #4 (Root history buffer)** — `is_known_root` checks the last
//!   `TreeConfig::root_history_size` roots. Checking only the current root would fail for
//!   concurrent depositors (the SDF Privacy Pools prototype hit this exact bug).
//!
//! ## TTL / archival
//!
//! Soroban archives ledger entries whose TTL expires. Every write to persistent storage bumps
//!the TTL. The constants `TREE_TTL` and `NULLIFIER_TTL` are set to a conservative high
//! value; see `docs/SECURITY-MODEL.md` for the rationale. An archived nullifier that later
//! gets restored must still read as *spent* — this is safe because the value is a boolean
//! `true` stored under the nullifier's bytes, which doesn't expire.
//!
//! ## Event emission
//!
//! `Tree::insert` emits `(leaf_index, commitment, new_root)` on every insertion. The
//! `occulta-sdk` indexer reconstructs the tree from these events; if the event is absent or
//! lossy, no client can build a Merkle path. See `events.rs`.
#![no_std]

mod error;
mod events;
mod nullifiers;
mod tree;

pub use error::MerkleError;
pub use nullifiers::Nullifiers;
pub use tree::{Tree, TreeConfig};

/// Ledger TTL extension for persistent tree entries (approximately 1 year at ~5s per ledger).
/// 365 * 24 * 3600 / 5 = 6_307_200. Rounded to a round number.
pub const TREE_TTL: u32 = 6_000_000;

/// Ledger TTL extension for nullifier entries.
/// Must be at least as long as the tree's TTL — a nullifier that expires while the tree
/// entry is still alive opens a double-spend window.
pub const NULLIFIER_TTL: u32 = 6_000_000;
