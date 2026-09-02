//! Event emission for the incremental Merkle tree.
//!
//! The `occulta-sdk` indexer reconstructs the full tree from these events; every insertion
//! must emit this event or clients cannot build Merkle paths. Missing an event is a liveness
//! failure.

use soroban_sdk::{Env, Symbol, U256};

/// Emit a leaf-insertion event carrying the leaf index, the commitment, and the new root.
///
/// Topic 1: `"occulta"` (the contract's event namespace).
/// Topic 2: `"leaf_insert"` (the event name).
/// Data: `(leaf_index: u32, commitment: U256, new_root: U256)`.
// `Events::publish` is deprecated in favor of the `#[contractevent]` macro (soroban-sdk 26.1.1),
// but switching changes the on-wire topic/data schema the `occulta-sdk` indexer depends on (see
// module doc above). Deferred to a dedicated migration rather than done incidentally here.
#[allow(deprecated)]
pub fn emit_leaf_insert(env: &Env, leaf_index: u32, commitment: &U256, new_root: &U256) {
    env.events().publish(
        (Symbol::new(env, "occulta"), Symbol::new(env, "leaf_insert")),
        (leaf_index, commitment.clone(), new_root.clone()),
    );
}
