pragma circom 2.1.0;

// Fixture circuit for `apps/private-vote`: Merkle membership + per-poll nullifier.
//
// A member's leaf is `Poseidon(identity_nullifier, identity_trapdoor)`. To vote, they prove:
//   1. their leaf is in the tree whose root is `root` (depth DEPTH, Poseidon(2) nodes), and
//   2. `nullifier == Poseidon(identity_nullifier, poll_id)`, so one identity gets one
//      nullifier per poll and nullifiers from different polls are unlinkable.
// `choice` is a public signal constrained to {0, 1}, so a copied proof cannot be replayed
// with a different choice.
//
// Public signals, in this exact order (circom orders public inputs by declaration):
//   [root, nullifier, choice, poll_id]
//
// All hashing is circomlib's Poseidon over BN254 — the same parameters as
// `occulta-poseidon`'s BN254 instance.

include "node_modules/circomlib/circuits/poseidon.circom";

template MerkleRoot(DEPTH) {
    signal input leaf;
    signal input path_elements[DEPTH];
    signal input path_indices[DEPTH]; // 0: current node is the left child, 1: right child
    signal output root;

    component hashers[DEPTH];
    signal left[DEPTH];
    signal right[DEPTH];
    signal level[DEPTH + 1];
    level[0] <== leaf;

    for (var i = 0; i < DEPTH; i++) {
        path_indices[i] * (path_indices[i] - 1) === 0;

        // left = idx ? sibling : node;  right = idx ? node : sibling
        left[i] <== level[i] + path_indices[i] * (path_elements[i] - level[i]);
        right[i] <== path_elements[i] + path_indices[i] * (level[i] - path_elements[i]);

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        level[i + 1] <== hashers[i].out;
    }

    root <== level[DEPTH];
}

template PrivateVote(DEPTH) {
    // Public
    signal input root;
    signal input nullifier;
    signal input choice;
    signal input poll_id;

    // Private
    signal input identity_nullifier;
    signal input identity_trapdoor;
    signal input path_elements[DEPTH];
    signal input path_indices[DEPTH];

    component leaf_hash = Poseidon(2);
    leaf_hash.inputs[0] <== identity_nullifier;
    leaf_hash.inputs[1] <== identity_trapdoor;

    component tree = MerkleRoot(DEPTH);
    tree.leaf <== leaf_hash.out;
    for (var i = 0; i < DEPTH; i++) {
        tree.path_elements[i] <== path_elements[i];
        tree.path_indices[i] <== path_indices[i];
    }
    tree.root === root;

    component nullifier_hash = Poseidon(2);
    nullifier_hash.inputs[0] <== identity_nullifier;
    nullifier_hash.inputs[1] <== poll_id;
    nullifier_hash.out === nullifier;

    choice * (choice - 1) === 0;
}

component main {public [root, nullifier, choice, poll_id]} = PrivateVote(8);
