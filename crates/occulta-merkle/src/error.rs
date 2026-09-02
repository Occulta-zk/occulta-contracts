use soroban_sdk::contracterror;

#[contracterror]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MerkleError {
    /// The tree is full — `next_index == 2^depth`. No more commitments can be inserted.
    TreeFull = 1,
    /// A `TreeConfig` with `depth` outside the allowed range (20..=32) was supplied.
    InvalidDepth = 2,
    /// A `TreeConfig` with `root_history_size == 0` was supplied.
    InvalidRootHistorySize = 3,
    /// The nullifier has already been spent (double-spend attempt). Security Invariant #3.
    NullifierAlreadySpent = 4,
}
