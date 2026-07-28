//! Paths that must be rejected.
//!
//! A proof path is only valid if every node hashes to the child hash its
//! parent points at *and* the trie key actually routes through the children
//! those nodes have. `DIVERGENT_SLOT_KEY` is a real key that is absent from
//! the Uniswap V2 storage trie used by the vectors: it shares the genuine
//! path's first nibbles and then routes into a branch child that the node
//! leaves empty. Such a key cannot be proven — there is no leaf to prove, and
//! an empty child slot is not something the traversal may descend into.
//!
//! (Proving that a key is *absent* would need an exclusion proof, which this
//! library does not implement — see the README.)

use crate::keccak::KeccakHasher;
use crate::slot_hash::compute_slot_hash;
use crate::types::StorageSlot;
use crate::verify_storage_proof;

use super::vectors::{
    DIVERGENT_NIBBLE, DIVERGENT_PATH_LENGTH, DIVERGENT_SLOT_KEY, slot, SLOT_KEY, storage_nodes,
    STORAGE_PATH_LENGTH, STORAGE_ROOT,
};

/// Any value claimed for the absent key, to check the path is rejected before
/// the leaf contents are ever reached.
fn claimed_slot() -> StorageSlot {
    StorageSlot {
        value: [
            211, 194, 27, 206, 204, 237, 161, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ],
        value_length: 10,
    }
}

#[test(should_fail_with = "branch child does not exist")]
unconstrained fn key_diverging_into_an_empty_child_is_rejected() {
    verify_storage_proof(
        STORAGE_ROOT,
        DIVERGENT_SLOT_KEY,
        claimed_slot(),
        storage_nodes(),
        DIVERGENT_PATH_LENGTH,
    );
}

/// The same, through the constrained (ACIR) code path.
#[test(should_fail_with = "branch child does not exist")]
fn key_diverging_into_an_empty_child_is_rejected_constrained() {
    verify_storage_proof(
        STORAGE_ROOT,
        DIVERGENT_SLOT_KEY,
        claimed_slot(),
        storage_nodes(),
        DIVERGENT_PATH_LENGTH,
    );
}

/// A subtree grafted onto the empty child slot, consistent all the way down:
/// the planted hash is exactly the leaf hash of the claimed value, so every
/// hash in the path — including the tampered node's own, which does not cover
/// rows it makes no claim to — agrees. Internal consistency of a grafted
/// subtree says nothing about the trie, so this must be rejected too.
#[test(should_fail)]
unconstrained fn grafted_subtree_on_an_empty_child_is_rejected() {
    let claimed = claimed_slot();
    let trie_key = KeccakHasher::hash_bytes(DIVERGENT_SLOT_KEY, 32);
    // One nibble is consumed per branch node, so the leaf would sit here.
    let leaf_hash = compute_slot_hash(claimed, DIVERGENT_PATH_LENGTH, trie_key);

    let mut nodes = storage_nodes();
    nodes[DIVERGENT_PATH_LENGTH - 1].rows[DIVERGENT_NIBBLE] = leaf_hash;

    verify_storage_proof(
        STORAGE_ROOT,
        DIVERGENT_SLOT_KEY,
        claimed,
        nodes,
        DIVERGENT_PATH_LENGTH,
    );
}

/// The same input defect on an otherwise entirely genuine path.
#[test(should_fail_with = "absent branch child must be zeroed")]
unconstrained fn non_zero_absent_row_is_rejected() {
    let mut nodes = storage_nodes();
    nodes[DIVERGENT_PATH_LENGTH - 1].rows[DIVERGENT_NIBBLE] = [0xdead, 0xbeef, 0xfeed, 0xface];

    verify_storage_proof(STORAGE_ROOT, SLOT_KEY, slot(), nodes, STORAGE_PATH_LENGTH);
}
