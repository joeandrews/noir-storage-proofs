//! Ethereum Merkle-Patricia-Trie storage and account proof verification for Noir.
//!
//! Verifies `eth_getProof` responses in-circuit: prove that an account exists
//! under a state root, and that a storage slot holds a value under an
//! account's storage root. Hashes are handled as `[u64; 4]` little-endian
//! limbs throughout (the `keccak256_limbs` convention).
//!
//! Vendored from AztecProtocol/aztec-packages (Apache-2.0), see NOTICE.

pub mod account_hash;
pub mod branch_hash;
pub mod bytes_sink;
pub mod extension_hash;
pub mod keccak;
pub mod path_verification;
pub mod slot_hash;
pub mod types;
pub mod utils;

mod tests;

use account_hash::compute_account_hash;
use keccak::KeccakHasher;
use path_verification::verify_path_section;
use slot_hash::compute_slot_hash;
use types::{Account, Node, StorageSlot};
use utils::to_nibbles;

/// Verifies that `account` is included in the state trie with root
/// `state_root` (as returned by `eth_getBlockByNumber(...).stateRoot`).
///
/// `nodes` is the account proof path — every node of
/// `eth_getProof(...).accountProof` except the trailing leaf — padded to
/// `MAX_PATH_LENGTH`, with `node_length` the number of real nodes.
///
/// In a constrained (ACIR) context the cost is always `MAX_PATH_LENGTH`
/// keccaks of branch-sized preimages, regardless of `node_length` — pick the
/// tightest bound your chain's state-trie depth allows.
pub fn verify_account_proof<let MAX_PATH_LENGTH: u32>(
    state_root: [u64; 4],
    account: Account,
    nodes: [Node; MAX_PATH_LENGTH],
    node_length: u32,
) {
    let trie_key = KeccakHasher::hash_bytes(account.address, 20);

    let (leaf_hash, leaf_nibble_index) =
        verify_path_section(nodes, node_length, 0, state_root, to_nibbles(trie_key));

    assert_eq(leaf_hash, compute_account_hash(account, leaf_nibble_index, trie_key));
}

/// Verifies that storage slot `slot_key` holds `slot` under `storage_root`
/// (the `storageHash` of a — separately verified — account, or
/// `eth_getProof(...).storageHash`).
///
/// `nodes` is `eth_getProof(...).storageProof[i].proof` without the trailing
/// leaf, padded to `MAX_PATH_LENGTH`. Only inclusion proofs of non-empty
/// slots are supported — a zero-valued slot is absent from the trie and its
/// "proof" is an exclusion proof, which this library cannot verify.
pub fn verify_storage_proof<let MAX_PATH_LENGTH: u32>(
    storage_root: [u64; 4],
    slot_key: [u8; 32],
    slot: StorageSlot,
    nodes: [Node; MAX_PATH_LENGTH],
    node_length: u32,
) {
    let trie_key = KeccakHasher::hash_bytes(slot_key, 32);

    let (leaf_hash, leaf_nibble_index) =
        verify_path_section(nodes, node_length, 0, storage_root, to_nibbles(trie_key));

    assert_eq(leaf_hash, compute_slot_hash(slot, leaf_nibble_index, trie_key));
}

/// Verifies an account proof and a storage proof against the account's
/// storage root in one call: the full `state_root → account → slot` chain.
pub fn verify_account_and_storage_proof<let MAX_ACCOUNT_PATH_LENGTH: u32, let MAX_STORAGE_PATH_LENGTH: u32>(
    state_root: [u64; 4],
    account: Account,
    account_nodes: [Node; MAX_ACCOUNT_PATH_LENGTH],
    account_node_length: u32,
    slot_key: [u8; 32],
    slot: StorageSlot,
    storage_nodes: [Node; MAX_STORAGE_PATH_LENGTH],
    storage_node_length: u32,
) {
    verify_account_proof(state_root, account, account_nodes, account_node_length);
    verify_storage_proof(
        account.storage_hash,
        slot_key,
        slot,
        storage_nodes,
        storage_node_length,
    );
}
