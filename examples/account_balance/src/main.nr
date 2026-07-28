//! Prove an Ethereum account's ETH balance and nonce at a given block.
//!
//! Inputs come from `eth_getProof(address, [], block)`; see
//! `scripts/generate_example_inputs.py`. Everything about the account is a
//! private witness — only the block's state root, the address being asked
//! about, and the resulting balance/nonce are public.
//!
//! Run with:
//!     nargo execute

use evm_storage_proofs::types::{Account, Node};
use evm_storage_proofs::verify_account_proof;

/// Mainnet account paths are 7–9 nodes deep. In a constrained circuit every
/// iteration costs a branch-node keccak whether or not it is used, so this
/// bound is what you pay — keep it tight.
global MAX_ACCOUNT_PATH: u32 = 10;

fn main(
    // A state root the verifier already trusts (from an L1 block header
    // delivered by a bridge, light client, …).
    state_root: pub [u64; 4],
    // The account being asked about.
    address: pub [u8; 20],
    // Witness: the account's trie leaf contents and the proof path to it.
    account: Account,
    nodes: [Node; MAX_ACCOUNT_PATH],
    node_length: u32,
) -> pub (Field, u64) {
    // Bind the proof to the address the caller asked about. Without this the
    // prover could prove *any* account under the state root and pass off its
    // balance as the answer.
    assert_eq(account.address, address, "proof is for a different account");

    verify_account_proof(state_root, account, nodes, node_length);

    // Sound to expose now: the leaf hash these came from was checked against
    // the trie path all the way up to state_root.
    (account.balance_as_field(), account.nonce_as_u64())
}
