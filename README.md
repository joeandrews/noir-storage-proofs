# noir-storage-proofs

Ethereum Merkle-Patricia-Trie **account and storage proof verification in [Noir](https://noir-lang.org)**.

Prove, in-circuit, that:

- an account (nonce, balance, storage root, code hash) exists under a block's state root, and
- a storage slot holds a given value under that account's storage root,

directly from a standard [`eth_getProof`](https://eips.ethereum.org/EIPS/eip-1186) response. Combined with a trusted source of L1 block hashes / state roots (an L1→L2 messaging bridge, a light client, …) this lets a circuit consume arbitrary Ethereum state.

The verification core is vendored from [AztecProtocol/aztec-packages](https://github.com/AztecProtocol/aztec-packages) (Apache-2.0 — see [NOTICE](NOTICE)), repackaged as a standalone library with no Aztec dependency.

## Usage

```toml
# Nargo.toml
[dependencies]
evm_storage_proofs = { git = "https://github.com/joeandrews/noir-storage-proofs", tag = "v0.2.0", directory = "lib" }
```

```noir
use evm_storage_proofs::{
    types::{Account, Node, StorageSlot},
    verify_account_proof, verify_storage_proof,
};

global MAX_ACCOUNT_PATH: u32 = 11; // mainnet state-trie depth headroom
global MAX_STORAGE_PATH: u32 = 7;

fn main(
    state_root: [u64; 4], // from a trusted block header
    account: Account,
    account_nodes: [Node; MAX_ACCOUNT_PATH],
    account_node_length: u32,
    slot_key: [u8; 32],
    slot: StorageSlot,
    storage_nodes: [Node; MAX_STORAGE_PATH],
    storage_node_length: u32,
) {
    // account is in the state trie under state_root
    verify_account_proof(state_root, account, account_nodes, account_node_length);

    // slot_key holds `slot` in that account's storage trie
    verify_storage_proof(account.storage_hash, slot_key, slot, storage_nodes, storage_node_length);

    // ... constrain account.address, slot_key and slot.value to whatever
    // your application expects.
}
```

Or `verify_account_and_storage_proof(...)` to do both in one call.

### Generating inputs

`scripts/fetch_proof_inputs.mjs` (dependency-free, Node 18+) converts an `eth_getProof` response into the library's input types as JSON:

```sh
node scripts/fetch_proof_inputs.mjs https://ethereum-rpc.publicnode.com \
  0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc \
  0x0000000000000000000000000000000000000000000000000000000000000008
```

Note the conventions, which the script implements:

- **Proof paths exclude the trailing leaf.** The leaf is reconstructed in-circuit from `Account` / `StorageSlot`, so `nodes` = `proof[0..len-1]`, padded with zeroed `Node`s up to your `MAX_PATH_LENGTH` generic, and `node_length` = the real count.
- **Hashes are `[u64; 4]` limbs**: limb `i` = bytes `8i..8i+8` of the 32-byte hash, little-endian within each limb.
- **Quantities are minimal big-endian bytes + a length**: `balance`/`nonce`/`value` arrays are left-aligned minimal big-endian bytes, zero-padded to the right, with `*_length` giving the real byte count (zero → length 0).

## How it works

Each trie node arrives pre-parsed as a `Node` — 16 rows of `[u64; 4]` plus existence flags — rather than raw RLP. In-circuit, the node is **re-RLP-encoded and keccak-hashed** to check it matches its parent's child hash, which is sound because RLP encoding is injective. Encoding runs through a hint-then-check pattern: an unconstrained pass produces the byte string, a constrained pass (`BytesChecker`) verifies it byte-by-byte, and the keccak (from [noir-lang/keccak256](https://github.com/noir-lang/keccak256)) hashes the checked bytes. Walking the path consumes the trie-key nibbles (`keccak(address)` for accounts, `keccak(slot_key)` for storage) through branch and extension nodes, and the final leaf hash is recomputed from the claimed `Account`/`StorageSlot` contents.

In a constrained (ACIR) context, path loops always run to `MAX_PATH_LENGTH` — each iteration costing a branch-node-sized keccak — regardless of the actual path length, so pick the tightest bound your target trie depth allows. Mainnet account paths are currently ~7–9 nodes; storage paths depend on the contract's trie size. In unconstrained (Brillig) contexts the loops run to the actual length.

## Input invariants

The `Node` / `Account` / `StorageSlot` inputs are prover-supplied witnesses, constrained in-circuit against the root you pass in. Two obligations stay with the caller:

- **Zero the rows you mark absent.** A `Node` with `row_exist[i] == false` must have `rows[i] == [0; 4]`. Only a node's present children contribute to its hash, so the verifier enforces this on the rest rather than trusting it. The bundled input scripts already comply.
- **Bind what you proved to what you meant.** Verification establishes "this account is under this state root" and "this key holds this value" — it says nothing about *which* account or key. Constrain `account.address`, `slot_key` (derive it with [`slot_key`](src/slot_key.nr) rather than taking it as an input) and the provenance of `state_root` yourself, or the prover will choose them for you.

## Limitations

- **Inclusion proofs only.** A zero-valued slot is absent from the trie; proving absence (exclusion proofs) is not supported.
- **No embedded nodes.** Nodes smaller than 32 bytes are inlined into their parent instead of hashed; such paths (only possible in very small storage tries) are rejected by the input scripts and unsupported in-circuit.
- **Branch nodes are assumed to carry no inlined value** (always true for the account trie and for keccak-keyed storage tries, where all keys are 32 bytes / 64 nibbles).

## Development

```sh
nargo test                                  # unit + real-mainnet-vector tests
python3 scripts/generate_test_vectors.py && nargo fmt   # regenerate src/tests/vectors.nr from live mainnet
```

Tested with nargo `1.0.0-beta.25`.

## License

[Apache-2.0](LICENSE). Verification core vendored from [AztecProtocol/aztec-packages](https://github.com/AztecProtocol/aztec-packages) `noir-projects/noir-contracts/contracts/test/storage_proof_test_contract/src/storage_proofs/` — see [NOTICE](NOTICE).
