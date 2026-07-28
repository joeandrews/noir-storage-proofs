#!/usr/bin/env python3
"""Regenerate src/tests/vectors.nr from live Ethereum mainnet data.

Fetches an eth_getProof for a contract with a deep storage trie at the
latest finalized block and emits the account + storage proofs as Noir test
vectors in the library's Node format.

Usage: python3 scripts/generate_test_vectors.py [RPC_URL]  (then run `nargo fmt`)
"""

import json
import sys
import urllib.request
from pathlib import Path

RPC_URL = sys.argv[1] if len(sys.argv) > 1 else "https://ethereum-rpc.publicnode.com"

# Uniswap V2 USDC/WETH pair: thousands of LP-token balance slots share the
# storage trie, so both proofs exercise real multi-node paths. Slot 8 packs
# (blockTimestampLast, reserve1, reserve0) and is always non-zero.
ADDRESS = "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc"
SLOT_KEY = "0x" + "00" * 31 + "08"


def rpc(method: str, params: list):
    req = urllib.request.Request(
        RPC_URL,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"content-type": "application/json", "user-agent": "curl/8.5.0"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.load(resp)
    if "error" in body:
        raise RuntimeError(f"{method}: {body['error']}")
    return body["result"]


def hex_bytes(h: str) -> list[int]:
    h = h[2:] if h.startswith("0x") else h
    if len(h) % 2:
        h = "0" + h
    return list(bytes.fromhex(h))


def pad_to(arr: list[int], length: int) -> list[int]:
    assert len(arr) <= length, f"{len(arr)} > {length}"
    return arr + [0] * (length - len(arr))


def to_u64_limbs(b: list[int]) -> list[int]:
    """32 bytes -> [u64; 4], limb i = bytes 8i..8i+8, little-endian within limb."""
    b = pad_to(b, 32)
    return [sum(b[i * 8 + j] << (j * 8) for j in range(8)) for i in range(4)]


def quantity_bytes(value: int) -> list[int]:
    """Minimal big-endian bytes of a quantity (0 -> empty)."""
    return list(value.to_bytes((value.bit_length() + 7) // 8, "big")) if value else []


# ---------------- minimal RLP decoder ----------------


def rlp_decode(data: bytes):
    item, rest = _rlp_item(data)
    assert not rest, "trailing bytes after RLP item"
    return item


def _rlp_item(data: bytes):
    prefix = data[0]
    if prefix <= 0x7F:
        return data[:1], data[1:]
    if prefix <= 0xB7:
        n = prefix - 0x80
        return data[1 : 1 + n], data[1 + n :]
    if prefix <= 0xBF:
        ln = prefix - 0xB7
        n = int.from_bytes(data[1 : 1 + ln], "big")
        return data[1 + ln : 1 + ln + n], data[1 + ln + n :]
    if prefix <= 0xF7:
        n = prefix - 0xC0
        return _rlp_list(data[1 : 1 + n]), data[1 + n :]
    ln = prefix - 0xF7
    n = int.from_bytes(data[1 : 1 + ln], "big")
    return _rlp_list(data[1 + ln : 1 + ln + n]), data[1 + ln + n :]


def _rlp_list(payload: bytes):
    items = []
    while payload:
        item, payload = _rlp_item(payload)
        items.append(item)
    return items


# ---------------- proof node -> library Node struct ----------------


def zero_node():
    return {"rows": [[0, 0, 0, 0] for _ in range(16)], "row_exist": [False] * 16, "node_type": 0}


def parse_node(rlp_hex: str):
    decoded = rlp_decode(bytes(hex_bytes(rlp_hex)))
    assert isinstance(decoded, list), "expected an RLP list node"
    node = zero_node()

    if len(decoded) == 17:
        for i in range(16):
            child = decoded[i]
            if child:
                assert len(child) == 32, f"embedded (<32-byte) branch child unsupported: {len(child)}"
                node["row_exist"][i] = True
                node["rows"][i] = to_u64_limbs(list(child))
    elif len(decoded) == 2:
        key = list(decoded[0])
        prefix = key[0] >> 4
        assert prefix < 2, "leaf node in proof path (path must exclude the trailing leaf)"
        assert len(decoded[1]) == 32, "embedded extension child unsupported"
        node["node_type"] = 1
        # Extension header layout expected by types.nr.
        row0 = [0] * 32
        row0[0] = prefix  # is_odd
        row0[8] = key[0] & 0x0F  # first_nibble
        row0[16] = len(key) - 1  # extension_length
        node["rows"][0] = to_u64_limbs(row0)
        row1 = pad_to(key[1:], 32)
        node["rows"][1] = to_u64_limbs(row1)
        node["rows"][2] = to_u64_limbs(list(decoded[1]))
        node["row_exist"][0] = node["row_exist"][1] = node["row_exist"][2] = True
    else:
        raise AssertionError(f"unexpected MPT node arity {len(decoded)}")
    return node


# ---------------- Noir literal formatting ----------------


def fmt_u8_array(values: list[int]) -> str:
    return "[" + ", ".join(str(v) for v in values) + "]"


def fmt_limbs(limbs: list[int]) -> str:
    return "[" + ", ".join(str(v) for v in limbs) + "]"


def fmt_node(node) -> str:
    rows = ",\n                ".join(fmt_limbs(r) for r in node["rows"])
    exist = ", ".join(str(e).lower() for e in node["row_exist"])
    return (
        "Node {\n"
        f"            rows: [\n                {rows},\n            ],\n"
        f"            row_exist: [{exist}],\n"
        f"            node_type: {node['node_type']},\n"
        "        }"
    )


def fmt_nodes(nodes) -> str:
    return "[\n        " + ",\n        ".join(fmt_node(n) for n in nodes) + ",\n    ]"


def main():
    block = rpc("eth_getBlockByNumber", ["finalized", False])
    block_number = block["number"]
    state_root = to_u64_limbs(hex_bytes(block["stateRoot"]))

    proof = rpc("eth_getProof", [ADDRESS, [SLOT_KEY], block_number])
    slot_proof = proof["storageProof"][0]
    slot_value = int(slot_proof["value"], 16)
    assert slot_value != 0, "slot is zero: exclusion proofs are unsupported"

    account_path = [parse_node(n) for n in proof["accountProof"][:-1]]
    storage_path = [parse_node(n) for n in slot_proof["proof"][:-1]]
    assert account_path and storage_path, "degenerate single-node proof"

    nonce = quantity_bytes(int(proof["nonce"], 16))
    balance = quantity_bytes(int(proof["balance"], 16))
    value = quantity_bytes(slot_value)

    out = f"""// Generated by scripts/generate_test_vectors.py — do not edit by hand.
//
// Real Ethereum mainnet data: eth_getProof for the Uniswap V2 USDC/WETH pair
// ({ADDRESS}), storage slot 8 (packed reserves),
// at finalized block {int(block_number, 16)} (state root {block["stateRoot"]}).

use crate::types::{{Account, Node, StorageSlot}};
use crate::{{verify_account_and_storage_proof, verify_account_proof, verify_storage_proof}};

global ACCOUNT_PATH_LENGTH: u32 = {len(account_path)};
global STORAGE_PATH_LENGTH: u32 = {len(storage_path)};

global STATE_ROOT: [u64; 4] = {fmt_limbs(state_root)};

global SLOT_KEY: [u8; 32] = {fmt_u8_array(hex_bytes(SLOT_KEY))};

fn account() -> Account {{
    Account {{
        nonce: {fmt_u8_array(pad_to(nonce, 8))},
        balance: {fmt_u8_array(pad_to(balance, 32))},
        address: {fmt_u8_array(hex_bytes(ADDRESS))},
        nonce_length: {len(nonce)},
        balance_length: {len(balance)},
        storage_hash: {fmt_limbs(to_u64_limbs(hex_bytes(proof["storageHash"])))},
        code_hash: {fmt_limbs(to_u64_limbs(hex_bytes(proof["codeHash"])))},
    }}
}}

fn slot() -> StorageSlot {{
    StorageSlot {{ value: {fmt_u8_array(pad_to(value, 32))}, value_length: {len(value)} }}
}}

fn account_nodes() -> [Node; ACCOUNT_PATH_LENGTH] {{
    {fmt_nodes(account_path)}
}}

fn storage_nodes() -> [Node; STORAGE_PATH_LENGTH] {{
    {fmt_nodes(storage_path)}
}}

#[test]
unconstrained fn account_proof_verifies() {{
    verify_account_proof(STATE_ROOT, account(), account_nodes(), ACCOUNT_PATH_LENGTH);
}}

#[test]
unconstrained fn storage_proof_verifies() {{
    verify_storage_proof(
        account().storage_hash,
        SLOT_KEY,
        slot(),
        storage_nodes(),
        STORAGE_PATH_LENGTH,
    );
}}

#[test]
unconstrained fn account_and_storage_proof_verifies() {{
    verify_account_and_storage_proof(
        STATE_ROOT,
        account(),
        account_nodes(),
        ACCOUNT_PATH_LENGTH,
        SLOT_KEY,
        slot(),
        storage_nodes(),
        STORAGE_PATH_LENGTH,
    );
}}

// The same verifications through the constrained (ACIR) code path, which
// exercises the hint-then-check BytesChecker circuits.
#[test]
fn account_proof_verifies_constrained() {{
    verify_account_proof(STATE_ROOT, account(), account_nodes(), ACCOUNT_PATH_LENGTH);
}}

#[test]
fn storage_proof_verifies_constrained() {{
    verify_storage_proof(
        account().storage_hash,
        SLOT_KEY,
        slot(),
        storage_nodes(),
        STORAGE_PATH_LENGTH,
    );
}}

#[test(should_fail)]
unconstrained fn tampered_slot_value_fails() {{
    let mut tampered = slot();
    tampered.value[0] += 1;
    verify_storage_proof(
        account().storage_hash,
        SLOT_KEY,
        tampered,
        storage_nodes(),
        STORAGE_PATH_LENGTH,
    );
}}

#[test(should_fail)]
unconstrained fn tampered_account_balance_fails() {{
    let mut tampered = account();
    tampered.balance = {fmt_u8_array(pad_to(quantity_bytes(12345), 32))};
    tampered.balance_length = 2;
    verify_account_proof(STATE_ROOT, tampered, account_nodes(), ACCOUNT_PATH_LENGTH);
}}

#[test(should_fail)]
unconstrained fn wrong_state_root_fails() {{
    let mut bad_root = STATE_ROOT;
    bad_root[0] += 1;
    verify_account_proof(bad_root, account(), account_nodes(), ACCOUNT_PATH_LENGTH);
}}

#[test(should_fail)]
unconstrained fn truncated_path_fails() {{
    verify_account_proof(STATE_ROOT, account(), account_nodes(), ACCOUNT_PATH_LENGTH - 1);
}}
"""
    path = Path(__file__).resolve().parent.parent / "src" / "tests" / "vectors.nr"
    path.write_text(out)
    print(
        f"wrote {path}: block {int(block_number, 16)}, "
        f"account path {len(account_path)} nodes, storage path {len(storage_path)} nodes, "
        f"slot value 0x{slot_value:x}"
    )


if __name__ == "__main__":
    main()
