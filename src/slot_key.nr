//! Solidity storage-slot locations.
//!
//! A proof only tells you that *some* trie key holds a value. These helpers
//! derive that key from the Solidity declaration, so a circuit can bind the
//! value it proved to the variable it cares about — e.g. that a balance really
//! is `_balances[holder]` and not some other slot the prover preferred.
//!
//! Layout rules follow the Solidity storage model: statically-sized variables
//! occupy consecutive slots from 0, mapping entries hash to
//! `keccak(pad32(key) ‖ pad32(declaration_slot))`, and dynamic arrays store
//! their elements from `keccak(pad32(declaration_slot))`.

use super::keccak::KeccakHasher;

/// `pad32(slot)` — the location of a statically-placed variable declared at
/// `slot` (`uint256 public total;` at slot 3 → `value_slot(3)`).
pub fn value_slot(slot: u32) -> [u8; 32] {
    let mut key = [0; 32];
    let slot_bytes: [u8; 4] = (slot as Field).to_be_bytes();
    for i in 0..4 {
        key[28 + i] = slot_bytes[i];
    }
    key
}

/// `keccak(key ‖ pad32(slot))` — the location of `m[key]` for a mapping
/// declared at `slot`, with `key` already padded to its 32-byte ABI encoding.
pub fn mapping_slot(key: [u8; 32], slot: u32) -> [u8; 32] {
    let slot_key = value_slot(slot);
    let mut buf = [0; 64];
    for i in 0..32 {
        buf[i] = key[i];
        buf[32 + i] = slot_key[i];
    }
    KeccakHasher::hash_bytes(buf, 64)
}

/// The location of `m[address]` for a `mapping(address => ...)` declared at
/// `slot` — the ERC-20 `balanceOf` / `allowance` shape. Addresses are
/// left-padded to 32 bytes.
pub fn address_mapping_slot(address: [u8; 20], slot: u32) -> [u8; 32] {
    let mut key = [0; 32];
    for i in 0..20 {
        key[12 + i] = address[i];
    }
    mapping_slot(key, slot)
}

/// The location of `m[outer][inner]` for a nested mapping declared at `slot`:
/// the outer lookup produces the slot the inner mapping is declared at.
/// Both keys are already 32-byte ABI encoded.
pub fn nested_mapping_slot(outer: [u8; 32], inner: [u8; 32], slot: u32) -> [u8; 32] {
    let outer_slot = mapping_slot(outer, slot);
    let mut buf = [0; 64];
    for i in 0..32 {
        buf[i] = inner[i];
        buf[32 + i] = outer_slot[i];
    }
    KeccakHasher::hash_bytes(buf, 64)
}

/// The location of `a[index]` for a dynamic `T[]` declared at `slot`, where `T`
/// occupies `slots_per_element` slots (1 for anything word-sized or smaller).
/// Elements start at `keccak(pad32(slot))`; the array's length lives in `slot`
/// itself (`value_slot(slot)`).
pub fn array_element_slot(slot: u32, index: u32, slots_per_element: u32) -> [u8; 32] {
    let base = KeccakHasher::hash_bytes(value_slot(slot), 32);
    add_offset(base, index * slots_per_element)
}

/// Adds a small offset to a 32-byte slot key (big-endian), for reaching
/// successive slots of a multi-slot struct or array element.
pub fn add_offset(key: [u8; 32], offset: u32) -> [u8; 32] {
    let mut out = key;
    let mut carry = offset as u64;
    for i in 0..32 {
        let idx = 31 - i;
        let sum = out[idx] as u64 + (carry & 0xff);
        out[idx] = sum as u8;
        carry = (carry >> 8) + (sum >> 8);
    }
    assert(carry == 0, "slot key overflow");
    out
}
