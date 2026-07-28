use crate::slot_key::{
    add_offset, address_mapping_slot, array_element_slot, mapping_slot, nested_mapping_slot,
    value_slot,
};
use crate::types::StorageSlot;
use crate::utils::{get_rlp_length, to_nibbles};

#[test]
fn to_nibbles_splits_bytes() {
    let nibbles: [u8; 4] = to_nibbles([0xab, 0x0f]);
    assert_eq(nibbles, [0xa, 0xb, 0x0, 0xf]);
}

#[test]
fn rlp_length_rules() {
    assert_eq(get_rlp_length(0, 0), 1); // empty string: 0x80
    assert_eq(get_rlp_length(0x7f, 1), 1); // single byte <= 127: itself
    assert_eq(get_rlp_length(0x80, 1), 2); // single byte > 127: prefix + byte
    assert_eq(get_rlp_length(0xff, 20), 21); // short string: prefix + payload
}

// ---------------- slot locations ----------------
//
// Expected values are keccak-derived Solidity slot locations, computed
// independently by scripts/_keccak.py.

#[test]
fn value_slot_is_big_endian_padded() {
    let mut expected = [0; 32];
    expected[31] = 3;
    assert_eq(value_slot(3), expected);

    let mut wide = [0; 32];
    wide[30] = 1;
    wide[31] = 0x2c;
    assert_eq(value_slot(300), wide);
}

#[test]
fn address_mapping_slot_matches_solidity() {
    // keccak(pad32(0xB4e1..C9Dc) ‖ pad32(0))
    let address = [
        180, 225, 109, 1, 104, 229, 45, 53, 202, 205, 44, 97, 133, 180, 66, 129, 236, 40, 201, 220,
    ];
    assert_eq(
        address_mapping_slot(address, 0),
        [
            241, 42, 91, 196, 113, 46, 44, 110, 171, 188, 170, 134, 61, 249, 171, 51, 240, 174, 75,
            252, 216, 40, 184, 223, 201, 113, 220, 198, 118, 253, 214, 78,
        ],
    );
}

#[test]
fn mapping_slot_matches_solidity() {
    // keccak(pad32(1) ‖ pad32(7))
    let mut key = [0; 32];
    key[31] = 1;
    assert_eq(
        mapping_slot(key, 7),
        [
            179, 146, 33, 172, 224, 83, 70, 94, 195, 69, 60, 226, 179, 100, 48, 189, 19, 139, 153,
            126, 206, 162, 92, 16, 67, 218, 12, 54, 104, 18, 184, 40,
        ],
    );
}

#[test]
fn nested_mapping_slot_matches_solidity() {
    // m[1][2] declared at slot 3
    let mut outer = [0; 32];
    outer[31] = 1;
    let mut inner = [0; 32];
    inner[31] = 2;
    assert_eq(
        nested_mapping_slot(outer, inner, 3),
        [
            99, 56, 48, 153, 17, 131, 105, 227, 183, 225, 8, 16, 69, 12, 32, 11, 163, 12, 167, 79,
            22, 167, 152, 194, 29, 132, 110, 123, 143, 41, 248, 229,
        ],
    );
}

#[test]
fn array_element_slot_matches_solidity() {
    // keccak(pad32(5)) + 2
    assert_eq(
        array_element_slot(5, 2, 1),
        [
            3, 107, 99, 132, 181, 236, 167, 145, 198, 39, 97, 21, 45, 12, 121, 187, 6, 4, 193, 4,
            165, 251, 111, 78, 176, 112, 63, 49, 84, 187, 61, 178,
        ],
    );
}

#[test]
fn add_offset_carries_across_bytes() {
    let mut key = [0; 32];
    key[31] = 0xff;
    let bumped = add_offset(key, 1);
    assert_eq(bumped[31], 0);
    assert_eq(bumped[30], 1);

    // Multi-byte offsets propagate too.
    let mut wide = [0; 32];
    wide[31] = 1;
    let sum = add_offset(wide, 0x1ff);
    assert_eq(sum[31], 0);
    assert_eq(sum[30], 2);
}

#[test(should_fail_with = "slot key overflow")]
fn add_offset_rejects_overflow() {
    let _ = add_offset([0xff; 32], 1);
}

// ---------------- value decoding ----------------

#[test]
fn slot_value_decodes_as_quantity() {
    // 0x0186a0 = 100000, left-aligned minimal big-endian.
    let mut value = [0; 32];
    value[0] = 0x01;
    value[1] = 0x86;
    value[2] = 0xa0;
    let slot = StorageSlot { value, value_length: 3 };

    assert_eq(slot.to_field(), 100000);
    assert_eq(slot.to_u128(), 100000);
    assert_eq(slot.to_u128_pair(), (0, 100000));
    assert(!slot.is_zero());
}

#[test]
fn empty_slot_decodes_as_zero() {
    let slot = StorageSlot { value: [0; 32], value_length: 0 };
    assert(slot.is_zero());
    assert_eq(slot.to_field(), 0);
    assert_eq(slot.to_u128(), 0);
    assert_eq(slot.to_u128_pair(), (0, 0));
}

#[test]
fn full_width_slot_splits_into_halves() {
    // A packed 256-bit slot: high half 1, low half 2.
    let mut value = [0; 32];
    value[15] = 1;
    value[31] = 2;
    let slot = StorageSlot { value, value_length: 32 };
    assert_eq(slot.to_u128_pair(), (1, 2));
}

#[test(should_fail_with = "slot value exceeds 128 bits")]
fn oversized_slot_rejected_as_u128() {
    let slot = StorageSlot { value: [0xff; 32], value_length: 32 };
    let _ = slot.to_u128();
}
