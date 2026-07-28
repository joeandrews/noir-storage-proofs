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
