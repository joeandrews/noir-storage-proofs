use super::utils::{balance_to_field, get_low_nibble, runtime_loop};

pub struct ExtensionHeader {
    pub is_odd: bool,
    pub first_nibble: u8,
    pub extension_length: u8,
}

pub struct Node {
    pub rows: [[u64; 4]; 16],
    pub row_exist: [bool; 16],
    pub node_type: u8,
}

impl Node {
    #[inline_always]
    pub fn is_branch_node(self) -> bool {
        self.node_type == 0
    }

    #[inline_always]
    pub fn is_extension_node(self) -> bool {
        self.node_type == 1
    }

    #[inline_always]
    pub fn get_row_byte(self, row: u32, byte_index: u32) -> u8 {
        let limb_index = byte_index / 8;
        let shift = ((byte_index % 8) * 8) as u64;
        (self.rows[row][limb_index] >> shift) as u8
    }

    /// A branch node's hash only covers the children it has, so rows flagged
    /// absent must be zeroed rather than left to carry arbitrary data. Callers
    /// building `Node`s are expected to zero them; this checks it.
    pub fn assert_absent_children_zeroed(self) {
        for i in 0..16 {
            if !self.row_exist[i] {
                assert_eq(self.rows[i], [0; 4], "absent branch child must be zeroed");
            }
        }
    }

    pub fn extract_extension_header(self) -> ExtensionHeader {
        let is_odd = self.rows[0][0] != 0;
        let first_nibble = if is_odd {
            get_low_nibble(self.rows[0][1] as u8)
        } else {
            0
        };
        let extension_length = (self.rows[0][2] as u8);
        ExtensionHeader { is_odd, first_nibble, extension_length }
    }
}

pub struct Account {
    pub nonce: [u8; 8],
    pub balance: [u8; 32],
    pub address: [u8; 20],
    pub nonce_length: u8,
    pub balance_length: u8,
    pub storage_hash: [u64; 4],
    pub code_hash: [u64; 4],
}

pub struct StorageSlot {
    pub value: [u8; 32],
    pub value_length: u8,
}

impl Account {
    /// The account's ETH balance in wei. Total supply is far below 2^248, so
    /// the value always fits a Field.
    pub fn balance_as_field(self) -> Field {
        assert(self.balance_length <= 31, "balance too large for a Field");
        balance_to_field(self.balance, self.balance_length)
    }

    pub fn nonce_as_u64(self) -> u64 {
        assert(self.nonce_length <= 8, "nonce too long");
        let mut result: u64 = 0;
        runtime_loop!(
            quote { i },
            quote { 0 },
            quote { (self.nonce_length as u32) },
            quote { 8 },
            quote {
                result = result * 256 + self.nonce[i] as u64;
            },
        );
        result
    }
}

impl StorageSlot {
    /// A slot the trie has no entry for. Solidity reads absent slots as zero,
    /// but note that this library cannot *prove* absence — see the crate docs.
    pub fn is_zero(self) -> bool {
        self.value_length == 0
    }

    /// The value as a Field. Asserts it fits (up to 31 bytes) — use
    /// `to_u128_pair` for values that may use the full 256 bits.
    pub fn to_field(self) -> Field {
        assert(self.value_length <= 31, "slot value too large for a Field");
        balance_to_field(self.value, self.value_length)
    }

    /// The value as a `u128`, for token balances and other quantities that fit
    /// 128 bits (asserts the proven value really does).
    pub fn to_u128(self) -> u128 {
        assert(self.value_length <= 16, "slot value exceeds 128 bits");
        balance_to_field(self.value, self.value_length) as u128
    }

    /// The full 256-bit value as `(high, low)` 128-bit halves.
    pub fn to_u128_pair(self) -> (u128, u128) {
        let len = self.value_length as u32;
        assert(len <= 32, "slot value too long");
        // Values are left-aligned minimal big-endian, so the high half only
        // exists once the value is longer than 16 bytes.
        let high_len = if len > 16 { len - 16 } else { 0 };
        let mut high: Field = 0;
        let mut low: Field = 0;
        for i in 0..32 {
            if i < high_len {
                high = high * 256 + self.value[i] as Field;
            } else if i < len {
                low = low * 256 + self.value[i] as Field;
            }
        }
        // Each accumulator absorbs at most 16 bytes, so neither cast truncates.
        (high as u128, low as u128)
    }
}
