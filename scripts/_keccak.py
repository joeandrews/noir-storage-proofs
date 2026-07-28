"""Pure-Python keccak256 (no dependencies).

Needed by the fixture generators to derive trie keys (`keccak(address)`,
`keccak(slot_key)`) and Solidity mapping slot locations. Ethereum's keccak256
is the original Keccak padding (0x01), not SHA3-256's 0x06, so hashlib's
sha3_256 cannot be used.
"""

_MASK = (1 << 64) - 1

_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# _ROT[x][y] = rho rotation offset for lane (x, y).
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl(v: int, n: int) -> int:
    n %= 64
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _keccak_f(a: list[list[int]]) -> list[list[int]]:
    for rnd in range(24):
        # theta
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        # rho + pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(a[x][y], _ROT[x][y])
        # chi
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y] & _MASK) & b[(x + 2) % 5][y])
        # iota
        a[0][0] ^= _RC[rnd]
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136  # (1600 - 2 * 256) / 8
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0x00)
    padded[-1] |= 0x80

    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            lane = int.from_bytes(block[i * 8 : i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        state = _keccak_f(state)

    out = bytearray()
    for i in range(4):  # first 32 bytes of the squeezed output
        out += (state[i % 5][i // 5]).to_bytes(8, "little")
    return bytes(out)


def to_nibbles(data: bytes) -> list[int]:
    return [n for b in data for n in (b >> 4, b & 0x0F)]


if __name__ == "__main__":
    # Known-answer tests. Multi-block inputs (> 136 bytes) are covered instead
    # by generate_test_vectors.py, which re-hashes every real proof node
    # (branch nodes are ~532 bytes) and checks it against its parent's child
    # hash.
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert (
        keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    )
    print("keccak256 self-test passed")
