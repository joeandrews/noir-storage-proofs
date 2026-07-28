#!/usr/bin/env node
// Fetch an eth_getProof and convert it into this library's Noir input types.
//
// Dependency-free (Node 18+). Prints JSON with every struct in the shape the
// library expects: hashes as [u64; 4] little-endian limbs (decimal strings),
// proof paths as Node structs with the trailing leaf dropped.
//
// Usage:
//   node scripts/fetch_proof_inputs.mjs <rpc-url> <address> [slot-key ...] [--block <tag>]
//
// Example:
//   node scripts/fetch_proof_inputs.mjs https://ethereum-rpc.publicnode.com \
//     0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc \
//     0x0000000000000000000000000000000000000000000000000000000000000008

const args = process.argv.slice(2);
const blockIdx = args.indexOf('--block');
const blockTag = blockIdx === -1 ? 'finalized' : args.splice(blockIdx, 2)[1];
const [rpcUrl, address, ...slotKeys] = args;
if (!rpcUrl || !address) {
  console.error('usage: fetch_proof_inputs.mjs <rpc-url> <address> [slot-key ...] [--block <tag>]');
  process.exit(1);
}

async function rpc(method, params) {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

const hexBytes = (hex) => {
  let h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length % 2) h = '0' + h;
  return Array.from(Buffer.from(h, 'hex'));
};

const padTo = (arr, len) => {
  if (arr.length > len) throw new Error(`array length ${arr.length} > ${len}`);
  return [...arr, ...Array(len - arr.length).fill(0)];
};

/** 32 bytes -> [u64; 4], limb i = bytes 8i..8i+8, little-endian within limb. */
const toU64Limbs = (bytes) => {
  const b = padTo(bytes, 32);
  return Array.from({ length: 4 }, (_, i) => {
    let val = 0n;
    for (let j = 0; j < 8; j++) val += BigInt(b[i * 8 + j]) << BigInt(j * 8);
    return val.toString();
  });
};

/** Minimal big-endian bytes of a quantity (0 -> empty). */
const quantityBytes = (value) => {
  if (value === 0n) return [];
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return hexBytes(hex);
};

// ---------------- minimal RLP decoder ----------------

function rlpDecode(data) {
  const [item, rest] = rlpItem(data);
  if (rest.length) throw new Error('trailing bytes after RLP item');
  return item;
}

function rlpItem(data) {
  const prefix = data[0];
  if (prefix <= 0x7f) return [data.subarray(0, 1), data.subarray(1)];
  if (prefix <= 0xb7) {
    const n = prefix - 0x80;
    return [data.subarray(1, 1 + n), data.subarray(1 + n)];
  }
  if (prefix <= 0xbf) {
    const ln = prefix - 0xb7;
    const n = Number(BigInt('0x' + Buffer.from(data.subarray(1, 1 + ln)).toString('hex')));
    return [data.subarray(1 + ln, 1 + ln + n), data.subarray(1 + ln + n)];
  }
  if (prefix <= 0xf7) {
    const n = prefix - 0xc0;
    return [rlpList(data.subarray(1, 1 + n)), data.subarray(1 + n)];
  }
  const ln = prefix - 0xf7;
  const n = Number(BigInt('0x' + Buffer.from(data.subarray(1, 1 + ln)).toString('hex')));
  return [rlpList(data.subarray(1 + ln, 1 + ln + n)), data.subarray(1 + ln + n)];
}

function rlpList(payload) {
  const items = [];
  while (payload.length) {
    const [item, rest] = rlpItem(payload);
    items.push(item);
    payload = rest;
  }
  return items;
}

// ---------------- proof node -> library Node struct ----------------

const zeroNode = () => ({
  rows: Array.from({ length: 16 }, () => ['0', '0', '0', '0']),
  row_exist: Array(16).fill(false),
  node_type: 0,
});

function parseNode(rlpHex) {
  const decoded = rlpDecode(Buffer.from(hexBytes(rlpHex)));
  if (!Array.isArray(decoded)) throw new Error('expected an RLP list node');
  const node = zeroNode();

  if (decoded.length === 17) {
    for (let i = 0; i < 16; i++) {
      if (decoded[i].length) {
        if (decoded[i].length !== 32) throw new Error('embedded (<32-byte) branch child unsupported');
        node.row_exist[i] = true;
        node.rows[i] = toU64Limbs(Array.from(decoded[i]));
      }
    }
  } else if (decoded.length === 2) {
    const key = Array.from(decoded[0]);
    const prefix = key[0] >> 4;
    if (prefix >= 2) throw new Error('leaf node in proof path (path must exclude the trailing leaf)');
    if (decoded[1].length !== 32) throw new Error('embedded extension child unsupported');
    node.node_type = 1;
    // Extension header layout expected by types.nr.
    const row0 = Array(32).fill(0);
    row0[0] = prefix; // is_odd
    row0[8] = key[0] & 0x0f; // first_nibble
    row0[16] = key.length - 1; // extension_length
    node.rows[0] = toU64Limbs(row0);
    node.rows[1] = toU64Limbs(padTo(key.slice(1), 32));
    node.rows[2] = toU64Limbs(Array.from(decoded[1]));
    node.row_exist[0] = node.row_exist[1] = node.row_exist[2] = true;
  } else {
    throw new Error(`unexpected MPT node arity ${decoded.length}`);
  }
  return node;
}

/** Path nodes of a proof: every node except the trailing leaf. */
const parseProofPath = (proof) => proof.slice(0, -1).map(parseNode);

// ---------------- main ----------------

const block = await rpc('eth_getBlockByNumber', [blockTag, false]);
const proof = await rpc('eth_getProof', [address, slotKeys, block.number]);

const nonce = quantityBytes(BigInt(proof.nonce));
const balance = quantityBytes(BigInt(proof.balance));

const output = {
  block_number: Number(block.number),
  state_root: toU64Limbs(hexBytes(block.stateRoot)),
  account: {
    nonce: padTo(nonce, 8),
    balance: padTo(balance, 32),
    address: hexBytes(address),
    nonce_length: nonce.length,
    balance_length: balance.length,
    storage_hash: toU64Limbs(hexBytes(proof.storageHash)),
    code_hash: toU64Limbs(hexBytes(proof.codeHash)),
  },
  account_proof: {
    nodes: parseProofPath(proof.accountProof),
    node_length: proof.accountProof.length - 1,
  },
  storage_proofs: proof.storageProof.map((sp) => {
    const value = quantityBytes(BigInt(sp.value));
    if (!value.length) {
      console.error(`warning: slot ${sp.key} is zero — exclusion proofs are unsupported`);
    }
    return {
      slot_key: padTo(hexBytes(sp.key), 32),
      slot: { value: padTo(value, 32), value_length: value.length },
      nodes: parseProofPath(sp.proof),
      node_length: sp.proof.length - 1,
    };
  }),
};

console.log(JSON.stringify(output, null, 2));
