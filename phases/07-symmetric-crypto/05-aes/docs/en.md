# AES from Scratch — One Block, Fully Explained
> A block cipher is a handful of byte transforms + round keys, repeated.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `07-symmetric-crypto/03-feistel/`, `07-symmetric-crypto/04-des-3des/`  
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain AES’s state layout and round structure.
- Compute GF(2^8) byte multiplication and relate it to MixColumns.
- Implement SubBytes, ShiftRows, MixColumns, and AddRoundKey.
- Distinguish AES (a block cipher) from modes (CBC/CTR/GCM) that use it.
- Apply FIPS 197 test vectors to validate an AES implementation.

## The Problem
AES shows up everywhere: disk encryption, TLS, messaging apps, cloud KMS APIs, firmware update chains, and hardware security modules. You will rarely “implement AES” in production, but you will frequently need to *reason about it*—to debug an integration, interpret a vulnerability report, or review whether a system is using it correctly.

AES failures are often silent. A single off-by-one in ShiftRows or a wrong constant in MixColumns can produce ciphertext that “looks random” but is incorrect, breaking interoperability and (worse) encouraging dangerous homegrown compatibility hacks. Understanding the internals lets you validate implementations against authoritative vectors and spot misuse (like ECB mode or IV reuse) before it ships.

## The Concept
AES is a 128-bit *block cipher*: it transforms a 16-byte plaintext block into a 16-byte ciphertext block under a secret key. It does this by repeatedly transforming a 4×4 “state” of bytes:

- **State layout:** AES fills the state *column-by-column* from the 16 input bytes. Indexing in code often uses `state[r + 4*c]`.
- **Round structure:** AES-128 runs 10 rounds (AES-192: 12, AES-256: 14). Each round uses a different **round key** derived from the master key (the **key schedule**).
- **Core transforms (encryption rounds):**
  - `SubBytes`: non-linear substitution via a fixed 256-entry S-box.
  - `ShiftRows`: permutes bytes by rotating each row left by 0/1/2/3 positions.
  - `MixColumns`: mixes each column using linear algebra over **GF(2^8)**.
  - `AddRoundKey`: XOR with the round key.

Two big mental models:
1. **AES is “bytes all the way down.”** Every operation is on bytes (0–255), with XOR as addition.
2. **MixColumns is “matrix multiplication” in GF(2^8).** The “multiply by 2” operation is `xtime()` (left shift + conditional XOR with `0x1b`).

## Build It
### Step 1: State and AddRoundKey
AES represents the working block as 16 bytes (the state). `AddRoundKey` is byte-wise XOR with a 16-byte round key.

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b))


def bytes_to_state(block: bytes) -> List[int]:
    if len(block) != 16:
        raise ValueError("AES state is exactly 16 bytes")
    return list(block)


def state_to_bytes(state: Sequence[int]) -> bytes:
    if len(state) != 16:
        raise ValueError("AES state must have length 16")
    return bytes(int(x) & 0xFF for x in state)


def add_round_key(state: List[int], round_key: bytes) -> List[int]:
    if len(round_key) != 16:
        raise ValueError("round_key must be 16 bytes")
    return [s ^ k for s, k in zip(state, round_key)]
```

### Step 2: SubBytes and ShiftRows
`SubBytes` applies a fixed lookup table (S-box) to each byte. `ShiftRows` rotates each row to spread bytes across columns.

```python
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def sub_bytes(state: List[int]) -> List[int]:
    return [SBOX[b] for b in state]


def inv_sub_bytes(state: List[int]) -> List[int]:
    return [INV_SBOX[b] for b in state]


def shift_rows(state: List[int]) -> List[int]:
    out = state[:]
    for r in range(4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            out[r + 4 * c] = row[c]
    return out


def inv_shift_rows(state: List[int]) -> List[int]:
    out = state[:]
    for r in range(4):
        row = [state[r + 4 * c] for c in range(4)]
        if r:
            row = row[-r:] + row[:-r]
        for c in range(4):
            out[r + 4 * c] = row[c]
    return out
```

### Step 3: GF(2^8) and MixColumns
MixColumns treats each column as a 4-byte vector and multiplies it by a fixed matrix in GF(2^8). The helper `xtime()` is “multiply by 2” modulo the AES irreducible polynomial.

```python
def xtime(a: int) -> int:
    a &= 0xFF
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gf_mul(a: int, b: int) -> int:
    a &= 0xFF
    b &= 0xFF
    res = 0
    x = a
    y = b
    for _ in range(8):
        if y & 1:
            res ^= x
        y >>= 1
        x = xtime(x)
    return res & 0xFF


def mix_single_column(col: Sequence[int]) -> List[int]:
    if len(col) != 4:
        raise ValueError("column must have 4 bytes")
    a0, a1, a2, a3 = (int(x) & 0xFF for x in col)
    return [
        gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3,
        a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3,
        a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3),
        gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2),
    ]


def inv_mix_single_column(col: Sequence[int]) -> List[int]:
    if len(col) != 4:
        raise ValueError("column must have 4 bytes")
    a0, a1, a2, a3 = (int(x) & 0xFF for x in col)
    return [
        gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9),
        gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13),
        gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11),
        gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14),
    ]


def mix_columns(state: List[int]) -> List[int]:
    out = state[:]
    for c in range(4):
        col = [state[r + 4 * c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            out[r + 4 * c] = mixed[r]
    return out


def inv_mix_columns(state: List[int]) -> List[int]:
    out = state[:]
    for c in range(4):
        col = [state[r + 4 * c] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            out[r + 4 * c] = mixed[r]
    return out
```

### Step 4: Key Expansion
AES derives one 16-byte round key per round from the master key. The logic depends on the key length (AES-128/192/256).

```python
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
]


def rot_word(word: bytes) -> bytes:
    if len(word) != 4:
        raise ValueError("word must be 4 bytes")
    return word[1:] + word[:1]


def sub_word(word: bytes) -> bytes:
    if len(word) != 4:
        raise ValueError("word must be 4 bytes")
    return bytes(SBOX[b] for b in word)


def _nk_nr_from_key_len(key_len: int) -> Tuple[int, int]:
    if key_len == 16:
        return 4, 10
    if key_len == 24:
        return 6, 12
    if key_len == 32:
        return 8, 14
    raise ValueError("AES key must be 16/24/32 bytes (128/192/256-bit)")


def expand_key(key: bytes) -> List[bytes]:
    nk, nr = _nk_nr_from_key_len(len(key))
    words: List[bytes] = [key[4 * i : 4 * (i + 1)] for i in range(nk)]
    i = nk
    while len(words) < 4 * (nr + 1):
        temp = words[-1]
        if i % nk == 0:
            temp = bytes(
                t ^ r
                for t, r in zip(sub_word(rot_word(temp)), bytes([RCON[i // nk], 0, 0, 0]))
            )
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp)
        words.append(bytes(a ^ b for a, b in zip(words[-nk], temp)))
        i += 1

    round_keys: List[bytes] = []
    for r in range(nr + 1):
        rk = b"".join(words[4 * r : 4 * (r + 1)])
        round_keys.append(rk)
    return round_keys
```

### Step 5: Encrypt and decrypt one block
Putting it all together: initial `AddRoundKey`, then `Nr-1` full rounds, then a final round without MixColumns. Decryption applies the inverse operations in reverse order.

```python
def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) != 16:
        raise ValueError("AES encrypt_block expects a single 16-byte block")
    round_keys = expand_key(key)
    nr = len(round_keys) - 1

    state = bytes_to_state(plaintext)
    state = add_round_key(state, round_keys[0])
    for r in range(1, nr):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[r])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[nr])
    return state_to_bytes(state)


def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) != 16:
        raise ValueError("AES decrypt_block expects a single 16-byte block")
    round_keys = expand_key(key)
    nr = len(round_keys) - 1

    state = bytes_to_state(ciphertext)
    state = add_round_key(state, round_keys[nr])
    for r in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[r])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return state_to_bytes(state)
```

Run it:
python3 code/main.py

## Use It
In production you almost never implement AES yourself; you use an audited library *and* an AEAD mode (e.g., AES-GCM) that provides both confidentiality and integrity.

- **Python:** `cryptography` (recommended) or PyCryptodome (`Crypto.Cipher.AES`)
- **Go:** `crypto/aes` + `cipher.NewGCM`
- **Rust:** `aes` + `gcm` crates (RustCrypto)
- **OpenSSL / BoringSSL:** widely deployed C implementations

## Pitfalls
- **Confusing AES with “AES-XYZ mode”.** AES is just the block cipher; security depends on the mode (ECB/CBC/CTR/GCM) and parameters.
- **Using ECB because it “works”.** ECB leaks patterns (identical plaintext blocks → identical ciphertext blocks).
- **Reusing IVs/nonces in stream-like modes (CTR/GCM).** Nonce reuse can completely break confidentiality and/or integrity.
- **Skipping test vectors.** AES bugs often look “random” but fail interoperability and can mask deeper mistakes.
- **Assuming this code is safe.** This implementation is not constant-time; side channels matter in real deployments.

## Ship It
Save the reusable checklist in `outputs/aes-audit-checklist.md` and use it as:
- a PR review checklist when you see “AES” in an implementation,
- a prompt template to audit an architecture doc (mode choice, IV rules, key handling),
- a quick “stop-the-line” list of the most common AES misuses.

## Exercises
1. Easy: Run `python3 code/main.py`. Observe how the round-1 intermediate states match the FIPS 197 vector.
2. Medium: Extend `code/main.py` to print the state after each round for AES-128 (round[1]..round[10]) and compare against FIPS 197 Appendix C.1.
3. Hard: Using an audited library, encrypt a multi-block message with AES-GCM. Document (in a short note) how you generate/store the nonce and how you rotate keys.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Block cipher | “AES encrypts data” | A deterministic function mapping 16-byte blocks under a key. |
| State | “the 4×4 matrix” | The internal 16-byte working array indexed as `state[r + 4*c]`. |
| Round key | “a subkey” | A derived 16-byte key mixed into each round via XOR. |
| S-box | “the lookup table” | The non-linear byte substitution that provides confusion. |
| MixColumns | “diffusion step” | Linear mixing of each column over GF(2^8). |

## Further Reading
- NIST, FIPS 197: Advanced Encryption Standard (AES) (2001) — the canonical spec and Appendix C test vectors. ([PDF](https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf))
