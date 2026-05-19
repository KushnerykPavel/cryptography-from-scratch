# DES & 3DES — History and Why They Died
> DES is a Feistel cipher; 3DES is DES stapled together — and that still wasn’t enough.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 07 · 03 (Feistel Networks)  
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why DES/3DES are no longer acceptable for new designs
- **Compute** one DES round’s `f(R, K)` output from the definition
- **Implement** DES encrypt/decrypt for a single 64-bit block (ECB core)
- **Distinguish** DES vs 3DES (TDEA) keying options and the EDE construction
- **Apply** test vectors to validate a block-cipher implementation

## The Problem
You inherit a system that still uses **DES** or **3DES (TDEA)** somewhere: legacy payment rails, old HSM key-wrapping formats, smartcards, embedded devices, or protocols that refuse to die. You need to answer two questions fast:

1) **Is this actually DES/3DES, and in what exact construction (mode, keying option, padding)?**  
2) **How do we migrate without breaking compatibility or weakening security during the transition?**

This lesson makes DES/3DES concrete: you’ll build the **block primitive** (64-bit block encryption) from scratch, verify it against **NIST example vectors**, and see why “just add more DES” still leaves you with a cipher that modern standards are retiring.

## The Concept
### DES in one picture
DES is a **16-round Feistel network** on a 64-bit block:

- Start with an **Initial Permutation (IP)** (a fixed bit shuffle).
- Split into two 32-bit halves `(L0, R0)`.
- For rounds `i = 1..16`:
  - `Li = Ri-1`
  - `Ri = Li-1 XOR f(Ri-1, Ki)`
- Swap halves and apply the **Final Permutation (FP)** (the inverse of IP).

The only “interesting” part is the round function `f`:

1) Expand `R` from 32 → 48 bits via `E` (bit-selection with overlaps).  
2) XOR with a 48-bit round key `Ki`.  
3) Split into eight 6-bit chunks, apply **S-boxes** (6 → 4 bits each).  
4) Permute the 32-bit result with `P`.

### Keys and parity bits
DES keys are written as **64 bits** (8 bytes), but 8 bits are parity. The effective key space is **56 bits**, which is brute-forceable today.

### 3DES (TDEA): why EDE
3DES applies DES three times (in a specific order) to be backwards-compatible with DES hardware:

`C = E_{K3}(D_{K2}(E_{K1}(P)))`

That EDE structure allows “set `K1=K2=K3`” to degenerate to DES (which is why standards forbid all-three-equal keys).

Even with 3 independent keys, 3DES still has practical problems:

- **64-bit block size** → birthday collisions after ~`2^(64/2)=2^32` blocks (the “Sweet32” style risk in long-lived sessions).
- Performance is ~3× DES, and DES is slow compared to modern ciphers.
- Standards have moved on to **AES** and modern AEADs (GCM/CCM/ChaCha20-Poly1305).

## Build It

### Step 1: Bits, bytes, and permutations
DES is “table-driven”: everything is defined as **bit permutations**. We’ll implement:
- `permute_bits` for tables like IP/FP/E/P/PC-1/PC-2
- `rotate_left` for the 28-bit key-schedule halves

```python
from __future__ import annotations

from dataclasses import dataclass


class DesError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise DesError(message)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def int_to_bytes(x: int, length: int) -> bytes:
    _require(x >= 0, "x must be non-negative")
    _require(length >= 0, "length must be non-negative")
    return x.to_bytes(length, byteorder="big", signed=False)


def _require_block8(block: bytes) -> bytes:
    _require(isinstance(block, (bytes, bytearray)), "block must be bytes-like")
    b = bytes(block)
    _require(len(b) == 8, "block must be exactly 8 bytes (64 bits)")
    return b


def _require_key8(key: bytes) -> bytes:
    _require(isinstance(key, (bytes, bytearray)), "key must be bytes-like")
    k = bytes(key)
    _require(len(k) == 8, "key must be exactly 8 bytes (64 bits, includes parity bits)")
    return k


def permute_bits(x: int, in_bits: int, table: list[int]) -> int:
    _require(in_bits > 0, "in_bits must be positive")
    _require(0 <= x < (1 << in_bits), "x out of range for in_bits")
    out = 0
    for p in table:
        _require(1 <= p <= in_bits, "table entry out of range")
        out = (out << 1) | ((x >> (in_bits - p)) & 1)
    return out


def rotate_left(x: int, shift: int, width: int) -> int:
    _require(width > 0, "width must be positive")
    _require(0 <= x < (1 << width), "x out of range for width")
    s = shift % width
    mask = (1 << width) - 1
    return ((x << s) | (x >> (width - s))) & mask


IP = [
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    60,
    52,
    44,
    36,
    28,
    20,
    12,
    4,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    64,
    56,
    48,
    40,
    32,
    24,
    16,
    8,
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
]

FP = [
    40,
    8,
    48,
    16,
    56,
    24,
    64,
    32,
    39,
    7,
    47,
    15,
    55,
    23,
    63,
    31,
    38,
    6,
    46,
    14,
    54,
    22,
    62,
    30,
    37,
    5,
    45,
    13,
    53,
    21,
    61,
    29,
    36,
    4,
    44,
    12,
    52,
    20,
    60,
    28,
    35,
    3,
    43,
    11,
    51,
    19,
    59,
    27,
    34,
    2,
    42,
    10,
    50,
    18,
    58,
    26,
    33,
    1,
    41,
    9,
    49,
    17,
    57,
    25,
]
```

This is the foundation: DES is just “apply these tables in the right order”.

### Step 2: DES key schedule (PC-1, shifts, PC-2)
DES turns a 64-bit key into 16 round keys `K1..K16` (48 bits each). The parity bits are dropped by `PC1`.

```python
PC1 = [
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    60,
    52,
    44,
    36,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    28,
    20,
    12,
    4,
]

PC2 = [
    14,
    17,
    11,
    24,
    1,
    5,
    3,
    28,
    15,
    6,
    21,
    10,
    23,
    19,
    12,
    4,
    26,
    8,
    16,
    7,
    27,
    20,
    13,
    2,
    41,
    52,
    31,
    37,
    47,
    55,
    30,
    40,
    51,
    45,
    33,
    48,
    44,
    49,
    39,
    56,
    34,
    53,
    46,
    42,
    50,
    36,
    29,
    32,
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def des_key_schedule(key: bytes) -> list[int]:
    k = _require_key8(key)
    key64 = bytes_to_int(k)
    key56 = permute_bits(key64, 64, PC1)
    c = (key56 >> 28) & ((1 << 28) - 1)
    d = key56 & ((1 << 28) - 1)
    subkeys: list[int] = []
    for shift in SHIFTS:
        c = rotate_left(c, shift, 28)
        d = rotate_left(d, shift, 28)
        cd56 = (c << 28) | d
        subkeys.append(permute_bits(cd56, 56, PC2))
    return subkeys
```

Now we can produce `K1..K16` for a key and feed them into the Feistel rounds.

### Step 3: The DES f-function (E, S-boxes, P)
This is the “confusion + diffusion” part: expand `R`, XOR a subkey, substitute through S-boxes, and permute.

```python
E = [
    32,
    1,
    2,
    3,
    4,
    5,
    4,
    5,
    6,
    7,
    8,
    9,
    8,
    9,
    10,
    11,
    12,
    13,
    12,
    13,
    14,
    15,
    16,
    17,
    16,
    17,
    18,
    19,
    20,
    21,
    20,
    21,
    22,
    23,
    24,
    25,
    24,
    25,
    26,
    27,
    28,
    29,
    28,
    29,
    30,
    31,
    32,
    1,
]

P = [
    16,
    7,
    20,
    21,
    29,
    12,
    28,
    17,
    1,
    15,
    23,
    26,
    5,
    18,
    31,
    10,
    2,
    8,
    24,
    14,
    32,
    27,
    3,
    9,
    19,
    13,
    30,
    6,
    22,
    11,
    4,
    25,
]

SBOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]


def des_round_f(right32: int, subkey48: int) -> int:
    _require(0 <= right32 < (1 << 32), "right32 out of range")
    _require(0 <= subkey48 < (1 << 48), "subkey48 out of range")
    expanded = permute_bits(right32, 32, E)  # 48 bits
    x = expanded ^ subkey48
    out32 = 0
    for i in range(8):
        chunk = (x >> (42 - 6 * i)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 0x01)
        col = (chunk >> 1) & 0x0F
        out32 = (out32 << 4) | SBOXES[i][row][col]
    return permute_bits(out32, 32, P)
```

This function is what turns a Feistel network into a “real” block cipher: without good `f`, rounds don’t mix enough.

### Step 4: DES encrypt/decrypt (single 64-bit block)
DES encryption is just Feistel rounds with `K1..K16`. Decryption uses the same code but with keys reversed.

```python
def _des_crypt_block(block: bytes, subkeys: list[int]) -> bytes:
    b = _require_block8(block)
    _require(len(subkeys) == 16, "DES needs exactly 16 subkeys")

    x = bytes_to_int(b)
    ip = permute_bits(x, 64, IP)
    left = (ip >> 32) & 0xFFFF_FFFF
    right = ip & 0xFFFF_FFFF

    for k in subkeys:
        left, right = right, left ^ des_round_f(right, k)

    preoutput = (right << 32) | left
    out = permute_bits(preoutput, 64, FP)
    return int_to_bytes(out, 8)


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    subkeys = des_key_schedule(key)
    return _des_crypt_block(block, subkeys)


def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    subkeys = list(reversed(des_key_schedule(key)))
    return _des_crypt_block(block, subkeys)
```

At this point you have the **primitive** that ECB mode is built from: 64-bit block-in, 64-bit block-out.

### Step 5: 3DES (TDEA) with EDE
3DES composes DES three times. The standardized construction is EDE.

```python
def tdea_encrypt_block(block: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    b = _require_block8(block)
    k1 = _require_key8(key1)
    k2 = _require_key8(key2)
    k3 = _require_key8(key3)
    _require(not (k1 == k2 == k3), "TDEA key bundle must not have three identical keys")
    return des_encrypt_block(des_decrypt_block(des_encrypt_block(b, k1), k2), k3)


def tdea_decrypt_block(block: bytes, key1: bytes, key2: bytes, key3: bytes) -> bytes:
    b = _require_block8(block)
    k1 = _require_key8(key1)
    k2 = _require_key8(key2)
    k3 = _require_key8(key3)
    _require(not (k1 == k2 == k3), "TDEA key bundle must not have three identical keys")
    return des_decrypt_block(des_encrypt_block(des_decrypt_block(b, k3), k2), k1)
```

This is the exact construction you’ll validate against NIST example vectors in `tests/vectors.json`.

Run it:

```bash
python3 code/main.py
```

## Use It
DES/3DES should not be used for new designs. If you still need it for interoperability, use an audited library:

- **OpenSSL**: `EVP_des_ede3_*` ciphers (and many modes); often used transitively via other libraries.
- **Python**:
  - `cryptography` (OpenSSL backend) exposes 3DES in legacy modules.
  - `PyCryptodome` supports DES/3DES and includes known-answer self-tests.
- **Java**: `"DESede"` / `"DESede/CBC/NoPadding"` (watch out for padding and IV defaults).

Prefer modern replacements:
- AES-GCM / AES-CTR + HMAC (if you must split)
- ChaCha20-Poly1305

## Pitfalls
1. **ECB mode**: repeated plaintext blocks produce repeated ciphertext blocks. (It “works” but leaks structure.)
2. **64-bit block size**: long-lived sessions leak via birthday collisions (the Sweet32-style risk).
3. **Keying confusion**: 3DES has keying options; “two-key 3DES” vs “three-key 3DES” is not the same security level.
4. **Parity bits and key formats**: some APIs expect odd parity bits; others accept raw 8 bytes and adjust or ignore parity.
5. **Padding and IV defaults**: “NoPadding” vs PKCS#7, IV reuse in CBC/CFB/OFB, and implicit zero-IVs are common integration bugs.

## Ship It
Save the reusable checklist at `outputs/des-3des-review-checklist.md`.

Use it in PR reviews or incident response when you see:
- `DES`, `DESede`, `3DES`, `TDEA`, `EVP_des_*`, `Cipher.getInstance("DESede/...")`, or suspicious 8-byte block assumptions.

Goal: quickly classify “is this legacy-only decrypt?” vs “are we still encrypting new data with 3DES?” and plan a safe migration path.

## Exercises
1. Easy: Run `python3 code/main.py`. Observe that IP/FP round-trip and that DES decrypt(encrypt(P)) recovers `P`.
2. Medium: Add a small helper in `code/main.py` that encrypts two identical 8-byte blocks with DES (ECB) and prints that the ciphertext blocks are identical. Explain why this is a problem.
3. Hard: Integrate a real library (e.g., OpenSSL or `cryptography`) to decrypt the NIST TDEA example blocks and verify you match the ciphertext values. Document the exact mode and padding you used.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| DES | “Old block cipher” | A 16-round Feistel cipher with 64-bit blocks and 56-bit effective key |
| Parity bit | “Part of the key” | A per-byte parity check bit; not part of the effective 56-bit key |
| S-box | “Lookup table” | Nonlinear substitution mapping 6 input bits → 4 output bits |
| EDE | “Triple encryption” | 3DES structure: encrypt with K1, decrypt with K2, encrypt with K3 |
| Sweet32 | “A 3DES bug” | Birthday-collision risk from 64-bit blocks after ~2^32 blocks in one key/session |

## Further Reading
- NIST, *Recommendation for the Triple Data Encryption Algorithm (TDEA) Block Cipher (SP 800-67 Rev. 1)* (2012) — Defines TDEA/3DES and includes a worked EDE example (Appendix B).
- NIST, *Modes of Operation Validation System (MOVS): Requirements and Procedures (SP 800-17)* (1998) — Contains DES known-answer test tables useful for validation.
- NIST, *Transitioning the Use of Cryptographic Algorithms and Key Lengths (SP 800-131A Rev. 2)* (2019) — Practical transition guidance that explains why 3DES is being retired.
