# Block Cipher Modes — ECB, CBC, CTR, CFB
> A block cipher is a 16-byte box; a mode is how you wire boxes together safely.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/07-symmetric-crypto/03-feistel/`, `phases/07-symmetric-crypto/05-aes/`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why block ciphers need modes to encrypt arbitrary-length data
- Distinguish ECB vs CBC vs CTR vs CFB by their leakage, IV/nonce needs, and error propagation
- Implement PKCS#7 padding and validation (unpadding)
- Compute mode encryption/decryption using only a block cipher and XOR
- Apply nonce/IV rules and spot mode-misuse bugs in real code reviews

## The Problem
You learned that a block cipher (like AES) encrypts a fixed-size block (usually 16 bytes). Real messages are not exactly 16 bytes, and they’re not a single block — they’re strings, files, JSON blobs, protocol frames, and database rows of arbitrary lengths.

If you “just encrypt each 16-byte chunk”, you get **ECB**, which leaks structure: identical plaintext blocks become identical ciphertext blocks. That’s enough to reveal patterns, repeated headers, and sometimes entire images or documents.

Even when you pick a “better” mode, it’s easy to misuse it: reusing a nonce in CTR, using a predictable IV in CBC, forgetting padding rules, or assuming “encryption” implies integrity. Mode misuse is one of the fastest ways to turn correct AES into broken crypto.

## The Concept
A **mode of operation** specifies how to turn a block cipher `E_K(·)` into an encryption scheme for messages of any length.

We’ll use:
- `E_K` / `D_K`: block cipher encrypt/decrypt a 16-byte block
- `P_i`: plaintext blocks, `C_i`: ciphertext blocks
- `⊕`: XOR
- `IV` / `nonce`: per-message value (must be unique; sometimes unpredictable)

### Quick comparison

| Mode | Needs padding? | Per-message value | Leaks patterns? | Parallelizable? | Main risk if misused |
|------|----------------|-------------------|-----------------|-----------------|----------------------|
| ECB  | Yes            | None              | Yes (bad)       | Yes             | Structure leakage    |
| CBC  | Yes            | IV (unique, ideally unpredictable) | No (if IV correct) | Encrypt: no, Decrypt: yes | IV reuse/predictability + padding bugs |
| CTR  | No             | nonce+counter (unique) | No (if nonce unique) | Yes | Nonce reuse → XOR-of-plaintexts |
| CFB  | No             | IV (unique)       | No (if IV correct) | No | Bit-flip malleability + IV reuse |

### The wiring diagrams (formulas)

ECB:
- `C_i = E_K(P_i)`

CBC:
- `C_0 = IV`
- `C_i = E_K(P_i ⊕ C_{i-1})`
- `P_i = D_K(C_i) ⊕ C_{i-1}`

CTR:
- `S_i = E_K(nonce || (counter+i))` (a keystream block)
- `C = P ⊕ S` (XOR stream, no padding)

CFB (CFB-128, full-block feedback):
- `S_i = E_K(C_{i-1})` with `C_0 = IV`
- `C_i = P_i ⊕ S_i`
- `P_i = C_i ⊕ E_K(C_{i-1})` (same keystream, but feedback uses ciphertext)

Important: CBC/CTR/CFB provide **confidentiality only**. They do not prevent an attacker from modifying ciphertext in transit. In practice you use an **AEAD** mode (GCM, ChaCha20-Poly1305) or “encrypt-then-MAC”.

## Build It

### Step 1: A toy 128-bit block cipher
We need a 16-byte encrypt/decrypt primitive to plug into modes. To keep the lesson stdlib-only, we’ll build a tiny Feistel cipher over 128-bit blocks. This is not secure like AES, but it is a real permutation, so modes behave “like they would” with a real block cipher.

```python
from __future__ import annotations

import hashlib
from dataclasses import dataclass


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor_bytes requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass(frozen=True)
class ToyFeistelCipher128:
    key: bytes
    rounds: int = 10

    block_size: int = 16
    half_size: int = 8

    def _f(self, round_index: int, right: bytes) -> bytes:
        if len(right) != self.half_size:
            raise ValueError("right must be 8 bytes")
        h = hashlib.sha256()
        h.update(self.key)
        h.update(round_index.to_bytes(4, "big"))
        h.update(right)
        return h.digest()[: self.half_size]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("block must be 16 bytes")
        left = block[: self.half_size]
        right = block[self.half_size :]
        for r in range(self.rounds):
            new_left = right
            new_right = xor_bytes(left, self._f(r, right))
            left, right = new_left, new_right
        return left + right

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("block must be 16 bytes")
        left = block[: self.half_size]
        right = block[self.half_size :]
        for r in reversed(range(self.rounds)):
            prev_right = left
            prev_left = xor_bytes(right, self._f(r, prev_right))
            left, right = prev_left, prev_right
        return left + right
```

### Step 2: PKCS#7 padding + ECB
ECB is “just encrypt each block”, but you must first handle arbitrary-length messages. We’ll use PKCS#7 padding: always add `1..block_size` bytes, each with the value equal to the pad length, and validate it strictly during unpadding.

```python
def split_blocks(data: bytes, block_size: int) -> list[bytes]:
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if len(data) % block_size != 0:
        raise ValueError("data length must be a multiple of block_size")
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    if not (2 <= block_size <= 255):
        raise ValueError("block_size must be in [2, 255]")
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int) -> bytes:
    if not (2 <= block_size <= 255):
        raise ValueError("block_size must be in [2, 255]")
    if len(padded) == 0 or (len(padded) % block_size) != 0:
        raise ValueError("invalid padded length")
    pad_len = padded[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid padding length")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding bytes")
    return padded[:-pad_len]


def ecb_encrypt(cipher: ToyFeistelCipher128, plaintext: bytes) -> bytes:
    padded = pkcs7_pad(plaintext, cipher.block_size)
    out = bytearray()
    for block in split_blocks(padded, cipher.block_size):
        out.extend(cipher.encrypt_block(block))
    return bytes(out)


def ecb_decrypt(cipher: ToyFeistelCipher128, ciphertext: bytes) -> bytes:
    out = bytearray()
    for block in split_blocks(ciphertext, cipher.block_size):
        out.extend(cipher.decrypt_block(block))
    return pkcs7_unpad(bytes(out), cipher.block_size)
```

### Step 3: CBC (chaining blocks with an IV)
CBC fixes ECB’s “identical blocks → identical ciphertext” problem by XORing each plaintext block with the previous ciphertext block before encryption. The IV must be unique per message (and ideally unpredictable). CBC still needs padding.

```python
def cbc_encrypt(cipher: ToyFeistelCipher128, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != cipher.block_size:
        raise ValueError("iv must be 16 bytes")
    padded = pkcs7_pad(plaintext, cipher.block_size)
    prev = iv
    out = bytearray()
    for block in split_blocks(padded, cipher.block_size):
        x = xor_bytes(block, prev)
        c = cipher.encrypt_block(x)
        out.extend(c)
        prev = c
    return bytes(out)


def cbc_decrypt(cipher: ToyFeistelCipher128, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != cipher.block_size:
        raise ValueError("iv must be 16 bytes")
    blocks = split_blocks(ciphertext, cipher.block_size)
    prev = iv
    out = bytearray()
    for c in blocks:
        x = cipher.decrypt_block(c)
        p = xor_bytes(x, prev)
        out.extend(p)
        prev = c
    return pkcs7_unpad(bytes(out), cipher.block_size)
```

### Step 4: CTR and CFB (turn the block cipher into a stream)
CTR and CFB do not need padding: they generate a keystream and XOR it with the data. CTR uses a nonce+counter input to the block cipher; CFB uses feedback from the previous ciphertext. Both are malleable: flipping bits in ciphertext predictably flips bits in plaintext.

```python
def ctr_xcrypt(
    cipher: ToyFeistelCipher128, nonce: bytes, data: bytes, initial_counter: int = 0
) -> bytes:
    if len(nonce) != 8:
        raise ValueError("nonce must be 8 bytes")
    if not (0 <= initial_counter < (1 << 64)):
        raise ValueError("initial_counter must fit in uint64")
    out = bytearray()
    counter = initial_counter
    offset = 0
    while offset < len(data):
        counter_bytes = counter.to_bytes(8, "big")
        keystream = cipher.encrypt_block(nonce + counter_bytes)
        take = min(len(keystream), len(data) - offset)
        chunk = data[offset : offset + take]
        out.extend(xor_bytes(chunk, keystream[:take]))
        offset += take
        counter = (counter + 1) % (1 << 64)
    return bytes(out)


def cfb_encrypt(cipher: ToyFeistelCipher128, iv: bytes, plaintext: bytes) -> bytes:
    if len(iv) != cipher.block_size:
        raise ValueError("iv must be 16 bytes")
    out = bytearray()
    prev = iv
    offset = 0
    while offset < len(plaintext):
        keystream = cipher.encrypt_block(prev)
        take = min(cipher.block_size, len(plaintext) - offset)
        chunk = plaintext[offset : offset + take]
        c = xor_bytes(chunk, keystream[:take])
        out.extend(c)
        prev = prev[take:] + c
        offset += take
    return bytes(out)


def cfb_decrypt(cipher: ToyFeistelCipher128, iv: bytes, ciphertext: bytes) -> bytes:
    if len(iv) != cipher.block_size:
        raise ValueError("iv must be 16 bytes")
    out = bytearray()
    prev = iv
    offset = 0
    while offset < len(ciphertext):
        keystream = cipher.encrypt_block(prev)
        take = min(cipher.block_size, len(ciphertext) - offset)
        chunk = ciphertext[offset : offset + take]
        p = xor_bytes(chunk, keystream[:take])
        out.extend(p)
        prev = prev[take:] + chunk
        offset += take
    return bytes(out)
```

Run it:
`python3 code/main.py`

## Use It
You almost never hand-roll modes in production. You use an audited library and you prefer AEAD.

- **PyCryptodome**
  - AES-ECB/CBC/CTR/CFB exist, but prefer AEAD (`AES.MODE_GCM`, `AES.MODE_EAX`) for real systems.
- **cryptography (Python)**
  - Use `Cipher(algorithms.AES(key), modes.GCM(nonce), backend=...)` (AEAD) rather than CBC+padding.
- **libsodium**
  - Prefer `crypto_aead_*` APIs (AEAD) and avoid raw block cipher modes entirely.

Rule of thumb: if your design document says “AES-CBC” or “AES-CTR”, it should also say “plus authentication (MAC/AEAD)” and specify key/nonce handling rules.

## Pitfalls
- **Assuming encryption implies integrity**: CBC/CTR/CFB are malleable; attackers can flip bits in ciphertext to flip bits in plaintext.
- **Nonce/IV reuse**: CTR nonce reuse is catastrophic; CBC/CFB IV reuse leaks relationships and breaks semantic security.
- **Predictable IVs in CBC**: “IV = 0” or “IV = timestamp” is a common real bug; you want unique and ideally unpredictable.
- **Padding oracles**: treating “bad padding” errors differently can leak plaintext in CBC (classic padding oracle attacks).
- **Reinventing AEAD**: “AES-CBC + homegrown checksum” tends to fail in reviews; use standardized AEAD.

## Ship It
Save and reuse the mode-selection checklist in `outputs/mode-selection-checklist.md`. Use it when:
- reviewing PRs that introduce “AES-CBC/CTR”
- writing a threat model for “encrypt data at rest”
- designing protocols (where nonce/IV lifecycle is where bugs hide)

## Exercises
1. Easy. Run `python3 code/main.py`. Observe how ECB ciphertext repeats when plaintext has repeated blocks.
2. Medium. Extend `code/main.py` to encrypt the same plaintext twice under CTR with the same `(key, nonce)` and compute `ct1 ⊕ ct2`. Explain what you learn about `pt1 ⊕ pt2`.
3. Hard. Replace CBC/CTR usage with an AEAD in a real library (PyCryptodome or `cryptography`) and write down exactly how you will store/transmit the nonce, tag, and key ID.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Block cipher | “AES encrypts data” | A permutation on fixed-size blocks (e.g., 16 bytes) under a key |
| Mode of operation | “AES-CBC” | A wiring pattern that turns a block cipher into a full message encryption scheme |
| IV | “random salt” | A per-message value for CBC/CFB; must be unique (and ideally unpredictable) |
| Nonce | “number used once” | A per-message value for CTR; must be unique under a key (reusing breaks security) |
| Padding | “extra bytes” | A rule to make message length a multiple of the block size (PKCS#7 is common) |
| Malleability | “encryption is breakable” | Property where modifying ciphertext causes predictable plaintext changes (no integrity) |

## Further Reading
- NIST SP 800-38A, *Recommendation for Block Cipher Modes of Operation* (2001) — canonical definitions for ECB/CBC/CFB/OFB/CTR.
- Rogaway, *Evaluation of Some Blockcipher Modes of Operation* (2011) — practical guidance and why “just pick a mode” is not enough.
- Ferguson, Schneier, Kohno, *Cryptography Engineering* (2010) — real-world pitfalls (IVs, padding oracles, authenticated encryption).
