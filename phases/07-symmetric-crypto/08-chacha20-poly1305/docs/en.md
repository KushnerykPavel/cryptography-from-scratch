# ChaCha20-Poly1305 from Scratch
> Encrypt with ChaCha20; authenticate *exactly what you meant* with Poly1305.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `07-symmetric-crypto/02-stream-ciphers`, `07-symmetric-crypto/07-aead-gcm-ccm-ocb`  
**Time:** ~75 minutes  

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain how ChaCha20 turns a key+nonce+counter into a keystream.
- Compute a ChaCha20 keystream block using quarter rounds and 32-bit arithmetic.
- Implement Poly1305 (clamp `r`, accumulate blocks mod `2^130-5`, add `s`).
- Distinguish ciphertext authentication (AEAD tag) from encryption (keystream XOR).
- Apply the RFC 8439 AEAD construction (AAD + padding + length encoding) and validate tags.

## The Problem
You want to send a message over an untrusted network. Encryption alone isn’t enough: an attacker who can flip bits in transit can *silently* change the decrypted plaintext. (Stream ciphers are especially malleable: flipping a ciphertext bit flips the same plaintext bit.)

AEAD fixes this by bundling **confidentiality** + **integrity**. ChaCha20-Poly1305 is the “fast-in-software” workhorse AEAD used in TLS 1.3, SSH, QUIC, WireGuard, and many other systems.

If you don’t understand how this AEAD is built, you’ll ship one of the classic failures: nonce reuse, authenticating the wrong bytes (or wrong lengths), skipping AAD, or verifying tags incorrectly.

## The Concept
**ChaCha20** is a stream cipher. It expands:

- key: 32 bytes
- nonce: 12 bytes (IETF variant)
- counter: 32-bit integer

into a keystream. Encryption is just XOR:

`ciphertext = plaintext XOR keystream`

That gives confidentiality, but *no integrity*.

**Poly1305** is a fast, one-time MAC. It takes a 32-byte one-time key `(r || s)` and produces a 16-byte tag. “One-time” matters: reuse the Poly1305 key on two different messages and you lose security guarantees.

**ChaCha20-Poly1305 AEAD (RFC 8439)** ties them together:

1. Derive the Poly1305 one-time key from `chacha20_block(key, counter=0, nonce)` (take first 32 bytes).
2. Encrypt plaintext with ChaCha20 starting at counter `1`.
3. MAC **exactly this byte string**:
   - `aad || pad16(aad) || ciphertext || pad16(ciphertext) || len(aad)_le64 || len(ciphertext)_le64`

The padding to 16 bytes and the two length fields prevent ambiguity (e.g., `aad="a", ct="bc"` vs `aad="ab", ct="c"`).

## Build It

### Step 1: ChaCha20 block function
Implement the ChaCha quarter-round and block function. The block function initializes a 16-word (512-bit) state, runs 20 rounds (10 “double rounds”), adds the original state back in, and serializes 64 bytes little-endian.

```python
def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def _rotl32(x: int, n: int) -> int:
    x = _u32(x)
    return _u32((x << n) | (x >> (32 - n)))


def _le_u32(data: bytes) -> int:
    return struct.unpack("<I", data)[0]


def _u32_le(x: int) -> bytes:
    return struct.pack("<I", _u32(x))


def quarter_round(a: int, b: int, c: int, d: int) -> Tuple[int, int, int, int]:
    a = _u32(a + b)
    d ^= a
    d = _rotl32(d, 16)

    c = _u32(c + d)
    b ^= c
    b = _rotl32(b, 12)

    a = _u32(a + b)
    d ^= a
    d = _rotl32(d, 8)

    c = _u32(c + d)
    b ^= c
    b = _rotl32(b, 7)

    return a, b, c, d


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if not (0 <= counter <= 0xFFFFFFFF):
        raise ValueError("counter must fit in 32 bits")

    constants = (b"expa", b"nd 3", b"2-by", b"te k")
    state = [0] * 16

    state[0] = _le_u32(constants[0])
    state[1] = _le_u32(constants[1])
    state[2] = _le_u32(constants[2])
    state[3] = _le_u32(constants[3])

    for i in range(8):
        state[4 + i] = _le_u32(key[i * 4 : (i + 1) * 4])

    state[12] = counter
    state[13] = _le_u32(nonce[0:4])
    state[14] = _le_u32(nonce[4:8])
    state[15] = _le_u32(nonce[8:12])

    working = state[:]

    for _ in range(10):
        working[0], working[4], working[8], working[12] = quarter_round(
            working[0], working[4], working[8], working[12]
        )
        working[1], working[5], working[9], working[13] = quarter_round(
            working[1], working[5], working[9], working[13]
        )
        working[2], working[6], working[10], working[14] = quarter_round(
            working[2], working[6], working[10], working[14]
        )
        working[3], working[7], working[11], working[15] = quarter_round(
            working[3], working[7], working[11], working[15]
        )

        working[0], working[5], working[10], working[15] = quarter_round(
            working[0], working[5], working[10], working[15]
        )
        working[1], working[6], working[11], working[12] = quarter_round(
            working[1], working[6], working[11], working[12]
        )
        working[2], working[7], working[8], working[13] = quarter_round(
            working[2], working[7], working[8], working[13]
        )
        working[3], working[4], working[9], working[14] = quarter_round(
            working[3], working[4], working[9], working[14]
        )

    out = bytearray()
    for i in range(16):
        out += _u32_le(working[i] + state[i])
    return bytes(out)
```

### Step 2: ChaCha20 stream cipher (XOR)
Turn the block function into a keystream generator, then XOR with data. Encryption and decryption are the same operation for a stream cipher.

```python
def chacha20_keystream(key: bytes, counter: int, nonce: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("length must be non-negative")
    out = bytearray()
    block_counter = counter
    while len(out) < length:
        out += chacha20_block(key, block_counter, nonce)
        block_counter = _u32(block_counter + 1)
    return bytes(out[:length])


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    ks = chacha20_keystream(key, counter, nonce, len(data))
    return _xor_bytes(data, ks)


def chacha20_encrypt(key: bytes, counter: int, nonce: bytes, plaintext: bytes) -> bytes:
    return chacha20_xor(key, counter, nonce, plaintext)


def chacha20_decrypt(key: bytes, counter: int, nonce: bytes, ciphertext: bytes) -> bytes:
    return chacha20_xor(key, counter, nonce, ciphertext)
```

### Step 3: Poly1305 one-time MAC
Poly1305 treats the message as 16-byte blocks, appends a `0x01` byte to each block (conceptually adding a high bit), accumulates modulo `2^130-5`, then adds `s` at the end and returns the low 128 bits.

```python
def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    return chacha20_block(key, 0, nonce)[:32]


def _poly1305_clamp_r(r: bytes) -> bytes:
    if len(r) != 16:
        raise ValueError("r must be 16 bytes")
    r = bytearray(r)
    r[3] &= 0x0F
    r[7] &= 0x0F
    r[11] &= 0x0F
    r[15] &= 0x0F
    r[4] &= 0xFC
    r[8] &= 0xFC
    r[12] &= 0xFC
    return bytes(r)


def poly1305_mac(msg: bytes, key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")

    r_bytes = _poly1305_clamp_r(key[:16])
    s_bytes = key[16:]

    r = int.from_bytes(r_bytes, "little")
    s = int.from_bytes(s_bytes, "little")
    p = (1 << 130) - 5

    a = 0
    for block in _chunks(msg, 16):
        n = int.from_bytes(block + b"\x01", "little")
        a = (a + n) % p
        a = (a * r) % p

    a = a + s
    tag = a & ((1 << 128) - 1)
    return tag.to_bytes(16, "little")
```

### Step 4: AEAD ChaCha20-Poly1305
Encrypt with ChaCha20 (counter starts at 1). Authenticate AAD + ciphertext with Poly1305 using the RFC-specified padding and length encoding. Reject decryption if the tag doesn’t match.

```python
def _pad16(data: bytes) -> bytes:
    rem = len(data) % 16
    if rem == 0:
        return b""
    return b"\x00" * (16 - rem)


def aead_chacha20_poly1305_encrypt(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes
) -> Tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")

    otk = poly1305_key_gen(key, nonce)
    ciphertext = chacha20_encrypt(key, 1, nonce, plaintext)

    mac_data = aad + _pad16(aad)
    mac_data += ciphertext + _pad16(ciphertext)
    mac_data += struct.pack("<Q", len(aad))
    mac_data += struct.pack("<Q", len(ciphertext))

    tag = poly1305_mac(mac_data, otk)
    return ciphertext, tag


def aead_chacha20_poly1305_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes
) -> bytes:
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("tag must be 16 bytes")

    otk = poly1305_key_gen(key, nonce)
    mac_data = aad + _pad16(aad)
    mac_data += ciphertext + _pad16(ciphertext)
    mac_data += struct.pack("<Q", len(aad))
    mac_data += struct.pack("<Q", len(ciphertext))
    expected = poly1305_mac(mac_data, otk)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("invalid tag")
    return chacha20_decrypt(key, 1, nonce, ciphertext)
```

Run it:

```bash
python3 code/main.py
```

## Use It
Use an audited library for real systems. Examples:

- Python `cryptography`: `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`
- libsodium: `crypto_aead_chacha20poly1305_ietf_encrypt()` / `crypto_aead_chacha20poly1305_ietf_decrypt()`
- OpenSSL EVP: `EVP_chacha20_poly1305()`

If you only remember one rule: **never reuse a nonce with the same key**.

## Pitfalls
- Nonce reuse with the same key: reuses keystream (plaintext XOR leak) and breaks authenticity in real protocols.
- Verifying tags incorrectly: comparing with `==` + early-exit differences leaks timing; or ignoring tag failures.
- Authenticating the wrong bytes: skipping AAD, skipping length fields, or forgetting the `pad16` rules changes what’s covered by the tag.
- Mixing variants: IETF ChaCha20-Poly1305 (12-byte nonce) vs older variants (8-byte nonce) vs XChaCha20-Poly1305 (24-byte nonce).
- Treating “stream cipher + MAC” as “encrypt-then-MAC” without matching the spec (especially the Poly1305 one-time key derivation).

## Ship It
Save and reuse the audit checklist in `outputs/chacha20-poly1305-aead-review-checklist.md` when:

- reviewing PRs that implement or wrap ChaCha20-Poly1305,
- deciding on nonce formats and message framing,
- writing integration tests that assert “tamper → reject”.

## Exercises
1. Easy: run `python3 code/main.py`. Observe the RFC ciphertext and tag match the printed hex.
2. Medium: extend `tests/test_vectors.py` with a case that flips a random bit in the tag and asserts decryption rejects.
3. Hard: replace the from-scratch AEAD in a tiny demo app with a production library (Python `cryptography`) and add tests that the serialized message format is stable and rejects tampering.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Nonce | “An IV” | A per-message unique value; must never repeat for a given key. |
| Counter | “Block number” | 32-bit integer selecting which ChaCha block you’re generating. |
| Keystream | “Random bytes” | Deterministic pseudorandom bytes derived from key+nonce+counter. |
| AAD | “Unencrypted header” | Data that stays plaintext but is covered by the authentication tag. |
| Tag | “MAC” | 16-byte authenticator that detects any modification to AAD/ciphertext/lengths. |

## Further Reading
- Y. Nir, A. Langley, *ChaCha20 and Poly1305 for IETF Protocols* (RFC 8439, 2018) — the definitive spec + test vectors.
- D. J. Bernstein, *ChaCha, a variant of Salsa20* (2008) — design rationale and security discussion.
- D. J. Bernstein, *The Poly1305-AES message-authentication code* (2005) — the original Poly1305 construction and analysis.
