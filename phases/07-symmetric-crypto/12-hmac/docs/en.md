# HMAC (SHA-256) — A MAC that survives length extension
> Wrap a hash twice (ipad/opad) and you get a secure, standard MAC.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 07 · 09 (SHA-256)  
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** why `hash(key || message)` is not a safe general-purpose MAC
- **Compute** the HMAC formula for a hash with 64-byte blocks (like SHA-256)
- **Implement** `hmac_sha256()` and key normalization (`K0`) from the definition
- **Distinguish** full-length tags vs intentionally truncated tags (and the security trade-off)
- **Apply** RFC test vectors to validate a MAC implementation end-to-end

## The Problem
You want to send data over an untrusted channel (HTTP, a queue, a file, a database record) and detect any tampering. Encryption is optional — but **integrity** is not. Without integrity, attackers can flip bits in ciphertexts, change JSON fields, or replay old messages and you won’t know.

A tempting “quick fix” is to do `tag = sha256(key || message)` and ship `(message, tag)`. That often *seems* to work in tests, but it’s a trap: for Merkle–Damgård hashes like SHA-256, that construction can enable **length-extension attacks** and other subtle breakage depending on how you combine values.

HMAC is the boring, standardized answer: it turns a hash function into a **keyed message authentication code** that is safe in common threat models and widely implemented in every crypto library and protocol stack.

## The Concept
HMAC takes an existing hash `H` and wraps it in a two-pass construction:

```
K0 = key normalized to the hash block size (64 bytes for SHA-256)

HMAC(K, M) = H( (K0 ⊕ opad) || H( (K0 ⊕ ipad) || M ) )

ipad = 0x36 repeated 64 times
opad = 0x5c repeated 64 times
```

Mentally, it’s “hash a keyed inner digest, then hash a keyed outer digest”:

```
          +---------------------+
K0 ⊕ ipad |                     |  inner = H( (K0 ⊕ ipad) || M )
----------+  hash (SHA-256)     +------------------------------+
M --------|                     |
          +---------------------+

          +---------------------+
K0 ⊕ opad |                     |  tag = H( (K0 ⊕ opad) || inner )
----------+  hash (SHA-256)     +------------------------------+
inner ----|                     |
          +---------------------+
```

### Key normalization (K0)
HMAC needs a fixed-size key block `K0`:
- If the key is longer than the block size: `K0 = H(key)` (then pad).
- Otherwise: `K0 = key` padded with zeros to the block size.

This makes the HMAC computation well-defined for any key length and avoids weird edge cases when keys are longer than the hash block size.

### Verification and truncation
A MAC is only useful if you verify it safely:
- Compare tags with a constant-time equality check (avoid early-exit `==` on secrets).
- Some protocols truncate tags (e.g., 16 bytes = 128-bit tag) to reduce overhead. Truncation is fine **when it is an intentional protocol choice** and you still verify correctly.

## Build It

### Step 1: Hash and byte helpers
```python
from __future__ import annotations

import hashlib


class HmacError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise HmacError(message)


def _as_bytes(x: bytes | bytearray, *, name: str) -> bytes:
    if not isinstance(x, (bytes, bytearray)):
        raise HmacError(f"{name} must be bytes-like")
    return bytes(x)


SHA256_BLOCK_SIZE = 64
SHA256_DIGEST_SIZE = 32


def sha256(data: bytes | bytearray) -> bytes:
    b = _as_bytes(data, name="data")
    return hashlib.sha256(b).digest()


def xor_bytes(a: bytes | bytearray, b: bytes | bytearray) -> bytes:
    aa = _as_bytes(a, name="a")
    bb = _as_bytes(b, name="b")
    _require(len(aa) == len(bb), "a and b must have the same length")
    return bytes(x ^ y for x, y in zip(aa, bb))
```
We’ll build HMAC “from scratch” using the stdlib SHA-256 as our underlying hash. The helper layer is small but important: enforce bytes inputs, define SHA-256’s block/digest sizes, and implement XOR (the core operation behind `ipad`/`opad`).

### Step 2: Normalize the HMAC key (K0)
```python
def normalize_hmac_key_sha256(key: bytes | bytearray) -> bytes:
    k = _as_bytes(key, name="key")
    if len(k) > SHA256_BLOCK_SIZE:
        k = sha256(k)
    return k.ljust(SHA256_BLOCK_SIZE, b"\x00")
```
HMAC needs a fixed-size key block. This function implements the exact rule from the definition: long keys get hashed down first, then everything gets zero-padded to 64 bytes.

### Step 3: Compute HMAC-SHA-256 (ipad/opad)
```python
def hmac_sha256(key: bytes | bytearray, msg: bytes | bytearray) -> bytes:
    k0 = normalize_hmac_key_sha256(key)
    m = _as_bytes(msg, name="msg")

    ipad = bytes([0x36]) * SHA256_BLOCK_SIZE
    opad = bytes([0x5C]) * SHA256_BLOCK_SIZE

    inner = sha256(xor_bytes(k0, ipad) + m)
    return sha256(xor_bytes(k0, opad) + inner)
```
This is HMAC in one function: compute the inner digest with `ipad`, then compute the outer digest with `opad`. The two-pass structure is what prevents many “MAC-from-a-hash” pitfalls, including length extension for Merkle–Damgård hashes.

### Step 4: Verify tags and truncate intentionally
```python
def hmac_sha256_truncated(key: bytes | bytearray, msg: bytes | bytearray, tag_len: int) -> bytes:
    _require(isinstance(tag_len, int), "tag_len must be int")
    _require(0 <= tag_len <= SHA256_DIGEST_SIZE, "tag_len out of range for SHA-256")
    return hmac_sha256(key, msg)[:tag_len]


def constant_time_equal(a: bytes | bytearray, b: bytes | bytearray) -> bool:
    aa = _as_bytes(a, name="a")
    bb = _as_bytes(b, name="b")
    if len(aa) != len(bb):
        return False
    diff = 0
    for x, y in zip(aa, bb):
        diff |= x ^ y
    return diff == 0


def verify_hmac_sha256(key: bytes | bytearray, msg: bytes | bytearray, tag: bytes | bytearray) -> bool:
    expected = hmac_sha256(key, msg)
    return constant_time_equal(expected, tag)


def verify_hmac_sha256_truncated(
    key: bytes | bytearray, msg: bytes | bytearray, tag: bytes | bytearray, tag_len: int
) -> bool:
    expected = hmac_sha256_truncated(key, msg, tag_len)
    t = _as_bytes(tag, name="tag")
    if len(t) != tag_len:
        return False
    return constant_time_equal(expected, t)
```
Verification is part of the primitive: “MAC” means “compute + verify”. We also implement truncation explicitly: if a protocol wants a 16-byte tag, you compute the full HMAC and then slice — and you verify against the truncated length exactly.

Run it:
`python3 code/main.py`

## Use It
Use a real library in production; keep the from-scratch version for learning and for test-vector understanding.

- **Python (stdlib):** `hmac` + `hashlib` (`hmac.new(key, msg, hashlib.sha256).digest()`)
- **libsodium:** `crypto_auth_hmacsha256` / `crypto_auth_hmacsha512256`
- **OpenSSL:** `HMAC(EVP_sha256(), ...)` / `EVP_MAC` APIs
- **Protocol reality:** modern AEAD modes include integrity, but HMAC still appears in KDFs (HKDF), token signing, request signing, and legacy TLS ciphersuites.

## Pitfalls
- **Using `sha256(key || msg)` as a MAC:** for SHA-256-style hashes, this can enable length extension and breaks composability; use HMAC instead.
- **Comparing tags with `==`:** timing differences can leak how many prefix bytes matched; always use a constant-time compare.
- **Truncating without a spec:** truncation is fine, but choose a length deliberately (e.g., 16 bytes = 128-bit tag) and enforce that length in verification.
- **Reusing keys across contexts:** use separate keys (or a KDF + labels) for “API tokens”, “cookies”, “file integrity”, etc.
- **Using passwords as HMAC keys:** HMAC keys should be random bytes; if you start from a password, run a real password KDF first (PBKDF2/scrypt/Argon2).

## Ship It
Save and use the reusable checklist at `outputs/hmac-review-checklist.md`:

- Paste it into PR reviews when you see “signed requests”, “webhooks”, “API tokens”, or “MAC tags”.
- Use it to sanity-check tag length, compare semantics, key management, and domain separation.

## Exercises
1. Easy: Run `python3 code/main.py`. Observe (a) key normalization outputs, (b) full tag length, and (c) truncated-tag verification behavior.
2. Medium: Generalize the implementation to `hmac(hash_fn, block_size, digest_size, key, msg)` and add HMAC-SHA-512 using `hashlib.sha512`.
3. Hard: Implement a small “signed message” format: `version || tag || message`, where `tag = HMAC(key, version || message)`, and verify it with constant-time comparison before parsing the message.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| MAC | “A hash with a key” | A keyed integrity mechanism with a security definition (forge-resistance). |
| HMAC | “Hash-based MAC” | A specific, standardized two-pass MAC construction built from a hash. |
| `ipad` / `opad` | “Magic constants” | Fixed pads XORed with `K0` to separate the inner/outer hash domains. |
| Key normalization (`K0`) | “Padding the key” | Hash-then-pad (for long keys) or zero-pad (for short keys) to the hash block size. |
| Tag truncation | “Shorter MAC” | A protocol choice that trades bandwidth for security; you still compute full HMAC then slice. |

## Further Reading
- H. Krawczyk, M. Bellare, R. Canetti, “HMAC: Keyed-Hashing for Message Authentication” (RFC 2104, 1997) — the original HMAC specification and security intuition.
- D. Nystrom, “Test Cases for HMAC-MD5 and HMAC-SHA-1” (RFC 2202, 1997) and D. Eastlake, “HMAC: Keyed-Hashing for Message Authentication” test cases (RFC 4231, 2005) — known answer tests; this lesson uses RFC 4231’s SHA-256 cases in `tests/vectors.json`.
