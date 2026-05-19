# ElGamal Encryption

> Diffie–Hellman, but you keep the shared secret and ship it as a mask.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 08 · 04 (Diffie-Hellman & Discrete Log), modular arithmetic basics
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why ElGamal is probabilistic and what the ephemeral exponent does
- **Compute** ElGamal encryption/decryption in \(\mathbb{Z}_p^\*\) by hand for small parameters
- **Implement** key generation, encryption, decryption, rerandomization, and ciphertext multiplication
- **Distinguish** IND-CPA security from IND-CCA security and connect malleability to real bugs
- **Apply** ElGamal as a KEM building block inside a hybrid (asymmetric + symmetric) construction

## The Problem

You already know how to agree on a shared secret with Diffie–Hellman. That solves “we both end up with the same key”, but it does not solve “I want to send you a message right now, with only your public key, without an interactive handshake”.

ElGamal is the simplest way to turn Diffie–Hellman into public-key encryption: you create a one-time Diffie–Hellman secret and use it as a multiplicative mask on the message. If you can’t write down ElGamal and reason about its randomness, you will also struggle to reason about the modern “DH-KEM + AEAD” designs that dominate real-world public-key encryption.

There is a second reason to learn it: ElGamal is intentionally *malleable*. If you don’t understand the ways an attacker can transform ciphertexts without decrypting them, you will accidentally ship systems that are “encrypted” but still trivially tamperable.

## The Concept

ElGamal encryption lives in a cyclic group where exponentiation is easy but discrete logs are hard. The classic teaching group is \(\mathbb{Z}_p^\*\), the non-zero integers modulo a prime \(p\), with a generator \(g\).

Key generation:

- Choose secret \(x\) (the private key)
- Publish \(y = g^x \bmod p\) (the public key)

Encryption of a message \(m \in \{1,\dots,p-1\}\):

- Pick fresh random \(k\)
- \(c_1 = g^k \bmod p\)
- \(s = y^k \bmod p\) (a one-time DH shared secret)
- \(c_2 = m \cdot s \bmod p\)

Decryption:

- Recompute the same shared secret \(s = c_1^x \bmod p\)
- Recover \(m = c_2 \cdot s^{-1} \bmod p\)

Two consequences fall out immediately:

1. **Probabilistic encryption:** same \(m\), different \(k\) → different ciphertext.
2. **Malleability / homomorphism:** multiplying ciphertext components multiplies plaintexts modulo \(p\).

## Build It

### Step 1: Parameters & helpers

We pick a *safe prime* \(p = 2q + 1\) (both \(p\) and \(q\) prime) so it’s easy to validate that \(g\) is a generator. We also implement modular inverse (via extended Euclid) and a tiny SHA-256-based keystream generator used later for a “hybrid” bytes demo.

```python
from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass
from typing import Tuple


Ciphertext = Tuple[int, int]


def _is_prime_trial_division(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    limit = int(math.isqrt(n))
    f = 3
    while f <= limit:
        if n % f == 0:
            return False
        f += 2
    return True


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, modulus: int) -> int:
    a %= modulus
    g, x, _ = _egcd(a, modulus)
    if g != 1:
        raise ValueError("not invertible modulo modulus")
    return x % modulus


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    if n < 0:
        raise ValueError("n must be non-negative")
    if length is None:
        if n == 0:
            return b"\x00"
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor requires equal-length buffers")
    return bytes(x ^ y for x, y in zip(a, b))


def sha256_stream(key_material: bytes, out_len: int, *, label: bytes = b"") -> bytes:
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        h = hashlib.sha256()
        h.update(label)
        h.update(counter.to_bytes(4, "big"))
        h.update(key_material)
        out.extend(h.digest())
        counter += 1
    return bytes(out[:out_len])
```

### Step 2: Key generation

We define the public parameters \((p, g)\), validate them, then generate a keypair \((x, y)\) where \(y = g^x \bmod p\).

```python
@dataclass(frozen=True)
class ElGamalParams:
    p: int
    g: int

    @property
    def q(self) -> int:
        return (self.p - 1) // 2


def validate_params(params: ElGamalParams) -> None:
    p, g = params.p, params.g
    if not _is_prime_trial_division(p):
        raise ValueError("p must be prime")
    if p <= 3:
        raise ValueError("p too small")
    if (p - 1) % 2 != 0:
        raise ValueError("p must be odd")
    q = (p - 1) // 2
    if not _is_prime_trial_division(q):
        raise ValueError("p must be a safe prime (q = (p-1)/2 prime)")
    if not (2 <= g <= p - 2):
        raise ValueError("g out of range")
    if pow(g, 2, p) == 1 or pow(g, q, p) == 1:
        raise ValueError("g must be a generator of Z_p* (order p-1)")


def demo_params() -> ElGamalParams:
    params = ElGamalParams(p=467, g=2)
    validate_params(params)
    return params


@dataclass(frozen=True)
class ElGamalPublicKey:
    params: ElGamalParams
    y: int


@dataclass(frozen=True)
class ElGamalPrivateKey:
    params: ElGamalParams
    x: int


def elgamal_keygen(params: ElGamalParams, *, x: int | None = None) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
    validate_params(params)
    if x is None:
        x = secrets.randbelow(params.p - 2) + 1
    if not (1 <= x <= params.p - 2):
        raise ValueError("x out of range")
    y = pow(params.g, x, params.p)
    return ElGamalPublicKey(params=params, y=y), ElGamalPrivateKey(params=params, x=x)
```

### Step 3: Encrypt/decrypt an integer mod p

This is textbook ElGamal: turn a fresh DH shared secret into a multiplicative mask on the message.

```python
def elgamal_encrypt_int(pub: ElGamalPublicKey, m: int, *, k: int | None = None) -> Ciphertext:
    p, g, y = pub.params.p, pub.params.g, pub.y
    if not (1 <= m <= p - 1):
        raise ValueError("message m must be in 1..p-1")
    if k is None:
        k = secrets.randbelow(p - 2) + 1
    if not (1 <= k <= p - 2):
        raise ValueError("k out of range")
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    return c1, c2


def elgamal_decrypt_int(priv: ElGamalPrivateKey, ct: Ciphertext) -> int:
    p = priv.params.p
    c1, c2 = ct
    if not (1 <= c1 <= p - 1 and 0 <= c2 <= p - 1):
        raise ValueError("ciphertext components out of range")
    s = pow(c1, priv.x, p)
    return (c2 * modinv(s, p)) % p
```

### Step 4: Rerandomize + homomorphism (and why it's a pitfall)

ElGamal ciphertexts can be “refreshed” without the private key, and ciphertexts can be multiplied to get an encryption of the product. Both properties are useful in protocols — and both properties are exactly why raw ElGamal is *malleable*.

```python
def elgamal_rerandomize(pub: ElGamalPublicKey, ct: Ciphertext, *, r: int | None = None) -> Ciphertext:
    p, g, y = pub.params.p, pub.params.g, pub.y
    c1, c2 = ct
    if r is None:
        r = secrets.randbelow(p - 2) + 1
    if not (1 <= r <= p - 2):
        raise ValueError("r out of range")
    return (c1 * pow(g, r, p)) % p, (c2 * pow(y, r, p)) % p


def elgamal_mul_ciphertexts(params: ElGamalParams, a: Ciphertext, b: Ciphertext) -> Ciphertext:
    p = params.p
    return (a[0] * b[0]) % p, (a[1] * b[1]) % p
```

### Step 5: Hybrid bytes demo (KDF + XOR stream; unauthenticated)

In real systems, you rarely encrypt raw group elements. You derive a symmetric key from the DH shared secret and use it with an authenticated cipher. Here we show the key-derivation + XOR part only (no authentication) so you can see the construction end-to-end with stdlib.

```python
def elgamal_encrypt_bytes(pub: ElGamalPublicKey, plaintext: bytes, *, k: int | None = None, label: bytes = b"") -> Tuple[int, bytes]:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    p, g, y = pub.params.p, pub.params.g, pub.y
    if k is None:
        k = secrets.randbelow(p - 2) + 1
    if not (1 <= k <= p - 2):
        raise ValueError("k out of range")
    c1 = pow(g, k, p)
    shared = pow(y, k, p)
    key_material = int_to_bytes(shared)
    stream = sha256_stream(key_material, len(plaintext), label=label)
    return c1, xor_bytes(bytes(plaintext), stream)


def elgamal_decrypt_bytes(priv: ElGamalPrivateKey, c1: int, ciphertext: bytes, *, label: bytes = b"") -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes-like")
    p = priv.params.p
    if not (1 <= c1 <= p - 1):
        raise ValueError("c1 out of range")
    shared = pow(c1, priv.x, p)
    key_material = int_to_bytes(shared)
    stream = sha256_stream(key_material, len(ciphertext), label=label)
    return xor_bytes(bytes(ciphertext), stream)
```

Run it:

```bash
python3 code/main.py
```

## Use It

ElGamal the *idea* shows up everywhere; raw ElGamal the *scheme* shows up less often.

- **GnuPG / OpenPGP**: GnuPG supports ElGamal encryption keys. (You’ll usually see ElGamal as an encryption subkey alongside a signing key.)  
- **PyCryptodome**: provides `Crypto.PublicKey.ElGamal` for key construction/generation (use it as a learning aid, not as a modern default).
- **Modern practice**: prefer **ECDH/X25519 + HKDF + AEAD** (or libsodium’s `crypto_box`) instead of “raw ElGamal over integers”.

## Pitfalls

1. **No authenticity:** raw ElGamal is malleable; you must authenticate ciphertexts (hybrid with AEAD, or a CCA-secure scheme like Cramer–Shoup).
2. **Reusing the ephemeral exponent \(k\):** two ciphertexts with the same \(c_1\) leak relations between plaintexts (and a known plaintext can reveal the other).
3. **Bad group parameters:** if \(p\) isn’t prime or \(g\) isn’t a generator of a large-order subgroup, attackers can force you into small subgroups.
4. **Encrypting structured data directly:** encrypting “IDs” or “balances” as integers invites guess-and-check attacks for small message spaces.
5. **Timing leaks:** modular exponentiation and inversion here are not constant-time; side channels matter in real implementations.

## Ship It

This lesson ships a reusable review prompt:

- `outputs/prompt-elgamal-encryption-review.md`

Use it when reviewing code that “does ElGamal” or “does DH-KEM” to catch the common security failures (missing authentication, nonce reuse, missing parameter validation, weak KDF context separation).

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that `rerand(ct)` decrypts to the same message but looks unrelated to `ct`.
2. Medium. Extend `code/main.py` to encrypt the same `m` twice with different `k` values and print both ciphertexts; confirm decryption matches and ciphertexts differ.
3. Hard. Replace the XOR-stream “bytes demo” with an authenticated construction (e.g., derive two keys from SHA-256 and implement Encrypt-then-MAC with `hmac`).

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Ephemeral exponent (`k`) | “nonce” | Fresh randomness per encryption that creates a one-time DH secret |
| IND-CPA | “secure encryption” | Attacker can’t distinguish encryptions of chosen messages (no decryption oracle) |
| IND-CCA | “secure even if I decrypt things” | Secure even if attacker can query a decryption oracle (except the challenge) |
| Malleability | “can tweak ciphertexts” | Attacker can transform a ciphertext into another valid ciphertext with related plaintext |
| Safe prime | “nice prime” | A prime \(p\) where \(p=2q+1\) and \(q\) is also prime |

## Further Reading

- Taher ElGamal, *A Public-Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms* (1985) — the original paper introducing the scheme.
- Wikipedia, *ElGamal encryption* — quick reference + notes on malleability and hybrid use.
- Wikipedia, *Chosen-ciphertext attack* — why “malleable” and “CCA-secure” are in tension.
