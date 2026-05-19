# One-Time Pad & Information-Theoretic Security
> Perfect secrecy is real — but only with a truly random, message-length key that is never reused.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 00 · 02 (Bytes, Hex, Base64), Phase 00 · 04 (Test Vectors)  
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** when OTP achieves perfect secrecy
- **Compute** OTP encryption/decryption as bytewise XOR
- **Implement** OTP encrypt/decrypt and key generation in Python
- **Distinguish** OTP from stream ciphers (and why nonces matter)
- **Apply** the two-time pad attack to recover a message under key reuse

## The Problem
Someone proposes a “simple encryption” scheme: `ciphertext = plaintext XOR key`. It feels plausible, it is fast, and it is easy to ship. Teams do ship this in the wild — in ad-hoc protocols, homegrown file “encryption”, and “lightweight” obfuscation layers.

Sometimes it works better than AES (at least on paper): the one-time pad can provide *information-theoretic* secrecy — even against an attacker with infinite compute. But the conditions are strict. If you violate them (especially key reuse), secrecy collapses in a way that looks like magic: ciphertexts start leaking relationships between plaintexts, and partial plaintext knowledge can recover entire messages.

This lesson gives you the exact conditions for “perfect secrecy”, and the exact failure mode that happens the moment you reuse an OTP key.

## The Concept
### XOR as “addition mod 2”
XOR operates bit-by-bit:

| a | b | a XOR b |
|---|---|---------|
| 0 | 0 | 0 |
| 0 | 1 | 1 |
| 1 | 0 | 1 |
| 1 | 1 | 0 |

Two properties make OTP work:

- **Self-inverse:** `(x XOR k) XOR k = x`
- **Cancellation:** `(x XOR k) XOR (y XOR k) = x XOR y` (when the same `k` is reused)

### One-time pad (OTP)
OTP encryption is:

`c = p XOR k`

where `p`, `c`, `k` are equal-length byte strings, and `k` is:

1. uniformly random,
2. as long as the message,
3. used once (never reused for any other message),
4. kept secret.

Under those conditions, the ciphertext leaks *no information* about the plaintext. Intuition: for any fixed ciphertext `c`, every plaintext `p` is possible with exactly one key `k = p XOR c`. If `k` is uniformly random, then `c` is uniformly random too.

### What OTP does *not* provide
OTP provides confidentiality only. It provides **no integrity**: an attacker can flip bits in the ciphertext and predictably flip bits in the decrypted plaintext.

## Build It
### Step 1: XOR bytes
We start by implementing XOR for equal-length byte strings. This is the single primitive OTP is built from.

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if not isinstance(a, (bytes, bytearray)):
        raise TypeError("a must be bytes-like")
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b must be bytes-like")
    if len(a) != len(b):
        raise ValueError("inputs must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))
```

This is bytewise XOR (`x ^ y`) zipped across the two inputs. The length check matters: OTP is defined only when message and key are the same length.

### Step 2: OTP encrypt and decrypt
OTP “encryption” and “decryption” are the same operation: XOR with the key.

```python
def otp_encrypt(plaintext: bytes, key: bytes) -> bytes:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes-like")
    if len(plaintext) != len(key):
        raise ValueError("OTP key must be the same length as the plaintext")
    return xor_bytes(plaintext, key)


def otp_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes-like")
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes-like")
    if len(ciphertext) != len(key):
        raise ValueError("OTP key must be the same length as the ciphertext")
    return xor_bytes(ciphertext, key)
```

The checks are deliberately strict: “almost correct” OTP is just incorrect OTP.

### Step 3: Generate a truly random OTP key
OTP requires a key that is uniform random and never reused. In Python, use `secrets.token_bytes`, not `random`.

```python
import secrets


def generate_otp_key(length: int) -> bytes:
    if not isinstance(length, int):
        raise TypeError("length must be int")
    if length < 0:
        raise ValueError("length must be >= 0")
    return secrets.token_bytes(length)
```

This produces cryptographically strong random bytes suitable for a one-time key — but you still have to manage it: distribution, storage, and absolute non-reuse.

### Step 4: Key reuse breaks secrecy (two-time pad)
If you reuse the same OTP key `k` for two messages, an attacker can compute:

`c1 XOR c2 = (p1 XOR k) XOR (p2 XOR k) = p1 XOR p2`

That leaks a relationship between the plaintexts. If the attacker knows (or guesses) one plaintext, they recover the other.

```python
def to_hex(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    return bytes(data).hex()


def from_hex(hex_str: str) -> bytes:
    if not isinstance(hex_str, str):
        raise TypeError("hex_str must be str")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError("invalid hex string") from e
```

These helpers let the demo print compact hex. The “attack” is in `code/main.py` Step 4, where you can see `(c1 XOR c2) XOR p1 = p2` happen on real bytes.

Run it:
`python3 code/main.py`

## Use It
You almost never ship OTP directly. You ship **stream ciphers** (or block ciphers in CTR mode), which approximate OTP using a short key expanded into a long pseudorandom keystream.

| What you want | What you use in practice | What plays the role of “never reuse the key” |
|---|---|---|
| OTP confidentiality | ChaCha20 or AES-CTR | Never reuse the `(key, nonce)` pair |
| OTP + integrity | ChaCha20-Poly1305 or AES-GCM | AEAD enforces authenticity and nonce discipline |

Rule: **XOR encryption without authentication is malleable.** If you need confidentiality in production, use an AEAD.

## Pitfalls
- **Key reuse (two-time pad):** reusing `k` once turns “perfect secrecy” into a solvable equation.
- **Non-random keys:** passwords, timestamps, PRNG output from `random`, or anything predictable breaks the “uniform random” assumption.
- **Key shorter than the message:** repeating a key (Vigenère-style) is not OTP; it is a classic cryptanalysis target.
- **No integrity:** OTP/CTR-style XOR encryption lets attackers flip plaintext bits by flipping ciphertext bits.
- **Key management reality:** OTP requires distributing and storing as much secret key material as the total message volume.

## Ship It
Save and use `outputs/otp-xor-audit-checklist.md` when reviewing code or protocols that use XOR, stream ciphers, AES-CTR, or “custom encryption”. It is a short checklist for spotting two-time pad / nonce reuse and missing authenticity.

## Exercises
1. **Easy.** Run `python3 code/main.py`. Observe that Step 4 recovers `p2` when the attacker knows `p1`.
2. **Medium.** Add a second “tamper” example: flip a bit in the middle of the ciphertext and show the exact changed plaintext byte after decryption.
3. **Hard.** Replace OTP with a real stream cipher + nonce (e.g., ChaCha20-Poly1305 in libsodium) and write a short note: what replaces “key used once”, and what new pitfalls appear?

## Key Terms
| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| One-time pad | “Unbreakable encryption” | Perfect secrecy *only if* the key is uniform random, message-length, secret, and never reused. |
| Perfect secrecy | “Even infinite compute can’t break it” | `Pr[P | C] = Pr[P]` for all plaintexts/ciphertexts: observing `C` gives zero information about `P`. |
| XOR | “Bitwise add” | Addition mod 2, with self-inverse property: `(x XOR k) XOR k = x`. |
| Two-time pad | “Reusing an OTP key” | Using the same OTP key twice leaks `p1 XOR p2` and enables plaintext recovery with guesses. |
| Malleability | “Attackers can change messages” | Flipping ciphertext bits flips plaintext bits under XOR-based encryption (no integrity). |

## Further Reading
- Claude Shannon, *Communication Theory of Secrecy Systems* (1949) — defines perfect secrecy and proves OTP is perfectly secret under its conditions.
- Ferguson, Schneier, Kohno, *Cryptography Engineering* (2010) — practical “don’t roll your own crypto”, including stream cipher and nonce discipline.
- Cryptopals, *Set 1: Basics* (no date) — bite-sized exercises that make XOR and key-reuse failure visceral.
