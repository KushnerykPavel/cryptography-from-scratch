# Diffie-Hellman Key Exchange (Finite-Field DH)
> Two people can agree on a shared secret in public — but only if they authenticate the exchange.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 01 · 01 (Modular Arithmetic), Phase 01 · 14 (Index Calculus & Discrete Log)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why DH works (and what it assumes)
- Compute public keys and shared secrets in a mod-`p` group
- Implement a DH exchange and derive a session key with HKDF-SHA256
- Distinguish authenticated DH from unauthenticated DH (MITM risk)
- Apply public-key validation (range + subgroup checks) to avoid small-subgroup problems

## The Problem

You and a server want to talk privately, but the network is hostile: someone can read, record, drop, and modify packets. If you simply send an encryption key, the attacker learns it. If you encrypt the key with something the attacker also sees, you are back where you started.

Diffie-Hellman (DH) is the classic solution: it lets two parties agree on a shared secret over a public channel. That shared secret becomes the root of symmetric keys (encryption + integrity) for the rest of the connection. This is why DH (more commonly its elliptic-curve variant, ECDH) sits at the heart of TLS, Noise, Signal, and modern VPN protocols.

But DH has a sharp edge: **it does not authenticate the peers.** If you run DH without signatures/certificates/PSKs, a man-in-the-middle (MITM) can silently negotiate two different shared secrets and read/modify everything. This lesson builds DH from scratch and makes that failure mode concrete.

## The Concept

DH lives in a cyclic group where exponentiation is easy but reversing it is hard.

Pick a large prime `p` and a generator `g`. Each side chooses a secret exponent:

- Alice picks `a`, publishes `A = g^a mod p`
- Bob picks `b`, publishes `B = g^b mod p`

They compute:

- Alice: `Z = B^a mod p = (g^b)^a mod p = g^(ab) mod p`
- Bob:   `Z = A^b mod p = (g^a)^b mod p = g^(ab) mod p`

Both get the same `Z` without ever sending `a` or `b`.

Security intuition:

- An eavesdropper sees `p, g, A, B`
- To recover `Z`, they’d need `a` from `A = g^a mod p` (a **discrete log**), or `b` from `B`
- For well-chosen parameters, discrete log is computationally infeasible

Two practical details matter in real systems:

1. **Validation.** Some DH groups use a small prime-order subgroup of size `q`. If you don’t validate that a received public key lies in that subgroup, an attacker can sometimes force “small subgroup” secrets and learn bits of your private exponent.
2. **KDF.** The raw shared secret `Z` is not a ready-to-use symmetric key. You feed it into a KDF (e.g., HKDF-SHA256) with context (“salt” and “info”) to derive encryption keys safely.

## Build It

### Step 1: Square-and-multiply modular exponentiation

This is the workhorse of finite-field crypto: compute `base^exponent mod p` efficiently in `O(log exponent)` multiplications.

```python
def modexp(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")

    base %= modulus
    result = 1
    e = exponent
    while e:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result
```

### Step 2: DH groups + public keys

A DH “group” is just parameters `(p, g)` plus (optionally) a subgroup order `q` when you’re operating in a prime-order subgroup. The public key is `g^x mod p`.

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class DHGroup:
    name: str
    p: int
    g: int
    q: int | None = None

    def __post_init__(self) -> None:
        if self.p <= 2:
            raise ValueError("p must be > 2")
        if not (2 <= self.g <= self.p - 2):
            raise ValueError("g must be in [2, p-2]")
        if self.q is not None and self.q <= 1:
            raise ValueError("q must be > 1")


def dh_public_key(*, group: DHGroup, private_key: int) -> int:
    if not (2 <= private_key <= group.p - 2):
        raise ValueError("private key out of range")
    return modexp(group.g, private_key, group.p)
```

### Step 3: Shared secret + validation + HKDF-SHA256

First validate the peer’s public key (at minimum: range checks; for subgroup DH: a subgroup check). Then compute the shared secret and run it through HKDF to produce a fixed-length session key.

```python
import hashlib
import hmac


def int_to_bytes(value: int, length: int | None = None) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if length is None:
        length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def hkdf_sha256(*, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("length must be positive")

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
        if counter > 255:
            raise ValueError("length too large for HKDF")
    return okm[:length]


def validate_dh_public_key(*, group: DHGroup, public_key: int) -> None:
    if not (2 <= public_key <= group.p - 2):
        raise ValueError("public key out of range")
    if group.q is not None and modexp(public_key, group.q, group.p) != 1:
        raise ValueError("public key not in expected subgroup")


def dh_shared_secret(
    *,
    group: DHGroup,
    private_key: int,
    peer_public_key: int,
    validate_public_key: bool = True,
) -> int:
    if validate_public_key:
        validate_dh_public_key(group=group, public_key=peer_public_key)
    if not (2 <= private_key <= group.p - 2):
        raise ValueError("private key out of range")
    return modexp(peer_public_key, private_key, group.p)
```

### Step 4: Attack demo — MITM on unauthenticated DH

DH alone gives secrecy against passive eavesdroppers, but it does nothing against an active attacker who can modify the handshake. This demo shows the classic MITM: Alice ends up sharing a key with Mallory, and Bob also shares a key with Mallory. Alice and Bob do **not** share a key with each other.

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def step4_mitm_demo() -> None:
    _print_step(4, "Attack demo: MITM when DH is unauthenticated")
    group = DHGroup(name="toy (p=23, g=5)", p=23, g=5, q=None)

    alice_private = 6
    bob_private = 15
    mallory_private_to_alice = 13
    mallory_private_to_bob = 7

    alice_public = dh_public_key(group=group, private_key=alice_private)
    bob_public = dh_public_key(group=group, private_key=bob_private)
    mallory_public_to_alice = dh_public_key(group=group, private_key=mallory_private_to_alice)
    mallory_public_to_bob = dh_public_key(group=group, private_key=mallory_private_to_bob)

    z_alice_mallory = dh_shared_secret(group=group, private_key=alice_private, peer_public_key=mallory_public_to_alice, validate_public_key=False)
    z_bob_mallory = dh_shared_secret(group=group, private_key=bob_private, peer_public_key=mallory_public_to_bob, validate_public_key=False)

    key_alice = hkdf_sha256(ikm=int_to_bytes(z_alice_mallory), salt=b"salt", info=b"toy", length=16)
    key_bob = hkdf_sha256(ikm=int_to_bytes(z_bob_mallory), salt=b"salt", info=b"toy", length=16)

    message = b"meet at dawn!!!"
    padded = message.ljust(16, b"\x00")
    ciphertext_from_alice = xor_bytes(padded, key_alice)
    recovered_by_mallory = xor_bytes(ciphertext_from_alice, key_alice)
    decrypted_by_bob_wrong = xor_bytes(ciphertext_from_alice, key_bob)

    print(f"Alice thinks shared key is with Bob; Bob thinks shared key is with Alice.")
    print(f"Alice derived key: {key_alice.hex()}")
    print(f"Bob   derived key: {key_bob.hex()}")
    print(f"Ciphertext (hex):  {ciphertext_from_alice.hex()}")
    print(f"Mallory recovers:  {recovered_by_mallory.rstrip(b'\x00')!r}")
    print(f"Bob decrypts to:   {decrypted_by_bob_wrong.rstrip(b'\x00')!r}")
```

Run it:

`python3 code/main.py`

## Use It

Production protocols almost never use finite-field DH directly anymore; they use **ECDH** (same idea, different group) because it is faster and uses smaller keys.

Still, the DH mental model transfers directly:

- **TLS 1.3:** uses ephemeral ECDH (forward secrecy) and authenticates the handshake with certificates (signatures).
- **Noise Protocol Framework:** a menu of authenticated DH patterns (e.g., `XX`, `IK`) that specify when keys are static vs ephemeral.
- **Signal:** uses X25519 (ECDH) and mixes outputs through a KDF (“double ratchet”).

If you do need finite-field DH, use audited implementations and standardized groups:

- OpenSSL: `EVP_PKEY` DH APIs (plus parameter validation utilities)
- libsodium: prefers X25519 (ECDH), which is the modern default
- Python `cryptography`: high-level ECDH APIs; finite-field DH is available but rarely recommended for new designs

## Pitfalls

1. **Unauthenticated DH (MITM).** DH does not prove who you are talking to. You must authenticate (certificates, signatures, PSKs, or a secure PAKE).
2. **No public-key validation.** Accepting `0`, `1`, or out-of-subgroup elements can leak information (small subgroup confinement) or force weak secrets.
3. **Reusing private exponents.** Ephemeral keys give forward secrecy; reusing exponents turns compromises into “decrypt the backlog.”
4. **Skipping a KDF.** Raw `Z` is not a uniform key; protocols derive keys with HKDF (salt + info + transcript binding).
5. **Custom groups / weird parameters.** Parameter generation is subtle. Prefer standardized groups (or, better, modern curves like X25519).

## Ship It

Save and reuse: `outputs/skill-dh-handshake-review.md`

It’s a copy-pastable prompt/checklist for reviewing a DH/ECDH handshake in a design doc or PR. Use it whenever you see “we do a quick Diffie-Hellman and then…” to catch MITM risk, missing validation, bad KDF use, and forward secrecy mistakes.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the MITM step produces two different derived keys (Alice≠Bob), and Bob’s “decryption” is garbage.
2. Medium. Extend the demo: add a fifth step that prints whether `validate_dh_public_key` accepts/rejects a few sample public keys for the RFC 5114 group 22 parameters.
3. Hard. Production integration: implement an authenticated ECDH handshake using an audited library (e.g., X25519 + Ed25519 signatures) and compare the resulting transcript to the unauthenticated DH MITM failure mode.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Diffie-Hellman (DH) | “Key exchange” | A way to compute a shared secret `g^(ab)` from public values `g^a`, `g^b` in a group |
| Discrete log | “Hard math problem” | Given `g` and `g^a`, find `a`; assumed infeasible for well-chosen groups |
| Generator | “A random number” | A group element whose powers cover a subgroup (ideally prime-order) |
| Subgroup order `q` | “The group size” | The size of the specific subgroup you operate in; used for validation |
| HKDF | “A hash” | A KDF that turns shared secret bytes into uniformly distributed keys with context binding |

## Further Reading

- Whitfield Diffie, Martin Hellman, *New Directions in Cryptography* (1976) — the original DH paper.
- RFC 3526, *More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)* (2003) — classic standardized MODP groups.
- RFC 5114, *Additional Diffie-Hellman Groups for Use with IETF Standards* (2008) — includes standardized subgroup groups and explicit test vectors.
