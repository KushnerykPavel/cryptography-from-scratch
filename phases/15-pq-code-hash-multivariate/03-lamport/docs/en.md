# Lamport One-Time Signatures (OTS)
> Sign a hash bit-by-bit: reveal one secret per bit.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 07 · 09 (SHA-256)
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Lamport signatures are *one-time*.
- Compute a SHA-256 digest and map it to 256 bits (MSB-first).
- Implement `lamport_keygen`, `lamport_sign`, and `lamport_verify`.
- Distinguish the **private** secrets from the **public** hashed commitments.
- Apply a key-reuse “leakage check” to quantify what an attacker learns.

## The Problem

Classical signatures (RSA/ECDSA/EdDSA) rely on math problems (factoring, discrete
log) that a large fault-tolerant quantum computer could solve efficiently with
Shor’s algorithm. If you want a post-quantum path, one of the oldest and
simplest alternatives is **hash-based signatures**: security rests on the
one-wayness and collision resistance of cryptographic hash functions.

Lamport OTS is the smallest “working example” of hash-based signatures. It is
not what you deploy directly (keys and signatures are huge, and it’s one-time),
but it *is* the core mental model you need before you can understand practical
schemes like Winternitz OTS, XMSS/LMS (Merkle tree composition), and SPHINCS+
(stateless hash-based signatures).

## The Concept

Lamport OTS turns a hash function into a signature scheme by signing the **bits
of a message digest**.

For each bit position `i` (0..255):

- You generate **two random secrets**: `sk0[i]` and `sk1[i]`.
- You publish **their hashes**: `pk0[i] = H(sk0[i])` and `pk1[i] = H(sk1[i])`.

To sign a message:

1. Compute `d = SHA256(message)` (32 bytes = 256 bits).
2. For each bit `d[i]`:
   - if `d[i] = 0`, reveal `sk0[i]`
   - if `d[i] = 1`, reveal `sk1[i]`

To verify, the verifier hashes each revealed secret and checks it matches the
corresponding public commitment.

Why it’s one-time:

- One signature reveals **one** secret per bit position.
- If you ever sign two different digests under the same key, then for many
  positions you will reveal *both* `sk0[i]` and `sk1[i]`. Each “fully revealed”
  position is a bit the attacker can now satisfy either way in a forged
  signature.

Sizes (with 256-bit SHA-256 and 32-byte secrets):

| Object | What it contains | Size |
|---|---|---:|
| Private key | 2 × 256 secrets | 16,384 bytes |
| Public key | 2 × 256 hashes | 16,384 bytes |
| Signature | 256 revealed secrets | 8,192 bytes |

## Build It

### Step 1: Hash-to-bits (SHA-256)

We sign the bits of `SHA256(message)`. The only tricky detail that must be
explicit is the bit order; we’ll use **MSB-first** within each byte.

```python
import hashlib
import secrets
from dataclasses import dataclass


N_BITS = 256
SECRET_SIZE = 32
PRG_DOMAIN = b"CRYPTO-FROM-SCRATCH/lamport-ots/prg/v1"


def sha256(data: bytes) -> bytes:
    _require_bytes("data", data)
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def bits_msb(data: bytes) -> list[int]:
    _require_bytes("data", data)
    out: list[int] = []
    for b in data:
        for i in range(7, -1, -1):
            out.append((b >> i) & 1)
    return out
```

### Step 2: Deterministic PRG + key generation

For tests and reproducible demos, we’ll generate key material from a seed using
SHA-256 as a simple PRG (not a standardized KDF; just stable and deterministic
for this lesson).

```python
def prg_sha256(seed: bytes, nbytes: int, *, domain: bytes = PRG_DOMAIN) -> bytes:
    _require_bytes("seed", seed)
    _require_bytes("domain", domain)
    if not isinstance(nbytes, int):
        raise TypeError("nbytes must be int")
    if nbytes < 0:
        raise ValueError("nbytes must be >= 0")

    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        ctr = counter.to_bytes(4, "big")
        out.extend(hashlib.sha256(domain + seed + ctr).digest())
        counter += 1
    return bytes(out[:nbytes])


@dataclass(frozen=True)
class LamportPrivateKey:
    zero: list[bytes]
    one: list[bytes]


@dataclass(frozen=True)
class LamportPublicKey:
    zero: list[bytes]
    one: list[bytes]


def lamport_keygen(*, seed: bytes | None = None) -> tuple[LamportPrivateKey, LamportPublicKey]:
    if seed is not None:
        _require_bytes("seed", seed)

    total = 2 * N_BITS * SECRET_SIZE
    material = prg_sha256(seed, total) if seed is not None else secrets.token_bytes(total)

    sk0: list[bytes] = []
    sk1: list[bytes] = []
    off = 0
    for _ in range(N_BITS):
        sk0.append(material[off : off + SECRET_SIZE])
        off += SECRET_SIZE
    for _ in range(N_BITS):
        sk1.append(material[off : off + SECRET_SIZE])
        off += SECRET_SIZE

    pk0 = [sha256(x) for x in sk0]
    pk1 = [sha256(x) for x in sk1]
    return LamportPrivateKey(sk0, sk1), LamportPublicKey(pk0, pk1)
```

### Step 3: Sign (reveal one secret per digest bit)

```python
def lamport_sign(message: bytes, sk: LamportPrivateKey) -> list[bytes]:
    _require_bytes("message", message)
    _require_private_key(sk)

    digest = sha256(message)
    bits = bits_msb(digest)
    if len(bits) != N_BITS:
        raise AssertionError("unexpected digest size")

    sig: list[bytes] = []
    for i, b in enumerate(bits):
        sig.append(sk.one[i] if b else sk.zero[i])
    return sig
```

### Step 4: Verify + quantify key-reuse leakage

Verification checks that each revealed secret hashes to the expected public
commitment. The leakage helper counts how many bit positions have had **both**
secrets revealed across multiple signatures (the core reason Lamport is OTS).

```python
def lamport_verify(message: bytes, sig: list[bytes], pk: LamportPublicKey) -> bool:
    _require_bytes("message", message)
    _require_public_key(pk)

    if not isinstance(sig, list):
        raise TypeError("sig must be list[bytes]")
    if len(sig) != N_BITS:
        return False
    for x in sig:
        if not isinstance(x, (bytes, bytearray)):
            return False
        if len(x) != SECRET_SIZE:
            return False

    digest = sha256(message)
    bits = bits_msb(digest)
    if len(bits) != N_BITS:
        raise AssertionError("unexpected digest size")

    for i, b in enumerate(bits):
        want = pk.one[i] if b else pk.zero[i]
        if sha256(sig[i]) != want:
            return False
    return True


def lamport_reuse_leakage(messages: list[bytes], sk: LamportPrivateKey) -> dict[str, int]:
    if not isinstance(messages, list):
        raise TypeError("messages must be list[bytes]")
    for m in messages:
        _require_bytes("message", m)
    _require_private_key(sk)

    have0 = [False] * N_BITS
    have1 = [False] * N_BITS
    for m in messages:
        digest = sha256(m)
        bits = bits_msb(digest)
        for i, b in enumerate(bits):
            if b:
                have1[i] = True
            else:
                have0[i] = True

    fully = sum(1 for i in range(N_BITS) if have0[i] and have1[i])
    return {
        "messages": len(messages),
        "fully_revealed_positions": fully,
        "partially_revealed_positions": N_BITS - sum(1 for i in range(N_BITS) if not have0[i] and not have1[i]),
    }
```

Run it:

```bash
python3 code/main.py
```

## Use It

Lamport OTS is a teaching tool and a building block. Real systems use more
efficient hash-based schemes and wrap one-time keys in Merkle trees.

Practical equivalents to look for:

- **WOTS+ / Winternitz OTS:** compresses the “one secret per bit” idea into
  chains to reduce signature size.
- **XMSS:** stateful hash-based signatures that compose many OTS keys with a
  Merkle tree.
- **LMS (Leighton–Micali):** similar “Merkle tree of OTS” idea with its own
  standardization.
- **SPHINCS+:** stateless hash-based signatures built from WOTS+ + Merkle
  constructions.

## Pitfalls

- **Reusing a Lamport key:** every extra signature reveals more secrets; after
  a few signatures, many bit positions become “fully revealed”.
- **Skipping the hash step:** Lamport signs a *fixed-length digest*; signing a
  variable-length message directly breaks the mental model and complicates
  security reasoning.
- **Ambiguous bit order:** you must define MSB-first vs LSB-first; mismatches
  will fail verification across implementations.
- **Poor randomness for secrets:** the private key is just random bytes; weak
  RNG means instantly broken signatures.
- **Trying to deploy Lamport directly:** signatures/keys are huge and key reuse
  must be enforced; production schemes add structure (WOTS+/XMSS/LMS/SPHINCS+).

## Ship It

Save a reusable review checklist for hash-based signature usage:

- File: `outputs/lamport-ots-integration-checklist.md`
- Use it when reviewing PRs that introduce a hash-based signature scheme, or
  when designing a migration plan away from classical signatures.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe how large the keys/signature are.
2. Medium: Change `seed` and `msg` in `main()` and confirm `lamport_verify`
   still returns `True` for the matching signature and `False` for modified
   messages.
3. Hard: Sketch (no code) how to turn many Lamport OTS keys into a multi-use
   signature scheme using a Merkle tree (you’ll implement this in later
   lessons).

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| One-time signature | “You can sign once” | Reusing the same key reveals secrets and enables forgeries. |
| One-way function | “Hard to invert” | Given `H(x)`, finding any `x'` with `H(x') = H(x)` is infeasible. |
| Public key | “The verifier’s key” | Here: 512 hash commitments to 512 private secrets. |
| Signature | “A short proof” | Here: 256 revealed secrets chosen by digest bits. |
| Domain separation | “A prefix” | A context tag so the same hash isn’t reused across protocols accidentally. |

## Further Reading

- Lamport, “Constructing digital signatures from a one-way function” (1979) — the original one-time signature idea.
- RFC 8391 (XMSS) — how one-time signatures get composed into a practical scheme.
- RFC 8554 (LMS/HSS) — another standardized Merkle-tree-of-OTS design.
