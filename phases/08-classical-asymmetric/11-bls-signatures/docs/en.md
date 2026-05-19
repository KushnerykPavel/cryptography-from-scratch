# BLS Signatures & Aggregation
> A pairing lets you “move the exponent across the equals sign”.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/03-elliptic-curves/09-pairings-weil-tate`, `phases/03-elliptic-curves/11-hash-to-curve`, `phases/08-classical-asymmetric/08-schnorr`  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** the BLS verification equation and why bilinearity makes it work.
- **Compute** a toy pairing check and read it as an “exponent equality” statement.
- **Implement** BLS sign/verify and aggregate verification for distinct messages.
- **Distinguish** “aggregate signatures” (distinct messages) from “multi-signatures” (same message) and why the latter needs extra defenses.
- **Apply** a review checklist for real BLS integrations: ciphersuites, hash-to-curve, subgroup checks, and rogue-key defenses.

## The Problem

You’re building a system where *many* parties sign *a lot* of messages: validator attestations, committee votes, threshold signing protocols, distributed key custody, or large fan-out authorization lists. If you use a “normal” signature scheme (ECDSA/Ed25519), verifying `n` signatures costs `n` separate signature verifications and the signatures take `O(n)` space.

BLS signatures are attractive because they are **linear**: you can combine many signatures into a single group element and then verify the aggregate with a small number of pairing operations. This is why BLS shows up in systems like proof-of-stake aggregation and protocols that want “one signature from many signers”.

But that same linearity has sharp edges. If you aggregate signatures incorrectly, or you skip proof-of-possession / message distinctness rules, you can end up “verifying” an aggregate that *never had all signers participate* (the classic rogue-key pitfall). This lesson gives you the mental model and a working toy implementation you can use to review real implementations safely.

## The Concept

BLS signatures work in three cyclic groups of the same prime order `q`:

```text
G1 (additive),  G2 (additive),  GT (multiplicative)
e : G1 × G2 → GT
```

The crucial property is **bilinearity**:

```text
e(a·P, b·Q) = e(P, Q)^(ab)
```

The BLS “core” scheme is:

- Secret key: `sk ∈ Z_q`
- Public key: `pk = sk·G2`
- Hash-to-curve: `H(m) ∈ G1` (deterministic mapping of bytes to a curve point)
- Signature: `sig = sk·H(m)`
- Verify: check `e(sig, G2) == e(H(m), pk)`

Why verification works:

```text
e(sig, G2) = e(sk·H(m), G2) = e(H(m), sk·G2) = e(H(m), pk)
```

Aggregation comes from linearity:

- Aggregate signatures (distinct messages): `sig_agg = sig_1 + ... + sig_n`
- Aggregate verify (distinct messages):  
  `e(sig_agg, G2) == Π_i e(H(m_i), pk_i)`

For the **same message** (multi-signature), you can verify faster:

```text
e(sig_agg, G2) == e(H(m), pk_1 + ... + pk_n)
```

But that “fast path” needs rogue-key defenses (proof-of-possession or message augmentation). We’ll implement the API surface so you can see where the checks belong.

## Build It

### Step 1: A toy bilinear pairing

We will not implement a real elliptic-curve pairing in stdlib Python. Instead, we build a *pedagogical* bilinear map that behaves like a pairing: `G1` and `G2` are additive groups, `GT` is multiplicative, and `pairing()` is bilinear.

This is enough to learn the BLS protocol logic (what is multiplied/added/hashed, and which equalities must hold), while leaving “real curve arithmetic” to audited libraries.

```python
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, Sequence

TOY_Q = 2**127 - 1

DST_KEYGEN = b"BLS_TOY_KEYGEN_V1"
DST_H2G1 = b"BLS_TOY_H2G1_V1"
DST_POP_H2G1 = b"BLS_TOY_POP_H2G1_V1"


def _mod_q(x: int) -> int:
    return x % TOY_Q


def hash_to_scalar(msg: bytes, dst: bytes) -> int:
    x = int.from_bytes(hashlib.sha256(dst + b"|" + msg).digest(), "big") % TOY_Q
    return x if x != 0 else 1


@dataclass(frozen=True)
class G1:
    exp: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "exp", _mod_q(self.exp))

    def __add__(self, other: "G1") -> "G1":
        return G1(self.exp + other.exp)

    def __rmul__(self, k: int) -> "G1":
        return G1(self.exp * _mod_q(k))


@dataclass(frozen=True)
class G2:
    exp: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "exp", _mod_q(self.exp))

    def __add__(self, other: "G2") -> "G2":
        return G2(self.exp + other.exp)

    def __rmul__(self, k: int) -> "G2":
        return G2(self.exp * _mod_q(k))


@dataclass(frozen=True)
class GT:
    exp: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "exp", _mod_q(self.exp))

    def __mul__(self, other: "GT") -> "GT":
        return GT(self.exp + other.exp)

    def __pow__(self, k: int) -> "GT":
        return GT(self.exp * _mod_q(k))


G1_GEN = G1(1)
G2_GEN = G2(1)
GT_GEN = GT(1)


def pairing(p: G1, q: G2) -> GT:
    return GT(p.exp * q.exp)
```

In this model:

- `G1(exp=a)` represents “`a·G1_GEN`”.
- `G2(exp=b)` represents “`b·G2_GEN`”.
- `pairing(G1(a), G2(b))` returns “`GT(a·b)`”, which is exactly the bilinear relation BLS needs.

### Step 2: Core BLS sign/verify

Now we implement the core BLS API: deterministic keygen (from a seed), public-key derivation, hash-to-`G1`, signing, and verification.

```python
def keygen(seed: bytes) -> int:
    return hash_to_scalar(seed, DST_KEYGEN)


def sk_to_pk(sk: int) -> G2:
    sk = _mod_q(sk)
    if sk == 0:
        raise ValueError("secret key must be nonzero mod q")
    return sk * G2_GEN


def hash_to_g1(message: bytes) -> G1:
    return hash_to_scalar(message, DST_H2G1) * G1_GEN


def bls_sign(sk: int, message: bytes) -> G1:
    sk = _mod_q(sk)
    if sk == 0:
        raise ValueError("secret key must be nonzero mod q")
    return sk * hash_to_g1(message)


def bls_verify(pk: G2, message: bytes, signature: G1) -> bool:
    left = pairing(signature, G2_GEN)
    right = pairing(hash_to_g1(message), pk)
    return left == right
```

In a real pairing library, `hash_to_g1()` must be *RFC 9380 hash-to-curve* with an explicit ciphersuite/domain tag. Here we use SHA-256 + modular reduction to keep the demo stdlib-only.

### Step 3: Aggregate signatures (distinct messages)

Aggregate signatures let you compress many `(pk_i, m_i, sig_i)` into one `sig_agg`, as long as you follow the scheme rules. In the “basic” scheme, the key rule is: **all messages must be distinct**.

```python
def aggregate_signatures(signatures: Sequence[G1]) -> G1:
    if not signatures:
        raise ValueError("need at least one signature")
    agg = G1(0)
    for s in signatures:
        agg = agg + s
    return agg


def aggregate_verify(pks: Sequence[G2], messages: Sequence[bytes], signature: G1) -> bool:
    if len(pks) != len(messages):
        raise ValueError("pks and messages must have the same length")
    if not pks:
        raise ValueError("need at least one (pk, message)")
    if len(set(messages)) != len(messages):
        return False

    left = pairing(signature, G2_GEN)
    right = GT(0)
    for pk, msg in zip(pks, messages, strict=True):
        right = right * pairing(hash_to_g1(msg), pk)
    return left == right
```

This `aggregate_verify()` returns `False` if it sees duplicate messages, because duplicates enable the “rogue-key” style pitfalls unless you switch schemes (message augmentation or proof-of-possession).

### Step 4: Fast aggregation + proof of possession

When all signatures are on the **same message**, aggregation can be verified with a single aggregated public key. That’s fast — and also where rogue-key defenses matter.

We implement:

- `pop_prove(sk)` / `pop_verify(pk, proof)`: a proof-of-possession for registering a public key.
- `fast_aggregate_verify_same_message(...)`: the fast verification equation for same-message aggregation.
- `fast_aggregate_verify_same_message_with_pops(...)`: the same check, but only after validating all PoPs.

```python
def pop_prove(sk: int) -> G1:
    pk = sk_to_pk(sk)
    pk_bytes = pk.exp.to_bytes(32, "big")
    return sk * (hash_to_scalar(pk_bytes, DST_POP_H2G1) * G1_GEN)


def pop_verify(pk: G2, proof: G1) -> bool:
    pk_bytes = pk.exp.to_bytes(32, "big")
    h = hash_to_scalar(pk_bytes, DST_POP_H2G1) * G1_GEN
    return pairing(proof, G2_GEN) == pairing(h, pk)


def fast_aggregate_verify_same_message(pks: Sequence[G2], message: bytes, signature: G1) -> bool:
    if not pks:
        raise ValueError("need at least one public key")
    pk_agg = G2(0)
    for pk in pks:
        pk_agg = pk_agg + pk
    return pairing(signature, G2_GEN) == pairing(hash_to_g1(message), pk_agg)


def fast_aggregate_verify_same_message_with_pops(
    pks: Sequence[G2], pops: Sequence[G1], message: bytes, signature: G1
) -> bool:
    if len(pks) != len(pops):
        raise ValueError("pks and pops must have the same length")
    if not pks:
        raise ValueError("need at least one public key")
    for pk, pop in zip(pks, pops, strict=True):
        if not pop_verify(pk, pop):
            return False
    return fast_aggregate_verify_same_message(pks, message, signature)
```

Run it:

```bash
python3 code/main.py
```

## Use It

Real BLS is implemented over pairing-friendly curves (most commonly BLS12-381) and uses standardized hash-to-curve and serialization rules.

Use audited libraries. Examples:

- **Rust:** `blst` (widely used), `arkworks` (research/zk ecosystem)
- **Go:** `github.com/cloudflare/circl` (depending on use), other vetted curve libs
- **C/C++:** `blst`, `herumi/mcl`
- **Ethereum consensus:** the “BLS12-381 + ciphersuites” choices are codified in ecosystem specs (don’t invent your own)

When reviewing a real implementation, always look for:

- Which scheme: **basic**, **message augmentation**, or **proof of possession**
- Which ciphersuite / domain separation tags
- Explicit subgroup checks / cofactor clearing

## Pitfalls

1) **Wrong ciphersuite / no domain separation.** Hash-to-curve must be RFC 9380-style with a fixed DST. Mixing DSTs between signing and PoP breaks the security story (and mixing protocols without context enables cross-protocol replay).

2) **Aggregating same-message signatures without PoP.** Fast aggregation for a common message is where rogue-key pitfalls live. If you don’t enforce PoP (or a secure scheme like message augmentation / secure key aggregation), you can “verify” signatures that didn’t include all signers.

3) **Skipping subgroup checks and cofactor clearing.** Pairing curves have cofactors; invalid subgroup inputs can enable attacks or consensus splits. The library API usually has “deserialize and validate” calls — use them.

4) **Ambiguous serialization and hashing the wrong bytes.** BLS signatures are deterministic: if two parties hash different bytes (JSON formatting, missing length prefixes, different encodings), you’ll get invalid signatures or replay bugs.

5) **Confusing aggregate signatures with multi-signatures.** “Aggregate signatures” (distinct messages) and “multi-signatures” (same message) look similar but have different safety rules and verification equations.

## Ship It

Save the reusable review artifact:

- `outputs/bls-signatures-integration-checklist.md`

Use it as a PR review checklist (or paste into an AI reviewer) when you see BLS signatures, aggregation, or validator key registration logic.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe how bilinearity makes `e(sig, G2) == e(H(m), pk)` work, and how aggregation becomes a single check.
2. Medium: Implement “message augmentation” in this toy model: define `hash_to_g1_aug(pk, msg)` using a separate DST and the bytes of `pk`, then update sign/verify so messages become distinct per key.
3. Hard: Write a short “audit note” for a real BLS integration (any open-source repo): identify which scheme it uses (basic / aug / PoP), how it enforces message-distinctness or PoP, and where subgroup validation happens.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Pairing | “A magic function for curves” | A bilinear map `e : G1 × G2 → GT` that turns additive relations into multiplicative relations. |
| Bilinearity | “Linear in both inputs” | `e(aP, bQ) = e(P, Q)^(ab)`; the property that makes BLS verification work. |
| Hash-to-curve | “Hash into G1/G2” | A standardized mapping from bytes to a curve point (RFC 9380), with domain separation. |
| Aggregate signature | “One sig for many messages” | One signature that authenticates many `(pk_i, m_i)` pairs (typically requires distinct messages). |
| Multi-signature | “Many signers, one message” | Aggregation where all signers sign the same message; needs rogue-key defenses for fast verification. |
| Proof of possession (PoP) | “Prove you own the key” | A registration-time proof that you know the secret key for the public key you’re claiming. |

## Test Vectors

Vectors live in `tests/vectors.json` and are exercised by `tests/test_vectors.py`. They are deterministic for this lesson’s toy model and check sign/verify, aggregation rules, and PoP wiring.

Run:

```bash
python3 tests/test_vectors.py
```

## Further Reading

- Dan Boneh, Ben Lynn, Hovav Shacham, “Short Signatures from the Weil Pairing” (2001) — the original BLS construction.
- CFRG, “BLS Signatures” (Internet-Draft) — modern scheme variants (basic / augmentation / PoP) and aggregation rules.
- RFC 9380, “Hashing to Elliptic Curves” (2023) — the standardized hash-to-curve machinery BLS relies on.
