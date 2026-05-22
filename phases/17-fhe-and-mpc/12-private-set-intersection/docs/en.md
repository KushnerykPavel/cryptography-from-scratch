# Private Set Intersection (PSI) from Scratch
> Compare two datasets and learn only the overlap (not the rest).

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 01 · 03 (Modular inverse & fast exponentiation), Phase 09 (Hash functions), Phase 10 · 11 (OPRF/VOPRF) (recommended)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what PSI reveals (and what it can’t hide by default).
- Compute commutative exponentiation “tags” and unblind them with modular inverses.
- Implement a toy PSI flow that reveals the client-side intersection (and a cardinality-only mode).
- Distinguish exact membership structures (sets) from probabilistic ones (Bloom filters) and their error modes.
- Apply a PSI review checklist to catch normalization, leakage, and abuse pitfalls in real systems.

## The Problem

You and a partner organization each have a list of identifiers (emails, phone numbers,
user IDs). You want to find the overlap — “which of *my* users are also in *your*
list?” — but neither side wants to reveal its full dataset.

Without PSI, teams often ship a bad substitute: upload plaintext IDs to a trusted
third party, exchange raw hashes that are easy to enumerate for small domains, or
give one side the other side’s full list “just this once”. These shortcuts create
privacy incidents and become compliance liabilities.

PSI is a practical building block for privacy-preserving matching, anti-abuse,
fraud detection, breach checks, and “do we share users?” analytics — as long as
you understand what it *does* and what it *still leaks*.

## The Concept

At a high level, PSI is a 2-party protocol for sets `A` (client) and `B` (server):

- The client learns something about `A ∩ B` (often the elements, sometimes only the size).
- The server learns as little as possible about `A` (often only `|A|`).

Two knobs you’ll see in practice:

1. **Reveal elements vs cardinality-only:** If the client learns *which* of its items match,
   the protocol can be abused as a membership oracle unless you add authorization and rate limits.
2. **Exact vs probabilistic membership:** A Bloom filter can compress server-side membership tests,
   but it introduces **false positives** (“maybe in”) and must be sized carefully.

In this lesson we implement a toy PSI sketch based on *commutative exponentiation*:

```
Enc_e(m) = m^e mod p
```

If `gcd(e, p-1) = 1`, we can compute `inv(e) mod (p-1)` and remove a layer:

```
(m^e)^(inv(e)) = m   (mod p)
```

This “add a layer / remove a layer” trick is enough to demonstrate the PSI flow, but
it is **not** a production PSI protocol: real systems use standardized groups/curves,
OPRF/VOPRF-based designs, malicious-security hardening, and careful leakage analysis.

## Build It

### Step 1: Hash items into group elements
```python
from __future__ import annotations

import hashlib
import math
import random
import secrets
from dataclasses import dataclass
from typing import Iterable, Sequence


DEFAULT_P = (1 << 127) - 1  # 2^127-1, a Mersenne prime (educational-sized)


def sha256(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return hashlib.sha256(bytes(data)).digest()


def _int_to_bytes(n: int) -> bytes:
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def hash_to_group_elem(*, item: str, p: int) -> int:
    """
    Deterministically map a string to an element of Z_p^* (excluding {0,1}).
    """
    if not isinstance(item, str):
        raise TypeError("item must be str")
    if not isinstance(p, int):
        raise TypeError("p must be int")
    if p <= 5:
        raise ValueError("p must be > 5")

    h = sha256(item.encode("utf-8"))
    x = int.from_bytes(h, "big")
    return (x % (p - 3)) + 2  # in [2, p-2]
```

PSI protocols need a deterministic way to turn real-world identifiers into
fixed “math objects” (group elements or field elements). Hashing gives you a
stable mapping, and the range restriction avoids degenerate values (`0` and `1`).

### Step 2: Commutative exponentiation + modular inverses
```python
def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if not isinstance(a, int) or not isinstance(b, int):
        raise TypeError("a and b must be int")
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(*, a: int, m: int) -> int:
    if not isinstance(a, int):
        raise TypeError("a must be int")
    if not isinstance(m, int):
        raise TypeError("m must be int")
    if m <= 1:
        raise ValueError("m must be > 1")
    g, x, _y = _egcd(a % m, m)
    if g != 1:
        raise ValueError("a is not invertible modulo m")
    return x % m


def choose_coprime_exponent(*, phi: int, seed: int | None = None) -> int:
    """
    Pick e uniformly-ish from [2, phi-1] such that gcd(e, phi) = 1.

    - With seed=None, uses secrets for randomness.
    - With seed=int, uses a deterministic RNG (useful for test vectors).
    """
    if not isinstance(phi, int):
        raise TypeError("phi must be int")
    if phi <= 4:
        raise ValueError("phi must be > 4")
    if seed is not None and not isinstance(seed, int):
        raise TypeError("seed must be int or None")

    if seed is None:
        def _randbelow(upper: int) -> int:
            return secrets.randbelow(upper)
    else:
        rng = random.Random(seed)

        def _randbelow(upper: int) -> int:
            return rng.randrange(0, upper)

    while True:
        e = _randbelow(phi - 2) + 2  # [2, phi-1]
        if math.gcd(e, phi) == 1:
            return e


def commutative_enc(*, m: int, e: int, p: int) -> int:
    if not isinstance(m, int):
        raise TypeError("m must be int")
    if not isinstance(e, int):
        raise TypeError("e must be int")
    if not isinstance(p, int):
        raise TypeError("p must be int")
    if p <= 5:
        raise ValueError("p must be > 5")
    if not (1 <= m <= p - 1):
        raise ValueError("m must be in [1, p-1]")
    if e <= 1 or e >= p - 1:
        raise ValueError("e must be in [2, p-2]")
    return pow(m, e, p)


def commutative_remove_layer(*, c: int, e: int, p: int) -> int:
    """
    Remove a commutative exponentiation layer by raising to inv(e) mod (p-1).
    Requires gcd(e, p-1)=1 and c in Z_p^*.
    """
    if not isinstance(c, int):
        raise TypeError("c must be int")
    if not isinstance(e, int):
        raise TypeError("e must be int")
    if not isinstance(p, int):
        raise TypeError("p must be int")
    if p <= 5:
        raise ValueError("p must be > 5")
    if not (1 <= c <= p - 1):
        raise ValueError("c must be in [1, p-1]")

    inv_e = modinv(a=e, m=p - 1)
    return pow(c, inv_e, p)
```

The whole toy protocol hangs on one constraint: you must be able to compute
`inv(e) mod (p-1)` to “unblind” values. That’s why `gcd(e, p-1)=1` is mandatory.

### Step 3: PSI flow (reveal intersection vs cardinality-only)
```python
def _dedupe_preserve_order(items: Iterable[str]) -> list[str]:
    if not isinstance(items, Iterable):
        raise TypeError("items must be iterable")
    out: list[str] = []
    seen: set[str] = set()
    for it in items:
        if not isinstance(it, str):
            raise TypeError("all items must be str")
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def server_tags(*, server_items: Sequence[str], p: int, b: int) -> set[int]:
    if not isinstance(server_items, Sequence):
        raise TypeError("server_items must be a sequence")
    tags: set[int] = set()
    for it in _dedupe_preserve_order(server_items):
        m = hash_to_group_elem(item=it, p=p)
        tags.add(commutative_enc(m=m, e=b, p=p))
    return tags


def client_request(*, client_items: Sequence[str], p: int, a: int) -> list[int]:
    if not isinstance(client_items, Sequence):
        raise TypeError("client_items must be a sequence")
    req: list[int] = []
    for it in _dedupe_preserve_order(client_items):
        m = hash_to_group_elem(item=it, p=p)
        req.append(commutative_enc(m=m, e=a, p=p))
    return req


def server_response(*, blinded_items: Sequence[int], p: int, b: int, reveal_intersection: bool) -> list[int]:
    if not isinstance(blinded_items, Sequence):
        raise TypeError("blinded_items must be a sequence")
    if not isinstance(reveal_intersection, bool):
        raise TypeError("reveal_intersection must be bool")

    out = [commutative_enc(m=v, e=b, p=p) for v in blinded_items]
    if not reveal_intersection:
        out.sort()
    return out


def client_unblind_response(*, response: Sequence[int], p: int, a: int) -> list[int]:
    if not isinstance(response, Sequence):
        raise TypeError("response must be a sequence")
    return [commutative_remove_layer(c=c, e=a, p=p) for c in response]


def psi_intersection(
    *,
    client_items: Sequence[str],
    server_items: Sequence[str],
    p: int = DEFAULT_P,
    a: int | None = None,
    b: int | None = None,
    reveal_intersection: bool = True,
    seed: int | None = None,
) -> list[str] | int:
    """
    End-to-end PSI simulation.

    - If reveal_intersection=True, returns the list of client items that are in the intersection.
      (Order is the client's input order after de-duplication.)
    - If reveal_intersection=False, returns an integer "intersection size" computed without
      preserving per-item alignment.
    """
    if not isinstance(client_items, Sequence):
        raise TypeError("client_items must be a sequence")
    if not isinstance(server_items, Sequence):
        raise TypeError("server_items must be a sequence")
    if not isinstance(p, int):
        raise TypeError("p must be int")
    if p <= 5:
        raise ValueError("p must be > 5")
    if not isinstance(reveal_intersection, bool):
        raise TypeError("reveal_intersection must be bool")
    if seed is not None and not isinstance(seed, int):
        raise TypeError("seed must be int or None")

    phi = p - 1
    if a is None:
        a = choose_coprime_exponent(phi=phi, seed=seed)
    if b is None:
        b = choose_coprime_exponent(phi=phi, seed=None if seed is None else seed + 1)

    if math.gcd(a, phi) != 1:
        raise ValueError("a must be coprime with (p-1)")
    if math.gcd(b, phi) != 1:
        raise ValueError("b must be coprime with (p-1)")

    client_items_u = _dedupe_preserve_order(client_items)
    req = client_request(client_items=client_items_u, p=p, a=a)
    resp = server_response(blinded_items=req, p=p, b=b, reveal_intersection=reveal_intersection)
    client_tags = client_unblind_response(response=resp, p=p, a=a)

    srv_tags = server_tags(server_items=server_items, p=p, b=b)

    if reveal_intersection:
        if len(client_tags) != len(client_items_u):
            raise AssertionError("internal error: tag/item length mismatch")
        intersection: list[str] = []
        for it, tag in zip(client_items_u, client_tags, strict=True):
            if tag in srv_tags:
                intersection.append(it)
        return intersection

    # Order was destroyed (sorted), so we only return a size.
    # Note: if you used a probabilistic membership structure (Bloom filter),
    # this count could have false positives.
    return len(set(client_tags).intersection(srv_tags))
```

This is the “shape” of many PSI designs:

- The server produces a membership structure for its (keyed) item tags.
- The client turns each of its items into the same kind of tag and checks membership.

Whether the client can map matches back to specific inputs depends on whether
the protocol preserves per-item alignment (reveal elements) or destroys it (cardinality-only).

### Step 4: Bloom filter membership (compact, but probabilistic)
```python
@dataclass(frozen=True)
class BloomFilter:
    m_bits: int
    k_hashes: int
    bits: bytes

    def maybe_contains(self, key: bytes) -> bool:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        for idx in bloom_indices(key=bytes(key), m_bits=self.m_bits, k_hashes=self.k_hashes):
            if not _bit_get(self.bits, idx):
                return False
        return True


def _bit_get(buf: bytes, bit_index: int) -> bool:
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        raise TypeError("buf must be bytes-like")
    if not isinstance(bit_index, int):
        raise TypeError("bit_index must be int")
    if bit_index < 0:
        raise ValueError("bit_index must be non-negative")
    byte_i = bit_index // 8
    bit_i = bit_index % 8
    if byte_i >= len(buf):
        raise ValueError("bit_index out of range")
    return (buf[byte_i] >> bit_i) & 1 == 1


def _bit_set(buf: bytearray, bit_index: int) -> None:
    if not isinstance(buf, bytearray):
        raise TypeError("buf must be bytearray")
    if not isinstance(bit_index, int):
        raise TypeError("bit_index must be int")
    if bit_index < 0:
        raise ValueError("bit_index must be non-negative")
    byte_i = bit_index // 8
    bit_i = bit_index % 8
    if byte_i >= len(buf):
        raise ValueError("bit_index out of range")
    buf[byte_i] |= 1 << bit_i


def bloom_indices(*, key: bytes, m_bits: int, k_hashes: int) -> list[int]:
    """
    Bloom indices via "double hashing" on SHA-256:

      idx_i = (h1 + i*h2) mod m
    """
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes-like")
    if not isinstance(m_bits, int):
        raise TypeError("m_bits must be int")
    if not isinstance(k_hashes, int):
        raise TypeError("k_hashes must be int")
    if m_bits <= 0:
        raise ValueError("m_bits must be > 0")
    if k_hashes <= 0:
        raise ValueError("k_hashes must be > 0")

    d = sha256(bytes(key))
    h1 = int.from_bytes(d[:16], "big")
    h2 = int.from_bytes(d[16:], "big") or 1
    return [((h1 + i * h2) % m_bits) for i in range(k_hashes)]


def bloom_build(*, keys: Sequence[bytes], m_bits: int, k_hashes: int) -> BloomFilter:
    if not isinstance(keys, Sequence):
        raise TypeError("keys must be a sequence")
    nbytes = (m_bits + 7) // 8
    buf = bytearray(nbytes)
    for k in keys:
        if not isinstance(k, (bytes, bytearray, memoryview)):
            raise TypeError("all keys must be bytes-like")
        for idx in bloom_indices(key=bytes(k), m_bits=m_bits, k_hashes=k_hashes):
            _bit_set(buf, idx)
    return BloomFilter(m_bits=m_bits, k_hashes=k_hashes, bits=bytes(buf))
```

Bloom filters are a classic PSI building block because they let the server send a
fixed-size membership “sketch” instead of a huge set. The trade-off is correctness:
you get **no false negatives** for inserted items, but you may get **false positives**
that inflate intersection counts unless you tune the parameters.

Run it:
python3 code/main.py

## Use It

Production PSI is usually *not* “pow mod p in a hand-rolled group”:

- **ECDH PSI:** standardized curves, careful encoding, and hardened implementations (often with optional “reveal intersection” vs “cardinality-only” modes).
- **OPRF/VOPRF-based PSI:** server-keyed tags without revealing the key; common when the identifier domain is small and enumerability matters.
- **HE-based PSI (e.g., APSI):** homomorphic encryption designs optimized for large sets and server-side matching.

When evaluating a real PSI library/protocol, look for:
- a clearly stated threat model (semi-honest vs malicious)
- a leakage statement (sizes, timing, error behavior)
- input normalization rules (canonicalization and encoding)
- key rotation and anti-abuse controls (PSI can become a membership oracle)

## Pitfalls

- **Skipping canonicalization:** `Alice@Example.com` vs `alice@example.com` vs Unicode confusables silently break matches.
- **Small-domain enumeration:** phone-number/email domains are enumerable; deterministic tags become guessable without an OPRF/VOPRF or other hardening.
- **Reusing keys forever:** stable tags across time enable linkability and correlation attacks; rotate keys and version your tag format.
- **Bloom filter misuse:** treating “maybe in” as “definitely in” turns false positives into data-quality bugs (or privacy bugs).
- **Unrestricted reveal-intersection PSI:** without authorization + rate limits, PSI becomes a high-powered membership-testing API.

## Ship It

Save and reuse the checklist in:
`outputs/psi-protocol-review-checklist.md`

Suggested use:
- paste it into a PR review when PSI code is introduced
- use it as a threat-modeling template when choosing a PSI protocol/library
- turn the checklist into acceptance criteria (quotas, normalization, key rotation)

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how Step 3 reveals which *client items* match, while Step 4 reports only a size.
2. Medium. In `code/main.py`, shrink the Bloom filter (e.g., `m_bits=128`) and increase server size; measure how often the Bloom-reported size exceeds the exact size.
3. Hard. Replace the toy “hash to Z_p^*” with an OPRF/VOPRF-style tag (see Phase 10 · 11) and design a key-rotation + versioning scheme for tags in a real service.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| PSI | “Private matching” | A protocol that reveals `A ∩ B` (or its size) while hiding (most of) `A \ (A ∩ B)` and `B \ (A ∩ B)` |
| Reveal intersection | “Show matches” | Client learns which of its items are in the intersection (powerful, but abusable) |
| Cardinality-only PSI | “Just the count” | Client learns only `|A ∩ B|` (often by destroying per-item alignment) |
| Commutative encryption | “Order doesn’t matter” | `Enc_a(Enc_b(m)) = Enc_b(Enc_a(m))`, enabling “double-encrypt then compare” patterns |
| Modular inverse | “Division mod n” | An `x` such that `a·x ≡ 1 (mod n)`; required to unblind in exponentiation-based sketches |
| Bloom filter | “Set membership bitmap” | A probabilistic membership structure with false positives but (for inserted items) no false negatives |

## Further Reading

- Freedman, Nissim, Pinkas, *Efficient Private Matching and Set Intersection* (2004) — classic early PSI formulation with different cryptographic techniques.
- De Cristofaro, Kim, Tsudik, *Linear-Complexity Private Set Intersection Protocols Secure in Malicious Model* (2010) — explores efficient PSI and malicious-security considerations.
- Pinkas et al., *Phasing: Private Set Intersection Using Permutation-Based Hashing* (2015) — scaling PSI and engineering constraints for large datasets.
- Katz, *Private Set Intersection* (survey notes) — a compact overview of PSI design space and trade-offs.

