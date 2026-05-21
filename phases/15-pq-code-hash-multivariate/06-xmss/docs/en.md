# XMSS — eXtended Merkle Signature Scheme (RFC 8391)

> One Merkle root commits to many one-time signatures.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 15 · 03 (Lamport OTS), Phase 15 · 04 (Winternitz / WOTS), Phase 15 · 05 (Merkle Signatures)  
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why XMSS is *stateful* and what breaks when an OTS key is reused.
- **Compute** a WOTS+ “codeword” (base-`w` message digits + checksum digits).
- **Implement** WOTS+ signing and reconstruct the WOTS+ public key from a signature.
- **Distinguish** the **L-tree** (compress WOTS+ public keys) from the **Merkle tree** (authenticate leaves).
- **Apply** an authentication path to recompute a Merkle root and verify an XMSS signature.

## The Problem

You want digital signatures that remain secure even if a large quantum computer exists in the future. Classical signatures like RSA/ECDSA rely on algebraic assumptions that Shor’s algorithm breaks. Hash-based signatures take a different bet: “hash functions remain hard to invert.”

But one-time signatures (Lamport, WOTS/WOTS+) only sign *one* message per key. Real systems must sign many messages: firmware updates, package releases, audit logs, or blockchain transactions. Without a way to *bundle* many one-time keys under one public key, you either (1) ship a huge public key, or (2) reuse one-time keys and lose security.

XMSS solves the bundling problem by authenticating many WOTS+ public keys with a Merkle tree root — and introduces a new engineering problem: **state management**. If you lose or duplicate the signing index, you can accidentally reuse a one-time key and “hard fail” security.

## The Concept

XMSS combines four moving parts:

1. **WOTS+** one-time signatures on a fixed-size message digest `M'` (an `n`-byte value).
2. A hash function `H` used to build trees.
3. A randomized message hash `H_msg` that produces `M'` from `(r, root, idx, message)`.
4. A **PRF** to generate per-signature randomness `r` and to derive many secret values from compact seeds.

### What a signature contains

XMSS signs **one message** using **one leaf index** `idx` (state), producing:

| Field | Meaning |
|------:|---------|
| `idx` | which WOTS+ key pair (which leaf) was used |
| `r` | per-signature randomness used by `H_msg` |
| `sig_ots` | WOTS+ signature on `M'` |
| `auth` | authentication path: sibling nodes from leaf → root |

In this lesson’s code, the signature is serialized as:

`idx (4 bytes) || r (n bytes) || sig_ots (len*n bytes) || auth (h*n bytes)`

### How verification works (mental model)

Verification is just “recompute the root and compare”:

1. Compute `M' = H_msg(r, root, idx, message)`.
2. Recompute the **WOTS+ public key** from `(sig_ots, M')`.
3. Compress that WOTS+ public key into a **leaf** via an **L-tree**.
4. Combine `(leaf, auth, idx)` to recompute a candidate root.
5. Accept iff candidate root == public root.

### The statefulness constraint

An XMSS key with height `h` has exactly `2^h` leaves, so it can sign at most `2^h` messages. Worse: if you sign two different messages with the same `idx` (same WOTS+ key), **key reuse attacks become practical**.

That’s the central XMSS engineering rule:

> The signer must persistently increment `idx` and never reuse an old index — even after crashes, restarts, or multi-process concurrency.

## Build It

### Step 1: Hash toolbox (F/PRF + base-`w`)

These helpers give you deterministic, testable building blocks: a truncated SHA-256 (`hash_n`), an HMAC-SHA256 PRF (`prf`), and the WOTS+ base-`w` encoding with checksum (`wots_message_digits`).

```python
import hashlib
import hmac
import math
from typing import List, Tuple


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def hash_n(data: bytes, n: int) -> bytes:
    _require(n > 0, "n must be positive")
    return hashlib.sha256(data).digest()[:n]


def prf(key: bytes, data: bytes, n: int) -> bytes:
    _require(len(key) > 0, "key must be non-empty")
    return hmac.new(key, data, hashlib.sha256).digest()[:n]


def int_to_bytes(x: int, length: int) -> bytes:
    _require(x >= 0, "x must be non-negative")
    _require(length >= 0, "length must be non-negative")
    return x.to_bytes(length, "big")


def _is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def _log2_int(x: int) -> int:
    _require(_is_power_of_two(x), "w must be a power of two")
    return x.bit_length() - 1


def wots_params(n: int, w: int) -> Tuple[int, int, int, int]:
    _require(n > 0, "n must be positive")
    _require(w >= 2 and _is_power_of_two(w), "w must be a power-of-two >= 2")
    log_w = _log2_int(w)
    len1 = math.ceil((8 * n) / log_w)
    len2 = math.floor(math.log(len1 * (w - 1), w)) + 1
    length = len1 + len2
    return log_w, len1, len2, length


def base_w(x: bytes, w: int, out_len: int) -> List[int]:
    log_w = _log2_int(w)
    _require(out_len >= 0, "out_len must be non-negative")
    _require(out_len <= (8 * len(x)) // log_w, "out_len too large for input")

    digits: List[int] = []
    total = 0
    bits = 0
    in_pos = 0
    while len(digits) < out_len:
        if bits == 0:
            total = x[in_pos]
            in_pos += 1
            bits = 8
        bits -= log_w
        digits.append((total >> bits) & (w - 1))
    return digits


def wots_message_digits(msg_digest: bytes, n: int, w: int) -> List[int]:
    log_w, len1, len2, _ = wots_params(n=n, w=w)
    _require(len(msg_digest) == n, "msg_digest must be n bytes")

    msg = base_w(msg_digest, w, len1)
    csum = sum((w - 1) - d for d in msg)

    csum_bits = len2 * log_w
    shift = (8 - (csum_bits % 8)) % 8
    csum_shifted = csum << shift
    len2_bytes = math.ceil(csum_bits / 8)
    csum_bytes = int_to_bytes(csum_shifted, len2_bytes)
    csum_digits = base_w(csum_bytes, w, len2)
    return msg + csum_digits
```

### Step 2: WOTS+ (sign one digest, never reuse the key)

WOTS+ replaces “one secret per bit” (Lamport) with “one secret per digit in base `w`”, using hash chains. The signer reveals the chain node at position `digit`. The verifier hashes forward to the end of the chain and compares to the public key.

```python
from typing import List, Sequence, Tuple


def _addr(leaf_idx: int, chain_idx: int, hash_idx: int) -> bytes:
    return int_to_bytes(leaf_idx, 4) + int_to_bytes(chain_idx, 4) + int_to_bytes(hash_idx, 4)


def wots_chain(
    x: bytes, start: int, steps: int, *, n: int, w: int, pub_seed: bytes, leaf_idx: int, chain_idx: int
) -> bytes:
    _require(0 <= start <= w - 1, "start out of range")
    _require(0 <= steps <= w - 1, "steps out of range")
    _require(start + steps <= w - 1, "start+steps out of range")
    _require(len(x) == n, "x must be n bytes")
    _require(len(pub_seed) == n, "pub_seed must be n bytes")

    out = x
    for j in range(start, start + steps):
        out = hash_n(b"F" + pub_seed + _addr(leaf_idx, chain_idx, j) + out, n)
    return out


def wots_gen_sk(sk_seed: bytes, *, n: int, length: int, leaf_idx: int) -> List[bytes]:
    _require(len(sk_seed) == n, "sk_seed must be n bytes")
    sk: List[bytes] = []
    for i in range(length):
        sk.append(prf(sk_seed, int_to_bytes(leaf_idx, 4) + int_to_bytes(i, 4), n))
    return sk


def wots_gen_pk(sk_seed: bytes, pub_seed: bytes, *, n: int, w: int, leaf_idx: int) -> List[bytes]:
    _, _, _, length = wots_params(n=n, w=w)
    sk = wots_gen_sk(sk_seed, n=n, length=length, leaf_idx=leaf_idx)
    pk: List[bytes] = []
    for i, sk_i in enumerate(sk):
        pk.append(wots_chain(sk_i, 0, w - 1, n=n, w=w, pub_seed=pub_seed, leaf_idx=leaf_idx, chain_idx=i))
    return pk


def wots_sign(sk_seed: bytes, pub_seed: bytes, msg_digest: bytes, *, n: int, w: int, leaf_idx: int) -> List[bytes]:
    _, _, _, length = wots_params(n=n, w=w)
    digits = wots_message_digits(msg_digest, n=n, w=w)
    _require(len(digits) == length, "unexpected digit length")

    sk = wots_gen_sk(sk_seed, n=n, length=length, leaf_idx=leaf_idx)
    sig: List[bytes] = []
    for i, (sk_i, d) in enumerate(zip(sk, digits)):
        sig.append(wots_chain(sk_i, 0, d, n=n, w=w, pub_seed=pub_seed, leaf_idx=leaf_idx, chain_idx=i))
    return sig


def wots_pk_from_sig(
    sig: Sequence[bytes], pub_seed: bytes, msg_digest: bytes, *, n: int, w: int, leaf_idx: int
) -> List[bytes]:
    _, _, _, length = wots_params(n=n, w=w)
    _require(len(sig) == length, "unexpected signature length")
    for s in sig:
        _require(len(s) == n, "signature element must be n bytes")

    digits = wots_message_digits(msg_digest, n=n, w=w)
    pk: List[bytes] = []
    for i, (sig_i, d) in enumerate(zip(sig, digits)):
        pk.append(wots_chain(sig_i, d, (w - 1) - d, n=n, w=w, pub_seed=pub_seed, leaf_idx=leaf_idx, chain_idx=i))
    return pk
```

### Step 3: L-tree + Merkle tree (compress leaves, authenticate paths)

A WOTS+ public key is a *vector* of `len` hash chain endpoints. XMSS compresses it into one `n`-byte **leaf** using an **L-tree**, then builds a Merkle tree over those leaves. An authentication path is just the list of sibling nodes you need to hash back to the root.

```python
from typing import List, Sequence


def rand_hash(left: bytes, right: bytes, pub_seed: bytes, *, n: int, leaf_idx: int, tree_height: int, tree_index: int) -> bytes:
    _require(len(left) == n and len(right) == n, "children must be n bytes")
    _require(len(pub_seed) == n, "pub_seed must be n bytes")
    adrs = int_to_bytes(leaf_idx, 4) + int_to_bytes(tree_height, 4) + int_to_bytes(tree_index, 4)
    return hash_n(b"H" + pub_seed + adrs + left + right, n)


def ltree(pk: Sequence[bytes], pub_seed: bytes, *, n: int, leaf_idx: int) -> bytes:
    for p in pk:
        _require(len(p) == n, "pk elements must be n bytes")

    nodes = list(pk)
    height = 0
    while len(nodes) > 1:
        next_nodes: List[bytes] = []
        for i in range(len(nodes) // 2):
            left = nodes[2 * i]
            right = nodes[2 * i + 1]
            next_nodes.append(
                rand_hash(left, right, pub_seed, n=n, leaf_idx=leaf_idx, tree_height=height, tree_index=i)
            )
        if len(nodes) % 2 == 1:
            next_nodes.append(nodes[-1])
        nodes = next_nodes
        height += 1
    return nodes[0]


def merkle_build(leaves: Sequence[bytes], pub_seed: bytes, *, n: int) -> List[List[bytes]]:
    _require(len(leaves) > 0, "need at least one leaf")
    _require(_is_power_of_two(len(leaves)), "leaf count must be power of two")
    for leaf in leaves:
        _require(len(leaf) == n, "leaf must be n bytes")

    levels: List[List[bytes]] = [list(leaves)]
    height = 0
    while len(levels[-1]) > 1:
        cur = levels[-1]
        parents: List[bytes] = []
        for i in range(0, len(cur), 2):
            parents.append(
                rand_hash(cur[i], cur[i + 1], pub_seed, n=n, leaf_idx=0, tree_height=height, tree_index=i // 2)
            )
        levels.append(parents)
        height += 1
    return levels


def merkle_auth_path(levels: Sequence[Sequence[bytes]], leaf_index: int) -> List[bytes]:
    _require(0 <= leaf_index < len(levels[0]), "leaf_index out of range")
    idx = leaf_index
    path: List[bytes] = []
    for level in range(len(levels) - 1):
        sibling = idx ^ 1
        path.append(levels[level][sibling])
        idx >>= 1
    return path


def merkle_root_from_path(leaf: bytes, auth: Sequence[bytes], pub_seed: bytes, *, n: int, leaf_index: int) -> bytes:
    _require(len(leaf) == n, "leaf must be n bytes")
    idx = leaf_index
    node = leaf
    for height, sibling in enumerate(auth):
        _require(len(sibling) == n, "auth node must be n bytes")
        if idx % 2 == 0:
            node = rand_hash(node, sibling, pub_seed, n=n, leaf_idx=0, tree_height=height, tree_index=idx // 2)
        else:
            node = rand_hash(sibling, node, pub_seed, n=n, leaf_idx=0, tree_height=height, tree_index=idx // 2)
        idx >>= 1
    return node
```

### Step 4: XMSS keygen / sign / verify (and the stateful rule)

Now you glue it together: build a tree of leaves (each leaf is a compressed WOTS+ public key), store the Merkle root as the public key, and sign with the next unused index.

```python
from dataclasses import dataclass
from typing import List, Sequence, Tuple


@dataclass
class XMSSPublicKey:
    root: bytes
    pub_seed: bytes
    n: int
    w: int
    height: int


@dataclass
class XMSSPrivateKey:
    sk_seed: bytes
    sk_prf: bytes
    pub_seed: bytes
    root: bytes
    n: int
    w: int
    height: int
    idx: int = 0
    _levels: List[List[bytes]] | None = None

    def levels(self) -> List[List[bytes]]:
        if self._levels is None:
            self._levels = xmss_build_tree(self.sk_seed, self.pub_seed, n=self.n, w=self.w, height=self.height)
        return self._levels


@dataclass(frozen=True)
class XMSSSignature:
    idx: int
    r: bytes
    sig_ots: Tuple[bytes, ...]
    auth: Tuple[bytes, ...]


def xmss_build_tree(sk_seed: bytes, pub_seed: bytes, *, n: int, w: int, height: int) -> List[List[bytes]]:
    leaves: List[bytes] = []
    for leaf_idx in range(2**height):
        pk = wots_gen_pk(sk_seed, pub_seed, n=n, w=w, leaf_idx=leaf_idx)
        leaves.append(ltree(pk, pub_seed, n=n, leaf_idx=leaf_idx))
    return merkle_build(leaves, pub_seed, n=n)


def xmss_keygen(sk_seed: bytes, sk_prf: bytes, pub_seed: bytes, *, n: int, w: int, height: int) -> Tuple[XMSSPrivateKey, XMSSPublicKey]:
    _require(len(sk_seed) == n and len(sk_prf) == n and len(pub_seed) == n, "seeds must be n bytes")
    levels = xmss_build_tree(sk_seed, pub_seed, n=n, w=w, height=height)
    root = levels[-1][0]
    sk = XMSSPrivateKey(sk_seed=sk_seed, sk_prf=sk_prf, pub_seed=pub_seed, root=root, n=n, w=w, height=height, idx=0, _levels=levels)
    pk = XMSSPublicKey(root=root, pub_seed=pub_seed, n=n, w=w, height=height)
    return sk, pk


def xmss_h_msg(r: bytes, root: bytes, idx: int, message: bytes, *, n: int) -> bytes:
    _require(len(r) == n and len(root) == n, "r and root must be n bytes")
    return hash_n(b"HMSG" + r + root + int_to_bytes(idx, 4) + message, n)


def xmss_sign(sk: XMSSPrivateKey, message: bytes) -> XMSSSignature:
    _require(sk.idx < 2**sk.height, "XMSS key exhausted (idx >= 2^h)")
    idx = sk.idx
    r = prf(sk.sk_prf, int_to_bytes(idx, 4), sk.n)
    m = xmss_h_msg(r, sk.root, idx, message, n=sk.n)

    sig_ots = tuple(wots_sign(sk.sk_seed, sk.pub_seed, m, n=sk.n, w=sk.w, leaf_idx=idx))
    auth = tuple(merkle_auth_path(sk.levels(), idx))
    sk.idx += 1
    return XMSSSignature(idx=idx, r=r, sig_ots=sig_ots, auth=auth)


def xmss_verify(pk: XMSSPublicKey, message: bytes, sig: XMSSSignature) -> bool:
    if not (0 <= sig.idx < 2**pk.height):
        return False
    if len(sig.r) != pk.n:
        return False

    log_w, len1, len2, length = wots_params(n=pk.n, w=pk.w)
    if len(sig.sig_ots) != length:
        return False
    if len(sig.auth) != pk.height:
        return False
    if any(len(x) != pk.n for x in sig.sig_ots):
        return False
    if any(len(x) != pk.n for x in sig.auth):
        return False

    m = xmss_h_msg(sig.r, pk.root, sig.idx, message, n=pk.n)
    pk_ots = wots_pk_from_sig(sig.sig_ots, pk.pub_seed, m, n=pk.n, w=pk.w, leaf_idx=sig.idx)
    leaf = ltree(pk_ots, pk.pub_seed, n=pk.n, leaf_idx=sig.idx)
    root2 = merkle_root_from_path(leaf, sig.auth, pk.pub_seed, n=pk.n, leaf_index=sig.idx)
    return root2 == pk.root
```

Run it:

`python3 code/main.py`

## Use It

Production implementations follow RFC 8391 (XMSS/XMSS^MT) and are profiled by NIST SP 800-208. When you need **stateless** signatures with similar “hash-only” assumptions, the modern alternative is SPHINCS+ / SLH-DSA.

Practical equivalents:

- **XMSS (RFC 8391)**: stateful hash-based signatures (this lesson’s focus).
- **LMS/HSS (RFC 8554)**: another stateful hash-based signature family (next lesson in this phase).
- **SPHINCS+ / SLH-DSA (FIPS 205)**: stateless hash-based signatures (Phase 15 · 08).

Implementation reality:

- Real XMSS implementations use standardized parameter sets (OID), domain-separated addressing, and optimized auth-path algorithms (e.g., BDS) to avoid rebuilding trees.
- Real code must do strict parsing/format checks on signature and key formats and must treat `idx` updates as part of the signing atomicity boundary.

## Pitfalls

1. **Index reuse after restart**: `idx` stored in memory only → crash → reuse `idx` → WOTS+ key reuse → catastrophic security loss.
2. **Concurrency bugs**: two threads/processes sign simultaneously using the same `idx` because increments aren’t atomic or are not persisted before signature output.
3. **Key cloning/backups without coordination**: copying a private key snapshot to two machines guarantees eventual `idx` reuse unless you introduce a single writer or strict partitioning.
4. **Silent key exhaustion**: allowing `idx` to wrap (or ignoring “out of leaves”) produces repeated leaves or undefined behavior.
5. **Parameter mismatch**: signing with one parameter set (different `n`, `h`, `w`) but verifying with another. In real formats, the OID pins parameters; don’t “guess.”

## Ship It

This lesson produces `outputs/xmss-stateful-signing-checklist.md`: a PR-review checklist for integrating XMSS/LMS-style **stateful** signatures safely.

How to use it:

1. Paste the checklist into a design doc / PR description for any “stateful hash-based signature” integration.
2. Use it to audit state storage, concurrency, key lifecycle, and failure modes (crash/restart/rollback).
3. Keep it next to the code that persists `idx` (and add tests that simulate crashes and rollbacks).

## Exercises

1. Easy: Run `code/main.py`. Observe that the XMSS private key consumes one leaf index per signature and that signatures verify by recomputing the same Merkle root.
2. Medium: Change `height` in `main()` from `4` to `3` and `5`. Measure how signature size and key capacity (`2^h`) change. Explain the tradeoff in one paragraph.
3. Hard: Write a file-signing wrapper that persists `idx` to disk atomically (e.g., write-ahead log + fsync + rename). Add a test that simulates a crash between “compute signature” and “persist idx” and show how your design prevents reuse.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| WOTS+ | “One-time signature” | Hash chains; each signature reveals chain nodes at message-dependent positions. |
| Winternitz parameter (`w`) | “Speed/size knob” | Larger `w` → shorter signatures but more hashing per signature. |
| L-tree | “Compress WOTS pk” | Hash tree that reduces a WOTS+ public key vector to a single `n`-byte leaf. |
| Merkle root | “Public key” | Commitment to all leaves (all one-time keys) in one `n`-byte value. |
| Authentication path | “Merkle proof” | Sibling nodes needed to recompute the root from a leaf and its index. |
| Stateful signature | “Needs a counter” | Security requires a monotone, never-reused index for leaf selection. |

## Further Reading

- Hülsing et al., *XMSS: eXtended Merkle Signature Scheme* (RFC 8391, 2018) — the standard specification and pseudocode.
- NIST, *Recommendation for Stateful Hash-Based Signature Schemes* (SP 800-208, 2020) — profiles XMSS/LMS for real deployments.
- Hülsing, *WOTS+ — Shorter Signatures for Hash-Based Signature Schemes* (2013/2017) — the one-time signature underlying XMSS.
