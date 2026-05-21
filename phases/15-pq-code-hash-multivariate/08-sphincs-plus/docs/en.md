# SPHINCS+ from Scratch

> Stateless signatures = many tiny one-time keys, glued together with Merkle trees.

**Type:** Build
**Languages:** Python
**Prerequisites:** `03-lamport`, `04-winternitz`, `05-merkle-signatures`, `06-xmss`, `07-lms`
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why SPHINCS+ can be stateless while XMSS/LMS are stateful.
- Compute a Merkle authentication path and recompute the root.
- Implement a (toy) WOTS+ chain-based one-time signature and verify it.
- Distinguish the roles of WOTS+, XMSS, and the SPHINCS+ hypertree.
- Apply a verification mindset: what values the verifier can compute vs must be given.

## The Problem

You want a signature scheme that stays secure even if large quantum computers arrive. Today’s common signatures (RSA, ECDSA, Ed25519) rely on number theory problems that Shor’s algorithm would break.

Hash-based signatures are one of the most conservative answers: if your hash function behaves like a random oracle, you can build signatures with very few assumptions. The catch is **state**: classic tree-based hash signatures (XMSS/LMS) require the signer to track which one-time keys have already been used.

SPHINCS+ gives you a practical trade: bigger signatures, but **stateless signing**. If you can’t afford state bugs (mobile clients, many devices, crash recovery), SPHINCS+ is worth understanding.

## The Concept

SPHINCS+ is a “stack” of smaller hash-based ideas:

1. **One-time signatures (WOTS+)** sign a fixed-size digest by revealing parts of many hash chains.
2. **XMSS** puts many WOTS+ keys under a Merkle tree root (an “identity” for that XMSS tree).
3. **Hypertree (XMSSMT-style)** stacks XMSS trees: the root of a lower tree is signed by a higher tree, and so on, until you reach the single public root you pre-trust.

The core verification pattern is:

```
signature  -> compute bottom XMSS root candidate
root cand  -> verify next XMSS signature on that root
...        -> finally compare against the top public root
```

So the verifier doesn’t need the signer’s secret seeds. They only need:
- the **top-level root** (`PK.root`)
- the **public seed** used for domain separation (`PK.seed` in real SPHINCS+; `pub_seed` in our toy)
- the signature itself

## Build It

### Step 1: Domain-separated hash + PRF
We build a deterministic “tweakable hash” wrapper: everything is SHA-256 under the hood, but we make collisions between different purposes harder by including a `domain` string and explicit length-prefixing. We also define `addr(...)` bytes that we can thread through the construction to separate nodes/keys.

```python
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass


N = 16
W = 16


def _u32(x: int) -> bytes:
    if x < 0 or x > 0xFFFFFFFF:
        raise ValueError("u32 out of range")
    return x.to_bytes(4, "big")


def _u64(x: int) -> bytes:
    if x < 0 or x > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("u64 out of range")
    return x.to_bytes(8, "big")


def h(domain: str, *parts: bytes, out_len: int = N) -> bytes:
    if out_len <= 0:
        raise ValueError("out_len must be positive")
    prefix = domain.encode("utf-8")
    buf = bytearray()
    buf += _u32(len(prefix))
    buf += prefix
    for p in parts:
        buf += _u32(len(p))
        buf += p
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        out += hashlib.sha256(buf + _u32(counter)).digest()
        counter += 1
    return bytes(out[:out_len])


def addr(layer: int, tree: int, typ: int, key_and_mask: int = 0, chain: int = 0, hash_idx: int = 0, idx: int = 0) -> bytes:
    if layer < 0:
        raise ValueError("layer must be non-negative")
    if tree < 0:
        raise ValueError("tree must be non-negative")
    if typ < 0:
        raise ValueError("typ must be non-negative")
    return b"".join(
        [
            _u32(layer),
            _u64(tree),
            _u32(typ),
            _u32(key_and_mask),
            _u32(chain),
            _u32(hash_idx),
            _u32(idx),
        ]
    )


def expand(seed: bytes, label: bytes, out_len: int) -> bytes:
    return h("EXPAND", seed, label, out_len=out_len)


def prf(seed: bytes, label: bytes, out_len: int = N) -> bytes:
    return h("PRF", seed, label, out_len=out_len)
```

### Step 2: Merkle tree + authentication path
We’ll need Merkle trees everywhere: WOTS+ public keys become leaves, and the verifier checks membership using an authentication path. The only real operation is hashing parent nodes; everything else is book-keeping.

```python
def merkle_parent(left: bytes, right: bytes, pub_seed: bytes, a: bytes) -> bytes:
    if len(left) != N or len(right) != N:
        raise ValueError("nodes must be n bytes")
    return h("MERKLE_PARENT", pub_seed, a, left, right, out_len=N)


def merkle_tree(leaves: list[bytes], pub_seed: bytes, a: bytes) -> list[list[bytes]]:
    if not leaves:
        raise ValueError("leaves must be non-empty")
    if any(len(x) != N for x in leaves):
        raise ValueError("leaves must be n bytes each")

    levels = [list(leaves)]
    height = 0
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = []
        for i in range(0, len(cur), 2):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else cur[i]
            ai = addr(layer=0, tree=height, typ=10, idx=i // 2)
            nxt.append(merkle_parent(left, right, pub_seed, ai + a))
        levels.append(nxt)
        height += 1
    return levels


def merkle_root(leaves: list[bytes], pub_seed: bytes, a: bytes) -> bytes:
    return merkle_tree(leaves, pub_seed, a)[-1][0]


def merkle_auth_path(tree: list[list[bytes]], leaf_index: int) -> list[bytes]:
    if leaf_index < 0:
        raise ValueError("leaf_index must be non-negative")
    if leaf_index >= len(tree[0]):
        raise ValueError("leaf_index out of range")
    path = []
    idx = leaf_index
    for level in tree[:-1]:
        sib = idx ^ 1
        path.append(level[sib] if sib < len(level) else level[idx])
        idx //= 2
    return path


def merkle_compute_root(leaf: bytes, leaf_index: int, auth_path: list[bytes], pub_seed: bytes, a: bytes) -> bytes:
    if len(leaf) != N:
        raise ValueError("leaf must be n bytes")
    if leaf_index < 0:
        raise ValueError("leaf_index must be non-negative")
    if any(len(x) != N for x in auth_path):
        raise ValueError("auth_path nodes must be n bytes")

    node = leaf
    idx = leaf_index
    for height, sibling in enumerate(auth_path):
        ai = addr(layer=0, tree=height, typ=10, idx=idx // 2)
        if idx % 2 == 0:
            node = merkle_parent(node, sibling, pub_seed, ai + a)
        else:
            node = merkle_parent(sibling, node, pub_seed, ai + a)
        idx //= 2
    return node
```

### Step 3: WOTS+ (toy)
WOTS+ signs by revealing *how far up* each hash chain you climbed. The verifier can continue hashing each revealed value to reach the public key.

```python
def _is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def base_w(data: bytes, w: int, out_len: int) -> list[int]:
    if not _is_power_of_two(w):
        raise ValueError("w must be a power of two")
    if out_len < 0:
        raise ValueError("out_len must be non-negative")

    logw = int(math.log2(w))
    value = 0
    bits = 0
    out = []
    for b in data:
        value = (value << 8) | b
        bits += 8
        while bits >= logw and len(out) < out_len:
            bits -= logw
            out.append((value >> bits) & (w - 1))
    while len(out) < out_len:
        if bits == 0:
            out.append(0)
        else:
            out.append((value << (logw - bits)) & (w - 1))
            bits = 0
    return out


def wots_lengths(n: int = N, w: int = W) -> tuple[int, int, int, int]:
    if not _is_power_of_two(w):
        raise ValueError("w must be a power of two")
    logw = int(math.log2(w))
    len1 = (8 * n + logw - 1) // logw
    len2 = math.floor(math.log(len1 * (w - 1), w)) + 1
    return len1, len2, len1 + len2, logw


def wots_checksum(msg_digits: list[int], w: int = W) -> list[int]:
    _, len2, _, _ = wots_lengths(N, w)
    csum = sum((w - 1) - x for x in msg_digits)
    csum_bytes_len = (len2 * int(math.log2(w)) + 7) // 8
    csum_bytes = csum.to_bytes(csum_bytes_len, "big")
    return base_w(csum_bytes, w, len2)


def wots_msg_digits(message_digest: bytes, n: int = N, w: int = W) -> list[int]:
    if len(message_digest) != n:
        raise ValueError("message_digest must be n bytes")
    len1, _, _, _ = wots_lengths(n, w)
    return base_w(message_digest, w, len1)


def wots_chain(x: bytes, start: int, steps: int, pub_seed: bytes, a: bytes) -> bytes:
    if len(x) != N:
        raise ValueError("x must be n bytes")
    if steps < 0:
        raise ValueError("steps must be non-negative")
    y = x
    for i in range(start, start + steps):
        y = h("WOTS_CHAIN", pub_seed, a, _u32(i), y, out_len=N)
    return y


def wots_gen_sk(sk_seed: bytes, pub_seed: bytes, a: bytes) -> list[bytes]:
    _, _, length, _ = wots_lengths(N, W)
    sk = []
    for i in range(length):
        sk.append(prf(sk_seed, b"wots_sk|" + a + _u32(i), out_len=N))
    return sk


def wots_gen_pk(sk_seed: bytes, pub_seed: bytes, a: bytes) -> list[bytes]:
    sk = wots_gen_sk(sk_seed, pub_seed, a)
    pk = []
    for i, x in enumerate(sk):
        ai = addr(0, 0, 1, chain=i) + a
        pk.append(wots_chain(x, 0, W - 1, pub_seed, ai))
    return pk


def wots_pk_compress(pk: list[bytes], pub_seed: bytes, a: bytes) -> bytes:
    if not pk:
        raise ValueError("pk must be non-empty")
    if any(len(x) != N for x in pk):
        raise ValueError("pk elements must be n bytes")

    level = list(pk)
    height = 0
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            ai = addr(layer=0, tree=height, typ=2, idx=i // 2)
            nxt.append(h("WOTS_LTREE", pub_seed, a, ai, left, right, out_len=N))
        level = nxt
        height += 1
    return level[0]


def wots_sign(message_digest: bytes, sk_seed: bytes, pub_seed: bytes, a: bytes) -> list[bytes]:
    msg = wots_msg_digits(message_digest, N, W)
    csum = wots_checksum(msg, W)
    all_digits = msg + csum
    sk = wots_gen_sk(sk_seed, pub_seed, a)
    sig = []
    for i, steps in enumerate(all_digits):
        ai = addr(0, 0, 1, chain=i) + a
        sig.append(wots_chain(sk[i], 0, steps, pub_seed, ai))
    return sig


def wots_pk_from_sig(message_digest: bytes, sig: list[bytes], pub_seed: bytes, a: bytes) -> list[bytes]:
    msg = wots_msg_digits(message_digest, N, W)
    csum = wots_checksum(msg, W)
    all_digits = msg + csum
    _, _, length, _ = wots_lengths(N, W)
    if len(sig) != length:
        raise ValueError("bad wots signature length")
    if any(len(x) != N for x in sig):
        raise ValueError("wots signature elements must be n bytes")

    pk = []
    for i, steps in enumerate(all_digits):
        ai = addr(0, 0, 1, chain=i) + a
        pk.append(wots_chain(sig[i], steps, (W - 1) - steps, pub_seed, ai))
    return pk


def wots_verify(message_digest: bytes, sig: list[bytes], pk_compressed: bytes, pub_seed: bytes, a: bytes) -> bool:
    pk = wots_pk_from_sig(message_digest, sig, pub_seed, a)
    return wots_pk_compress(pk, pub_seed, a) == pk_compressed
```

### Step 4: XMSS (toy)
XMSS turns “one-time” into “few-times” by giving you a Merkle tree of WOTS+ keys. A signature is: `(leaf_index, wots_sig, auth_path)`.

```python
def xmss_leaf(sk_seed: bytes, pub_seed: bytes, leaf_index: int, a: bytes) -> bytes:
    ai = addr(0, 0, 100, idx=leaf_index)
    pk = wots_gen_pk(sk_seed, pub_seed, ai + a)
    return h("XMSS_LEAF", pub_seed, ai + a, wots_pk_compress(pk, pub_seed, ai + a), out_len=N)


def xmss_tree(sk_seed: bytes, pub_seed: bytes, height: int, a: bytes) -> list[list[bytes]]:
    if height < 1:
        raise ValueError("height must be >= 1")
    leaves = [xmss_leaf(sk_seed, pub_seed, i, a) for i in range(1 << height)]
    return merkle_tree(leaves, pub_seed, a)


@dataclass(frozen=True)
class XMSSPublicKey:
    root: bytes
    pub_seed: bytes
    height: int


@dataclass(frozen=True)
class XMSSSignature:
    leaf_index: int
    wots_sig: list[bytes]
    auth_path: list[bytes]


def xmss_keygen(sk_seed: bytes, pub_seed: bytes, height: int, a: bytes) -> XMSSPublicKey:
    tree = xmss_tree(sk_seed, pub_seed, height, a)
    return XMSSPublicKey(root=tree[-1][0], pub_seed=pub_seed, height=height)


def xmss_sign(message: bytes, sk_seed: bytes, pub_seed: bytes, height: int, leaf_index: int, a: bytes) -> XMSSSignature:
    if leaf_index < 0 or leaf_index >= (1 << height):
        raise ValueError("leaf_index out of range")
    mhash = h("XMSS_MSG", message, out_len=N)
    leaf_addr = addr(0, 0, 100, idx=leaf_index) + a
    wots_sig = wots_sign(mhash, sk_seed, pub_seed, leaf_addr)
    tree = xmss_tree(sk_seed, pub_seed, height, a)
    auth_path = merkle_auth_path(tree, leaf_index)
    return XMSSSignature(leaf_index=leaf_index, wots_sig=wots_sig, auth_path=auth_path)


def xmss_verify(message: bytes, sig: XMSSSignature, pk: XMSSPublicKey, a: bytes) -> bool:
    try:
        return xmss_root_from_sig(message, sig, pk.pub_seed, a, expected_height=pk.height) == pk.root
    except ValueError:
        return False


def xmss_root_from_sig(message: bytes, sig: XMSSSignature, pub_seed: bytes, a: bytes, expected_height: int | None = None) -> bytes:
    if expected_height is not None and len(sig.auth_path) != expected_height:
        raise ValueError("bad auth_path length")
    mhash = h("XMSS_MSG", message, out_len=N)
    leaf_addr = addr(0, 0, 100, idx=sig.leaf_index) + a
    wots_pk = wots_pk_from_sig(mhash, sig.wots_sig, pub_seed, leaf_addr)
    leaf = h("XMSS_LEAF", pub_seed, leaf_addr, wots_pk_compress(wots_pk, pub_seed, leaf_addr), out_len=N)
    return merkle_compute_root(leaf, sig.leaf_index, sig.auth_path, pub_seed, a)
```

### Step 5: SPHINCS+ (toy 2-layer hypertree)
Finally, we stack XMSS trees. The “bottom” XMSS signs the message. The “top” XMSS signs the bottom root. Verification is implicit: compute the bottom root from the bottom signature, then verify the top signature against the single top public root.

```python
@dataclass(frozen=True)
class SPHINCSPublicKey:
    root: bytes
    pub_seed: bytes
    top_height: int
    bottom_height: int


@dataclass(frozen=True)
class SPHINCSSignature:
    subtree_index: int
    bottom_sig: XMSSSignature
    top_sig: XMSSSignature


def sphincs_keygen(sk_seed: bytes, pub_seed: bytes, top_height: int, bottom_height: int, a: bytes) -> SPHINCSPublicKey:
    top_sk_seed = prf(sk_seed, b"sphincs_top", out_len=N)
    top_pk = xmss_keygen(top_sk_seed, pub_seed, top_height, a)
    return SPHINCSPublicKey(root=top_pk.root, pub_seed=pub_seed, top_height=top_height, bottom_height=bottom_height)


def _sphincs_bottom_seed(sk_seed: bytes, subtree_index: int) -> bytes:
    return prf(sk_seed, b"sphincs_bottom|" + _u32(subtree_index), out_len=N)


def sphincs_sign(message: bytes, sk_seed: bytes, pub_seed: bytes, top_height: int, bottom_height: int, a: bytes) -> SPHINCSSignature:
    digest = h("SPHINCS_MSG", message, out_len=4)
    subtree_index = int.from_bytes(digest, "big") % (1 << top_height)
    leaf_index = int.from_bytes(h("SPHINCS_LEAF", message, out_len=4), "big") % (1 << bottom_height)

    bottom_seed = _sphincs_bottom_seed(sk_seed, subtree_index)
    bottom_pk = xmss_keygen(bottom_seed, pub_seed, bottom_height, a)
    bottom_sig = xmss_sign(message, bottom_seed, pub_seed, bottom_height, leaf_index, a)

    top_seed = prf(sk_seed, b"sphincs_top", out_len=N)
    top_sig = xmss_sign(bottom_pk.root, top_seed, pub_seed, top_height, subtree_index, a)
    return SPHINCSSignature(subtree_index=subtree_index, bottom_sig=bottom_sig, top_sig=top_sig)


def sphincs_verify(message: bytes, sig: SPHINCSSignature, pk: SPHINCSPublicKey, a: bytes) -> bool:
    digest = h("SPHINCS_MSG", message, out_len=4)
    subtree_index = int.from_bytes(digest, "big") % (1 << pk.top_height)
    if subtree_index != sig.subtree_index:
        return False
    if sig.top_sig.leaf_index != sig.subtree_index:
        return False

    try:
        bottom_root = xmss_root_from_sig(message, sig.bottom_sig, pk.pub_seed, a, expected_height=pk.bottom_height)
    except ValueError:
        return False
    top_sig = XMSSSignature(leaf_index=sig.top_sig.leaf_index, wots_sig=sig.top_sig.wots_sig, auth_path=sig.top_sig.auth_path)
    top_pk = XMSSPublicKey(root=pk.root, pub_seed=pk.pub_seed, height=pk.top_height)
    try:
        return xmss_verify(bottom_root, top_sig, top_pk, a)
    except ValueError:
        return False
```

Run it:

`python3 code/main.py`

## Use It

From-scratch SPHINCS+ is for learning only. For real systems:

- Use a **vetted implementation** (C/Rust) that matches a standardized parameter set.
- Expect **large signatures** and plan bandwidth/storage accordingly.

Examples of production-grade sources to look for:
- Reference implementations from the SPHINCS+ authors (and clean-room ports).
- Post-quantum libraries that bundle multiple algorithms (e.g., Open Quantum Safe style stacks).

## Pitfalls

1. **Treating SPHINCS+ like XMSS/LMS**: SPHINCS+ is stateless, but *your implementation can accidentally become stateful* if you cache or reuse one-time keys.
2. **Forgetting domain separation**: hash-based schemes reuse SHA-256 everywhere. Without careful domain separation, “different” hashes can collide by construction.
3. **Assuming small signatures**: SPHINCS+ trades statelessness for signature size. If you ignore this, you’ll ship timeouts and bloated logs.
4. **Side-channels and faults**: naive Python is not constant-time. Even in C, table lookups and branching can leak key material if you aren’t careful.
5. **Parameter confusion**: “n”, “w”, tree heights, and layer counts are easy to mix up. Treat them as part of the algorithm definition, not a tuning knob.

## Ship It

Save the reusable checklist in `outputs/sphincs-plus-review-checklist.md` and use it when:
- reviewing a PR that adds SPHINCS+ / SLH-DSA support
- designing key management and message formats
- auditing a “stateless hash-based signature” claim

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how verification “walks up” from the bottom signature to the public root.
2. Medium. Change `top_height` / `bottom_height` in `demo_step_5()` and measure how signature size and runtime change.
3. Hard. Replace the toy message-derived indices in `sphincs_sign()` with a randomized salt `R` (still deterministic for tests) and explain how it reduces accidental index reuse.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| WOTS+ | “A hash-based signature” | A one-time signature made of many short hash chains. |
| Merkle tree | “A commitment to many values” | A binary hash tree whose root authenticates all leaves. |
| Auth path | “A Merkle proof” | The sibling nodes needed to recompute the root for one leaf. |
| XMSS | “Stateful hash signatures” | A Merkle tree of WOTS+ keys; you must not reuse a leaf index. |
| Hypertree | “A tree of trees” | A stack of XMSS trees where each layer signs the layer below. |
| Stateless (SPHINCS+) | “No state needed” | The signer derives indices from the message (and randomness in real SPHINCS+), avoiding global counters. |

## Further Reading

- Bernstein et al., *SPHINCS+ Specification* (NIST PQC submission) — the definitive description of the full scheme and parameter sets.
- RFC 8391, *XMSS: eXtended Merkle Signature Scheme* (2018) — background for the XMSS component and terminology.
- RFC 8554, *LMS / HSS* (2019) — a practical alternative, also Merkle-tree based, but stateful.
