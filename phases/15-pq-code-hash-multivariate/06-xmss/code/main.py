"""
Educational XMSS (RFC 8391) demo with toy parameters.

This file implements:
- A minimal hash toolbox (SHA-256 truncation + HMAC-based PRF).
- WOTS+ (Winternitz One-Time Signature Plus) over a message digest.
- L-tree compression of a WOTS+ public key into a Merkle leaf.
- An XMSS-style Merkle tree that authenticates many WOTS+ keys under one root.
- Signing/verifying with an explicit leaf index (stateful signatures).

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


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


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    _require(len(a) == len(b), "xor requires equal-length byte strings")
    return bytes(x ^ y for x, y in zip(a, b))


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


def xmss_sig_to_bytes(sig: XMSSSignature, *, n: int) -> bytes:
    return int_to_bytes(sig.idx, 4) + sig.r + b"".join(sig.sig_ots) + b"".join(sig.auth)


def xmss_sig_from_bytes(data: bytes, *, n: int, w: int, height: int) -> XMSSSignature:
    _, _, _, length = wots_params(n=n, w=w)
    want = 4 + n + (length + height) * n
    _require(len(data) == want, f"signature must be {want} bytes for these parameters")
    idx = bytes_to_int(data[:4])
    r = data[4 : 4 + n]
    pos = 4 + n
    sig_ots = tuple(data[pos + i * n : pos + (i + 1) * n] for i in range(length))
    pos += length * n
    auth = tuple(data[pos + i * n : pos + (i + 1) * n] for i in range(height))
    return XMSSSignature(idx=idx, r=r, sig_ots=sig_ots, auth=auth)


def _hex(b: bytes) -> str:
    return b.hex()


def demo_wots_reuse_forgery() -> None:
    n = 2
    w = 16
    sk_seed = hash_n(b"demo sk_seed", n)
    pub_seed = hash_n(b"demo pub_seed", n)
    leaf_idx = 0

    digest_a = hash_n(b"message A", n)
    digest_b = hash_n(b"message B", n)

    sig_a = wots_sign(sk_seed, pub_seed, digest_a, n=n, w=w, leaf_idx=leaf_idx)
    sig_b = wots_sign(sk_seed, pub_seed, digest_b, n=n, w=w, leaf_idx=leaf_idx)

    digits_a = wots_message_digits(digest_a, n=n, w=w)
    digits_b = wots_message_digits(digest_b, n=n, w=w)
    mins = [min(x, y) for x, y in zip(digits_a, digits_b)]

    forged_digest = None
    forged_digits = None
    for x in range(1, 1 << (8 * n)):
        cand = int_to_bytes(x, n)
        d = wots_message_digits(cand, n=n, w=w)
        if all(di >= mi for di, mi in zip(d, mins)):
            forged_digest = cand
            forged_digits = d
            break

    _require(forged_digest is not None and forged_digits is not None, "failed to find a forgeable digest (unexpected)")

    forged_sig: List[bytes] = []
    for i, target_d in enumerate(forged_digits):
        if digits_a[i] <= digits_b[i]:
            base_node = sig_a[i]
            base_d = digits_a[i]
        else:
            base_node = sig_b[i]
            base_d = digits_b[i]
        forged_sig.append(
            wots_chain(base_node, base_d, target_d - base_d, n=n, w=w, pub_seed=pub_seed, leaf_idx=leaf_idx, chain_idx=i)
        )

    forged_pk = wots_pk_from_sig(forged_sig, pub_seed, forged_digest, n=n, w=w, leaf_idx=leaf_idx)
    real_pk = wots_gen_pk(sk_seed, pub_seed, n=n, w=w, leaf_idx=leaf_idx)
    ok = forged_pk == real_pk

    print("Forged digest:", forged_digest.hex())
    print("Forgery verifies against the real WOTS+ public key:", ok)


def main() -> None:
    n = 16
    w = 16
    height = 4

    sk_seed = hash_n(b"lesson sk_seed", n)
    sk_prf = hash_n(b"lesson sk_prf", n)
    pub_seed = hash_n(b"lesson pub_seed", n)

    print("=== Step 1: Hash toolbox (F/PRF + base-w) ===")
    log_w, len1, len2, length = wots_params(n=n, w=w)
    print("n bytes:", n, "w:", w, "log_w:", log_w, "len1:", len1, "len2:", len2, "len:", length)
    print("hash_n('hi'):", _hex(hash_n(b"hi", n)))
    print("prf(sk_prf, idx=0):", _hex(prf(sk_prf, int_to_bytes(0, 4), n)))

    digest = hash_n(b"example message", n)
    digits = wots_message_digits(digest, n=n, w=w)
    print("digest:", digest.hex())
    print("first 8 WOTS digits:", digits[:8], "(... total", len(digits), ")")

    print()
    print("=== Step 2: WOTS+ one-time signature ===")
    leaf_idx = 3
    wots_pk = wots_gen_pk(sk_seed, pub_seed, n=n, w=w, leaf_idx=leaf_idx)
    wots_sig = wots_sign(sk_seed, pub_seed, digest, n=n, w=w, leaf_idx=leaf_idx)
    wots_pk2 = wots_pk_from_sig(wots_sig, pub_seed, digest, n=n, w=w, leaf_idx=leaf_idx)
    print("wots pk element 0:", _hex(wots_pk[0]))
    print("wots sig element 0:", _hex(wots_sig[0]))
    print("wots verify:", wots_pk2 == wots_pk)

    print()
    print("=== Step 3: Merkle tree over WOTS+ leaves ===")
    levels = xmss_build_tree(sk_seed, pub_seed, n=n, w=w, height=height)
    root = levels[-1][0]
    print("merkle root:", _hex(root))
    leaf = levels[0][leaf_idx]
    auth = merkle_auth_path(levels, leaf_idx)
    root2 = merkle_root_from_path(leaf, auth, pub_seed, n=n, leaf_index=leaf_idx)
    print("auth path length:", len(auth))
    print("root from leaf+auth:", _hex(root2))

    print()
    print("=== Step 4: XMSS signing + statefulness ===")
    xmss_sk, xmss_pk = xmss_keygen(sk_seed, sk_prf, pub_seed, n=n, w=w, height=height)
    msg1 = b"transaction: pay bob 10"
    msg2 = b"transaction: pay bob 11"
    sig1 = xmss_sign(xmss_sk, msg1)
    sig2 = xmss_sign(xmss_sk, msg2)
    print("sig1 idx:", sig1.idx, "verify:", xmss_verify(xmss_pk, msg1, sig1))
    print("sig2 idx:", sig2.idx, "verify:", xmss_verify(xmss_pk, msg2, sig2))
    print("remaining signatures:", (2**height) - xmss_sk.idx)

    print()
    print("WOTS+ key reuse is catastrophic (tiny demo):")
    demo_wots_reuse_forgery()


if __name__ == "__main__":
    main()
