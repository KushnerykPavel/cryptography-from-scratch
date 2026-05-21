"""
Toy SPHINCS+ (hash-based signatures) in pure Python + stdlib.

This file is a runnable, educational demo that builds up:
1) domain-separated hashing (PRF/expand)
2) Merkle trees + authentication paths
3) a simplified WOTS+ one-time signature
4) XMSS (WOTS+ inside a Merkle tree)
5) a tiny 2-layer SPHINCS+-like hypertree

Run:
  python3 code/main.py

Security warning:
  Educational implementation. Not constant-time. Not production-safe.
"""

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


def demo_step_1():
    print("=== Step 1: Domain-separated hash + PRF ===")
    seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    print("seed:", seed.hex())
    print("prf(seed, 'example'):", prf(seed, b"example").hex())
    print("expand(seed, '64-bytes'):", expand(seed, b"demo", 64).hex())


def demo_step_2():
    print("\n=== Step 2: Merkle tree + authentication path ===")
    pub_seed = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    a = b"lesson"
    leaves = [h("LEAF", _u32(i), out_len=N) for i in range(8)]
    tree = merkle_tree(leaves, pub_seed, a)
    root = tree[-1][0]
    idx = 3
    path = merkle_auth_path(tree, idx)
    recomputed = merkle_compute_root(leaves[idx], idx, path, pub_seed, a)
    print("root:", root.hex())
    print("leaf_index:", idx)
    print("auth_path_len:", len(path))
    print("recomputed_root_matches:", recomputed == root)


def demo_step_3():
    print("\n=== Step 3: WOTS+ (toy) ===")
    sk_seed = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    pub_seed = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    a = addr(0, 0, 200) + b"lesson"
    message = b"hello wots"
    mhash = h("XMSS_MSG", message, out_len=N)
    pk = wots_gen_pk(sk_seed, pub_seed, a)
    pkc = wots_pk_compress(pk, pub_seed, a)
    sig = wots_sign(mhash, sk_seed, pub_seed, a)
    ok = wots_verify(mhash, sig, pkc, pub_seed, a)
    print("message:", message)
    print("message_digest:", mhash.hex())
    print("pk_compressed:", pkc.hex())
    print("signature_len_elements:", len(sig))
    print("verify_ok:", ok)


def demo_step_4():
    print("\n=== Step 4: XMSS (toy) ===")
    sk_seed = bytes.fromhex("1112131415161718191a1b1c1d1e1f20")
    pub_seed = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
    a = b"lesson"
    height = 4
    pk = xmss_keygen(sk_seed, pub_seed, height, a)
    message = b"hello xmss"
    sig = xmss_sign(message, sk_seed, pub_seed, height, leaf_index=0, a=a)
    ok = xmss_verify(message, sig, pk, a)
    print("xmss_height:", height)
    print("xmss_root:", pk.root.hex())
    print("signature_leaf_index:", sig.leaf_index)
    print("auth_path_len:", len(sig.auth_path))
    print("verify_ok:", ok)


def demo_step_5():
    print("\n=== Step 5: SPHINCS+ (toy 2-layer hypertree) ===")
    sk_seed = bytes.fromhex("303132333435363738393a3b3c3d3e3f")
    pub_seed = bytes.fromhex("404142434445464748494a4b4c4d4e4f")
    a = b"lesson"
    top_height = 2
    bottom_height = 3
    pk = sphincs_keygen(sk_seed, pub_seed, top_height, bottom_height, a)
    message = b"hello sphincs"
    sig = sphincs_sign(message, sk_seed, pub_seed, top_height, bottom_height, a)
    ok = sphincs_verify(message, sig, pk, a)
    print("public_root:", pk.root.hex())
    print("subtree_index:", sig.subtree_index)
    print("bottom_leaf_index:", sig.bottom_sig.leaf_index)
    print("top_leaf_index:", sig.top_sig.leaf_index)
    print("verify_ok:", ok)


def main():
    demo_step_1()
    demo_step_2()
    demo_step_3()
    demo_step_4()
    demo_step_5()


if __name__ == "__main__":
    main()
