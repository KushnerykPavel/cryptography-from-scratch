"""
Merkle trees from scratch (SHA-256).

This script builds Merkle roots and inclusion proofs using a simple,
deterministic "duplicate-last" rule for odd node counts.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Iterable, Sequence


LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _u32be(n: int) -> bytes:
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("n out of range for u32")
    return struct.pack(">I", n)


def sha256(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    return hashlib.sha256(bytes(data)).digest()


def sha256_hex(data: bytes) -> str:
    return sha256(data).hex()


def encode_leaf_value(*, value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("value must be bytes-like")
    v = bytes(value)
    return _u32be(len(v)) + v


def hash_leaf(*, value: bytes) -> bytes:
    return sha256(LEAF_PREFIX + encode_leaf_value(value=value))


def hash_node(*, left: bytes, right: bytes) -> bytes:
    if not isinstance(left, (bytes, bytearray, memoryview)):
        raise TypeError("left must be bytes-like")
    if not isinstance(right, (bytes, bytearray, memoryview)):
        raise TypeError("right must be bytes-like")
    return sha256(NODE_PREFIX + bytes(left) + bytes(right))


def build_merkle_levels(*, leaves: Sequence[bytes]) -> list[list[bytes]]:
    if not isinstance(leaves, Sequence):
        raise TypeError("leaves must be a sequence")
    if len(leaves) == 0:
        raise ValueError("leaves must be non-empty")

    level0 = [hash_leaf(value=v) for v in leaves]
    levels: list[list[bytes]] = [level0]

    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt: list[bytes] = []
        i = 0
        while i < len(cur):
            left = cur[i]
            if i + 1 < len(cur):
                right = cur[i + 1]
            else:
                right = cur[i]
            nxt.append(hash_node(left=left, right=right))
            i += 2
        levels.append(nxt)

    return levels


def merkle_root(*, leaves: Sequence[bytes]) -> bytes:
    return build_merkle_levels(leaves=leaves)[-1][0]


def merkle_root_hex(*, leaves: Sequence[bytes]) -> str:
    return merkle_root(leaves=leaves).hex()


def merkle_proof(*, leaves: Sequence[bytes], index: int) -> list[tuple[str, bytes]]:
    if not isinstance(index, int):
        raise TypeError("index must be int")
    if index < 0:
        raise ValueError("index must be non-negative")
    if index >= len(leaves):
        raise ValueError("index out of range")

    levels = build_merkle_levels(leaves=leaves)
    proof: list[tuple[str, bytes]] = []
    idx = index

    for level in levels[:-1]:
        if idx % 2 == 0:
            sib_idx = idx + 1
            if sib_idx >= len(level):
                sibling = level[idx]
            else:
                sibling = level[sib_idx]
            proof.append(("right", sibling))
        else:
            sibling = level[idx - 1]
            proof.append(("left", sibling))
        idx //= 2

    return proof


def verify_merkle_proof(
    *,
    leaf_value: bytes,
    proof: Sequence[tuple[str, bytes]],
    root: bytes,
) -> bool:
    if not isinstance(proof, Sequence):
        raise TypeError("proof must be a sequence")
    if not isinstance(root, (bytes, bytearray, memoryview)):
        raise TypeError("root must be bytes-like")

    cur = hash_leaf(value=leaf_value)
    for side, sibling in proof:
        if side not in ("left", "right"):
            raise ValueError("proof side must be 'left' or 'right'")
        if not isinstance(sibling, (bytes, bytearray, memoryview)):
            raise TypeError("proof sibling must be bytes-like")
        sib = bytes(sibling)
        if side == "left":
            cur = hash_node(left=sib, right=cur)
        else:
            cur = hash_node(left=cur, right=sib)

    return hmac.compare_digest(cur, bytes(root))


def _print_step(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def _as_bytes_list(values: Iterable[str]) -> list[bytes]:
    return [v.encode("utf-8") for v in values]


def step1_hashing_conventions() -> None:
    _print_step(1, "Hash leaves and nodes (domain separation)")
    leaf = b"hello"
    leaf_h = hash_leaf(value=leaf)
    print(f"leaf value: {leaf!r}")
    print(f"leaf hash:  {leaf_h.hex()}")

    left = leaf_h
    right = hash_leaf(value=b"world")
    node_h = hash_node(left=left, right=right)
    print(f"node hash:  {node_h.hex()}")


def step2_build_tree_and_root() -> None:
    _print_step(2, "Build the tree and compute the root")
    leaves = _as_bytes_list(["tx0", "tx1", "tx2", "tx3", "tx4"])
    root = merkle_root(leaves=leaves)
    print(f"leaves (n={len(leaves)}): {[v.decode('utf-8') for v in leaves]}")
    print(f"merkle root: {root.hex()}")


def step3_make_inclusion_proof() -> tuple[list[bytes], int, bytes, list[tuple[str, bytes]]]:
    _print_step(3, "Create an inclusion proof")
    leaves = _as_bytes_list(["tx0", "tx1", "tx2", "tx3", "tx4"])
    index = 2
    root = merkle_root(leaves=leaves)
    proof = merkle_proof(leaves=leaves, index=index)
    print(f"prove leaf[{index}] = {leaves[index]!r}")
    for i, (side, sib) in enumerate(proof, start=1):
        print(f"  step {i}: sibling on {side}: {sib.hex()}")
    return leaves, index, root, proof


def step4_verify_inclusion_proof(
    *,
    leaves: Sequence[bytes],
    index: int,
    root: bytes,
    proof: Sequence[tuple[str, bytes]],
) -> None:
    _print_step(4, "Verify an inclusion proof")
    ok = verify_merkle_proof(leaf_value=leaves[index], proof=proof, root=root)
    print(f"verify: {ok}")

    tampered_leaf = b"tx2!"
    ok2 = verify_merkle_proof(leaf_value=tampered_leaf, proof=proof, root=root)
    print(f"verify with tampered leaf: {ok2}")

    bad_proof = list(proof)
    bad_side, bad_sib = bad_proof[0]
    bad_proof[0] = (bad_side, bytes([bad_sib[0] ^ 1]) + bad_sib[1:])
    ok3 = verify_merkle_proof(leaf_value=leaves[index], proof=bad_proof, root=root)
    print(f"verify with tampered proof: {ok3}")


def main() -> None:
    step1_hashing_conventions()
    print()
    step2_build_tree_and_root()
    print()
    leaves, index, root, proof = step3_make_inclusion_proof()
    print()
    step4_verify_inclusion_proof(leaves=leaves, index=index, root=root, proof=proof)


if __name__ == "__main__":
    main()
