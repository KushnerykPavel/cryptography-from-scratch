"""
Merkle-based vector commitments (VCs): commit to an ordered list of values and later
open a single position with a short proof.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


Hash32 = bytes
ProofStep = Tuple[str, Hash32]  # ("L" | "R", sibling_hash)


def sha256(data: bytes) -> Hash32:
    return hashlib.sha256(data).digest()


def u32be(n: int) -> bytes:
    if not (0 <= n < 2**32):
        raise ValueError("u32 out of range")
    return n.to_bytes(4, "big")


def _require_bytes_seq(values: Sequence[bytes]) -> None:
    for v in values:
        if not isinstance(v, (bytes, bytearray)):
            raise TypeError("values must be a sequence of bytes-like objects")


def leaf_hash(index: int, value: bytes) -> Hash32:
    if index < 0:
        raise ValueError("index must be non-negative")
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes-like")
    v = bytes(value)
    payload = b"VC:leaf" + u32be(index) + u32be(len(v)) + v
    return sha256(payload)


def node_hash(left: Hash32, right: Hash32) -> Hash32:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("node children must be 32-byte hashes")
    return sha256(b"VC:node" + left + right)


def merkle_levels(leaf_hashes: Sequence[Hash32]) -> List[List[Hash32]]:
    if len(leaf_hashes) == 0:
        raise ValueError("cannot build Merkle tree for empty list")
    for h in leaf_hashes:
        if len(h) != 32:
            raise ValueError("leaf hashes must be 32 bytes")

    levels: List[List[Hash32]] = [list(leaf_hashes)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt: List[Hash32] = []
        i = 0
        while i < len(cur):
            left = cur[i]
            right = cur[i + 1] if i + 1 < len(cur) else cur[i]
            nxt.append(node_hash(left, right))
            i += 2
        levels.append(nxt)
    return levels


def merkle_root(leaf_hashes: Sequence[Hash32]) -> Hash32:
    return merkle_levels(leaf_hashes)[-1][0]


def vector_commit(values: Sequence[bytes]) -> Hash32:
    _require_bytes_seq(values)
    n = len(values)
    if n == 0:
        raise ValueError("cannot commit to empty vector")

    leaves = [leaf_hash(i, v) for i, v in enumerate(values)]
    root = merkle_root(leaves)
    return sha256(b"VC:root" + u32be(n) + root)


def vector_open(values: Sequence[bytes], index: int) -> Tuple[Hash32, List[ProofStep]]:
    _require_bytes_seq(values)
    n = len(values)
    if not (0 <= index < n):
        raise IndexError("index out of range")

    leaves = [leaf_hash(i, v) for i, v in enumerate(values)]
    levels = merkle_levels(leaves)

    proof: List[ProofStep] = []
    i = index
    for level in levels[:-1]:
        if i % 2 == 0:
            sib_index = i + 1
            sibling = level[sib_index] if sib_index < len(level) else level[i]
            proof.append(("R", sibling))
        else:
            sibling = level[i - 1]
            proof.append(("L", sibling))
        i //= 2

    root = sha256(b"VC:root" + u32be(n) + levels[-1][0])
    return root, proof


def vector_verify(root: Hash32, index: int, value: bytes, proof: Iterable[ProofStep], n: int) -> bool:
    if len(root) != 32:
        raise ValueError("root must be a 32-byte hash")
    if not (0 <= index < n):
        return False
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("value must be bytes-like")

    acc = leaf_hash(index, bytes(value))
    i = index
    for side, sibling in proof:
        if side not in ("L", "R"):
            raise ValueError("proof side must be 'L' or 'R'")
        if len(sibling) != 32:
            raise ValueError("proof hash must be 32 bytes")

        if side == "L":
            acc = node_hash(sibling, acc)
        else:
            acc = node_hash(acc, sibling)
        i //= 2

    computed = sha256(b"VC:root" + u32be(n) + acc)
    return computed == root


@dataclass(frozen=True)
class Opened:
    root: Hash32
    index: int
    value: bytes
    proof: List[ProofStep]
    n: int


def _h(h: Hash32) -> str:
    return h.hex()


def _step(title: str) -> None:
    print(f"=== {title} ===")


def main() -> None:
    values = [b"alice", b"bob", b"carol", b"dave", b"erin"]

    _step("Step 1: Domain-separated leaf hashing (bind index + value)")
    for i, v in enumerate(values[:3]):
        print(f"leaf_hash({i}, {v!r}) = {_h(leaf_hash(i, v))}")
    print()

    _step("Step 2: Merkle tree building (hash pairs upward)")
    leaves = [leaf_hash(i, v) for i, v in enumerate(values)]
    mroot = merkle_root(leaves)
    print(f"n={len(values)}")
    print(f"merkle_root = {_h(mroot)}")
    print()

    _step("Step 3: Commit to the vector (length-bound root)")
    root = vector_commit(values)
    print("commit = H('VC:root' || n || merkle_root)")
    print(f"commitment_root = {_h(root)}")
    print()

    _step("Step 4: Open and verify one index")
    index = 2
    root2, proof = vector_open(values, index=index)
    opened = Opened(root=root2, index=index, value=values[index], proof=proof, n=len(values))
    assert opened.root == root
    print(f"open index={opened.index} value={opened.value!r}")
    print(f"proof_len={len(opened.proof)}")
    ok = vector_verify(opened.root, opened.index, opened.value, opened.proof, opened.n)
    print(f"verify(open) = {ok}")
    print()

    print("-- tampering / updates --")
    bad_value = b"car0l"
    ok_bad_value = vector_verify(opened.root, opened.index, bad_value, opened.proof, opened.n)
    print(f"verify(wrong value) = {ok_bad_value}")

    tampered = list(opened.proof)
    side0, h0 = tampered[0]
    tampered[0] = (side0, sha256(b"tamper" + h0))
    ok_tampered = vector_verify(opened.root, opened.index, opened.value, tampered, opened.n)
    print(f"verify(tampered proof) = {ok_tampered}")

    updated = list(values)
    updated[index] = b"CAROL"
    new_root = vector_commit(updated)
    ok_old_under_new = vector_verify(new_root, opened.index, opened.value, opened.proof, opened.n)
    print(f"new_root = {_h(new_root)}")
    print(f"verify(old opening under new root) = {ok_old_under_new}")


if __name__ == "__main__":
    main()
