"""Proof aggregation & recursion: toy commitments, Merkle roots, segment folding.

This lesson implements minimal, stdlib-only building blocks that mirror real
systems:
- bind "proofs" to a statement via domain-separated hashes
- aggregate many proofs by committing to their digests in a Merkle root
- recursively fold sequential step proofs into one segment proof

Run: python3 code/main.py
"""

from dataclasses import dataclass
import hashlib
import json
import math


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def u32be(n):
    if n < 0 or n >= 2**32:
        raise ValueError("u32 out of range")
    return int(n).to_bytes(4, "big")


def tagged_hash(tag, *parts):
    h = hashlib.sha256()
    h.update(tag.encode("utf-8"))
    h.update(b"\x00")
    for p in parts:
        if not isinstance(p, (bytes, bytearray)):
            raise TypeError("tagged_hash parts must be bytes")
        h.update(u32be(len(p)))
        h.update(p)
    return h.digest()


def tagged_hash_hex(tag, *parts):
    return tagged_hash(tag, *parts).hex()


def state_step(start_state_hex, message):
    start = bytes.fromhex(start_state_hex)
    msg = message.encode("utf-8")
    return tagged_hash_hex("state.step.v1", start, msg)


@dataclass(frozen=True)
class StepProof:
    start_state_hex: str
    message: str
    end_state_hex: str
    digest_hex: str


def prove_step(start_state_hex, message):
    end_state_hex = state_step(start_state_hex, message)
    digest_hex = tagged_hash_hex(
        "proof.step.v1",
        bytes.fromhex(start_state_hex),
        message.encode("utf-8"),
        bytes.fromhex(end_state_hex),
    )
    return StepProof(
        start_state_hex=start_state_hex,
        message=message,
        end_state_hex=end_state_hex,
        digest_hex=digest_hex,
    )


def verify_step(proof):
    if not isinstance(proof, StepProof):
        return False
    expected_end = state_step(proof.start_state_hex, proof.message)
    if expected_end != proof.end_state_hex:
        return False
    expected_digest = tagged_hash_hex(
        "proof.step.v1",
        bytes.fromhex(proof.start_state_hex),
        proof.message.encode("utf-8"),
        bytes.fromhex(proof.end_state_hex),
    )
    return expected_digest == proof.digest_hex


def merkle_leaf_hash(leaf_bytes):
    if not isinstance(leaf_bytes, (bytes, bytearray)):
        raise TypeError("leaf must be bytes")
    return sha256(b"\x00" + bytes(leaf_bytes))


def merkle_node_hash(left, right):
    return sha256(b"\x01" + left + right)


def merkle_root(leaf_bytes_list):
    if len(leaf_bytes_list) == 0:
        return sha256(b"")
    level = [merkle_leaf_hash(b) for b in leaf_bytes_list]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(merkle_node_hash(level[i], level[i + 1]))
        level = nxt
    return level[0]


def merkle_inclusion_proof(leaf_bytes_list, index):
    if index < 0 or index >= len(leaf_bytes_list):
        raise IndexError("leaf index out of range")
    level = [merkle_leaf_hash(b) for b in leaf_bytes_list]
    idx = index
    proof = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        sibling_idx = idx ^ 1
        sibling = level[sibling_idx]
        side = "L" if sibling_idx < idx else "R"
        proof.append((side, sibling))
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(merkle_node_hash(level[i], level[i + 1]))
        level = nxt
        idx //= 2
    return proof


def verify_merkle_inclusion(leaf_bytes, index, proof, expected_root):
    h = merkle_leaf_hash(leaf_bytes)
    idx = index
    for side, sib in proof:
        if side == "L":
            h = merkle_node_hash(sib, h)
        elif side == "R":
            h = merkle_node_hash(h, sib)
        else:
            return False
        idx //= 2
    return h == expected_root


@dataclass(frozen=True)
class SegmentProof:
    start_state_hex: str
    end_state_hex: str
    step_count: int
    commitment_root_hex: str
    digest_hex: str


def prove_segment(step_proofs):
    if len(step_proofs) == 0:
        raise ValueError("segment needs at least 1 step")
    for p in step_proofs:
        if not verify_step(p):
            raise ValueError("invalid step proof in segment")
    for a, b in zip(step_proofs, step_proofs[1:]):
        if a.end_state_hex != b.start_state_hex:
            raise ValueError("segment is not sequentially linked")
    leaves = [bytes.fromhex(p.digest_hex) for p in step_proofs]
    root = merkle_root(leaves).hex()
    start_state_hex = step_proofs[0].start_state_hex
    end_state_hex = step_proofs[-1].end_state_hex
    step_count = len(step_proofs)
    digest_hex = tagged_hash_hex(
        "proof.segment.v1",
        bytes.fromhex(start_state_hex),
        bytes.fromhex(end_state_hex),
        u32be(step_count),
        bytes.fromhex(root),
    )
    return SegmentProof(
        start_state_hex=start_state_hex,
        end_state_hex=end_state_hex,
        step_count=step_count,
        commitment_root_hex=root,
        digest_hex=digest_hex,
    )


def verify_segment(segment, step_proofs):
    if not isinstance(segment, SegmentProof):
        return False
    if len(step_proofs) != segment.step_count:
        return False
    try:
        expected = prove_segment(step_proofs)
    except Exception:
        return False
    return expected == segment


def fold_two_segments(left, right):
    if left.end_state_hex != right.start_state_hex:
        raise ValueError("segments are not sequentially linked")
    combined_root = merkle_root([bytes.fromhex(left.digest_hex), bytes.fromhex(right.digest_hex)]).hex()
    step_count = left.step_count + right.step_count
    digest_hex = tagged_hash_hex(
        "proof.segment_fold.v1",
        bytes.fromhex(left.start_state_hex),
        bytes.fromhex(right.end_state_hex),
        u32be(step_count),
        bytes.fromhex(combined_root),
        bytes.fromhex(left.digest_hex),
        bytes.fromhex(right.digest_hex),
    )
    return SegmentProof(
        start_state_hex=left.start_state_hex,
        end_state_hex=right.end_state_hex,
        step_count=step_count,
        commitment_root_hex=combined_root,
        digest_hex=digest_hex,
    )


def fold_segments_binary(segments):
    if len(segments) == 0:
        raise ValueError("need at least 1 segment")
    level = list(segments)
    while len(level) > 1:
        nxt = []
        i = 0
        while i + 1 < len(level):
            nxt.append(fold_two_segments(level[i], level[i + 1]))
            i += 2
        if i < len(level):
            nxt.append(level[i])
        level = nxt
    return level[0]


def main():
    genesis = sha256_hex(b"genesis")
    messages = ["tx: alice->bob 3", "tx: bob->carol 1", "tx: carol->dave 2", "tx: dave->alice 1", "tx: fee 1"]

    print("=== Step 1: Statement binding with tagged hashes ===")
    p0 = prove_step(genesis, messages[0])
    print(f"start_state: {p0.start_state_hex[:16]}..")
    print(f"message:     {p0.message}")
    print(f"end_state:   {p0.end_state_hex[:16]}..")
    print(f"proof_digest:{p0.digest_hex[:16]}..")
    print(f"verifies:    {verify_step(p0)}")

    print()
    print("=== Step 2: Batch aggregation with a Merkle root ===")
    proofs = []
    state = genesis
    for m in messages:
        p = prove_step(state, m)
        proofs.append(p)
        state = p.end_state_hex
    leaves = [bytes.fromhex(p.digest_hex) for p in proofs]
    root = merkle_root(leaves)
    idx = 2
    mp = merkle_inclusion_proof(leaves, idx)
    ok = verify_merkle_inclusion(leaves[idx], idx, mp, root)
    print(f"proofs: {len(proofs)}  merkle_root: {root.hex()[:16]}..")
    print(f"inclusion proof for index {idx}: path_len={len(mp)} verifies={ok}")

    print()
    print("=== Step 3: Recursion as 'segment proofs' over sequential steps ===")
    seg = prove_segment(proofs)
    print(f"segment start: {seg.start_state_hex[:16]}..")
    print(f"segment end:   {seg.end_state_hex[:16]}..")
    print(f"steps:         {seg.step_count}")
    print(f"commitment:    {seg.commitment_root_hex[:16]}..")
    print(f"digest:        {seg.digest_hex[:16]}..")
    print(f"verifies:      {verify_segment(seg, proofs)}")

    print()
    print("=== Step 4: Aggregation topology (binary fold depth) ===")
    chunk = 2
    segments = []
    for i in range(0, len(proofs), chunk):
        segments.append(prove_segment(proofs[i : i + chunk]))
    folded = fold_segments_binary(segments)
    depth = int(math.ceil(math.log2(len(segments)))) if len(segments) > 1 else 0
    print(f"chunks: {len(segments)} (size {chunk})  fold_depth≈{depth}  final_digest: {folded.digest_hex[:16]}..")


if __name__ == "__main__":
    main()
