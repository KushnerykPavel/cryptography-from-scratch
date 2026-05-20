"""
Toy STARK-style proof for a Fibonacci trace (AIR + Merkle commitments) — stdlib Python.

This lesson builds a minimal, educational "commit-and-spot-check" STARK-like protocol:
  - a trace table for a computation (Fibonacci)
  - an AIR (boundary + transition constraints)
  - a Merkle commitment to the trace
  - Fiat–Shamir to sample a few random positions
  - Merkle openings + constraint checks at those positions

It is not constant-time and it omits the low-degree test (FRI), so it is not
production-safe.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


P = 2_147_483_647  # 2^31-1 (prime)


def modinv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0")
    return pow(a, p - 2, p)


def hash256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def u64be(x: int) -> bytes:
    if x < 0:
        raise ValueError("u64be expects non-negative")
    if x >= 1 << 64:
        raise ValueError("u64be expects < 2^64")
    return x.to_bytes(8, "big", signed=False)


def hash_leaf(payload: bytes) -> bytes:
    return hash256(b"\x00" + payload)


def hash_node(left: bytes, right: bytes) -> bytes:
    return hash256(b"\x01" + left + right)


def merkle_build(leaf_payloads: Sequence[bytes]) -> List[List[bytes]]:
    if not leaf_payloads:
        raise ValueError("empty tree")
    level = [hash_leaf(p) for p in leaf_payloads]
    levels = [level]
    while len(level) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hash_node(left, right))
        level = nxt
        levels.append(level)
    return levels


def merkle_root(levels: Sequence[Sequence[bytes]]) -> bytes:
    if not levels or not levels[-1]:
        raise ValueError("invalid merkle levels")
    return levels[-1][0]


def merkle_open(levels: Sequence[Sequence[bytes]], index: int) -> List[Tuple[bytes, int]]:
    if index < 0 or index >= len(levels[0]):
        raise IndexError("leaf index out of range")
    path: List[Tuple[bytes, int]] = []
    idx = index
    for level in levels[:-1]:
        is_right = idx & 1
        sib_idx = idx - 1 if is_right else idx + 1
        sibling = level[sib_idx] if sib_idx < len(level) else level[idx]
        path.append((sibling, is_right))
        idx //= 2
    return path


def merkle_verify(root: bytes, leaf_payload: bytes, index: int, path: Sequence[Tuple[bytes, int]]) -> bool:
    acc = hash_leaf(leaf_payload)
    idx = index
    for sibling, is_right in path:
        if is_right:
            acc = hash_node(sibling, acc)
        else:
            acc = hash_node(acc, sibling)
        idx //= 2
    return acc == root


def fs_challenges(root: bytes, n: int, count: int) -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if count < 0:
        raise ValueError("count must be non-negative")
    out: List[int] = []
    ctr = 0
    while len(out) < count:
        digest = hash256(b"fs" + root + u64be(ctr))
        x = int.from_bytes(digest[:8], "big") % n
        if x not in out:
            out.append(x)
        ctr += 1
    return out


def fib_trace(a0: int, a1: int, steps: int, p: int) -> List[Tuple[int, int]]:
    if steps < 2:
        raise ValueError("steps must be >= 2")
    x0 = a0 % p
    x1 = a1 % p
    out: List[Tuple[int, int]] = [(x0, x1)]
    for _ in range(steps - 1):
        x0, x1 = x1, (x0 + x1) % p
        out.append((x0, x1))
    return out


def fib_air_boundary(trace: Sequence[Tuple[int, int]], a0: int, a1: int, p: int) -> bool:
    if not trace:
        return False
    return trace[0][0] % p == a0 % p and trace[0][1] % p == a1 % p


def fib_air_transition_ok(curr: Tuple[int, int], nxt: Tuple[int, int], p: int) -> bool:
    x0, x1 = curr
    y0, y1 = nxt
    if y0 % p != x1 % p:
        return False
    return y1 % p == (x0 + x1) % p


def fib_air_all_transitions(trace: Sequence[Tuple[int, int]], p: int) -> bool:
    return all(fib_air_transition_ok(trace[i], trace[i + 1], p) for i in range(len(trace) - 1))


def trace_row_payload(row: Tuple[int, int]) -> bytes:
    return u64be(row[0]) + u64be(row[1])


@dataclass(frozen=True)
class StarkProof:
    p: int
    steps: int
    a0: int
    a1: int
    root: str
    boundary: dict
    queries: List[dict]


def prove_fib(a0: int, a1: int, steps: int, p: int, query_count: int) -> StarkProof:
    trace = fib_trace(a0, a1, steps, p)
    leaves = [trace_row_payload(r) for r in trace]
    levels = merkle_build(leaves)
    root = merkle_root(levels)
    qs = fs_challenges(root, n=len(trace) - 1, count=query_count)

    row0 = trace[0]
    boundary = {
        "row0": list(row0),
        "path0": [(sib.hex(), side) for sib, side in merkle_open(levels, 0)],
    }

    queries: List[dict] = []
    for i in qs:
        row_i = trace[i]
        row_ip1 = trace[i + 1]
        leaf_i = trace_row_payload(row_i)
        leaf_ip1 = trace_row_payload(row_ip1)
        path_i = [(sib.hex(), side) for sib, side in merkle_open(levels, i)]
        path_ip1 = [(sib.hex(), side) for sib, side in merkle_open(levels, i + 1)]
        queries.append(
            {
                "i": i,
                "row_i": list(row_i),
                "row_ip1": list(row_ip1),
                "path_i": path_i,
                "path_ip1": path_ip1,
            }
        )

    return StarkProof(
        p=p,
        steps=steps,
        a0=a0,
        a1=a1,
        root=root.hex(),
        boundary=boundary,
        queries=queries,
    )


def verify_fib(proof: StarkProof, query_count: int) -> bool:
    if proof.p != P:
        return False
    if proof.steps < 2:
        return False
    root = bytes.fromhex(proof.root)
    if not proof.queries:
        return False

    qs = fs_challenges(root, n=proof.steps - 1, count=query_count)
    if [q["i"] for q in proof.queries] != qs:
        return False

    row0 = (int(proof.boundary["row0"][0]) % proof.p, int(proof.boundary["row0"][1]) % proof.p)
    path0 = [(bytes.fromhex(h), int(side)) for h, side in proof.boundary["path0"]]
    if not merkle_verify(root, trace_row_payload(row0), 0, path0):
        return False
    if not fib_air_boundary([row0], proof.a0, proof.a1, proof.p):
        return False

    for q in proof.queries:
        i = q["i"]
        row_i = (int(q["row_i"][0]) % proof.p, int(q["row_i"][1]) % proof.p)
        row_ip1 = (int(q["row_ip1"][0]) % proof.p, int(q["row_ip1"][1]) % proof.p)

        leaf_i = trace_row_payload(row_i)
        leaf_ip1 = trace_row_payload(row_ip1)
        path_i = [(bytes.fromhex(h), int(side)) for h, side in q["path_i"]]
        path_ip1 = [(bytes.fromhex(h), int(side)) for h, side in q["path_ip1"]]

        if not merkle_verify(root, leaf_i, i, path_i):
            return False
        if not merkle_verify(root, leaf_ip1, i + 1, path_ip1):
            return False
        if not fib_air_transition_ok(row_i, row_ip1, proof.p):
            return False

    return True


def demo_print_trace(trace: Sequence[Tuple[int, int]], rows: int) -> None:
    print("row | x0        | x1")
    print("----+-----------+-----------")
    for i, (x0, x1) in enumerate(trace[:rows]):
        print(f"{i:>3} | {x0:>9} | {x1:>9}")


def main() -> None:
    a0, a1 = 1, 1
    steps = 32
    query_count = 6

    print("=== Step 1: Trace table (Fibonacci) ===")
    trace = fib_trace(a0, a1, steps, P)
    demo_print_trace(trace, rows=8)
    print(f"... ({len(trace)} rows total)")

    print("\n=== Step 2: AIR constraints (boundary + transition) ===")
    ok_boundary = fib_air_boundary(trace, a0, a1, P)
    ok_transitions = fib_air_all_transitions(trace, P)
    print(f"boundary ok:   {ok_boundary}")
    print(f"transitions ok:{ok_transitions}")

    print("\n=== Step 3: Merkle commitment to the trace ===")
    leaves = [trace_row_payload(r) for r in trace]
    levels = merkle_build(leaves)
    root = merkle_root(levels)
    print(f"merkle root: {root.hex()}")
    i = 5
    path = merkle_open(levels, i)
    print(f"open row {i}: row={trace[i]}  path_len={len(path)}  ok={merkle_verify(root, leaves[i], i, path)}")

    print("\n=== Step 4: Fiat–Shamir sampling + spot-check proof ===")
    proof = prove_fib(a0, a1, steps, P, query_count=query_count)
    print("proof summary:")
    print(json.dumps({"root": proof.root, "queries": len(proof.queries)}, indent=2))
    print(f"verify: {verify_fib(proof, query_count=query_count)}")

    print("\n=== Step 5: What this is (and what it is not) ===")
    print("This is a STARK-shaped protocol: trace + AIR + commitments + random queries.")
    print("Missing piece: a low-degree test (FRI) that stops a prover from committing")
    print("to an arbitrary table that passes a few spot checks but is not a low-degree")
    print("polynomial evaluation over a domain. That comes in the FRI lessons.")


if __name__ == "__main__":
    main()
