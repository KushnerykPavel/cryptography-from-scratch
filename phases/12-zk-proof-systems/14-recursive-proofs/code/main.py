"""Recursive Proofs / IVC (Incrementally Verifiable Computation) — toy model.

One proof that verifies another — O(1) size regardless of steps.

Run: python3 code/main.py
"""

import hashlib
from typing import Tuple

# Goldilocks prime: 2^64 - 2^32 + 1
MODULUS = 18446744069414584321


# ---------------------------------------------------------------------------
# Core primitives
# ---------------------------------------------------------------------------

def fhash(*vals: int, p: int = MODULUS) -> int:
    """Hash field elements into F_p.

    data = concat of each val as 8 big-endian bytes.
    return int.from_bytes(sha256(data).digest(), 'big') % p
    """
    data = b"".join(int(v).to_bytes(8, "big") for v in vals)
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % p


def step_fn(z: int, a: int, b: int, c: int, p: int = MODULUS) -> int:
    """F(z) = (a*z*z + b*z + c) % p"""
    return (a * z * z + b * z + c) % p


# ---------------------------------------------------------------------------
# IVC core
# ---------------------------------------------------------------------------

def ivc_init(z0: int, p: int = MODULUS) -> Tuple[int, int, int]:
    """Return (0, z0, fhash(0, z0, 0, p=p))."""
    acc = fhash(0, z0, 0, p=p)
    return (0, z0, acc)


def ivc_extend(proof: Tuple[int, int, int], a: int, b: int, c: int, p: int = MODULUS) -> Tuple[int, int, int]:
    """Given (n, zn, acc), return (n+1, F(zn), fhash(n+1, F(zn), acc, p=p)). O(1)."""
    n, zn, acc = proof
    zn1 = step_fn(zn, a, b, c, p=p)
    n1 = n + 1
    new_acc = fhash(n1, zn1, acc, p=p)
    return (n1, zn1, new_acc)


def ivc_verify_step(prev: Tuple[int, int, int], curr: Tuple[int, int, int], a: int, b: int, c: int, p: int = MODULUS) -> bool:
    """Check curr extends prev by one valid F step. O(1)."""
    n, zn, acc = prev
    n1, zn1, acc1 = curr
    if n1 != n + 1:
        return False
    if zn1 != step_fn(zn, a, b, c, p=p):
        return False
    if acc1 != fhash(n1, zn1, acc, p=p):
        return False
    return True


def ivc_verify_full(z0: int, proof: Tuple[int, int, int], a: int, b: int, c: int, p: int = MODULUS) -> bool:
    """Rebuild accumulator from z0 in O(n) and compare to proof. Returns bool."""
    n, zn, acc = proof
    # Replay the chain from z0
    curr = ivc_init(z0, p=p)
    for _ in range(n):
        curr = ivc_extend(curr, a, b, c, p=p)
    return curr == proof


def proof_size(proof: Tuple[int, int, int]) -> int:
    """Return 3 (always — n, zn, acc)."""
    return 3


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main():
    a, b, c, z0 = 2, 3, 7, 5

    print("=== Step 1: step function and trace (a=2, b=3, c=7, z0=5) ===")
    z = z0
    trace = [z]
    for i in range(8):
        z = step_fn(z, a, b, c)
        trace.append(z)
    print(f"  F(z) = {a}*z^2 + {b}*z + {c}  over Goldilocks prime p={MODULUS}")
    print(f"  trace (9 values): {trace[:9]}")
    print(f"  trace[0]={trace[0]}  trace[1]={trace[1]}  trace[2]={trace[2]}")

    print()
    print("=== Step 2: build IVC proof incrementally (8 steps) ===")
    proof = ivc_init(z0)
    print(f"  ivc_init(z0={z0}) -> (n={proof[0]}, zn={proof[1]}, acc={proof[2]})")
    for i in range(8):
        proof = ivc_extend(proof, a, b, c)
    n, zn, acc = proof
    print(f"  after 8 steps: n={n}, zn={zn}")
    print(f"  acc (hash accumulator) = {acc}")
    print(f"  proof_size = {proof_size(proof)} elements (always O(1) regardless of n)")

    print()
    print("=== Step 3: step verification O(1) per step ===")
    # Rebuild chain to verify step 3 -> 4
    p0 = ivc_init(z0)
    for _ in range(3):
        p0 = ivc_extend(p0, a, b, c)
    p1 = ivc_extend(p0, a, b, c)
    ok = ivc_verify_step(p0, p1, a, b, c)
    print(f"  verify_step(step3 -> step4): {ok}")
    # Tampered step state
    p_bad = (p1[0], p1[1] + 1, p1[2])
    ok_bad = ivc_verify_step(p0, p_bad, a, b, c)
    print(f"  verify_step with tampered zn+1: {ok_bad}")
    # Wrong accumulator
    p_bad_acc = (p1[0], p1[1], (p1[2] + 1) % MODULUS)
    ok_bad_acc = ivc_verify_step(p0, p_bad_acc, a, b, c)
    print(f"  verify_step with tampered acc: {ok_bad_acc}")

    print()
    print("=== Step 4: full verification O(n) ===")
    full_proof = ivc_init(z0)
    for _ in range(8):
        full_proof = ivc_extend(full_proof, a, b, c)
    ok_full = ivc_verify_full(z0, full_proof, a, b, c)
    print(f"  ivc_verify_full(z0={z0}, 8-step proof): {ok_full}")
    # Wrong z0
    ok_wrong_z0 = ivc_verify_full(z0 + 1, full_proof, a, b, c)
    print(f"  ivc_verify_full(z0={z0+1}, same proof): {ok_wrong_z0}")

    print()
    print("=== Step 5: tampered proof rejection ===")
    tampered = (full_proof[0], full_proof[1], (full_proof[2] + 1) % MODULUS)
    ok_tampered_full = ivc_verify_full(z0, tampered, a, b, c)
    print(f"  verify_full with tampered acc: {ok_tampered_full}")
    tampered_zn = (full_proof[0], (full_proof[1] + 1) % MODULUS, full_proof[2])
    ok_tampered_zn = ivc_verify_full(z0, tampered_zn, a, b, c)
    print(f"  verify_full with tampered zn: {ok_tampered_zn}")
    tampered_n = (full_proof[0] + 1, full_proof[1], full_proof[2])
    ok_tampered_n = ivc_verify_full(z0, tampered_n, a, b, c)
    print(f"  verify_full with tampered n: {ok_tampered_n}")


if __name__ == "__main__":
    main()
