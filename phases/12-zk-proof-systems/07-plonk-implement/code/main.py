"""
Toy PLONK (no commitments) in pure Python.

This file implements a small, educational subset of PLONK over a tiny prime
field. It is *not* constant-time and it omits polynomial commitments, so it is
not production-safe.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple


def modinv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0")
    return pow(a, p - 2, p)


def is_power_of_two(n: int) -> bool:
    return n > 0 and (n & (n - 1)) == 0


def find_primitive_root(p: int) -> int:
    if p < 3:
        raise ValueError("p must be an odd prime")
    phi = p - 1
    factors: List[int] = []
    x = phi
    f = 2
    while f * f <= x:
        if x % f == 0:
            factors.append(f)
            while x % f == 0:
                x //= f
        f += 1
    if x > 1:
        factors.append(x)

    for g in range(2, p):
        ok = True
        for q in factors:
            if pow(g, phi // q, p) == 1:
                ok = False
                break
        if ok:
            return g
    raise ValueError("no primitive root found")


def primitive_root_of_unity(p: int, n: int) -> int:
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1")
    g = find_primitive_root(p)
    w = pow(g, (p - 1) // n, p)
    if pow(w, n, p) != 1 or pow(w, n // 2, p) == 1:
        raise ValueError("failed to find primitive n-th root of unity")
    return w


def eval_poly(coeffs: Sequence[int], x: int, p: int) -> int:
    acc = 0
    power = 1
    x %= p
    for c in coeffs:
        acc = (acc + (c % p) * power) % p
        power = (power * x) % p
    return acc


def poly_add(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return trim_poly(out, p)


def poly_sub(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % p
    return trim_poly(out, p)


def poly_scale(a: Sequence[int], k: int, p: int) -> List[int]:
    return trim_poly([(k * (c % p)) % p for c in a], p)


def poly_mul(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    if not a or not b:
        return []
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + (ai % p) * (bj % p)) % p
    return trim_poly(out, p)


def trim_poly(a: Sequence[int], p: int) -> List[int]:
    out = list(a)
    while out and out[-1] % p == 0:
        out.pop()
    return out


def lagrange_interpolate(xs: Sequence[int], ys: Sequence[int], p: int) -> List[int]:
    if len(xs) != len(ys):
        raise ValueError("xs and ys length mismatch")
    n = len(xs)
    if n == 0:
        return []

    for i in range(n):
        for j in range(i + 1, n):
            if xs[i] % p == xs[j] % p:
                raise ValueError("duplicate x values")

    result: List[int] = []
    for i in range(n):
        numer = [1]
        denom = 1
        xi = xs[i] % p
        for j in range(n):
            if i == j:
                continue
            xj = xs[j] % p
            numer = poly_mul(numer, [(-xj) % p, 1], p)
            denom = (denom * ((xi - xj) % p)) % p
        li = poly_scale(numer, (ys[i] % p) * modinv(denom, p), p)
        result = poly_add(result, li, p)
    return trim_poly(result, p)


def evals_to_coeffs(domain: Sequence[int], values: Sequence[int], p: int) -> List[int]:
    return lagrange_interpolate(domain, values, p)


def poly_div_xn_minus_1(a: Sequence[int], n: int, p: int) -> Tuple[List[int], List[int]]:
    if n <= 0:
        raise ValueError("n must be positive")
    if not a:
        return [], []
    dividend = [c % p for c in a]
    q = [0] * max(0, len(dividend) - n)
    for i in range(len(dividend) - 1, n - 1, -1):
        lead = dividend[i] % p
        if lead == 0:
            continue
        q_idx = i - n
        q[q_idx] = (q[q_idx] + lead) % p
        dividend[i] = 0
        dividend[q_idx] = (dividend[q_idx] + lead) % p
    r = dividend[:n]
    return trim_poly(q, p), trim_poly(r, p)


def poly_mod_xn_minus_1(a: Sequence[int], n: int, p: int) -> List[int]:
    _, r = poly_div_xn_minus_1(a, n, p)
    out = [0] * n
    for i, c in enumerate(r):
        if i < n:
            out[i] = c % p
    return trim_poly(out, p)


@dataclass(frozen=True)
class Transcript:
    state: bytes = b""

    def absorb_ints(self, label: str, ints: Iterable[int]) -> "Transcript":
        h = hashlib.sha256()
        h.update(self.state)
        h.update(label.encode("utf-8"))
        for v in ints:
            h.update(int(v).to_bytes(32, "big", signed=False))
        return Transcript(h.digest())

    def challenge(self, label: str, p: int) -> Tuple["Transcript", int]:
        t2 = self.absorb_ints(label, [])
        c = int.from_bytes(t2.state, "big") % p
        return t2, c


def build_toy_circuit_witness(p: int, n: int) -> Dict[str, List[int]]:
    if n < 3:
        raise ValueError("need n>=3 for this toy circuit")
    x = 3 % p
    y = 11 % p
    z = (x * y) % p
    t = (z + x) % p
    u = (t + 5) % p

    a = [0] * n
    b = [0] * n
    c = [0] * n

    a[0], b[0], c[0] = x, y, z
    a[1], b[1], c[1] = z, x, t
    a[2], b[2], c[2] = t, 5 % p, u

    ql = [0] * n
    qr = [0] * n
    qm = [0] * n
    qo = [0] * n
    qc = [0] * n

    ql[1], qr[1], qo[1] = 1, 1, (-1) % p
    ql[2], qr[2], qo[2] = 1, 1, (-1) % p
    qm[0], qo[0] = 1, (-1) % p

    return {
        "a": a,
        "b": b,
        "c": c,
        "ql": ql,
        "qr": qr,
        "qm": qm,
        "qo": qo,
        "qc": qc,
        "public_u": [u],
    }


def derive_permutation_mapping(n: int) -> List[int]:
    perm = list(range(3 * n))

    def swap(pos1: int, pos2: int) -> None:
        perm[pos1], perm[pos2] = perm[pos2], perm[pos1]

    swap(0 * n + 0, 1 * n + 1)
    swap(2 * n + 0, 0 * n + 1)
    swap(2 * n + 1, 0 * n + 2)
    return perm


def compute_grand_product_z(
    a: Sequence[int],
    b: Sequence[int],
    c: Sequence[int],
    perm: Sequence[int],
    beta: int,
    gamma: int,
    roots: Sequence[int],
    p: int,
) -> List[int]:
    n = len(roots)
    if not (len(a) == len(b) == len(c) == n):
        raise ValueError("witness length must equal domain size")
    if len(perm) != 3 * n:
        raise ValueError("perm length must be 3n")

    id_pos = [(wire, i) for wire in range(3) for i in range(n)]
    z = [0] * (n + 1)
    z[0] = 1

    for i in range(n):
        num = 1
        den = 1
        for wire in range(3):
            v = [a, b, c][wire][i] % p
            x_id = roots[i] * (wire + 1) % p

            w2, j2 = id_pos[perm[wire * n + i]]
            x_sigma = roots[j2] * (w2 + 1) % p

            num = (num * ((v + beta * x_id + gamma) % p)) % p
            den = (den * ((v + beta * x_sigma + gamma) % p)) % p
        z[i + 1] = (z[i] * num * modinv(den, p)) % p

    return z


def check_gate_constraints(
    witness: Dict[str, List[int]], roots: Sequence[int], p: int
) -> bool:
    a = witness["a"]
    b = witness["b"]
    c = witness["c"]
    ql = witness["ql"]
    qr = witness["qr"]
    qm = witness["qm"]
    qo = witness["qo"]
    qc = witness["qc"]

    n = len(roots)
    for i in range(n):
        lhs = (
            ql[i] * a[i]
            + qr[i] * b[i]
            + qm[i] * a[i] * b[i]
            + qo[i] * c[i]
            + qc[i]
        ) % p
        if lhs != 0:
            return False
    return True


def check_permutation_constraints(
    witness: Dict[str, List[int]],
    perm: Sequence[int],
    roots: Sequence[int],
    beta: int,
    gamma: int,
    p: int,
) -> bool:
    a = witness["a"]
    b = witness["b"]
    c = witness["c"]
    z = compute_grand_product_z(a, b, c, perm, beta, gamma, roots, p)
    if z[0] % p != 1 or z[-1] % p != 1:
        return False

    n = len(roots)
    id_pos = [(wire, i) for wire in range(3) for i in range(n)]

    for i in range(n):
        num = 1
        den = 1
        for wire in range(3):
            v = [a, b, c][wire][i] % p
            x_id = roots[i] * (wire + 1) % p
            w2, j2 = id_pos[perm[wire * n + i]]
            x_sigma = roots[j2] * (w2 + 1) % p
            num = (num * ((v + beta * x_id + gamma) % p)) % p
            den = (den * ((v + beta * x_sigma + gamma) % p)) % p

        if (z[i + 1] * den - z[i] * num) % p != 0:
            return False
    return True


def prove_and_verify_toy_plonk(p: int, n: int) -> bool:
    if not is_power_of_two(n):
        raise ValueError("n must be a power of two")
    w = primitive_root_of_unity(p, n)
    roots = [pow(w, i, p) for i in range(n)]

    witness = build_toy_circuit_witness(p, n)

    perm = derive_permutation_mapping(n)
    transcript = Transcript()
    transcript = transcript.absorb_ints("witness_a", witness["a"])
    transcript = transcript.absorb_ints("witness_b", witness["b"])
    transcript = transcript.absorb_ints("witness_c", witness["c"])
    transcript = transcript.absorb_ints("selectors", witness["ql"] + witness["qr"] + witness["qm"])
    transcript = transcript.absorb_ints("perm", perm)

    transcript, beta = transcript.challenge("beta", p)
    transcript, gamma = transcript.challenge("gamma", p)

    gates_ok = check_gate_constraints(witness, roots, p)
    perm_ok = check_permutation_constraints(witness, perm, roots, beta, gamma, p)
    return gates_ok and perm_ok


def main() -> None:
    p = 97
    n = 8

    print("=== Step 1: Field arithmetic ===")
    w = primitive_root_of_unity(p, n)
    print(f"p={p}, n={n}, primitive n-th root w={w}, w^n mod p={pow(w, n, p)}")

    print("=== Step 2: Polynomials ===")
    poly = [5, 7, 2]
    x = 11
    print(f"f(x)=5+7x+2x^2, f({x}) mod p = {eval_poly(poly, x, p)}")

    print("=== Step 3: Circuit as gate constraints ===")
    witness = build_toy_circuit_witness(p, n)
    print(f"public u = {witness['public_u'][0]}")
    roots = [pow(w, i, p) for i in range(n)]
    print(f"gate constraints satisfied? {check_gate_constraints(witness, roots, p)}")

    print("=== Step 4: Permutation argument (copy constraints) ===")
    perm = derive_permutation_mapping(n)
    beta, gamma = 7, 13
    z = compute_grand_product_z(
        witness["a"], witness["b"], witness["c"], perm, beta, gamma, roots, p
    )
    print(f"Z values (beta={beta}, gamma={gamma}): {z}")
    print(
        f"permutation constraints satisfied? {check_permutation_constraints(witness, perm, roots, beta, gamma, p)}"
    )

    print("=== Step 5: Fiat–Shamir transcript (toy prover/verifier) ===")
    ok = prove_and_verify_toy_plonk(p, n)
    print(f"prove+verify ok? {ok}")


if __name__ == "__main__":
    main()
