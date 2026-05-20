"""
Pinocchio (toy) in pure Python: R1CS -> QAP -> divisibility check -> single-point verification.

Run:
  python3 code/main.py

This is an educational, non-cryptographic model of the *algebra* behind Pinocchio-style
pairing-based zkSNARKs. It uses a small prime field and naive polynomial arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse of 0 does not exist")
    return pow(a, p - 2, p)


def _poly_trim(poly: Sequence[int], p: int) -> List[int]:
    out = [c % p for c in poly]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    if not out:
        return [0]
    return out


def poly_add(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return _poly_trim(out, p)


def poly_sub(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % p
    return _poly_trim(out, p)


def poly_scale(a: Sequence[int], k: int, p: int) -> List[int]:
    k %= p
    return _poly_trim([(k * c) % p for c in a], p)


def poly_mul(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    if (len(a) == 1 and a[0] % p == 0) or (len(b) == 1 and b[0] % p == 0):
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        ai %= p
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * (bj % p)) % p
    return _poly_trim(out, p)


def poly_eval(poly: Sequence[int], x: int, p: int) -> int:
    x %= p
    acc = 0
    for c in reversed(poly):
        acc = (acc * x + (c % p)) % p
    return acc


def poly_divmod(numer: Sequence[int], denom: Sequence[int], p: int) -> Tuple[List[int], List[int]]:
    n = _poly_trim(numer, p)
    d = _poly_trim(denom, p)
    if len(d) == 1 and d[0] == 0:
        raise ValueError("division by zero polynomial")

    if len(n) < len(d):
        return [0], list(n)

    num = list(n)
    den_lead_inv = mod_inv(d[-1], p)
    q = [0] * (len(num) - len(d) + 1)
    while len(num) >= len(d) and not (len(num) == 1 and num[0] == 0):
        deg_diff = len(num) - len(d)
        lead = (num[-1] * den_lead_inv) % p
        q[deg_diff] = lead

        for i in range(len(d)):
            num[deg_diff + i] = (num[deg_diff + i] - lead * d[i]) % p
        num = _poly_trim(num, p)

    return _poly_trim(q, p), _poly_trim(num, p)


def poly_from_roots(roots: Iterable[int], p: int) -> List[int]:
    out = [1]
    for r in roots:
        out = poly_mul(out, [(-r) % p, 1], p)
    return _poly_trim(out, p)


def vanishing_poly(num_constraints: int, p: int) -> List[int]:
    return poly_from_roots(range(1, num_constraints + 1), p)


def lagrange_interpolate(points: Sequence[Tuple[int, int]], p: int) -> List[int]:
    if not points:
        raise ValueError("need at least one point")
    xs = [x % p for x, _ in points]
    if len(set(xs)) != len(xs):
        raise ValueError("x coordinates must be distinct")

    out = [0]
    for i, (xi, yi) in enumerate(points):
        xi %= p
        yi %= p
        num = [1]
        denom = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            xj %= p
            num = poly_mul(num, [(-xj) % p, 1], p)
            denom = (denom * (xi - xj)) % p
        out = poly_add(out, poly_scale(num, yi * mod_inv(denom, p), p), p)
    return _poly_trim(out, p)


def _poly_vec_lincomb(polys: Sequence[Sequence[int]], scalars: Sequence[int], p: int) -> List[int]:
    if len(polys) != len(scalars):
        raise ValueError("mismatched lengths")
    out = [0]
    for poly, k in zip(polys, scalars):
        out = poly_add(out, poly_scale(poly, k, p), p)
    return _poly_trim(out, p)


@dataclass(frozen=True)
class R1CS:
    p: int
    A: List[List[int]]
    B: List[List[int]]
    C: List[List[int]]

    def num_constraints(self) -> int:
        return len(self.A)

    def num_variables(self) -> int:
        if not self.A:
            return 0
        return len(self.A[0])


def r1cs_is_satisfied(r1cs: R1CS, witness: Sequence[int]) -> bool:
    p = r1cs.p
    m = r1cs.num_constraints()
    n = r1cs.num_variables()
    if len(witness) != n:
        raise ValueError("witness length mismatch")
    if witness[0] % p != 1:
        raise ValueError("witness[0] must be 1 (constant wire)")

    for i in range(m):
        left = sum((r1cs.A[i][j] % p) * (witness[j] % p) for j in range(n)) % p
        right = sum((r1cs.B[i][j] % p) * (witness[j] % p) for j in range(n)) % p
        out = sum((r1cs.C[i][j] % p) * (witness[j] % p) for j in range(n)) % p
        if (left * right) % p != out:
            return False
    return True


@dataclass(frozen=True)
class QAP:
    p: int
    A_polys: List[List[int]]
    B_polys: List[List[int]]
    C_polys: List[List[int]]
    Z: List[int]

    def num_constraints(self) -> int:
        return len(self.Z) - 1

    def num_variables(self) -> int:
        return len(self.A_polys)


def r1cs_to_qap(r1cs: R1CS) -> QAP:
    p = r1cs.p
    m = r1cs.num_constraints()
    n = r1cs.num_variables()
    xs = list(range(1, m + 1))

    def col_to_poly(col_values: Sequence[int]) -> List[int]:
        points = list(zip(xs, col_values))
        return lagrange_interpolate(points, p)

    A_polys: List[List[int]] = []
    B_polys: List[List[int]] = []
    C_polys: List[List[int]] = []
    for j in range(n):
        A_polys.append(col_to_poly([r1cs.A[i][j] % p for i in range(m)]))
        B_polys.append(col_to_poly([r1cs.B[i][j] % p for i in range(m)]))
        C_polys.append(col_to_poly([r1cs.C[i][j] % p for i in range(m)]))

    return QAP(
        p=p,
        A_polys=A_polys,
        B_polys=B_polys,
        C_polys=C_polys,
        Z=vanishing_poly(m, p),
    )


def qap_abc(qap: QAP, witness: Sequence[int]) -> Tuple[List[int], List[int], List[int]]:
    if len(witness) != qap.num_variables():
        raise ValueError("witness length mismatch")
    p = qap.p
    A = _poly_vec_lincomb(qap.A_polys, witness, p)
    B = _poly_vec_lincomb(qap.B_polys, witness, p)
    C = _poly_vec_lincomb(qap.C_polys, witness, p)
    return A, B, C


def qap_h_and_remainder(qap: QAP, witness: Sequence[int]) -> Tuple[List[int], List[int]]:
    p = qap.p
    A, B, C = qap_abc(qap, witness)
    P = poly_sub(poly_mul(A, B, p), C, p)
    H, R = poly_divmod(P, qap.Z, p)
    return H, R


def qap_is_satisfied(qap: QAP, witness: Sequence[int]) -> bool:
    _, R = qap_h_and_remainder(qap, witness)
    return len(R) == 1 and R[0] % qap.p == 0


@dataclass(frozen=True)
class ToyProof:
    p: int
    s: int
    A_s: int
    B_s: int
    C_s: int
    H_s: int
    Z_s: int


def pinocchio_toy_prove(qap: QAP, witness: Sequence[int], s: int) -> ToyProof:
    p = qap.p
    A, B, C = qap_abc(qap, witness)
    H, R = qap_h_and_remainder(qap, witness)
    if not (len(R) == 1 and R[0] % p == 0):
        raise ValueError("witness does not satisfy QAP; H(x) would have a remainder")

    return ToyProof(
        p=p,
        s=s % p,
        A_s=poly_eval(A, s, p),
        B_s=poly_eval(B, s, p),
        C_s=poly_eval(C, s, p),
        H_s=poly_eval(H, s, p),
        Z_s=poly_eval(qap.Z, s, p),
    )


def pinocchio_toy_verify(proof: ToyProof) -> bool:
    p = proof.p
    lhs = (proof.A_s * proof.B_s - proof.C_s) % p
    rhs = (proof.H_s * proof.Z_s) % p
    return lhs == rhs


def example_r1cs_x3_plus_x_plus_5_eq_35(p: int) -> Tuple[R1CS, List[int]]:
    names = ["1", "x", "out", "x2", "x3", "x3_plus_x"]
    idx = {name: i for i, name in enumerate(names)}

    def lc(**kwargs: int) -> List[int]:
        row = [0] * len(names)
        for k, v in kwargs.items():
            row[idx[k]] = v % p
        return row

    A = [
        lc(x=1),
        lc(x2=1),
        lc(x3=1, x=1),
        lc(x3_plus_x=1, **{"1": 5}),
        lc(out=1),
    ]
    B = [
        lc(x=1),
        lc(x=1),
        lc(**{"1": 1}),
        lc(**{"1": 1}),
        lc(**{"1": 1}),
    ]
    C = [
        lc(x2=1),
        lc(x3=1),
        lc(x3_plus_x=1),
        lc(out=1),
        lc(**{"1": 35}),
    ]

    r1cs = R1CS(p=p, A=A, B=B, C=C)
    x = 3 % p
    x2 = (x * x) % p
    x3 = (x2 * x) % p
    x3_plus_x = (x3 + x) % p
    out = (x3_plus_x + 5) % p
    witness = [1, x, out, x2, x3, x3_plus_x]
    return r1cs, witness


def _fmt_poly(poly: Sequence[int]) -> str:
    return "[" + ", ".join(str(int(c)) for c in poly) + "]"


def main() -> None:
    p = 101

    print("=== Step 1: Field polynomials ===")
    points = [(1, 1), (2, 4), (3, 9)]
    poly = lagrange_interpolate(points, p)
    print("interpolate points:", points)
    print("poly coefficients (low->high):", _fmt_poly(poly))
    print("eval at x=5:", poly_eval(poly, 5, p))
    print()

    print("=== Step 2: R1CS for a toy circuit ===")
    r1cs, witness = example_r1cs_x3_plus_x_plus_5_eq_35(p)
    print("witness [1, x, out, x2, x3, x3_plus_x] =", witness)
    print("R1CS satisfied?", r1cs_is_satisfied(r1cs, witness))
    bad_witness = list(witness)
    bad_witness[1] = (bad_witness[1] + 1) % p
    print("R1CS satisfied with wrong x?", r1cs_is_satisfied(r1cs, bad_witness))
    print()

    print("=== Step 3: R1CS -> QAP (divisibility) ===")
    qap = r1cs_to_qap(r1cs)
    H, R = qap_h_and_remainder(qap, witness)
    print("Z(x) coefficients:", _fmt_poly(qap.Z))
    print("H(x) coefficients:", _fmt_poly(H))
    print("remainder:", _fmt_poly(R))
    print("QAP satisfied?", qap_is_satisfied(qap, witness))
    print("QAP satisfied with wrong x?", qap_is_satisfied(qap, bad_witness))
    print()

    print("=== Step 4: Pinocchio-style single-point check ===")
    s = 42
    proof = pinocchio_toy_prove(qap, witness, s=s)
    print("check at s =", s, ":", pinocchio_toy_verify(proof))

    forged = ToyProof(
        p=p,
        s=s % p,
        A_s=7,
        B_s=9,
        H_s=3,
        Z_s=proof.Z_s,
        C_s=(7 * 9 - 3 * proof.Z_s) % p,
    )
    print("forged proof passes single check?", pinocchio_toy_verify(forged))
    print("note: real Pinocchio adds consistency checks so you can't forge like this.")


if __name__ == "__main__":
    main()
