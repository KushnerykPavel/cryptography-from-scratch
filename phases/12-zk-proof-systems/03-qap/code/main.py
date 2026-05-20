"""
QAP — Quadratic Arithmetic Programs (toy, educational).

This script:
1) implements tiny prime-field + polynomial arithmetic,
2) builds Lagrange-interpolated polynomials from per-constraint values,
3) converts a small R1CS instance into a QAP, and
4) checks the core QAP property: t(x) divides A(x)B(x) - C(x) for a valid witness.

Run:
  python3 phases/12-zk-proof-systems/03-qap/code/main.py
"""

from __future__ import annotations

import sys
from typing import Iterable, List, Sequence, Tuple


Poly = List[int]  # coefficients low->high (a0 + a1*x + a2*x^2 + ...)


def modp(x: int, p: int) -> int:
    return x % p


def field_inv(a: int, p: int) -> int:
    a = a % p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 is undefined")
    return pow(a, p - 2, p)


def poly_trim(poly: Poly) -> Poly:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_add(a: Poly, b: Poly, p: int) -> Poly:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = modp((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0), p)
    return poly_trim(out)


def poly_sub(a: Poly, b: Poly, p: int) -> Poly:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = modp((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0), p)
    return poly_trim(out)


def poly_scale(a: Poly, k: int, p: int) -> Poly:
    k = k % p
    return poly_trim([modp(k * c, p) for c in a])


def poly_mul(a: Poly, b: Poly, p: int) -> Poly:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] = modp(out[i + j] + ai * bj, p)
    return poly_trim(out)


def poly_eval(poly: Poly, x: int, p: int) -> int:
    x = x % p
    acc = 0
    for coeff in reversed(poly):
        acc = modp(acc * x + coeff, p)
    return acc


def poly_divmod(numer: Poly, denom: Poly, p: int) -> Tuple[Poly, Poly]:
    denom = poly_trim(denom[:])
    if denom == [0]:
        raise ZeroDivisionError("polynomial division by 0")

    numer = poly_trim(numer[:])
    if numer == [0]:
        return [0], [0]

    q = [0] * max(0, len(numer) - len(denom) + 1)
    r = numer[:]

    while len(r) >= len(denom) and r != [0]:
        r = poly_trim(r)
        if len(r) < len(denom) or r == [0]:
            break

        deg = len(r) - len(denom)
        lead_factor = modp(r[-1] * field_inv(denom[-1], p), p)
        q[deg] = lead_factor

        sub = [0] * deg + poly_scale(denom, lead_factor, p)
        r = poly_sub(r, sub, p)

    return poly_trim(q if q else [0]), poly_trim(r)


def lagrange_interpolate(xs: Sequence[int], ys: Sequence[int], p: int) -> Poly:
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have the same length")
    if len(xs) == 0:
        raise ValueError("need at least one point")

    n = len(xs)
    poly = [0]
    xs_mod = [x % p for x in xs]

    if len(set(xs_mod)) != len(xs_mod):
        raise ValueError("xs must be distinct mod p")

    for i in range(n):
        xi = xs_mod[i]
        yi = ys[i] % p

        num = [1]
        den = 1
        for j in range(n):
            if j == i:
                continue
            xj = xs_mod[j]
            num = poly_mul(num, [modp(-xj, p), 1], p)
            den = modp(den * (xi - xj), p)

        scale = modp(yi * field_inv(den, p), p)
        poly = poly_add(poly, poly_scale(num, scale, p), p)

    return poly_trim(poly)


def target_polynomial(xs: Sequence[int], p: int) -> Poly:
    t = [1]
    for x in xs:
        t = poly_mul(t, [modp(-x, p), 1], p)
    return poly_trim(t)


def r1cs_to_qap(
    A: Sequence[Sequence[int]],
    B: Sequence[Sequence[int]],
    C: Sequence[Sequence[int]],
    xs: Sequence[int],
    p: int,
) -> Tuple[List[Poly], List[Poly], List[Poly], Poly]:
    m = len(A)
    if m == 0:
        raise ValueError("R1CS must have at least one constraint")
    if len(B) != m or len(C) != m:
        raise ValueError("A, B, C must have the same number of constraints")
    if len(xs) != m:
        raise ValueError("xs must contain exactly one evaluation point per constraint")

    n = len(A[0])
    if n == 0:
        raise ValueError("R1CS must have at least one wire (including the constant wire)")

    for row in A:
        if len(row) != n:
            raise ValueError("A rows must have a consistent width")
    for row in B:
        if len(row) != n:
            raise ValueError("B rows must have a consistent width")
    for row in C:
        if len(row) != n:
            raise ValueError("C rows must have a consistent width")

    A_polys: List[Poly] = []
    B_polys: List[Poly] = []
    C_polys: List[Poly] = []

    for col in range(n):
        A_polys.append(lagrange_interpolate(xs, [A[row][col] for row in range(m)], p))
        B_polys.append(lagrange_interpolate(xs, [B[row][col] for row in range(m)], p))
        C_polys.append(lagrange_interpolate(xs, [C[row][col] for row in range(m)], p))

    return A_polys, B_polys, C_polys, target_polynomial(xs, p)


def lincomb_polys(polys: Sequence[Poly], witness: Sequence[int], p: int) -> Poly:
    if len(polys) != len(witness):
        raise ValueError("polys and witness must have the same length")
    out = [0]
    for poly, coef in zip(polys, witness):
        out = poly_add(out, poly_scale(poly, coef, p), p)
    return poly_trim(out)


def qap_p_poly(A_polys: Sequence[Poly], B_polys: Sequence[Poly], C_polys: Sequence[Poly], witness: Sequence[int], p: int) -> Poly:
    ax = lincomb_polys(A_polys, witness, p)
    bx = lincomb_polys(B_polys, witness, p)
    cx = lincomb_polys(C_polys, witness, p)
    return poly_trim(poly_sub(poly_mul(ax, bx, p), cx, p))


def poly_to_string(poly: Poly, p: int) -> str:
    poly = poly_trim(poly[:])
    if poly == [0]:
        return "0"
    terms: List[str] = []
    for power, coeff in enumerate(poly):
        coeff = coeff % p
        if coeff == 0:
            continue
        if power == 0:
            terms.append(str(coeff))
        elif power == 1:
            terms.append(f"{coeff}*x")
        else:
            terms.append(f"{coeff}*x^{power}")
    return " + ".join(reversed(terms)) if terms else "0"


def example_r1cs_for_z_eq_x_mul_y_plus_x() -> Tuple[List[List[int]], List[List[int]], List[List[int]]]:
    # Wires: [1, x, y, w, z]
    # Constraints:
    # 1) x * y = w
    # 2) (x + w) * 1 = z
    A = [
        [0, 1, 0, 0, 0],
        [0, 1, 0, 1, 0],
    ]
    B = [
        [0, 0, 1, 0, 0],
        [1, 0, 0, 0, 0],
    ]
    C = [
        [0, 0, 0, 1, 0],
        [0, 0, 0, 0, 1],
    ]
    return A, B, C


def main() -> int:
    p = 101
    xs = [1, 2]

    print("\n=== Step 1: Field + polynomials ===\n")
    print(f"Field: F_{p}")
    print(f"inv(3) = {field_inv(3, p)}  (since 3*inv(3) mod p = {modp(3*field_inv(3, p), p)})")
    demo_mul = poly_mul([1, 2], [3, 4, 5], p)
    print(f"poly_mul([1,2], [3,4,5]) = {demo_mul}  ({poly_to_string(demo_mul, p)})")

    print("\n=== Step 2: Lagrange interpolation ===\n")
    f = lagrange_interpolate([1, 2], [0, 1], p)  # f(1)=0, f(2)=1 => f(x)=x-1
    print(f"Interpolate points (1->0), (2->1): f(x) = {f}  ({poly_to_string(f, p)})")
    print(f"f(1)={poly_eval(f, 1, p)}, f(2)={poly_eval(f, 2, p)}")
    t = target_polynomial(xs, p)
    print(f"Target polynomial t(x)=∏(x-x_i) for x_i={xs}: t(x) = {t}  ({poly_to_string(t, p)})")

    print("\n=== Step 3: R1CS → QAP ===\n")
    A, B, C = example_r1cs_for_z_eq_x_mul_y_plus_x()
    A_polys, B_polys, C_polys, t_from_r1cs = r1cs_to_qap(A, B, C, xs, p)
    assert t_from_r1cs == t

    print("Per-wire polynomials (showing non-zero ones):")
    wire_names = ["1", "x", "y", "w", "z"]
    for name, ap, bp, cp in zip(wire_names, A_polys, B_polys, C_polys):
        if ap != [0] or bp != [0] or cp != [0]:
            print(f"  wire {name}: A={ap}, B={bp}, C={cp}")

    print("\n=== Step 4: The QAP divisibility check ===\n")
    x_val, y_val = 3, 4
    w_val = modp(x_val * y_val, p)
    z_val = modp(w_val + x_val, p)
    witness = [1, x_val, y_val, w_val, z_val]
    print(f"Witness for z = x*y + x with x={x_val}, y={y_val}: {witness}")

    P_poly = qap_p_poly(A_polys, B_polys, C_polys, witness, p)
    h, rem = poly_divmod(P_poly, t, p)
    print(f"P(x)=A(x)B(x)-C(x) = {P_poly}  ({poly_to_string(P_poly, p)})")
    print(f"Divide by t(x): h(x)={h}, remainder={rem}")
    print(f"Check: P(1)={poly_eval(P_poly, 1, p)}, P(2)={poly_eval(P_poly, 2, p)} (should both be 0)")

    witness_bad = [1, x_val, y_val, w_val, modp(z_val + 1, p)]
    P_bad = qap_p_poly(A_polys, B_polys, C_polys, witness_bad, p)
    _, rem_bad = poly_divmod(P_bad, t, p)
    print(f"\nTamper the witness (wrong z): {witness_bad}")
    print(f"Remainder becomes non-zero: {rem_bad}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
