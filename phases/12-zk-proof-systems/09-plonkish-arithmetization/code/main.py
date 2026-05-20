"""
PLONKish arithmetization, from rows to one polynomial identity.

This script builds a tiny PLONK-style gate system:

- witness columns: a[i], b[i], c[i]
- selector columns: ql[i], qr[i], qm[i], qo[i], qc[i]
- per-row constraint: ql*a + qr*b + qm*(a*b) + qo*c + qc == 0

Then it "arithmetizes" the whole table into polynomials over a roots-of-unity domain:

- A(X), B(X), C(X) interpolate the witness columns
- QL(X), ..., QC(X) interpolate the selector columns
- F(X) = QL*A + QR*B + QM*(A*B) + QO*C + QC

If every row constraint holds, then F(ω^i) == 0 for all domain points ω^i, and
F(X) is divisible by the vanishing polynomial Z_H(X) = X^n - 1.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple


MODULUS = 18446744069414584321  # Goldilocks prime: 2^64 - 2^32 + 1
PRIMITIVE_ROOT = 7


def inv_mod(a: int, p: int = MODULUS) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    return pow(a, p - 2, p)


def poly_trim(poly: Sequence[int], p: int = MODULUS) -> List[int]:
    out = [c % p for c in poly]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def poly_add(a: Sequence[int], b: Sequence[int], p: int = MODULUS) -> List[int]:
    m = max(len(a), len(b))
    out = [0] * m
    for i in range(m):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return poly_trim(out, p)


def poly_sub(a: Sequence[int], b: Sequence[int], p: int = MODULUS) -> List[int]:
    m = max(len(a), len(b))
    out = [0] * m
    for i in range(m):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % p
    return poly_trim(out, p)


def poly_scale(a: Sequence[int], k: int, p: int = MODULUS) -> List[int]:
    return poly_trim([(c % p) * (k % p) % p for c in a], p)


def poly_mul(a: Sequence[int], b: Sequence[int], p: int = MODULUS) -> List[int]:
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        ai %= p
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * (bj % p)) % p
    return poly_trim(out, p)


def poly_eval(poly: Sequence[int], x: int, p: int = MODULUS) -> int:
    x %= p
    acc = 0
    for c in reversed(poly):
        acc = (acc * x + (c % p)) % p
    return acc


def poly_divmod(numer: Sequence[int], denom: Sequence[int], p: int = MODULUS) -> Tuple[List[int], List[int]]:
    numer_t = poly_trim(numer, p)
    denom_t = poly_trim(denom, p)
    if len(denom_t) == 1 and denom_t[0] == 0:
        raise ZeroDivisionError("polynomial division by zero")
    if len(numer_t) < len(denom_t):
        return [0], numer_t

    q = [0] * (len(numer_t) - len(denom_t) + 1)
    rem = numer_t[:]
    inv_lead = inv_mod(denom_t[-1], p)

    while len(rem) >= len(denom_t) and not (len(rem) == 1 and rem[0] == 0):
        d = len(rem) - len(denom_t)
        coeff = rem[-1] * inv_lead % p
        q[d] = coeff
        for i in range(len(denom_t)):
            rem[i + d] = (rem[i + d] - coeff * denom_t[i]) % p
        rem = poly_trim(rem, p)

    return poly_trim(q, p), rem


def nth_root_of_unity(n: int, p: int = MODULUS, g: int = PRIMITIVE_ROOT) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1 to get an n-th root of unity")
    return pow(g % p, (p - 1) // n, p)


def domain_points(n: int, omega: int, p: int = MODULUS) -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    omega %= p
    out = []
    cur = 1
    for _ in range(n):
        out.append(cur)
        cur = cur * omega % p
    return out


def lagrange_interpolate(xs: Sequence[int], ys: Sequence[int], p: int = MODULUS) -> List[int]:
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have the same length")
    if not xs:
        raise ValueError("need at least one point to interpolate")

    xs_n = [x % p for x in xs]
    ys_n = [y % p for y in ys]
    if len(set(xs_n)) != len(xs_n):
        raise ValueError("xs must be distinct")

    poly = [0]
    n = len(xs_n)
    for i in range(n):
        xi = xs_n[i]
        num = [1]
        den = 1
        for j in range(n):
            if j == i:
                continue
            xj = xs_n[j]
            num = poly_mul(num, [(-xj) % p, 1], p)
            den = den * (xi - xj) % p
        scale = ys_n[i] * inv_mod(den, p) % p
        poly = poly_add(poly, poly_scale(num, scale, p), p)
    return poly_trim(poly, p)


def vanishing_polynomial(n: int, p: int = MODULUS) -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    return [(p - 1)] + [0] * (n - 1) + [1]


def plonk_gate_row_residual(
    *,
    ql: int,
    qr: int,
    qm: int,
    qo: int,
    qc: int,
    a: int,
    b: int,
    c: int,
    p: int = MODULUS,
) -> int:
    return (ql * a + qr * b + qm * a * b + qo * c + qc) % p


def example_rows(p: int = MODULUS) -> List[Dict[str, int]]:
    m1 = p - 1
    rows = [
        dict(ql=1, qr=1, qm=0, qo=m1, qc=0, a=3, b=4, c=7),
        dict(ql=0, qr=0, qm=1, qo=m1, qc=0, a=5, b=6, c=30),
        dict(ql=2, qr=0, qm=0, qo=m1, qc=5, a=9, b=0, c=23),
        dict(ql=1, qr=1, qm=0, qo=m1, qc=7, a=11, b=12, c=30),
        dict(ql=0, qr=0, qm=1, qo=m1, qc=9, a=2, b=10, c=29),
        dict(ql=3, qr=0, qm=0, qo=m1, qc=p - 5, a=4, b=0, c=7),
        dict(ql=0, qr=0, qm=1, qo=m1, qc=m1, a=3, b=9, c=26),
        dict(ql=1, qr=0, qm=0, qo=m1, qc=0, a=42, b=0, c=42),
    ]
    for r in rows:
        if plonk_gate_row_residual(**r, p=p) != 0:
            raise AssertionError("internal example rows do not satisfy the gate equation")
    return rows


def columns_from_rows(rows: Sequence[Dict[str, int]], names: Sequence[str]) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    for name in names:
        out[name] = [int(r[name]) for r in rows]
    return out


def interpolate_columns(domain: Sequence[int], columns: Dict[str, Sequence[int]], p: int = MODULUS) -> Dict[str, List[int]]:
    return {name: lagrange_interpolate(domain, values, p) for name, values in columns.items()}


def plonk_gate_composition_polynomial(polys: Dict[str, Sequence[int]], p: int = MODULUS) -> List[int]:
    a = polys["a"]
    b = polys["b"]
    c = polys["c"]
    ql = polys["ql"]
    qr = polys["qr"]
    qm = polys["qm"]
    qo = polys["qo"]
    qc = polys["qc"]

    ab = poly_mul(a, b, p)
    term = poly_add(poly_mul(ql, a, p), poly_mul(qr, b, p), p)
    term = poly_add(term, poly_mul(qm, ab, p), p)
    term = poly_add(term, poly_mul(qo, c, p), p)
    term = poly_add(term, qc, p)
    return poly_trim(term, p)


def format_poly(poly: Sequence[int], max_terms: int = 6) -> str:
    if not poly:
        return "0"
    terms = []
    for i, c in enumerate(poly):
        if c == 0:
            continue
        if i == 0:
            terms.append(str(c))
        elif i == 1:
            terms.append(f"{c}*X")
        else:
            terms.append(f"{c}*X^{i}")
    if not terms:
        return "0"
    if len(terms) > max_terms:
        return " + ".join(terms[:max_terms]) + f" + ... ({len(terms)} terms)"
    return " + ".join(terms)


def main() -> None:
    print("=== Step 1: Finite field + polynomials ===")
    inv7 = inv_mod(7)
    print(f"MODULUS p = {MODULUS}")
    print(f"inv_mod(7) = {inv7} (check: 7*inv % p = {(7*inv7)%MODULUS})")
    sample = [3, 2, 1]  # 3 + 2X + 1X^2
    x = 10
    print(f"poly_eval([3,2,1], 10) = {poly_eval(sample, x)}")

    print("\n=== Step 2: Roots of unity domain + interpolation ===")
    n = 8
    omega = nth_root_of_unity(n)
    domain = domain_points(n, omega)
    print(f"n = {n}")
    print(f"omega = {omega}")
    print(f"domain = {domain}")
    print(f"omega^n mod p = {pow(omega, n, MODULUS)}")

    xs = [1, 2, 4]
    ys = [3, 0, 10]
    interp = lagrange_interpolate(xs, ys)
    print(f"lagrange_interpolate(xs={xs}, ys={ys}) = {interp}")
    print(f"check at xs: {[poly_eval(interp, t) for t in xs]}")

    print("\n=== Step 3: Gate rows (selectors + witness) ===")
    rows = example_rows()
    for i, r in enumerate(rows):
        res = plonk_gate_row_residual(**r)
        print(f"row {i}: residual = {res}")

    print("\n=== Step 4: One polynomial identity + vanishing check ===")
    cols = columns_from_rows(rows, ["a", "b", "c", "ql", "qr", "qm", "qo", "qc"])
    polys = interpolate_columns(domain, cols)
    F = plonk_gate_composition_polynomial(polys)
    ZH = vanishing_polynomial(n)

    evals = [poly_eval(F, x) for x in domain]
    print(f"F(X) = {format_poly(F)}")
    print(f"Z_H(X) = X^{n} - 1")
    print(f"F(omega^i) for i=0..{n-1} = {evals}")

    Q, R = poly_divmod(F, ZH)
    print(f"Q(X) = F(X) / Z_H(X) has degree {len(Q)-1}")
    print(f"remainder = {R}")

    print("\n=== Step 5: What breaks if you only check one point ===")
    r = 123456789
    fake = [(-r) % MODULUS, 1]  # fake(X) = X - r
    print(f"fake(X) = X - r, r = {r}")
    print(f"fake(r) = {poly_eval(fake, r)}")
    print(f"fake(omega^i) for i=0..{n-1} = {[poly_eval(fake, x) for x in domain]}")


if __name__ == "__main__":
    main()
