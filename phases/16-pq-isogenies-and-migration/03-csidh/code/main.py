"""
Toy CSIDH building blocks (finite-field ECC + Vélu isogenies) over a tiny prime field.

This lesson script:
1) implements elliptic-curve arithmetic over F_p in short Weierstrass form,
2) finds small-order torsion points on a supersingular curve,
3) constructs odd-degree isogenies using Vélu's formulas, and
4) demonstrates an "order-independent" two-prime quotient walk (a toy commutative pattern).

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
from typing import Iterable, Optional


class ModSqrtError(ValueError):
    pass


def inv_mod(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("division by zero mod p")
    return pow(a, p - 2, p)


def legendre_symbol(a: int, p: int) -> int:
    a %= p
    if a == 0:
        return 0
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def sqrt_mod(a: int, p: int) -> int:
    """
    Return y such that y^2 ≡ a (mod p), for odd prime p.

    Deterministic: returns the smaller root min(y, p-y).
    Raises ModSqrtError if no square root exists.
    """
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if legendre_symbol(a, p) != 1:
        raise ModSqrtError("not a quadratic residue")

    if p % 4 == 3:
        y = pow(a, (p + 1) // 4, p)
        return min(y, (-y) % p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    while t != 1:
        i = 1
        t2i = (t * t) % p
        while i < m and t2i != 1:
            t2i = (t2i * t2i) % p
            i += 1
        if i == m:
            raise ModSqrtError("tonelli-shanks failed")
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p

    return min(r, (-r) % p)


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int

    def normalize(self) -> "Curve":
        return Curve(self.p, self.a % self.p, self.b % self.p)


@dataclass(frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]

    @staticmethod
    def inf() -> "Point":
        return Point(None, None)

    def is_inf(self) -> bool:
        return self.x is None and self.y is None


def is_on_curve(curve: Curve, pt: Point) -> bool:
    if pt.is_inf():
        return True
    assert pt.x is not None and pt.y is not None
    p = curve.p
    x = pt.x % p
    y = pt.y % p
    return (y * y - (x * x * x + curve.a * x + curve.b)) % p == 0


def point_neg(curve: Curve, pt: Point) -> Point:
    if pt.is_inf():
        return pt
    assert pt.x is not None and pt.y is not None
    return Point(pt.x % curve.p, (-pt.y) % curve.p)


def point_add(curve: Curve, p1: Point, p2: Point) -> Point:
    if p1.is_inf():
        return p2
    if p2.is_inf():
        return p1

    p = curve.p
    assert p1.x is not None and p1.y is not None
    assert p2.x is not None and p2.y is not None

    x1, y1 = p1.x % p, p1.y % p
    x2, y2 = p2.x % p, p2.y % p

    if x1 == x2 and (y1 + y2) % p == 0:
        return Point.inf()

    if x1 == x2 and y1 == y2:
        num = (3 * x1 * x1 + curve.a) % p
        den = (2 * y1) % p
    else:
        num = (y2 - y1) % p
        den = (x2 - x1) % p

    lam = (num * inv_mod(den, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return Point(x3, y3)


def scalar_mul(curve: Curve, k: int, pt: Point) -> Point:
    if k == 0 or pt.is_inf():
        return Point.inf()
    if k < 0:
        return scalar_mul(curve, -k, point_neg(curve, pt))

    acc = Point.inf()
    base = pt
    while k:
        if k & 1:
            acc = point_add(curve, acc, base)
        base = point_add(curve, base, base)
        k >>= 1
    return acc


def j_invariant(curve: Curve) -> int:
    """
    j(E) = 1728 * 4a^3 / (4a^3 + 27b^2)  (short Weierstrass, char != 2,3)
    """
    p = curve.p
    a = curve.a % p
    b = curve.b % p
    num = (1728 * 4 * pow(a, 3, p)) % p
    den = (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p
    return (num * inv_mod(den, p)) % p


def count_points(curve: Curve) -> int:
    p = curve.p
    total = 1  # point at infinity
    for x in range(p):
        rhs = (x * x * x + curve.a * x + curve.b) % p
        ls = legendre_symbol(rhs, p)
        if ls == 0:
            total += 1
        elif ls == 1:
            total += 2
    return total


def iter_points(curve: Curve) -> Iterable[Point]:
    p = curve.p
    for x in range(p):
        rhs = (x * x * x + curve.a * x + curve.b) % p
        if rhs == 0:
            yield Point(x, 0)
            continue
        if legendre_symbol(rhs, p) == 1:
            y = sqrt_mod(rhs, p)
            yield Point(x, y)
            if y != 0:
                yield Point(x, (-y) % p)


def find_point_of_order(curve: Curve, ell: int, group_order: int) -> Point:
    if group_order % ell != 0:
        raise ValueError("ell does not divide group order")
    cofactor = group_order // ell
    for r in iter_points(curve):
        p = scalar_mul(curve, cofactor, r)
        if not p.is_inf() and scalar_mul(curve, ell, p).is_inf():
            return p
    raise ValueError("no point of the requested order found")


def subgroup_points(curve: Curve, gen: Point, ell: int) -> list[Point]:
    pts: list[Point] = []
    acc = Point.inf()
    for k in range(1, ell):
        acc = point_add(curve, acc, gen) if not acc.is_inf() else gen
        pts.append(acc)
    return pts


def velu_isogeny_odd_prime(curve: Curve, gen: Point, ell: int) -> tuple[Curve, list[Point]]:
    """
    Vélu for odd prime-degree cyclic kernel <gen>, on y^2 = x^3 + a x + b (char != 2,3).

    Returns (codomain_curve, kernel_points_nonzero).
    """
    if ell <= 2:
        raise ValueError("this helper is for odd prime ell")
    if scalar_mul(curve, ell, gen).is_inf() is False:
        raise ValueError("gen is not of order ell")

    p = curve.p
    ker = subgroup_points(curve, gen, ell)

    t = 0
    w = 0
    for q in ker:
        assert q.x is not None and q.y is not None
        xq = q.x % p
        yq = q.y % p
        t_q = (3 * xq * xq + curve.a) % p
        u_q = (2 * yq * yq) % p
        w_q = (u_q + t_q * xq) % p
        t = (t + t_q) % p
        w = (w + w_q) % p

    a2 = (curve.a - 5 * t) % p
    b2 = (curve.b - 7 * w) % p
    return Curve(p, a2, b2), ker


def velu_map_point(curve: Curve, kernel_nonzero: list[Point], pt: Point) -> Point:
    """
    Evaluate φ(x,y) = (r(x), r'(x) * y) where
      r(x) = x + Σ_{Q != O} ( t_Q/(x-x_Q) + u_Q/(x-x_Q)^2 )
      t_Q = 3 x_Q^2 + a
      u_Q = 2 y_Q^2

    Raises ValueError if pt is in the kernel (division by zero).
    """
    if pt.is_inf():
        return pt

    p = curve.p
    assert pt.x is not None and pt.y is not None
    x = pt.x % p
    y = pt.y % p

    rx = x
    rpx = 1
    for q in kernel_nonzero:
        assert q.x is not None and q.y is not None
        xq = q.x % p
        yq = q.y % p
        denom = (x - xq) % p
        if denom == 0:
            raise ValueError("point is in the kernel (or shares x with it)")
        inv1 = inv_mod(denom, p)
        inv2 = (inv1 * inv1) % p
        inv3 = (inv2 * inv1) % p

        t_q = (3 * xq * xq + curve.a) % p
        u_q = (2 * yq * yq) % p

        rx = (rx + t_q * inv1 + u_q * inv2) % p
        rpx = (rpx - t_q * inv2 - 2 * u_q * inv3) % p

    return Point(rx, (rpx * y) % p)


def velu_demo_two_prime_commute(base: Curve, p3: Point, p5: Point) -> dict[str, int]:
    """
    Demonstrate order-independence when quotients are taken by two coprime-order subgroups,
    as long as we transport the "other" subgroup through the isogeny map.
    """
    e3, ker3 = velu_isogeny_odd_prime(base, p3, 3)
    p5_on_e3 = velu_map_point(base, ker3, p5)
    e35, _ = velu_isogeny_odd_prime(e3, p5_on_e3, 5)

    e5, ker5 = velu_isogeny_odd_prime(base, p5, 5)
    p3_on_e5 = velu_map_point(base, ker5, p3)
    e53, _ = velu_isogeny_odd_prime(e5, p3_on_e5, 3)

    return {"j_e35": j_invariant(e35), "j_e53": j_invariant(e53)}


def _emit_vectors() -> None:
    p = 419
    base = Curve(p=p, a=1, b=0).normalize()
    order = count_points(base)
    p3 = find_point_of_order(base, 3, order)
    p5 = find_point_of_order(base, 5, order)
    e3, ker3 = velu_isogeny_odd_prime(base, p3, 3)
    phi_p5 = velu_map_point(base, ker3, p5)
    commute = velu_demo_two_prime_commute(base, p3, p5)

    vectors = [
        {"op": "inv_mod", "p": p, "a": 17, "expected": inv_mod(17, p)},
        {"op": "sqrt_mod", "p": p, "a": 4, "expected": sqrt_mod(4, p)},
        {"op": "sqrt_mod", "p": p, "a": 2, "expected": None},
        {
            "op": "point_add",
            "curve": {"p": p, "a": 1, "b": 0},
            "p1": {"x": p3.x, "y": p3.y},
            "p2": {"x": p3.x, "y": (-p3.y) % p},
            "expected": {"inf": True},
        },
        {
            "op": "scalar_mul",
            "curve": {"p": p, "a": 1, "b": 0},
            "k": 3,
            "pt": {"x": p3.x, "y": p3.y},
            "expected": {"inf": True},
        },
        {
            "op": "velu_codomain_curve",
            "curve": {"p": p, "a": 1, "b": 0},
            "ell": 3,
            "gen": {"x": p3.x, "y": p3.y},
            "expected": {"p": e3.p, "a": e3.a, "b": e3.b},
        },
        {
            "op": "velu_map_point",
            "curve": {"p": p, "a": 1, "b": 0},
            "ell": 3,
            "gen": {"x": p3.x, "y": p3.y},
            "pt": {"x": p5.x, "y": p5.y},
            "expected": {"x": phi_p5.x, "y": phi_p5.y},
        },
        {"op": "commute_demo_j", "expected": commute},
    ]

    out = {"source": "Generated by phases/16-pq-isogenies-and-migration/03-csidh/code/main.py --emit-vectors", "vectors": vectors}
    print(json.dumps(out, indent=2, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--emit-vectors", action="store_true", help="Print tests/vectors.json content and exit")
    args = parser.parse_args()

    if args.emit_vectors:
        _emit_vectors()
        return

    p = 419
    base = Curve(p=p, a=1, b=0).normalize()

    print("=== Step 1: Finite-field building blocks ===")
    print(f"p = {p}")
    print(f"inv_mod(17) = {inv_mod(17, p)}")
    print(f"sqrt_mod(4) = {sqrt_mod(4, p)}  (since 2^2 ≡ 4 mod p)")

    print("\n=== Step 2: Elliptic curve group law over F_p ===")
    print(f"Base curve: y^2 = x^3 + {base.a}x + {base.b} over F_{p}")
    n = count_points(base)
    print(f"#E(F_p) = {n}")
    if n != p + 1:
        raise RuntimeError("unexpected point count for the base curve")

    print("\n=== Step 3: Find small torsion points ===")
    p3 = find_point_of_order(base, 3, n)
    p5 = find_point_of_order(base, 5, n)
    print(f"Found P3 (order 3): {p3}")
    print(f"Found P5 (order 5): {p5}")
    if not scalar_mul(base, 3, p3).is_inf():
        raise RuntimeError("P3 check failed")
    if not scalar_mul(base, 5, p5).is_inf():
        raise RuntimeError("P5 check failed")

    print("\n=== Step 4: Build an odd-degree isogeny with Vélu's formulas ===")
    e3, ker3 = velu_isogeny_odd_prime(base, p3, 3)
    print(f"E3 = E/<P3> has coefficients: a={e3.a}, b={e3.b}")
    q = velu_map_point(base, ker3, p5)
    if not is_on_curve(e3, q):
        raise RuntimeError("Vélu map output is not on codomain curve")
    print(f"φ_3(P5) on E3: {q}")

    print("\n=== Step 5: A toy order-independent two-prime quotient walk ===")
    commute = velu_demo_two_prime_commute(base, p3, p5)
    print(f"j(E/(<P3> then <P5>)) = {commute['j_e35']}")
    print(f"j(E/(<P5> then <P3>)) = {commute['j_e53']}")
    print(f"Equal j-invariant? {commute['j_e35'] == commute['j_e53']}")


if __name__ == "__main__":
    main()
