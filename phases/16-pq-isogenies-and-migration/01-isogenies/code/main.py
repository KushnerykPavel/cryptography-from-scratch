"""
Toy isogenies over small prime fields.

This file implements a minimal elliptic-curve group (short Weierstrass form)
and uses Vélu's formulas to build an explicit isogeny from a chosen kernel.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass


Point = tuple[int, int] | None  # None == point at infinity


def inv_mod(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 mod p does not exist")
    t0, t1 = 0, 1
    r0, r1 = p, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise ZeroDivisionError("a is not invertible mod p")
    return t0 % p


def div_mod(n: int, d: int, p: int) -> int:
    return (n % p) * inv_mod(d, p) % p


@dataclass(frozen=True)
class ShortWeierstrassCurve:
    p: int
    a: int
    b: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "a", self.a % self.p)
        object.__setattr__(self, "b", self.b % self.p)
        if self.p <= 3:
            raise ValueError("p must be an odd prime > 3 for short Weierstrass demo")
        if self.discriminant() == 0:
            raise ValueError("singular curve (discriminant == 0)")

    def discriminant(self) -> int:
        p = self.p
        return (-16 * (4 * pow(self.a, 3, p) + 27 * pow(self.b, 2, p))) % p

    def is_on_curve(self, pt: Point) -> bool:
        if pt is None:
            return True
        x, y = pt
        p = self.p
        return (y * y - (x * x * x + self.a * x + self.b)) % p == 0

    def neg(self, pt: Point) -> Point:
        if pt is None:
            return None
        x, y = pt
        return (x % self.p, (-y) % self.p)

    def add(self, p1: Point, p2: Point) -> Point:
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2
        p = self.p

        x1 %= p
        y1 %= p
        x2 %= p
        y2 %= p

        if x1 == x2 and (y1 + y2) % p == 0:
            return None

        if x1 == x2 and y1 == y2:
            if y1 % p == 0:
                return None
            m = div_mod(3 * x1 * x1 + self.a, 2 * y1, p)
        else:
            m = div_mod(y2 - y1, x2 - x1, p)

        x3 = (m * m - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return (x3, y3)

    def mul(self, k: int, pt: Point) -> Point:
        if k < 0:
            return self.mul(-k, self.neg(pt))
        acc: Point = None
        addend = pt
        while k:
            if k & 1:
                acc = self.add(acc, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return acc

    def enumerate_points(self) -> list[Point]:
        p = self.p
        pts: list[Point] = [None]
        for x in range(p):
            rhs = (x * x * x + self.a * x + self.b) % p
            for y in range(p):
                if (y * y) % p == rhs:
                    pts.append((x, y))
        return pts

    def subgroup_points(self, generator: Point) -> list[Point]:
        if generator is None:
            return [None]
        if not self.is_on_curve(generator):
            raise ValueError("generator is not on curve")
        pts = [None]
        cur = generator
        seen: set[Point] = {None}
        while cur not in seen:
            pts.append(cur)
            seen.add(cur)
            cur = self.add(cur, generator)
        if cur is not None:
            raise RuntimeError("subgroup generation did not return to infinity")
        return pts

    def order(self, pt: Point) -> int:
        if pt is None:
            return 1
        cur = None
        for k in range(1, self.p + 2 + 2 * int(self.p**0.5) + 10):
            cur = self.add(cur, pt)
            if cur is None:
                return k
        raise RuntimeError("failed to find point order (p too large for demo?)")


def velu_kernel_representatives(curve: ShortWeierstrassCurve, kernel: list[Point]) -> list[Point]:
    p = curve.p
    reps: dict[tuple[int, int], Point] = {}
    for q in kernel:
        if q is None:
            continue
        xq, yq = q
        xq %= p
        yq %= p
        if yq == 0:
            reps[(xq, 0)] = (xq, 0)
            continue
        yneg = (-yq) % p
        yrep = yq if yq < yneg else yneg
        reps[(xq, yrep)] = (xq, yrep)
    return [reps[k] for k in sorted(reps)]


def velu_isogeny_short_weierstrass(
    curve: ShortWeierstrassCurve, kernel_generator: Point
) -> tuple[ShortWeierstrassCurve, callable[[Point], Point], list[Point]]:
    kernel = curve.subgroup_points(kernel_generator)
    if len(kernel) <= 2:
        raise ValueError("kernel must have size >= 3 (non-trivial separable isogeny)")

    s_points = velu_kernel_representatives(curve, kernel)

    p = curve.p
    a = curve.a
    b = curve.b

    v_sum = 0
    w_sum = 0
    per_q: list[tuple[Point, int, int, int]] = []
    for q in s_points:
        if q is None:
            continue
        xq, yq = q
        xq %= p
        yq %= p
        u_q = (4 * yq * yq) % p
        base = (3 * xq * xq + a) % p
        v_q = base if yq == 0 else (2 * base) % p
        v_sum = (v_sum + v_q) % p
        w_sum = (w_sum + u_q + xq * v_q) % p
        per_q.append((q, u_q, v_q, base))

    a2 = (a - 5 * v_sum) % p
    b2 = (b - 7 * w_sum) % p
    codomain = ShortWeierstrassCurve(p=p, a=a2, b=b2)

    kernel_set = set(kernel)

    def isogeny_map(pt: Point) -> Point:
        if pt is None:
            return None
        if pt in kernel_set:
            return None
        x, y = pt
        x %= p
        y %= p
        if not curve.is_on_curve((x, y)):
            raise ValueError("point is not on the domain curve")
        x_img = x
        y_img = y
        for q, u_q, v_q, base in per_q:
            xq, yq = q  # type: ignore[misc]
            dx = (x - xq) % p
            if dx == 0:
                raise ZeroDivisionError("isogeny undefined for this point (dx == 0)")
            inv_dx = inv_mod(dx, p)
            inv_dx2 = (inv_dx * inv_dx) % p
            inv_dx3 = (inv_dx2 * inv_dx) % p

            x_img = (x_img + v_q * inv_dx + u_q * inv_dx2) % p

            term1 = (u_q * (2 * y % p) * inv_dx3) % p
            term2 = (v_q * ((y - yq) % p) * inv_dx2) % p
            term3 = ((2 * yq % p) * base * inv_dx2) % p
            y_img = (y_img - term1 - term2 - term3) % p

        return (x_img, y_img)

    return codomain, isogeny_map, kernel


def find_point_with_order(curve: ShortWeierstrassCurve, target_order: int) -> Point:
    for pt in curve.enumerate_points():
        if pt is None:
            continue
        if curve.order(pt) == target_order:
            return pt
    raise ValueError(f"no point of order {target_order} found on this curve")


def step_header(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    curve = ShortWeierstrassCurve(p=101, a=2, b=3)

    step_header(1, "Elliptic curve group law (toy)")
    p = curve.p
    g = (1, 39)
    if not curve.is_on_curve(g):
        raise RuntimeError("expected base point is not on curve")
    print(f"Curve: y^2 = x^3 + {curve.a}x + {curve.b}  (mod {p})")
    print(f"G = {g}")
    print(f"2G = {curve.mul(2, g)}")
    print(f"7G = {curve.mul(7, g)}")

    step_header(2, "Find a small kernel subgroup")
    kgen = find_point_with_order(curve, target_order=3)
    kernel = curve.subgroup_points(kgen)
    print(f"Kernel generator (order 3): K = {kgen}")
    print(f"Kernel points: {kernel}")

    step_header(3, "Build an isogeny using Vélu's formulas")
    codomain, phi, kernel_pts = velu_isogeny_short_weierstrass(curve, kgen)
    print(f"Codomain curve: y^2 = x^3 + {codomain.a}x + {codomain.b}  (mod {codomain.p})")
    print(f"|E(F_p)| = {len(curve.enumerate_points())}")
    print(f"|E'(F_p)| = {len(codomain.enumerate_points())}")

    step_header(4, "Migration demo: map a 'public key' point to the new curve")
    pub = curve.mul(7, g)
    pub2 = phi(pub)
    print(f"Public key point P = 7G = {pub}")
    print(f"Mapped point φ(P) = {pub2}")
    if pub2 is not None and not codomain.is_on_curve(pub2):
        raise RuntimeError("mapped point is not on codomain curve")
    print("Done.")


if __name__ == "__main__":
    main()
