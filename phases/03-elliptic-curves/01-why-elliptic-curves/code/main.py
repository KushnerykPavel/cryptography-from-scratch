from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int


@dataclass(frozen=True)
class Point:
    x: int
    y: int


ECPoint = Point | None


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse does not exist")
    t, new_t = 0, 1
    r, new_r = p, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("inverse does not exist")
    return t % p


def is_on_curve(curve: Curve, p: ECPoint) -> bool:
    if p is None:
        return True
    x, y = p.x, p.y
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def point_neg(curve: Curve, p: ECPoint) -> ECPoint:
    if p is None:
        return None
    return Point(p.x, (-p.y) % curve.p)


def point_add(curve: Curve, p: ECPoint, q: ECPoint) -> ECPoint:
    if p is None:
        return q
    if q is None:
        return p

    if p.x == q.x and (p.y + q.y) % curve.p == 0:
        return None

    if p != q:
        lam = (q.y - p.y) * mod_inv(q.x - p.x, curve.p)
    else:
        if p.y % curve.p == 0:
            return None
        lam = (3 * p.x * p.x + curve.a) * mod_inv(2 * p.y, curve.p)

    lam %= curve.p
    x3 = (lam * lam - p.x - q.x) % curve.p
    y3 = (lam * (p.x - x3) - p.y) % curve.p
    return Point(x3, y3)


def scalar_mul(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul(curve, -k, point_neg(curve, p))

    acc: ECPoint = None
    addend: ECPoint = p

    while k > 0:
        if k & 1:
            acc = point_add(curve, acc, addend)
        addend = point_add(curve, addend, addend)
        k >>= 1

    return acc


def enumerate_points(curve: Curve) -> list[Point]:
    points: list[Point] = []
    for x in range(curve.p):
        rhs = (x * x * x + curve.a * x + curve.b) % curve.p
        for y in range(curve.p):
            if (y * y - rhs) % curve.p == 0:
                points.append(Point(x, y))
    return points


def group_order(curve: Curve) -> int:
    return len(enumerate_points(curve)) + 1


def discrete_log_bruteforce(curve: Curve, base: Point, target: ECPoint) -> int | None:
    if target is None:
        return 0
    current: ECPoint = None
    for k in range(1, group_order(curve) + 1):
        current = point_add(curve, current, base)
        if current == target:
            return k
    return None


def main():
    curve = Curve(p=211, a=0, b=7)
    g = Point(3, 33)
    assert is_on_curve(curve, g)

    n = group_order(curve)
    print(f"Toy curve: y^2 = x^3 + 7 (mod {curve.p})")
    print(f"Group order: {n}")
    print()

    for k in range(1, 11):
        p = scalar_mul(curve, k, g)
        print(f"{k:>3}·G = {p}")
    print()

    k = 123
    target = scalar_mul(curve, k, g)
    recovered = discrete_log_bruteforce(curve, g, target)
    assert recovered == k
    print(f"Bruteforce discrete log recovers k={recovered} for P={target}")


if __name__ == "__main__":
    main()
