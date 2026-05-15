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


def curve_is_singular(curve: Curve) -> bool:
    p = curve.p
    return (4 * pow(curve.a, 3, p) + 27 * pow(curve.b, 2, p)) % p == 0


def validate_curve(curve: Curve) -> None:
    if curve.p <= 3:
        raise ValueError("p must be > 3 for short Weierstrass form")
    if curve_is_singular(curve):
        raise ValueError("curve is singular")


def is_on_curve(curve: Curve, point: ECPoint) -> bool:
    validate_curve(curve)
    if point is None:
        return True
    x, y = point.x % curve.p, point.y % curve.p
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def require_on_curve(curve: Curve, point: ECPoint) -> None:
    if not is_on_curve(curve, point):
        raise ValueError("point is not on curve")


def point_neg(curve: Curve, point: ECPoint) -> ECPoint:
    validate_curve(curve)
    if point is None:
        return None
    require_on_curve(curve, point)
    return Point(point.x % curve.p, (-point.y) % curve.p)


def point_add(curve: Curve, p: ECPoint, q: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    require_on_curve(curve, q)

    if p is None:
        return q
    if q is None:
        return p

    if p.x % curve.p == q.x % curve.p and (p.y + q.y) % curve.p == 0:
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
    result: ECPoint = Point(x3, y3)
    require_on_curve(curve, result)
    return result


def scalar_mul(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
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


def point_order(curve: Curve, p: Point) -> int:
    validate_curve(curve)
    require_on_curve(curve, p)
    acc: ECPoint = None
    upper = int(curve.p + 1 + 2 * (curve.p**0.5)) + 2
    for k in range(1, upper + 1):
        acc = point_add(curve, acc, p)
        if acc is None:
            return k
    raise ValueError("order search failed")


def main():
    toy = Curve(p=97, a=0, b=1)
    g = Point(10, 15)
    small = Point(60, 46)
    print("Toy curve: y^2 = x^3 + 1 (mod 97)")
    print(f"G = {g}, order(G) = {point_order(toy, g)}")
    print(f"2G = {point_add(toy, g, g)}")
    print(f"7G = {scalar_mul(toy, 7, g)}")
    print()
    print("Small-subgroup caution (toy demo):")
    print(f"Q = {small}, order(Q) = {point_order(toy, small)}")
    k = 123
    shared = scalar_mul(toy, k, small)
    print(f"Shared secret with k={k} is k·Q = {shared}")
    print()

    from ecdsa.curves import SECP256k1

    secp = Curve(p=SECP256k1.curve.p(), a=SECP256k1.curve.a(), b=SECP256k1.curve.b())
    G = Point(SECP256k1.generator.x(), SECP256k1.generator.y())
    twoG = point_add(secp, G, G)
    print("secp256k1 sanity check (library cross-check recommended):")
    print(f"G = {G}")
    print(f"2G = {twoG}")


if __name__ == "__main__":
    main()
