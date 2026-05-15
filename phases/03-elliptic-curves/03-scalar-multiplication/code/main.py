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


def naf_digits(k: int) -> list[int]:
    if k < 0:
        raise ValueError("k must be >= 0")

    digits: list[int] = []
    while k > 0:
        if k & 1:
            u = 2 - (k & 3)
            digits.append(u)
            k -= u
        else:
            digits.append(0)
        k //= 2
    return digits


def wnaf_digits(k: int, w: int) -> list[int]:
    if k < 0:
        raise ValueError("k must be >= 0")
    if w < 2:
        raise ValueError("w must be >= 2")

    digits: list[int] = []
    two_w = 1 << w
    two_w_1 = 1 << (w - 1)

    while k > 0:
        if k & 1:
            u = k % two_w
            if u >= two_w_1:
                u -= two_w
            digits.append(u)
            k -= u
        else:
            digits.append(0)
        k //= 2
    return digits


def scalar_mul_double_and_add(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_double_and_add(curve, -k, point_neg(curve, p))

    acc: ECPoint = None
    addend: ECPoint = p

    while k > 0:
        if k & 1:
            acc = point_add(curve, acc, addend)
        addend = point_add(curve, addend, addend)
        k >>= 1

    return acc


def scalar_mul_naf(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_naf(curve, -k, point_neg(curve, p))

    digits = naf_digits(k)
    acc: ECPoint = None
    for d in reversed(digits):
        if acc is not None:
            acc = point_add(curve, acc, acc)
        if d == 1:
            acc = point_add(curve, acc, p)
        elif d == -1:
            acc = point_add(curve, acc, point_neg(curve, p))
    return acc


def _precompute_odd_multiples(curve: Curve, p: ECPoint, w: int) -> dict[int, ECPoint]:
    if p is None:
        return {}
    max_odd = (1 << (w - 1)) - 1
    pre: dict[int, ECPoint] = {1: p}
    if max_odd == 1:
        return pre

    two_p = point_add(curve, p, p)
    odd = 3
    while odd <= max_odd:
        pre[odd] = point_add(curve, pre[odd - 2], two_p)
        odd += 2
    return pre


def scalar_mul_wnaf(curve: Curve, k: int, p: ECPoint, w: int = 5) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_wnaf(curve, -k, point_neg(curve, p), w=w)

    digits = wnaf_digits(k, w)
    pre = _precompute_odd_multiples(curve, p, w)

    acc: ECPoint = None
    for d in reversed(digits):
        if acc is not None:
            acc = point_add(curve, acc, acc)
        if d != 0:
            add = pre[abs(d)]
            if d < 0:
                add = point_neg(curve, add)
            acc = point_add(curve, acc, add)
    return acc


def scalar_mul(curve: Curve, k: int, p: ECPoint, *, method: str = "wnaf", w: int = 5) -> ECPoint:
    if method == "double_and_add":
        return scalar_mul_double_and_add(curve, k, p)
    if method == "naf":
        return scalar_mul_naf(curve, k, p)
    if method == "wnaf":
        return scalar_mul_wnaf(curve, k, p, w=w)
    raise ValueError("unknown method")


def trace_double_and_add(k: int) -> str:
    if k < 0:
        raise ValueError("k must be >= 0")
    if k == 0:
        return ""
    ops: list[str] = []
    while k > 0:
        if k & 1:
            ops.append("A")
        ops.append("D")
        k >>= 1
    return "".join(ops)


def recover_bits_from_trace(trace: str) -> list[int]:
    bits: list[int] = []
    for ch in trace:
        if ch == "A":
            if not bits:
                bits.append(1)
            else:
                bits[-1] = 1
        elif ch == "D":
            bits.append(0)
        else:
            raise ValueError("invalid trace")
    if bits:
        bits.pop()
    return bits


def main():
    toy = Curve(p=97, a=0, b=1)
    g = Point(10, 15)
    k = 12345
    r1 = scalar_mul(toy, k, g, method="double_and_add")
    r2 = scalar_mul(toy, k, g, method="naf")
    r3 = scalar_mul(toy, k, g, method="wnaf", w=5)
    print("Toy curve: y^2 = x^3 + 1 (mod 97)")
    print(f"k = {k}")
    print(f"double-and-add: {r1}")
    print(f"NAF:            {r2}")
    print(f"wNAF(w=5):      {r3}")
    print()
    print("Side-channel toy trace (A=add, D=double):")
    t = trace_double_and_add(37)
    print(t)
    print("Recovered bits (LSB first):", recover_bits_from_trace(t))


if __name__ == "__main__":
    main()
