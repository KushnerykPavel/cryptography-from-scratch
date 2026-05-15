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


def point_double(curve: Curve, p: ECPoint) -> ECPoint:
    return point_add(curve, p, p)


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
        addend = point_double(curve, addend)
        k >>= 1

    return acc


def scalar_mul_montgomery_ladder(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_montgomery_ladder(curve, -k, point_neg(curve, p))

    r0: ECPoint = None
    r1: ECPoint = p

    for i in range(k.bit_length() - 1, -1, -1):
        bit = (k >> i) & 1
        if bit == 0:
            r1 = point_add(curve, r0, r1)
            r0 = point_double(curve, r0)
        else:
            r0 = point_add(curve, r0, r1)
            r1 = point_double(curve, r1)

    return r0


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


def trace_montgomery_ladder(k: int) -> str:
    if k < 0:
        raise ValueError("k must be >= 0")
    if k == 0:
        return ""
    return "AD" * k.bit_length()


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
    k = 37
    r_da = scalar_mul_double_and_add(toy, k, g)
    r_ml = scalar_mul_montgomery_ladder(toy, k, g)
    print("Toy curve: y^2 = x^3 + 1 (mod 97)")
    print(f"k = {k}")
    print(f"double-and-add:      {r_da}")
    print(f"Montgomery ladder:   {r_ml}")
    print()
    print("Side-channel toy traces (A=add, D=double):")
    t1 = trace_double_and_add(k)
    t2 = trace_montgomery_ladder(k)
    print(f"double-and-add:    {t1}")
    print(f"ladder (idealized): {t2}")
    print("Recovered bits from double-and-add trace (LSB first):", recover_bits_from_trace(t1))


if __name__ == "__main__":
    main()
