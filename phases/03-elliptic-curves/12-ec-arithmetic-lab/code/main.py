from __future__ import annotations

from dataclasses import dataclass


class ECError(ValueError):
    pass


class InvalidCurveError(ECError):
    pass


class InvalidPointError(ECError):
    pass


class NoInverseError(ECError):
    pass


class NoSquareRootError(ECError):
    pass


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


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ECError("x must be >= 0")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0 and b == 0:
        return 0, 0, 0

    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    if a < 0:
        old_s = -old_s
    if b < 0:
        old_t = -old_t

    return old_r, old_s, old_t


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise NoInverseError("inverse does not exist")
    g, x, _ = egcd(a, p)
    if g != 1:
        raise NoInverseError("inverse does not exist")
    return x % p


def curve_is_singular(curve: Curve) -> bool:
    p = curve.p
    return (4 * pow(curve.a, 3, p) + 27 * pow(curve.b, 2, p)) % p == 0


def validate_curve(curve: Curve) -> None:
    if curve.p <= 3:
        raise InvalidCurveError("p must be > 3 for short Weierstrass form")
    if curve_is_singular(curve):
        raise InvalidCurveError("curve is singular")


def is_on_curve(curve: Curve, point: ECPoint) -> bool:
    validate_curve(curve)
    if point is None:
        return True
    x, y = point.x % curve.p, point.y % curve.p
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def require_on_curve(curve: Curve, point: ECPoint) -> None:
    if not is_on_curve(curve, point):
        raise InvalidPointError("point is not on curve")


def point_normalize(curve: Curve, point: ECPoint) -> ECPoint:
    validate_curve(curve)
    if point is None:
        return None
    return Point(point.x % curve.p, point.y % curve.p)


def point_neg(curve: Curve, point: ECPoint) -> ECPoint:
    validate_curve(curve)
    if point is None:
        return None
    require_on_curve(curve, point)
    p = point_normalize(curve, point)
    if p is None:
        return None
    return Point(p.x, (-p.y) % curve.p)


def point_add_affine(curve: Curve, p: ECPoint, q: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    require_on_curve(curve, q)
    p = point_normalize(curve, p)
    q = point_normalize(curve, q)

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
    r: ECPoint = Point(x3, y3)
    require_on_curve(curve, r)
    return r


@dataclass(frozen=True)
class JacobianPoint:
    x: int
    y: int
    z: int


def jacobian_from_affine(curve: Curve, p: ECPoint) -> JacobianPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None:
        return JacobianPoint(0, 1, 0)
    p = point_normalize(curve, p)
    if p is None:
        return JacobianPoint(0, 1, 0)
    return JacobianPoint(p.x, p.y, 1)


def jacobian_to_affine(curve: Curve, p: JacobianPoint) -> ECPoint:
    validate_curve(curve)
    if p.z % curve.p == 0:
        return None
    zinv = mod_inv(p.z, curve.p)
    z2 = (zinv * zinv) % curve.p
    z3 = (z2 * zinv) % curve.p
    x = (p.x * z2) % curve.p
    y = (p.y * z3) % curve.p
    out: ECPoint = Point(x, y)
    require_on_curve(curve, out)
    return out


def jacobian_double(curve: Curve, p: JacobianPoint) -> JacobianPoint:
    validate_curve(curve)
    mod = curve.p
    if p.z % mod == 0 or p.y % mod == 0:
        return JacobianPoint(0, 1, 0)

    x1, y1, z1 = p.x % mod, p.y % mod, p.z % mod
    yy = (y1 * y1) % mod
    s = (4 * x1 * yy) % mod
    m = (3 * x1 * x1 + curve.a * pow(z1, 4, mod)) % mod
    x3 = (m * m - 2 * s) % mod
    y3 = (m * (s - x3) - 8 * yy * yy) % mod
    z3 = (2 * y1 * z1) % mod
    return JacobianPoint(x3, y3, z3)


def jacobian_add_mixed(curve: Curve, p: JacobianPoint, q: ECPoint) -> JacobianPoint:
    validate_curve(curve)
    require_on_curve(curve, q)
    mod = curve.p

    if p.z % mod == 0:
        return jacobian_from_affine(curve, q)
    if q is None:
        return p

    q = point_normalize(curve, q)
    if q is None:
        return p

    x1, y1, z1 = p.x % mod, p.y % mod, p.z % mod
    x2, y2 = q.x % mod, q.y % mod

    z1z1 = (z1 * z1) % mod
    u2 = (x2 * z1z1) % mod
    s2 = (y2 * z1z1 * z1) % mod

    h = (u2 - x1) % mod
    r = (s2 - y1) % mod

    if h == 0:
        if r == 0:
            return jacobian_double(curve, p)
        return JacobianPoint(0, 1, 0)

    hh = (h * h) % mod
    hhh = (h * hh) % mod
    v = (x1 * hh) % mod

    x3 = (r * r - hhh - 2 * v) % mod
    y3 = (r * (v - x3) - y1 * hhh) % mod
    z3 = (z1 * h) % mod
    return JacobianPoint(x3, y3, z3)


def jacobian_add(curve: Curve, p: JacobianPoint, q: JacobianPoint) -> JacobianPoint:
    validate_curve(curve)
    mod = curve.p

    if p.z % mod == 0:
        return q
    if q.z % mod == 0:
        return p

    x1, y1, z1 = p.x % mod, p.y % mod, p.z % mod
    x2, y2, z2 = q.x % mod, q.y % mod, q.z % mod

    z1z1 = (z1 * z1) % mod
    z2z2 = (z2 * z2) % mod
    u1 = (x1 * z2z2) % mod
    u2 = (x2 * z1z1) % mod
    s1 = (y1 * z2 * z2z2) % mod
    s2 = (y2 * z1 * z1z1) % mod

    h = (u2 - u1) % mod
    r = (s2 - s1) % mod

    if h == 0:
        if r == 0:
            return jacobian_double(curve, p)
        return JacobianPoint(0, 1, 0)

    hh = (h * h) % mod
    hhh = (h * hh) % mod
    v = (u1 * hh) % mod

    x3 = (r * r - hhh - 2 * v) % mod
    y3 = (r * (v - x3) - s1 * hhh) % mod
    z3 = (h * z1 * z2) % mod
    return JacobianPoint(x3, y3, z3)

def scalar_mul_affine(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_affine(curve, -k, point_neg(curve, p))

    acc: ECPoint = None
    addend: ECPoint = p

    while k > 0:
        if k & 1:
            acc = point_add_affine(curve, acc, addend)
        addend = point_add_affine(curve, addend, addend)
        k >>= 1

    return acc


def scalar_mul_montgomery_ladder_affine(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_montgomery_ladder_affine(curve, -k, point_neg(curve, p))

    r0: ECPoint = None
    r1: ECPoint = p
    for i in range(k.bit_length() - 1, -1, -1):
        bit = (k >> i) & 1
        if bit == 0:
            r1 = point_add_affine(curve, r0, r1)
            r0 = point_add_affine(curve, r0, r0)
        else:
            r0 = point_add_affine(curve, r0, r1)
            r1 = point_add_affine(curve, r1, r1)
    return r0


def naf_digits(k: int) -> list[int]:
    if k < 0:
        raise ECError("k must be >= 0")
    digits: list[int] = []
    while k:
        if k & 1:
            u = 2 - (k & 3)
            digits.append(u)
            k -= u
        else:
            digits.append(0)
        k //= 2
    return digits


def scalar_mul_naf_affine(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_naf_affine(curve, -k, point_neg(curve, p))

    digits = naf_digits(k)
    acc: ECPoint = None
    neg = point_neg(curve, p)
    for d in reversed(digits):
        if acc is not None:
            acc = point_add_affine(curve, acc, acc)
        if d == 1:
            acc = point_add_affine(curve, acc, p)
        elif d == -1:
            acc = point_add_affine(curve, acc, neg)
    return acc


def wnaf_digits(k: int, w: int) -> list[int]:
    if k < 0:
        raise ECError("k must be >= 0")
    if w < 2:
        raise ECError("w must be >= 2")

    digits: list[int] = []
    two_w = 1 << w
    two_w_1 = 1 << (w - 1)

    while k:
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


def _precompute_odd_multiples(curve: Curve, p: ECPoint, w: int) -> dict[int, ECPoint]:
    if p is None:
        return {}
    max_odd = (1 << (w - 1)) - 1
    pre: dict[int, ECPoint] = {1: p}
    if max_odd == 1:
        return pre
    two_p = point_add_affine(curve, p, p)
    odd = 3
    while odd <= max_odd:
        pre[odd] = point_add_affine(curve, pre[odd - 2], two_p)
        odd += 2
    return pre


def scalar_mul_wnaf_affine(curve: Curve, k: int, p: ECPoint, w: int = 5) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_wnaf_affine(curve, -k, point_neg(curve, p), w=w)

    digits = wnaf_digits(k, w)
    table = _precompute_odd_multiples(curve, p, w)
    neg_table = {d: point_neg(curve, pt) for d, pt in table.items()}

    acc: ECPoint = None
    for d in reversed(digits):
        if acc is not None:
            acc = point_add_affine(curve, acc, acc)
        if d == 0:
            continue
        if d > 0:
            acc = point_add_affine(curve, acc, table[d])
        else:
            acc = point_add_affine(curve, acc, neg_table[-d])
    return acc


def scalar_mul_jacobian(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_jacobian(curve, -k, point_neg(curve, p))

    acc = JacobianPoint(0, 1, 0)
    addend = jacobian_from_affine(curve, p)

    while k:
        if k & 1:
            acc = jacobian_add(curve, acc, addend)
        addend = jacobian_double(curve, addend)
        k >>= 1

    return jacobian_to_affine(curve, acc)


def point_order(curve: Curve, p: Point, upper_bound: int | None = None) -> int:
    validate_curve(curve)
    require_on_curve(curve, p)
    bound = upper_bound
    if bound is None:
        bound = int(curve.p + 1 + 2 * (curve.p**0.5)) + 2

    acc: ECPoint = None
    for k in range(1, bound + 1):
        acc = point_add_affine(curve, acc, p)
        if acc is None:
            return k
    raise ECError("order search failed")


def legendre_symbol(a: int, p: int) -> int:
    a %= p
    if a == 0:
        return 0
    ls = pow(a, (p - 1) // 2, p)
    if ls == p - 1:
        return -1
    return ls


def mod_sqrt(a: int, p: int) -> int:
    if p <= 2 or p % 2 == 0:
        raise ECError("p must be an odd prime")

    a %= p
    if a == 0:
        return 0
    if legendre_symbol(a, p) != 1:
        raise NoSquareRootError("no square root exists")
    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        if (x * x) % p != a:
            raise NoSquareRootError("no square root exists")
        return x

    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

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
        while t2i != 1:
            i += 1
            if i >= m:
                raise NoSquareRootError("no square root exists")
            t2i = (t2i * t2i) % p

        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p

    if (r * r) % p != a:
        raise NoSquareRootError("no square root exists")
    return r


def lift_x(curve: Curve, x: int, y_parity: int) -> Point:
    validate_curve(curve)
    if y_parity not in {0, 1}:
        raise ECError("y_parity must be 0 or 1")
    p = curve.p
    x %= p
    rhs = (pow(x, 3, p) + (curve.a * x) + curve.b) % p
    y = mod_sqrt(rhs, p)
    if (y & 1) != y_parity:
        y = (-y) % p
    out = Point(x, y)
    require_on_curve(curve, out)
    return out


def coordinate_size_bytes(curve: Curve) -> int:
    validate_curve(curve)
    return (curve.p.bit_length() + 7) // 8


def serialize_uncompressed(curve: Curve, point: ECPoint) -> bytes:
    require_on_curve(curve, point)
    if point is None:
        raise InvalidPointError("cannot serialize point at infinity")
    point = point_normalize(curve, point)
    if point is None:
        raise InvalidPointError("cannot serialize point at infinity")
    size = coordinate_size_bytes(curve)
    return b"\x04" + int_to_bytes(point.x, size) + int_to_bytes(point.y, size)


def serialize_compressed(curve: Curve, point: ECPoint) -> bytes:
    require_on_curve(curve, point)
    if point is None:
        raise InvalidPointError("cannot serialize point at infinity")
    point = point_normalize(curve, point)
    if point is None:
        raise InvalidPointError("cannot serialize point at infinity")
    size = coordinate_size_bytes(curve)
    prefix = 2 + (point.y & 1)
    return bytes([prefix]) + int_to_bytes(point.x, size)


def parse_point_sec1(curve: Curve, data: bytes) -> Point:
    validate_curve(curve)
    size = coordinate_size_bytes(curve)

    if len(data) == 1 + size and data[0] in {2, 3}:
        x = bytes_to_int(data[1:])
        parity = data[0] & 1
        return lift_x(curve, x, parity)

    if len(data) == 1 + 2 * size and data[0] == 4:
        x = bytes_to_int(data[1 : 1 + size])
        y = bytes_to_int(data[1 + size : 1 + 2 * size])
        p = Point(x, y)
        require_on_curve(curve, p)
        normalized = point_normalize(curve, p)
        if normalized is None:
            raise InvalidPointError("point is not on curve")
        return normalized

    raise InvalidPointError("invalid SEC1 encoding")


def main() -> None:
    toy = Curve(p=97, a=0, b=1)
    g = Point(10, 15)
    k = 37
    print("Curve lab demo (toy curve)")
    print("E: y^2 = x^3 + 1 (mod 97)")
    print("G =", g)
    print("k =", k)
    print("k·G (affine double-and-add) =", scalar_mul_affine(toy, k, g))
    print("k·G (Montgomery ladder)     =", scalar_mul_montgomery_ladder_affine(toy, k, g))
    print("k·G (wNAF)                  =", scalar_mul_wnaf_affine(toy, k, g, w=5))
    print("k·G (Jacobian)              =", scalar_mul_jacobian(toy, k, g))


if __name__ == "__main__":
    main()
