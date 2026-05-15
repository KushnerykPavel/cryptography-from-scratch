from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int


@dataclass(frozen=True)
class PointFp:
    x: int
    y: int


ECPointFp = PointFp | None


TOY_P = 103
TOY_A = 1
TOY_B = 0
TOY_R = 13
TOY_CURVE = Curve(p=TOY_P, a=TOY_A, b=TOY_B)

TOY_G1_GENERATOR = PointFp(18, 44)


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


def is_on_curve_fp(curve: Curve, point: ECPointFp) -> bool:
    if point is None:
        return True
    x, y = point.x % curve.p, point.y % curve.p
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def require_on_curve_fp(curve: Curve, point: ECPointFp) -> None:
    if not is_on_curve_fp(curve, point):
        raise ValueError("point is not on curve")


def point_neg_fp(curve: Curve, point: ECPointFp) -> ECPointFp:
    if point is None:
        return None
    require_on_curve_fp(curve, point)
    return PointFp(point.x % curve.p, (-point.y) % curve.p)


def point_add_fp(curve: Curve, p: ECPointFp, q: ECPointFp) -> ECPointFp:
    require_on_curve_fp(curve, p)
    require_on_curve_fp(curve, q)

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
    result: ECPointFp = PointFp(x3, y3)
    require_on_curve_fp(curve, result)
    return result


def scalar_mul_fp(curve: Curve, k: int, p: ECPointFp) -> ECPointFp:
    require_on_curve_fp(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_fp(curve, -k, point_neg_fp(curve, p))

    acc: ECPointFp = None
    addend: ECPointFp = p

    while k > 0:
        if k & 1:
            acc = point_add_fp(curve, acc, addend)
        addend = point_add_fp(curve, addend, addend)
        k >>= 1

    return acc


@dataclass(frozen=True)
class Fp2:
    a: int
    b: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "a", self.a % TOY_P)
        object.__setattr__(self, "b", self.b % TOY_P)

    def is_zero(self) -> bool:
        return (self.a % TOY_P) == 0 and (self.b % TOY_P) == 0

    def conjugate(self) -> Fp2:
        return Fp2(self.a, -self.b)

    def __add__(self, other: Fp2) -> Fp2:
        return Fp2(self.a + other.a, self.b + other.b)

    def __sub__(self, other: Fp2) -> Fp2:
        return Fp2(self.a - other.a, self.b - other.b)

    def __neg__(self) -> Fp2:
        return Fp2(-self.a, -self.b)

    def __mul__(self, other: Fp2) -> Fp2:
        a, b, c, d = self.a, self.b, other.a, other.b
        return Fp2(a * c - b * d, a * d + b * c)

    def inv(self) -> Fp2:
        denom = (self.a * self.a + self.b * self.b) % TOY_P
        if denom == 0:
            raise ZeroDivisionError("inverse does not exist")
        inv_denom = mod_inv(denom, TOY_P)
        return Fp2(self.a * inv_denom, -self.b * inv_denom)

    def __truediv__(self, other: Fp2) -> Fp2:
        return self * other.inv()

    def __pow__(self, e: int) -> Fp2:
        if e < 0:
            return (self.inv()) ** (-e)

        acc = Fp2(1, 0)
        base = self
        while e > 0:
            if e & 1:
                acc = acc * base
            base = base * base
            e >>= 1
        return acc


@dataclass(frozen=True)
class PointFp2:
    x: Fp2
    y: Fp2


ECPointFp2 = PointFp2 | None

FP2_ZERO = Fp2(0, 0)
FP2_ONE = Fp2(1, 0)
FP2_I = Fp2(0, 1)


def fp_to_fp2(x: int) -> Fp2:
    return Fp2(x, 0)


def point_fp_to_fp2(point: ECPointFp) -> ECPointFp2:
    if point is None:
        return None
    return PointFp2(fp_to_fp2(point.x), fp_to_fp2(point.y))


def is_on_curve_fp2(curve: Curve, point: ECPointFp2) -> bool:
    if point is None:
        return True
    x, y = point.x, point.y
    a = fp_to_fp2(curve.a)
    b = fp_to_fp2(curve.b)
    return (y * y - (x * x * x + a * x + b)).is_zero()


def require_on_curve_fp2(curve: Curve, point: ECPointFp2) -> None:
    if not is_on_curve_fp2(curve, point):
        raise ValueError("point is not on curve")


def point_neg_fp2(curve: Curve, point: ECPointFp2) -> ECPointFp2:
    if point is None:
        return None
    require_on_curve_fp2(curve, point)
    return PointFp2(point.x, -point.y)


def point_add_fp2(curve: Curve, p: ECPointFp2, q: ECPointFp2) -> ECPointFp2:
    require_on_curve_fp2(curve, p)
    require_on_curve_fp2(curve, q)

    if p is None:
        return q
    if q is None:
        return p

    if p.x == q.x and (p.y + q.y).is_zero():
        return None

    if p != q:
        lam = (q.y - p.y) / (q.x - p.x)
    else:
        if p.y.is_zero():
            return None
        lam = (Fp2(3, 0) * p.x * p.x + fp_to_fp2(curve.a)) / (Fp2(2, 0) * p.y)

    x3 = lam * lam - p.x - q.x
    y3 = lam * (p.x - x3) - p.y
    result: ECPointFp2 = PointFp2(x3, y3)
    require_on_curve_fp2(curve, result)
    return result


def scalar_mul_fp2(curve: Curve, k: int, p: ECPointFp2) -> ECPointFp2:
    require_on_curve_fp2(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_fp2(curve, -k, point_neg_fp2(curve, p))

    acc: ECPointFp2 = None
    addend: ECPointFp2 = p

    while k > 0:
        if k & 1:
            acc = point_add_fp2(curve, acc, addend)
        addend = point_add_fp2(curve, addend, addend)
        k >>= 1

    return acc


def distortion_map(point: ECPointFp2) -> ECPointFp2:
    if point is None:
        return None
    x, y = point.x, point.y
    return PointFp2(-x, FP2_I * y)


def _line_value(curve: Curve, r: PointFp2, s: PointFp2, q: PointFp2) -> Fp2:
    xq, yq = q.x, q.y
    x1, y1 = r.x, r.y
    x2, y2 = s.x, s.y

    if x1 == x2 and (y1 + y2).is_zero():
        return xq - x1

    if r != s:
        lam = (y2 - y1) / (x2 - x1)
    else:
        if y1.is_zero():
            return xq - x1
        lam = (Fp2(3, 0) * x1 * x1 + fp_to_fp2(curve.a)) / (Fp2(2, 0) * y1)

    return yq - y1 - lam * (xq - x1)


def miller_function(curve: Curve, p: ECPointFp2, q: ECPointFp2, n: int) -> Fp2:
    require_on_curve_fp2(curve, p)
    require_on_curve_fp2(curve, q)

    if p is None or q is None:
        return FP2_ONE

    v: ECPointFp2 = p
    f = FP2_ONE

    bits = bin(n)[3:]
    for bit in bits:
        if v is None:
            raise ValueError("unexpected point at infinity during Miller loop")

        lv = _line_value(curve, v, v, q)
        v2 = point_add_fp2(curve, v, v)
        denom = FP2_ONE if v2 is None else (q.x - v2.x)
        f = f * f * (lv / denom)
        v = v2

        if bit == "1":
            if v is None:
                lv = q.x - p.x
            else:
                lv = _line_value(curve, v, p, q)

            v3 = point_add_fp2(curve, v, p)
            denom = FP2_ONE if v3 is None else (q.x - v3.x)
            f = f * (lv / denom)
            v = v3

    return f


def reduced_tate_pairing(curve: Curve, r: int, p: ECPointFp2, q: ECPointFp2) -> Fp2:
    require_on_curve_fp2(curve, p)
    require_on_curve_fp2(curve, q)

    if p is None or q is None:
        return FP2_ONE

    if scalar_mul_fp2(curve, r, p) is not None:
        raise ValueError("p is not r-torsion")
    if scalar_mul_fp2(curve, r, q) is not None:
        raise ValueError("q is not r-torsion")

    f = miller_function(curve, p, q, r)
    exp = (pow(curve.p, 2) - 1) // r
    return f**exp


def weil_pairing(curve: Curve, r: int, p: ECPointFp2, q: ECPointFp2) -> Fp2:
    require_on_curve_fp2(curve, p)
    require_on_curve_fp2(curve, q)

    if p is None or q is None:
        return FP2_ONE

    if scalar_mul_fp2(curve, r, p) is not None:
        raise ValueError("p is not r-torsion")
    if scalar_mul_fp2(curve, r, q) is not None:
        raise ValueError("q is not r-torsion")

    s: ECPointFp2 = None
    for x in range(curve.p):
        rhs = (x * x * x + curve.a * x + curve.b) % curve.p
        for y in range(curve.p):
            if (y * y - rhs) % curve.p != 0:
                continue
            candidate = point_fp_to_fp2(PointFp(x, y))
            if candidate is None:
                continue
            if scalar_mul_fp2(curve, r, candidate) is None:
                continue
            if candidate == p or candidate == q:
                continue
            if candidate == point_neg_fp2(curve, p) or candidate == point_neg_fp2(curve, q):
                continue
            if point_add_fp2(curve, q, candidate) is None:
                continue
            if point_add_fp2(curve, p, point_neg_fp2(curve, candidate)) is None:
                continue
            s = candidate
            break
        if s is not None:
            break

    if s is None:
        raise ValueError("failed to find a suitable auxiliary point")

    num = miller_function(curve, p, point_add_fp2(curve, q, s), r) / miller_function(curve, p, s, r)
    den = miller_function(curve, q, point_add_fp2(curve, p, point_neg_fp2(curve, s)), r) / miller_function(
        curve, q, point_neg_fp2(curve, s), r
    )
    return num / den


def fp2_to_json(x: Fp2) -> list[int]:
    return [x.a % TOY_P, x.b % TOY_P]


def point_fp2_to_json(point: ECPointFp2) -> list[list[int]] | None:
    if point is None:
        return None
    return [fp2_to_json(point.x), fp2_to_json(point.y)]


def main() -> None:
    p = TOY_G1_GENERATOR
    if scalar_mul_fp(TOY_CURVE, TOY_R, p) is not None:
        raise AssertionError("toy generator does not have order r")

    p2 = point_fp_to_fp2(p)
    q2 = distortion_map(p2)

    w = weil_pairing(TOY_CURVE, TOY_R, p2, q2)
    t = reduced_tate_pairing(TOY_CURVE, TOY_R, p2, q2)

    print("toy pairing demo (educational)")
    print("p =", (p.x, p.y))
    print("q = distortion(p)")
    print("weil(p, q) =", fp2_to_json(w))
    print("tate(p, q) =", fp2_to_json(t))


if __name__ == "__main__":
    main()
