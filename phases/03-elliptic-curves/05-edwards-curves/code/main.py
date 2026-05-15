from __future__ import annotations

from dataclasses import dataclass


ED25519_P = 2**255 - 19
ED25519_A = (-1) % ED25519_P
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P
ED25519_L = 2**252 + 27742317777372353535851937790883648493
ED25519_SQRT_M1 = pow(2, (ED25519_P - 1) // 4, ED25519_P)
ED25519_B_ENC = bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"
)


@dataclass(frozen=True)
class Point:
    x: int
    y: int


@dataclass(frozen=True)
class ExtPoint:
    X: int
    Y: int
    Z: int
    T: int


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse does not exist")
    return pow(a, p - 2, p)


def _sqrt_mod_p_25519(a: int) -> int | None:
    p = ED25519_P
    a %= p
    if a == 0:
        return 0

    x = pow(a, (p + 3) // 8, p)
    if (x * x - a) % p != 0:
        x = (x * ED25519_SQRT_M1) % p
    if (x * x - a) % p != 0:
        return None
    return x


def ed25519_is_on_curve(p: Point) -> bool:
    x, y = p.x % ED25519_P, p.y % ED25519_P
    x2 = (x * x) % ED25519_P
    y2 = (y * y) % ED25519_P
    left = (ED25519_A * x2 + y2) % ED25519_P
    right = (1 + ED25519_D * x2 % ED25519_P * y2) % ED25519_P
    return left == right


def ed25519_identity() -> Point:
    return Point(0, 1)


def ed25519_neg(p: Point) -> Point:
    if not ed25519_is_on_curve(p):
        raise ValueError("point is not on curve")
    return Point((-p.x) % ED25519_P, p.y % ED25519_P)


def ed25519_add_affine(p: Point, q: Point) -> Point:
    if not ed25519_is_on_curve(p) or not ed25519_is_on_curve(q):
        raise ValueError("point is not on curve")

    x1, y1 = p.x % ED25519_P, p.y % ED25519_P
    x2, y2 = q.x % ED25519_P, q.y % ED25519_P
    x1x2 = (x1 * x2) % ED25519_P
    y1y2 = (y1 * y2) % ED25519_P
    x1y2 = (x1 * y2) % ED25519_P
    y1x2 = (y1 * x2) % ED25519_P

    den = (ED25519_D * x1x2 % ED25519_P * y1y2) % ED25519_P
    denom_x = (1 + den) % ED25519_P
    denom_y = (1 - den) % ED25519_P
    if denom_x == 0 or denom_y == 0:
        raise ValueError("affine formula hit a zero denominator")

    x3 = (x1y2 + y1x2) * mod_inv(denom_x, ED25519_P) % ED25519_P
    y3 = (y1y2 - ED25519_A * x1x2) * mod_inv(denom_y, ED25519_P) % ED25519_P
    r = Point(x3, y3)
    if not ed25519_is_on_curve(r):
        raise ValueError("addition produced an off-curve point")
    return r


def ed25519_to_ext(p: Point) -> ExtPoint:
    if not ed25519_is_on_curve(p):
        raise ValueError("point is not on curve")
    x, y = p.x % ED25519_P, p.y % ED25519_P
    return ExtPoint(x, y, 1, (x * y) % ED25519_P)


def ed25519_from_ext(p: ExtPoint) -> Point:
    zinv = mod_inv(p.Z, ED25519_P)
    x = (p.X * zinv) % ED25519_P
    y = (p.Y * zinv) % ED25519_P
    r = Point(x, y)
    if not ed25519_is_on_curve(r):
        raise ValueError("invalid extended point (not on curve)")
    return r


def ed25519_ext_identity() -> ExtPoint:
    return ExtPoint(0, 1, 1, 0)


def ed25519_ext_add(p: ExtPoint, q: ExtPoint) -> ExtPoint:
    pX, pY, pZ, pT = p.X % ED25519_P, p.Y % ED25519_P, p.Z % ED25519_P, p.T % ED25519_P
    qX, qY, qZ, qT = q.X % ED25519_P, q.Y % ED25519_P, q.Z % ED25519_P, q.T % ED25519_P

    A = (pY - pX) * (qY - qX) % ED25519_P
    B = (pY + pX) * (qY + qX) % ED25519_P
    C = (2 * ED25519_D % ED25519_P) * pT % ED25519_P * qT % ED25519_P
    D = (2 * pZ) % ED25519_P * qZ % ED25519_P
    E = (B - A) % ED25519_P
    F = (D - C) % ED25519_P
    G = (D + C) % ED25519_P
    H = (B + A) % ED25519_P
    X3 = E * F % ED25519_P
    Y3 = G * H % ED25519_P
    T3 = E * H % ED25519_P
    Z3 = F * G % ED25519_P
    return ExtPoint(X3, Y3, Z3, T3)


def ed25519_ext_double(p: ExtPoint) -> ExtPoint:
    pX, pY, pZ = p.X % ED25519_P, p.Y % ED25519_P, p.Z % ED25519_P

    A = (pX * pX) % ED25519_P
    B = (pY * pY) % ED25519_P
    C = (2 * pZ * pZ) % ED25519_P
    D = (-A) % ED25519_P
    E = ((pX + pY) * (pX + pY) - A - B) % ED25519_P
    G = (D + B) % ED25519_P
    F = (G - C) % ED25519_P
    H = (D - B) % ED25519_P
    X3 = E * F % ED25519_P
    Y3 = G * H % ED25519_P
    T3 = E * H % ED25519_P
    Z3 = F * G % ED25519_P
    return ExtPoint(X3, Y3, Z3, T3)


def ed25519_scalar_mul(k: int, p: ExtPoint) -> ExtPoint:
    if k == 0:
        return ed25519_ext_identity()
    if k < 0:
        return ed25519_scalar_mul(-k, ed25519_ext_neg(p))

    acc = ed25519_ext_identity()
    addend = p
    while k > 0:
        if k & 1:
            acc = ed25519_ext_add(acc, addend)
        addend = ed25519_ext_double(addend)
        k >>= 1
    return acc


def ed25519_ext_neg(p: ExtPoint) -> ExtPoint:
    return ExtPoint((-p.X) % ED25519_P, p.Y % ED25519_P, p.Z % ED25519_P, (-p.T) % ED25519_P)


def ed25519_encode(p: Point) -> bytes:
    if not ed25519_is_on_curve(p):
        raise ValueError("point is not on curve")
    x, y = p.x % ED25519_P, p.y % ED25519_P
    out = bytearray(y.to_bytes(32, "little"))
    out[31] |= (x & 1) << 7
    return bytes(out)


def ed25519_decode(enc: bytes) -> Point:
    if len(enc) != 32:
        raise ValueError("encoding must be 32 bytes")
    sign = (enc[31] >> 7) & 1
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    if y >= ED25519_P:
        raise ValueError("invalid encoding (y out of range)")

    y2 = (y * y) % ED25519_P
    u = (y2 - 1) % ED25519_P
    v = (ED25519_D * y2 + 1) % ED25519_P
    x2 = u * mod_inv(v, ED25519_P) % ED25519_P
    x = _sqrt_mod_p_25519(x2)
    if x is None:
        raise ValueError("invalid encoding (no square root)")
    if x & 1 != sign:
        x = (-x) % ED25519_P

    p = Point(x, y)
    if not ed25519_is_on_curve(p):
        raise ValueError("decoded point is not on curve")
    return p


def ed25519_is_in_prime_subgroup(p: Point) -> bool:
    if not ed25519_is_on_curve(p):
        return False
    r = ed25519_scalar_mul(ED25519_L, ed25519_to_ext(p))
    return ed25519_from_ext(r) == ed25519_identity()


def ed25519_clear_cofactor(p: Point) -> Point:
    if not ed25519_is_on_curve(p):
        raise ValueError("point is not on curve")
    return ed25519_from_ext(ed25519_scalar_mul(8, ed25519_to_ext(p)))


def main():
    b = ed25519_decode(ED25519_B_ENC)
    b_ext = ed25519_to_ext(b)

    print("Ed25519 basepoint (affine):")
    print("x =", b.x)
    print("y =", b.y)
    print()

    two_b = ed25519_from_ext(ed25519_scalar_mul(2, b_ext))
    three_b = ed25519_from_ext(ed25519_scalar_mul(3, b_ext))
    print("2B enc =", ed25519_encode(two_b).hex())
    print("3B enc =", ed25519_encode(three_b).hex())
    print("l·B == identity?", ed25519_is_in_prime_subgroup(b), "and", ed25519_from_ext(ed25519_scalar_mul(ED25519_L, b_ext)) == ed25519_identity())
    print()

    torsion_enc = bytes.fromhex(
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
    )
    t = ed25519_decode(torsion_enc)
    print("Torsion point T (order 8):")
    print("T enc =", torsion_enc.hex())
    print("8T == identity?", ed25519_from_ext(ed25519_scalar_mul(8, ed25519_to_ext(t))) == ed25519_identity())
    print()
    print("Small-subgroup confinement demo (never do this in production):")
    secret = 123456789
    shared = ed25519_from_ext(ed25519_scalar_mul(secret, ed25519_to_ext(t)))
    print("secret mod 8 =", secret % 8)
    print("shared = secret·T enc =", ed25519_encode(shared).hex())


if __name__ == "__main__":
    main()
