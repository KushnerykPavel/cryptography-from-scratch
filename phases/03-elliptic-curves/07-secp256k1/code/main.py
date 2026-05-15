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


SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
SECP256K1 = Curve(p=SECP256K1_P, a=SECP256K1_A, b=SECP256K1_B)


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


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


def scalar_mul(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    return scalar_mul_double_and_add(curve, k, p)


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


def mod_sqrt_p_3mod4(a: int, p: int) -> int:
    if p % 4 != 3:
        raise ValueError("p must be 3 (mod 4)")
    a %= p
    if a == 0:
        return 0
    x = pow(a, (p + 1) // 4, p)
    if (x * x) % p != a:
        raise ValueError("no square root exists")
    return x


def lift_x_secp256k1(x: int, y_parity: int) -> Point:
    if y_parity not in {0, 1}:
        raise ValueError("y_parity must be 0 or 1")
    p = SECP256K1_P
    x %= p
    rhs = (pow(x, 3, p) + SECP256K1_B) % p
    y = mod_sqrt_p_3mod4(rhs, p)
    if (y & 1) != y_parity:
        y = (-y) % p
    point = Point(x, y)
    require_on_curve(SECP256K1, point)
    return point


def serialize_uncompressed(point: ECPoint) -> bytes:
    require_on_curve(SECP256K1, point)
    if point is None:
        raise ValueError("cannot serialize point at infinity")
    return b"\x04" + int_to_bytes(point.x, 32) + int_to_bytes(point.y, 32)


def serialize_compressed(point: ECPoint) -> bytes:
    require_on_curve(SECP256K1, point)
    if point is None:
        raise ValueError("cannot serialize point at infinity")
    prefix = 2 + (point.y & 1)
    return bytes([prefix]) + int_to_bytes(point.x, 32)


def parse_public_key(data: bytes) -> Point:
    if len(data) == 33 and data[0] in {2, 3}:
        x = bytes_to_int(data[1:])
        y_parity = data[0] & 1
        return lift_x_secp256k1(x, y_parity)

    if len(data) == 65 and data[0] == 4:
        x = bytes_to_int(data[1:33])
        y = bytes_to_int(data[33:65])
        p = Point(x, y)
        require_on_curve(SECP256K1, p)
        return p

    raise ValueError("invalid public key encoding")


def validate_private_key(k: int) -> None:
    if not (1 <= k < SECP256K1_N):
        raise ValueError("private key must be in [1, n-1]")


def pubkey_from_privkey(k: int) -> Point:
    validate_private_key(k)
    p = scalar_mul(SECP256K1, k, SECP256K1_G)
    if p is None:
        raise AssertionError("unexpected infinity from nonzero scalar * G")
    return p


def main() -> None:
    k = 1
    pub = pubkey_from_privkey(k)
    print("secp256k1 public key demo")
    print(f"k = {k}")
    print("Q = k·G")
    print("x =", hex(pub.x))
    print("y =", hex(pub.y))
    print("compressed =", serialize_compressed(pub).hex())
    print("uncompressed =", serialize_uncompressed(pub).hex())


if __name__ == "__main__":
    main()
