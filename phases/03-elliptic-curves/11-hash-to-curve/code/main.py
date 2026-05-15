from __future__ import annotations

import hashlib
import math
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


P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = (P256_P - 3) % P256_P
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256 = Curve(p=P256_P, a=P256_A, b=P256_B)

P256_SSWU_Z = (-10) % P256_P
P256_SSWU_C1 = (P256_P - 3) // 4
P256_SSWU_C2 = pow((-P256_SSWU_Z) % P256_P, (P256_P + 1) // 4, P256_P)


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def i2osp(x: int, length: int) -> bytes:
    return int_to_bytes(x, length)


def os2ip(b: bytes) -> int:
    return bytes_to_int(b)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor requires equal lengths")
    return bytes(x ^ y for x, y in zip(a, b))


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


def inv0(a: int, p: int) -> int:
    a %= p
    if a == 0:
        return 0
    return mod_inv(a, p)


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


def sgn0_fp(x: int) -> int:
    return x & 1


def is_square_fp(x: int, p: int) -> bool:
    x %= p
    if x == 0:
        return True
    return pow(x, (p - 1) // 2, p) == 1


def sqrt_3mod4_fp(x: int, p: int) -> int:
    if p % 4 != 3:
        raise ValueError("p must be 3 (mod 4)")
    return pow(x % p, (p + 1) // 4, p)


def sqrt_ratio_3mod4_fp(u: int, v: int, *, p: int, z: int) -> tuple[bool, int]:
    if v % p == 0:
        return False, 0

    c1 = (p - 3) // 4
    c2 = sqrt_3mod4_fp((-z) % p, p)

    tv1 = pow(v, 2, p)
    tv2 = (u * v) % p
    tv1 = (tv1 * tv2) % p
    y1 = pow(tv1, c1, p)
    y1 = (y1 * tv2) % p
    y2 = (y1 * c2) % p
    tv3 = pow(y1, 2, p)
    tv3 = (tv3 * v) % p
    is_qr = tv3 == (u % p)
    y = y1 if is_qr else y2
    return is_qr, y


def map_to_curve_simple_swu_p256(u: int) -> Point:
    p = P256_P
    a = P256_A
    b = P256_B
    z = P256_SSWU_Z

    u %= p
    tv1 = (u * u) % p
    tv1 = (z * tv1) % p
    tv2 = (tv1 * tv1) % p
    tv2 = (tv2 + tv1) % p
    tv3 = (tv2 + 1) % p
    tv3 = (b * tv3) % p
    tv4 = (-tv2) % p if tv2 != 0 else z
    tv4 = (a * tv4) % p
    tv2 = (tv3 * tv3) % p
    tv6 = (tv4 * tv4) % p
    tv5 = (a * tv6) % p
    tv2 = (tv2 + tv5) % p
    tv2 = (tv2 * tv3) % p
    tv6 = (tv6 * tv4) % p
    tv5 = (b * tv6) % p
    tv2 = (tv2 + tv5) % p
    x = (tv1 * tv3) % p
    is_gx1_square, y1 = sqrt_ratio_3mod4_fp(tv2, tv6, p=p, z=z)
    y = (tv1 * u) % p
    y = (y * y1) % p
    if is_gx1_square:
        x = tv3
        y = y1
    if sgn0_fp(u) != sgn0_fp(y):
        y = (-y) % p
    x = (x * inv0(tv4, p)) % p
    point = Point(x % p, y % p)
    require_on_curve(P256, point)
    return point


def expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int, *, hash_fn=hashlib.sha256) -> bytes:
    if len(dst) > 255:
        dst = hash_fn(b"H2C-OVERSIZE-DST-" + dst).digest()
    if len(dst) > 255:
        raise ValueError("DST too long")

    b_in_bytes = hash_fn().digest_size
    s_in_bytes = hash_fn().block_size
    ell = math.ceil(len_in_bytes / b_in_bytes)
    if ell > 255 or len_in_bytes > 65535:
        raise ValueError("invalid len_in_bytes")

    dst_prime = dst + i2osp(len(dst), 1)
    z_pad = b"\x00" * s_in_bytes
    l_i_b_str = i2osp(len_in_bytes, 2)
    b0 = hash_fn(z_pad + msg + l_i_b_str + b"\x00" + dst_prime).digest()
    b1 = hash_fn(b0 + b"\x01" + dst_prime).digest()

    uniform_bytes = bytearray(b1)
    bi = b1
    for i in range(2, ell + 1):
        bi = hash_fn(xor_bytes(b0, bi) + i2osp(i, 1) + dst_prime).digest()
        uniform_bytes.extend(bi)

    return bytes(uniform_bytes[:len_in_bytes])


def hash_to_field_fp(msg: bytes, count: int, dst: bytes, *, p: int, k: int, hash_fn=hashlib.sha256) -> list[int]:
    if count < 1:
        raise ValueError("count must be >= 1")

    log2p = p.bit_length()
    l = math.ceil((log2p + k) / 8)
    len_in_bytes = count * l
    uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes, hash_fn=hash_fn)
    els: list[int] = []
    for i in range(count):
        tv = uniform_bytes[i * l : (i + 1) * l]
        els.append(os2ip(tv) % p)
    return els


def encode_to_curve_p256_xmd_sha256_sswu(msg: bytes, dst: bytes) -> Point:
    u0 = hash_to_field_fp(msg, 1, dst, p=P256_P, k=128, hash_fn=hashlib.sha256)[0]
    return map_to_curve_simple_swu_p256(u0)


def hash_to_curve_p256_xmd_sha256_sswu(msg: bytes, dst: bytes) -> Point:
    u0, u1 = hash_to_field_fp(msg, 2, dst, p=P256_P, k=128, hash_fn=hashlib.sha256)
    q0 = map_to_curve_simple_swu_p256(u0)
    q1 = map_to_curve_simple_swu_p256(u1)
    p_sum = point_add(P256, q0, q1)
    if p_sum is None:
        raise AssertionError("unexpected infinity for P-256 hash_to_curve")
    return p_sum


def main() -> None:
    dst_ro = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"
    dst_nu = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_"

    msg = b"abc"
    ro = hash_to_curve_p256_xmd_sha256_sswu(msg, dst_ro)
    nu = encode_to_curve_p256_xmd_sha256_sswu(msg, dst_nu)

    print("hash-to-curve demo (RFC 9380, P-256, educational)")
    print("- msg =", msg.decode("ascii"))
    print("- RO  x =", hex(ro.x))
    print("- RO  y =", hex(ro.y))
    print("- NU  x =", hex(nu.x))
    print("- NU  y =", hex(nu.y))

    dst1 = b"example-protocol-v1"
    dst2 = b"example-protocol-v2"
    p1 = hash_to_curve_p256_xmd_sha256_sswu(msg, dst1)
    p2 = hash_to_curve_p256_xmd_sha256_sswu(msg, dst2)
    print()
    print("DST separation demo")
    print("- same msg, different DST -> different points:", (p1.x, p1.y) != (p2.x, p2.y))


if __name__ == "__main__":
    main()
