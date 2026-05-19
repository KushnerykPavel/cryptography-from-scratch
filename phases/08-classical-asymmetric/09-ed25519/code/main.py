"""
Ed25519 (EdDSA over edwards25519) educational implementation.

Run:
  python3 code/main.py

This file demonstrates key derivation, signing, and verification using only the
Python standard library. It is not constant-time and is not production-safe.
"""

from __future__ import annotations

import hashlib
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


def ed25519_ext_neg(p: ExtPoint) -> ExtPoint:
    return ExtPoint((-p.X) % ED25519_P, p.Y % ED25519_P, p.Z % ED25519_P, (-p.T) % ED25519_P)


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


def ed25519_ext_eq(p: ExtPoint, q: ExtPoint) -> bool:
    return (p.X * q.Z - q.X * p.Z) % ED25519_P == 0 and (p.Y * q.Z - q.Y * p.Z) % ED25519_P == 0


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


def sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def sha512_mod_l(data: bytes) -> int:
    return int.from_bytes(sha512(data), "little") % ED25519_L


def ed25519_secret_expand(secret: bytes) -> tuple[int, bytes]:
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def ed25519_secret_to_public(secret: bytes) -> bytes:
    a, _prefix = ed25519_secret_expand(secret)
    b = ed25519_to_ext(ed25519_decode(ED25519_B_ENC))
    A = ed25519_scalar_mul(a, b)
    return ed25519_encode(ed25519_from_ext(A))


def ed25519_sign(secret: bytes, msg: bytes) -> bytes:
    a, prefix = ed25519_secret_expand(secret)
    A = ed25519_secret_to_public(secret)
    r = sha512_mod_l(prefix + msg)

    b = ed25519_to_ext(ed25519_decode(ED25519_B_ENC))
    R = ed25519_scalar_mul(r, b)
    R_enc = ed25519_encode(ed25519_from_ext(R))

    k = sha512_mod_l(R_enc + A + msg)
    s = (r + k * a) % ED25519_L
    return R_enc + s.to_bytes(32, "little")


def ed25519_verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False

    try:
        A_aff = ed25519_decode(public)
        R_aff = ed25519_decode(signature[:32])
    except ValueError:
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= ED25519_L:
        return False

    b = ed25519_to_ext(ed25519_decode(ED25519_B_ENC))
    A = ed25519_to_ext(A_aff)
    R = ed25519_to_ext(R_aff)

    k = sha512_mod_l(signature[:32] + public + msg)
    sB = ed25519_scalar_mul(s, b)
    kA = ed25519_scalar_mul(k, A)
    return ed25519_ext_eq(sB, ed25519_ext_add(R, kA))


def _demo_step_1_point_encoding():
    b = ed25519_decode(ED25519_B_ENC)
    roundtrip = ed25519_decode(ed25519_encode(b))
    print("B enc =", ED25519_B_ENC.hex())
    print("B x (parity) =", b.x & 1)
    print("B roundtrip ok?", b == roundtrip)


def _demo_step_2_scalar_mul():
    b = ed25519_to_ext(ed25519_decode(ED25519_B_ENC))
    two_b = ed25519_from_ext(ed25519_scalar_mul(2, b))
    three_b = ed25519_from_ext(ed25519_scalar_mul(3, b))
    print("2B enc =", ed25519_encode(two_b).hex())
    print("3B enc =", ed25519_encode(three_b).hex())


def _demo_step_3_key_derivation():
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = ed25519_secret_to_public(seed)
    print("seed =", seed.hex())
    print("public key =", pk.hex())


def _demo_step_4_sign_and_verify():
    seed = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    msg = bytes.fromhex("72")
    pk = ed25519_secret_to_public(seed)
    sig = ed25519_sign(seed, msg)
    ok = ed25519_verify(pk, msg, sig)
    print("msg =", msg.hex())
    print("sig =", sig.hex())
    print("verify(public, msg, sig) =", ok)


if __name__ == "__main__":
    print("=== Step 1: Encode/decode points ===")
    _demo_step_1_point_encoding()
    print()
    print("=== Step 2: Scalar multiplication ===")
    _demo_step_2_scalar_mul()
    print()
    print("=== Step 3: Derive a public key ===")
    _demo_step_3_key_derivation()
    print()
    print("=== Step 4: Sign and verify ===")
    _demo_step_4_sign_and_verify()
