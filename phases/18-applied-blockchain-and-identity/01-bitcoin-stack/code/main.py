"""
Bitcoin Crypto Stack (educational): SHA-256 utilities, secp256k1 math, and BIP340 Schnorr.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


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


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def bytes_xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor length mismatch")
    return bytes(x ^ y for x, y in zip(a, b))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256(tag.encode("utf-8"))
    return sha256(tag_hash + tag_hash + msg)


def is_on_curve(point: ECPoint) -> bool:
    if point is None:
        return True
    x = point.x % SECP256K1_P
    y = point.y % SECP256K1_P
    return (y * y - (x * x * x + SECP256K1_A * x + SECP256K1_B)) % SECP256K1_P == 0


def require_on_curve(point: ECPoint) -> None:
    if not is_on_curve(point):
        raise ValueError("point is not on secp256k1")


def has_even_y(point: Point) -> bool:
    return (point.y % 2) == 0


def point_neg(point: ECPoint) -> ECPoint:
    require_on_curve(point)
    if point is None:
        return None
    return Point(point.x % SECP256K1_P, (-point.y) % SECP256K1_P)


def point_add(p: ECPoint, q: ECPoint) -> ECPoint:
    require_on_curve(p)
    require_on_curve(q)

    if p is None:
        return q
    if q is None:
        return p

    if (p.x - q.x) % SECP256K1_P == 0 and (p.y + q.y) % SECP256K1_P == 0:
        return None

    if p == q:
        if p.y % SECP256K1_P == 0:
            return None
        lam = (3 * p.x * p.x + SECP256K1_A) * pow(2 * p.y, SECP256K1_P - 2, SECP256K1_P)
    else:
        lam = (q.y - p.y) * pow(q.x - p.x, SECP256K1_P - 2, SECP256K1_P)

    lam %= SECP256K1_P
    x3 = (lam * lam - p.x - q.x) % SECP256K1_P
    y3 = (lam * (p.x - x3) - p.y) % SECP256K1_P
    out: ECPoint = Point(x3, y3)
    require_on_curve(out)
    return out


def point_mul(k: int, point: ECPoint) -> ECPoint:
    require_on_curve(point)
    if point is None or k == 0:
        return None
    if k < 0:
        return point_mul(-k, point_neg(point))

    acc: ECPoint = None
    addend: ECPoint = point

    while k:
        if k & 1:
            acc = point_add(acc, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return acc


def lift_x(x: int) -> Point | None:
    if x >= SECP256K1_P:
        return None
    y_sq = (pow(x, 3, SECP256K1_P) + SECP256K1_B) % SECP256K1_P
    y = pow(y_sq, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if pow(y, 2, SECP256K1_P) != y_sq:
        return None
    y_even = y if (y & 1) == 0 else (SECP256K1_P - y)
    point = Point(x, y_even)
    require_on_curve(point)
    return point


def xonly_bytes(point: Point) -> bytes:
    return int_to_bytes(point.x % SECP256K1_P, 32)


def pubkey_gen_xonly(seckey32: bytes) -> bytes:
    if len(seckey32) != 32:
        raise ValueError("seckey must be 32 bytes")
    d0 = bytes_to_int(seckey32)
    if not (1 <= d0 <= SECP256K1_N - 1):
        raise ValueError("seckey must be an integer in the range 1..n-1")
    P = point_mul(d0, SECP256K1_G)
    assert P is not None
    return xonly_bytes(P)


def schnorr_sign(msg: bytes, seckey32: bytes, aux_rand32: bytes) -> bytes:
    if len(seckey32) != 32:
        raise ValueError("seckey must be 32 bytes")
    if len(aux_rand32) != 32:
        raise ValueError(f"aux_rand must be 32 bytes instead of {len(aux_rand32)}")

    d0 = bytes_to_int(seckey32)
    if not (1 <= d0 <= SECP256K1_N - 1):
        raise ValueError("seckey must be an integer in the range 1..n-1")

    P = point_mul(d0, SECP256K1_G)
    assert P is not None
    d = d0 if has_even_y(P) else SECP256K1_N - d0

    t = bytes_xor(int_to_bytes(d, 32), tagged_hash("BIP0340/aux", aux_rand32))
    k0 = bytes_to_int(tagged_hash("BIP0340/nonce", t + xonly_bytes(P) + msg)) % SECP256K1_N
    if k0 == 0:
        raise RuntimeError("failure: k0 is 0")

    R = point_mul(k0, SECP256K1_G)
    assert R is not None
    k = SECP256K1_N - k0 if not has_even_y(R) else k0

    e = bytes_to_int(tagged_hash("BIP0340/challenge", xonly_bytes(R) + xonly_bytes(P) + msg)) % SECP256K1_N
    sig = xonly_bytes(R) + int_to_bytes((k + e * d) % SECP256K1_N, 32)
    if not schnorr_verify(msg, xonly_bytes(P), sig):
        raise RuntimeError("created signature does not pass verification")
    return sig


def schnorr_verify(msg: bytes, pubkey32: bytes, sig64: bytes) -> bool:
    if len(pubkey32) != 32:
        raise ValueError("pubkey must be 32 bytes")
    if len(sig64) != 64:
        raise ValueError("sig must be 64 bytes")

    P = lift_x(bytes_to_int(pubkey32))
    r = bytes_to_int(sig64[0:32])
    s = bytes_to_int(sig64[32:64])

    if P is None or r >= SECP256K1_P or s >= SECP256K1_N:
        return False

    e = bytes_to_int(tagged_hash("BIP0340/challenge", sig64[0:32] + pubkey32 + msg)) % SECP256K1_N
    R = point_add(point_mul(s, SECP256K1_G), point_mul(SECP256K1_N - e, P))
    if R is None:
        return False
    if not has_even_y(R):
        return False
    return (R.x % SECP256K1_P) == r


def _hx(b: bytes) -> str:
    return b.hex()


def main():
    print("=== Step 1: SHA-256 and tagged hashing ===")
    data = b"hello"
    print("sha256('hello') =", _hx(sha256(data)))
    print("hash256('hello') =", _hx(hash256(data)))
    print("tagged_hash('BIP0340/aux', 32x00) =", _hx(tagged_hash("BIP0340/aux", b"\x00" * 32)))
    print()

    print("=== Step 2: secp256k1 points and scalar multiplication ===")
    require_on_curve(SECP256K1_G)
    two_g = point_add(SECP256K1_G, SECP256K1_G)
    assert two_g is not None
    print("G.x =", hex(SECP256K1_G.x))
    print("2G.x =", hex(two_g.x))
    k = 7
    p7 = point_mul(k, SECP256K1_G)
    assert p7 is not None
    print("7G.x =", hex(p7.x))
    print("7G has even y? =", has_even_y(p7))
    print()

    print("=== Step 3: BIP340 Schnorr sign/verify ===")
    seckey = int_to_bytes(3, 32)
    pubkey = pubkey_gen_xonly(seckey)
    msg = b"\x00" * 32
    aux = b"\x00" * 32
    sig = schnorr_sign(msg, seckey, aux)
    ok = schnorr_verify(msg, pubkey, sig)
    print("pubkey (x-only) =", _hx(pubkey))
    print("sig =", _hx(sig))
    print("verify =", ok)
    print()

    print("=== Step 4: Double-SHA256 'txid'-style hashing ===")
    tx_like = b"version=1|in=...|out=...|locktime=0"
    txid = hash256(tx_like)
    sig2 = schnorr_sign(txid, seckey, b"\x01" * 32)
    ok2 = schnorr_verify(txid, pubkey, sig2)
    print("tx_like =", tx_like.decode("utf-8"))
    print("txid = hash256(tx_like) =", _hx(txid))
    print("sig(txid) =", _hx(sig2))
    print("verify(sig, txid) =", ok2)


if __name__ == "__main__":
    main()
