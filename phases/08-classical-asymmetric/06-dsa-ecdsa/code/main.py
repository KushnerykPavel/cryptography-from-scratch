"""
DSA and ECDSA from scratch (educational).

Runs a small, deterministic demo of signing and verification, plus a nonce-reuse
attack demonstration on toy DSA parameters.

Run:
    python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def mod_inv(a: int, modulus: int) -> int:
    a %= modulus
    if a == 0:
        raise ValueError("inverse does not exist")

    t, new_t = 0, 1
    r, new_r = modulus, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r

    if r != 1:
        raise ValueError("inverse does not exist")
    return t % modulus


def bits2int(b: bytes, qlen: int) -> int:
    x = bytes_to_int(b)
    blen = 8 * len(b)
    if blen > qlen:
        x >>= blen - qlen
    return x


def hash_to_int(message: bytes, q: int, hashfunc=hashlib.sha256) -> int:
    return bits2int(hashfunc(message).digest(), q.bit_length())


def int2octets(x: int, rolen: int) -> bytes:
    return int_to_bytes(x, rolen)


def bits2octets(h1: bytes, q: int, qlen: int, rolen: int) -> bytes:
    z1 = bits2int(h1, qlen)
    z2 = z1 % q
    return int2octets(z2, rolen)


def rfc6979_generate_k(x: int, h1: bytes, q: int, hashfunc=hashlib.sha256) -> int:
    qlen = q.bit_length()
    holen = hashfunc().digest_size
    rolen = (qlen + 7) // 8

    bx = int2octets(x, rolen) + bits2octets(h1, q, qlen, rolen)
    v = b"\x01" * holen
    k = b"\x00" * holen

    k = hmac.new(k, v + b"\x00" + bx, hashfunc).digest()
    v = hmac.new(k, v, hashfunc).digest()
    k = hmac.new(k, v + b"\x01" + bx, hashfunc).digest()
    v = hmac.new(k, v, hashfunc).digest()

    while True:
        t = b""
        while len(t) < rolen:
            v = hmac.new(k, v, hashfunc).digest()
            t += v

        candidate = bits2int(t, qlen)
        if 1 <= candidate < q:
            return candidate

        k = hmac.new(k, v + b"\x00", hashfunc).digest()
        v = hmac.new(k, v, hashfunc).digest()


DSA_P = 1019
DSA_Q = 509
DSA_G = pow(2, (DSA_P - 1) // DSA_Q, DSA_P)


def dsa_public_key(p: int, g: int, x: int) -> int:
    if x <= 0:
        raise ValueError("private key must be > 0")
    return pow(g, x, p)


def dsa_sign(
    message: bytes,
    p: int,
    q: int,
    g: int,
    x: int,
    *,
    k: int | None = None,
    hashfunc=hashlib.sha256,
) -> tuple[int, int]:
    if k is None:
        h1 = hashfunc(message).digest()
        k = rfc6979_generate_k(x, h1, q, hashfunc)
    k %= q
    if k == 0:
        raise ValueError("k must be non-zero modulo q")

    r = pow(g, k, p) % q
    if r == 0:
        raise ValueError("r must be non-zero")

    e = hash_to_int(message, q, hashfunc)
    s = (mod_inv(k, q) * (e + (x % q) * r)) % q
    if s == 0:
        raise ValueError("s must be non-zero")
    return r, s


def dsa_verify(
    message: bytes,
    p: int,
    q: int,
    g: int,
    y: int,
    signature: tuple[int, int],
    *,
    hashfunc=hashlib.sha256,
) -> bool:
    r, s = signature
    if not (1 <= r < q and 1 <= s < q):
        return False

    e = hash_to_int(message, q, hashfunc)
    w = mod_inv(s, q)
    u1 = (e * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r


def recover_private_key_from_nonce_reuse(
    q: int,
    e1: int,
    e2: int,
    r: int,
    s1: int,
    s2: int,
) -> tuple[int, int]:
    if (s1 - s2) % q == 0:
        raise ValueError("s1 must differ from s2 (mod q)")
    k = ((e1 - e2) * mod_inv((s1 - s2) % q, q)) % q
    x = ((s1 * k - e1) * mod_inv(r, q)) % q
    return k, x


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
    55066263022277343669578718895168534326250603453777594175500187360389116729240,
    32670510020758816978083085130507043184471273380659243275938904335757337482424,
)


def is_on_secp256k1(point: ECPoint) -> bool:
    if point is None:
        return True
    x, y = point.x % SECP256K1_P, point.y % SECP256K1_P
    return (y * y - (x * x * x + SECP256K1_A * x + SECP256K1_B)) % SECP256K1_P == 0


def require_on_secp256k1(point: ECPoint) -> None:
    if not is_on_secp256k1(point):
        raise ValueError("point is not on secp256k1")


def point_neg_secp256k1(point: ECPoint) -> ECPoint:
    require_on_secp256k1(point)
    if point is None:
        return None
    return Point(point.x % SECP256K1_P, (-point.y) % SECP256K1_P)


def point_add_secp256k1(p: ECPoint, q: ECPoint) -> ECPoint:
    require_on_secp256k1(p)
    require_on_secp256k1(q)

    if p is None:
        return q
    if q is None:
        return p

    if p.x % SECP256K1_P == q.x % SECP256K1_P and (p.y + q.y) % SECP256K1_P == 0:
        return None

    if p != q:
        lam = (q.y - p.y) * mod_inv(q.x - p.x, SECP256K1_P)
    else:
        if p.y % SECP256K1_P == 0:
            return None
        lam = (3 * p.x * p.x + SECP256K1_A) * mod_inv(2 * p.y, SECP256K1_P)

    lam %= SECP256K1_P
    x3 = (lam * lam - p.x - q.x) % SECP256K1_P
    y3 = (lam * (p.x - x3) - p.y) % SECP256K1_P
    result: ECPoint = Point(x3, y3)
    require_on_secp256k1(result)
    return result


def scalar_mul_secp256k1(k: int, point: ECPoint) -> ECPoint:
    require_on_secp256k1(point)
    if point is None or k == 0:
        return None
    if k < 0:
        return scalar_mul_secp256k1(-k, point_neg_secp256k1(point))

    acc: ECPoint = None
    addend: ECPoint = point

    while k > 0:
        if k & 1:
            acc = point_add_secp256k1(acc, addend)
        addend = point_add_secp256k1(addend, addend)
        k >>= 1

    return acc


def ecdsa_public_key(d: int) -> Point:
    if not (1 <= d < SECP256K1_N):
        raise ValueError("private key must be in [1, n-1]")
    q = scalar_mul_secp256k1(d, SECP256K1_G)
    if q is None:
        raise ValueError("invalid private key")
    return q


def normalize_s_low_s(n: int, signature: tuple[int, int]) -> tuple[int, int]:
    r, s = signature
    if s > n // 2:
        return r, n - s
    return r, s


def ecdsa_sign(
    message: bytes,
    d: int,
    *,
    k: int | None = None,
    hashfunc=hashlib.sha256,
    low_s: bool = True,
) -> tuple[int, int]:
    if not (1 <= d < SECP256K1_N):
        raise ValueError("private key must be in [1, n-1]")

    e = hash_to_int(message, SECP256K1_N, hashfunc)

    if k is None:
        h1 = hashfunc(message).digest()
        k = rfc6979_generate_k(d, h1, SECP256K1_N, hashfunc)
    k %= SECP256K1_N
    if k == 0:
        raise ValueError("k must be non-zero modulo n")

    r_point = scalar_mul_secp256k1(k, SECP256K1_G)
    if r_point is None:
        raise ValueError("k produced point at infinity")
    r = r_point.x % SECP256K1_N
    if r == 0:
        raise ValueError("r must be non-zero")

    s = (mod_inv(k, SECP256K1_N) * (e + r * d)) % SECP256K1_N
    if s == 0:
        raise ValueError("s must be non-zero")

    signature = (r, s)
    if low_s:
        signature = normalize_s_low_s(SECP256K1_N, signature)
    return signature


def ecdsa_verify(
    message: bytes,
    q: Point,
    signature: tuple[int, int],
    *,
    hashfunc=hashlib.sha256,
) -> bool:
    require_on_secp256k1(q)
    r, s = signature
    if not (1 <= r < SECP256K1_N and 1 <= s < SECP256K1_N):
        return False

    e = hash_to_int(message, SECP256K1_N, hashfunc)
    w = mod_inv(s, SECP256K1_N)
    u1 = (e * w) % SECP256K1_N
    u2 = (r * w) % SECP256K1_N
    x_point = point_add_secp256k1(
        scalar_mul_secp256k1(u1, SECP256K1_G), scalar_mul_secp256k1(u2, q)
    )
    if x_point is None:
        return False
    return (x_point.x % SECP256K1_N) == r


def step_header(step: int, name: str) -> None:
    print(f"=== Step {step}: {name} ===")


def main() -> None:
    step_header(1, "Modular inverses and hashing-to-int")
    a = 17
    inv = mod_inv(a, DSA_Q)
    print(f"{a}^(-1) mod {DSA_Q} = {inv}")
    msg = b"hello"
    print(f"hash_to_int({msg!r}, q={DSA_Q}) = {hash_to_int(msg, DSA_Q)}")

    step_header(2, "DSA signatures (toy group)")
    x = 37
    y = dsa_public_key(DSA_P, DSA_G, x)
    sig = dsa_sign(msg, DSA_P, DSA_Q, DSA_G, x)
    print(f"public y = {y}")
    print(f"signature (r, s) = {sig}")
    print("verify ok:", dsa_verify(msg, DSA_P, DSA_Q, DSA_G, y, sig))
    print("verify wrong msg:", dsa_verify(b"hellO", DSA_P, DSA_Q, DSA_G, y, sig))

    step_header(3, "Elliptic-curve group (secp256k1)")
    require_on_secp256k1(SECP256K1_G)
    infinity = scalar_mul_secp256k1(SECP256K1_N, SECP256K1_G)
    print("n*G is infinity:", infinity is None)
    two_g = scalar_mul_secp256k1(2, SECP256K1_G)
    print(f"2*G.x (mod p) = {two_g.x}")

    step_header(4, "ECDSA signatures (deterministic k)")
    d = 1
    q = ecdsa_public_key(d)
    sig_ec = ecdsa_sign(msg, d, low_s=False)
    print(f"public Q.x = {q.x}")
    print(f"signature (r, s) = {sig_ec}")
    print("verify ok:", ecdsa_verify(msg, q, sig_ec))

    r, s = sig_ec
    malleable = (r, (SECP256K1_N - s) % SECP256K1_N)
    print("verify malleable (r, n-s):", ecdsa_verify(msg, q, malleable))
    print("low-s normalized:", normalize_s_low_s(SECP256K1_N, sig_ec))

    step_header(5, "Nonce reuse leaks the private key (DSA demo)")
    bad_k = 123
    m1 = b"m1"
    m2 = b"m2"
    r1, s1 = dsa_sign(m1, DSA_P, DSA_Q, DSA_G, x, k=bad_k)
    r2, s2 = dsa_sign(m2, DSA_P, DSA_Q, DSA_G, x, k=bad_k)
    e1 = hash_to_int(m1, DSA_Q)
    e2 = hash_to_int(m2, DSA_Q)
    recovered_k, recovered_x = recover_private_key_from_nonce_reuse(
        DSA_Q, e1, e2, r1, s1, s2
    )
    print(f"reused k produced r1==r2: {r1 == r2}")
    print("recovered k:", recovered_k)
    print("recovered x:", recovered_x)


if __name__ == "__main__":
    main()
