"""ECDSA attacks: nonce reuse, nonce leakage, and weak RNG.

This script implements a minimal (educational) ECDSA over secp256k1 using only
the Python standard library, then demonstrates three practical key-recovery
attacks:

1) Reused nonce (same k for two signatures) => recover k and the private key.
2) Known nonce (k leaked via logs/debug/side-channel) => recover private key.
3) Small nonce (k drawn from a tiny range) => brute-force k, then private key.

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

Point = Optional[tuple[int, int]]  # (x, y) or None for point-at-infinity


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def G(self) -> Point:
        return (self.gx, self.gy)


SECP256K1 = Curve(
    name="secp256k1",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    gx=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    gy=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


def mod_inv(a: int, m: int) -> int:
    a %= m
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")

    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("a is not invertible mod m")
    return t % m


def is_on_curve(P: Point, curve: Curve = SECP256K1) -> bool:
    if P is None:
        return True
    x, y = P
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def point_add(P: Point, Q: Point, curve: Curve = SECP256K1) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    if x1 == x2 and (y1 + y2) % curve.p == 0:
        return None

    if P == Q:
        lam = (3 * x1 * x1 + curve.a) * mod_inv(2 * y1, curve.p)
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1, curve.p)
    lam %= curve.p

    x3 = (lam * lam - x1 - x2) % curve.p
    y3 = (lam * (x1 - x3) - y1) % curve.p
    return (x3, y3)


def scalar_mul(k: int, P: Point, curve: Curve = SECP256K1) -> Point:
    if k % curve.n == 0 or P is None:
        return None
    if k < 0:
        x, y = scalar_mul(-k, P, curve)
        return (x, (-y) % curve.p)

    out = None
    addend = P
    while k:
        if k & 1:
            out = point_add(out, addend, curve)
        addend = point_add(addend, addend, curve)
        k >>= 1
    return out


def sha256_int(msg: bytes, n: int) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % n


def ecdsa_pubkey(priv: int, curve: Curve = SECP256K1) -> Point:
    if not (1 <= priv < curve.n):
        raise ValueError("private key out of range")
    return scalar_mul(priv, curve.G, curve)


def ecdsa_sign_with_k(msg: bytes, priv: int, k: int, curve: Curve = SECP256K1) -> tuple[int, int]:
    if not (1 <= priv < curve.n):
        raise ValueError("private key out of range")
    k = k % curve.n
    if k == 0:
        raise ValueError("k must be in [1, n-1]")

    R = scalar_mul(k, curve.G, curve)
    if R is None:
        raise ValueError("invalid k (k*G == infinity)")
    r = R[0] % curve.n
    if r == 0:
        raise ValueError("invalid k (r == 0)")

    z = sha256_int(msg, curve.n)
    s = (mod_inv(k, curve.n) * (z + r * priv)) % curve.n
    if s == 0:
        raise ValueError("invalid k (s == 0)")
    return (r, s)


def ecdsa_verify(msg: bytes, pub: Point, sig: tuple[int, int], curve: Curve = SECP256K1) -> bool:
    r, s = sig
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    if not is_on_curve(pub, curve):
        return False

    z = sha256_int(msg, curve.n)
    try:
        w = mod_inv(s, curve.n)
    except Exception:
        return False
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n
    X = point_add(scalar_mul(u1, curve.G, curve), scalar_mul(u2, pub, curve), curve)
    if X is None:
        return False
    return (X[0] % curve.n) == r


def recover_k_from_reused_nonce(
    msg1: bytes,
    sig1: tuple[int, int],
    msg2: bytes,
    sig2: tuple[int, int],
    curve: Curve = SECP256K1,
) -> int:
    r1, s1 = sig1
    r2, s2 = sig2
    if r1 != r2:
        raise ValueError("nonce reuse attack needs r1 == r2 (same k => same r)")

    z1 = sha256_int(msg1, curve.n)
    z2 = sha256_int(msg2, curve.n)
    return ((z1 - z2) * mod_inv(s1 - s2, curve.n)) % curve.n


def recover_privkey_from_known_nonce(
    msg: bytes, sig: tuple[int, int], k: int, curve: Curve = SECP256K1
) -> int:
    r, s = sig
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        raise ValueError("invalid signature")
    z = sha256_int(msg, curve.n)
    return ((s * (k % curve.n) - z) * mod_inv(r, curve.n)) % curve.n


def recover_privkey_from_reused_nonce(
    msg1: bytes,
    sig1: tuple[int, int],
    msg2: bytes,
    sig2: tuple[int, int],
    curve: Curve = SECP256K1,
) -> tuple[int, int]:
    k = recover_k_from_reused_nonce(msg1, sig1, msg2, sig2, curve)
    d = recover_privkey_from_known_nonce(msg1, sig1, k, curve)
    return (d, k)


def brute_force_k_from_small_range(
    r: int, max_k: int, curve: Curve = SECP256K1, start_k: int = 1
) -> int:
    if max_k < start_k:
        raise ValueError("empty search range")
    target = r % curve.n
    for k in range(start_k, max_k + 1):
        R = scalar_mul(k, curve.G, curve)
        if R is None:
            continue
        if (R[0] % curve.n) == target:
            return k
    raise ValueError("k not found in range")


def rfc6979_nonce_sha256(msg: bytes, priv: int, curve: Curve = SECP256K1) -> int:
    if not (1 <= priv < curve.n):
        raise ValueError("private key out of range")

    x = priv.to_bytes(32, "big")
    h1 = hashlib.sha256(msg).digest()
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()

    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        nonce = candidate % curve.n
        if 1 <= nonce < curve.n:
            return nonce
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def main() -> None:
    curve = SECP256K1

    print("=== Step 1: Implement secp256k1 ECDSA (sign/verify) ===")
    d = 1
    Q = ecdsa_pubkey(d, curve)
    msg = b"hello"
    k = 2
    sig = ecdsa_sign_with_k(msg, d, k, curve)
    print(f"curve: {curve.name}")
    print(f"priv d: {d}")
    print(f"pub  Q: ({hex(Q[0])[:14]}..., {hex(Q[1])[:14]}...)")
    print(f"msg: {msg!r}")
    print(f"k: {k}")
    print(f"sig: (r={hex(sig[0])[:14]}..., s={hex(sig[1])[:14]}...)")
    print(f"verify: {ecdsa_verify(msg, Q, sig, curve)}")

    print()
    print("=== Step 2: Attack reused nonce (same k twice) ===")
    m1 = b"msg1"
    m2 = b"msg2"
    k_reused = 2
    sig1 = ecdsa_sign_with_k(m1, d, k_reused, curve)
    sig2 = ecdsa_sign_with_k(m2, d, k_reused, curve)
    print(f"sig1.r == sig2.r: {sig1[0] == sig2[0]}")
    d_rec, k_rec = recover_privkey_from_reused_nonce(m1, sig1, m2, sig2, curve)
    print(f"recovered k: {k_rec}")
    print(f"recovered d: {d_rec}")
    print(f"matches: {d_rec == d}")

    print()
    print("=== Step 3: Attack known nonce (k leak) ===")
    d2 = 0xBEEF
    Q2 = ecdsa_pubkey(d2, curve)
    m3 = b"leak"
    k_leaked = 0xCAFE
    sig3 = ecdsa_sign_with_k(m3, d2, k_leaked, curve)
    d2_rec = recover_privkey_from_known_nonce(m3, sig3, k_leaked, curve)
    print(f"verify: {ecdsa_verify(m3, Q2, sig3, curve)}")
    print(f"recovered d: {hex(d2_rec)}")
    print(f"matches: {d2_rec == d2}")

    print()
    print("=== Step 4: Attack small nonces (brute-force k) ===")
    d3 = 0x12345
    Q3 = ecdsa_pubkey(d3, curve)
    m4 = b"weak"
    k_small = 1337
    sig4 = ecdsa_sign_with_k(m4, d3, k_small, curve)
    k_found = brute_force_k_from_small_range(sig4[0], max_k=5000, curve=curve)
    d3_rec = recover_privkey_from_known_nonce(m4, sig4, k_found, curve)
    print(f"assume k in [1, 5000], actual k={k_small}, found k={k_found}")
    print(f"recovered d: {hex(d3_rec)}  matches: {d3_rec == d3}")

    print()
    print("=== Step 5: Mitigation: deterministic nonce (RFC6979-style) ===")
    m5 = b"deterministic"
    d4 = 0x4242
    k_det = rfc6979_nonce_sha256(m5, d4, curve)
    sig5 = ecdsa_sign_with_k(m5, d4, k_det, curve)
    print(f"derived k: {hex(k_det)}")
    print(f"verify: {ecdsa_verify(m5, ecdsa_pubkey(d4, curve), sig5, curve)}")
    print("note: deterministic nonces remove RNG failures, but side-channels can still leak k bits.")


if __name__ == "__main__":
    main()
