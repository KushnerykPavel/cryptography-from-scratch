"""
Schnorr signatures (toy finite-field subgroup) from scratch.

Run:
  python3 code/main.py

This script implements a small, educational Schnorr signature scheme in a
subgroup of (Z/pZ)*. It demonstrates key generation, signing, verification, and
the classic "nonce reuse" failure mode.
"""

from __future__ import annotations

import hashlib
import hmac


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
    return bits2int(hashfunc(message).digest(), q.bit_length()) % q


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

    bx = int2octets(x % q, rolen) + bits2octets(h1, q, qlen, rolen)
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


def validate_schnorr_params(p: int, q: int, g: int) -> None:
    if p <= 2:
        raise ValueError("p must be > 2")
    if q <= 2:
        raise ValueError("q must be > 2")
    if (p - 1) % q != 0:
        raise ValueError("q must divide p-1")
    if not (2 <= g <= p - 2):
        raise ValueError("g out of range")
    if pow(g, q, p) != 1:
        raise ValueError("g^q mod p must be 1 (g not in subgroup of order q)")


def schnorr_public_key(p: int, g: int, x: int) -> int:
    if x <= 0:
        raise ValueError("private key must be > 0")
    return pow(g, x, p)


def schnorr_challenge(message: bytes, r: int, p: int, q: int, hashfunc=hashlib.sha256) -> int:
    r_len = (p.bit_length() + 7) // 8
    return hash_to_int(message + int_to_bytes(r, r_len), q, hashfunc)


def schnorr_sign(
    message: bytes,
    p: int,
    q: int,
    g: int,
    x: int,
    *,
    k: int | None = None,
    hashfunc=hashlib.sha256,
) -> tuple[int, int]:
    validate_schnorr_params(p, q, g)
    if x <= 0:
        raise ValueError("private key must be > 0")

    if k is None:
        h1 = hashfunc(b"SCHNORR:" + message).digest()
        k = rfc6979_generate_k(x, h1, q, hashfunc)
    k %= q
    if k == 0:
        raise ValueError("k must be non-zero modulo q")

    r = pow(g, k, p)
    e = schnorr_challenge(message, r, p, q, hashfunc)
    s = (k + e * (x % q)) % q
    return e, s


def schnorr_verify(
    message: bytes,
    p: int,
    q: int,
    g: int,
    y: int,
    signature: tuple[int, int],
    *,
    hashfunc=hashlib.sha256,
) -> bool:
    try:
        validate_schnorr_params(p, q, g)
    except ValueError:
        return False

    e, s = signature
    if not (0 <= e < q and 0 <= s < q):
        return False
    if not (1 <= y <= p - 1):
        return False

    y_inv = mod_inv(y, p)
    r = (pow(g, s, p) * pow(y_inv, e, p)) % p
    e2 = schnorr_challenge(message, r, p, q, hashfunc)
    return e2 == e


def recover_x_from_nonce_reuse(
    q: int,
    e1: int,
    s1: int,
    e2: int,
    s2: int,
) -> int:
    de = (e1 - e2) % q
    if de == 0:
        raise ValueError("e1 must differ from e2 (mod q)")
    ds = (s1 - s2) % q
    return (ds * mod_inv(de, q)) % q


def main() -> None:
    p = 1019
    q = 509
    g = pow(2, (p - 1) // q, p)
    validate_schnorr_params(p, q, g)

    print("=== Step 1: Choose parameters and helpers ===")
    print(f"p={p}, q={q}, g={g}")
    print(f"check g^q mod p = {pow(g, q, p)}")
    print()

    print("=== Step 2: Key generation ===")
    x = 123
    y = schnorr_public_key(p, g, x)
    print(f"private x={x}")
    print(f"public  y={y}")
    print()

    print("=== Step 3: Sign and verify ===")
    message = b"hello schnorr"
    sig = schnorr_sign(message, p, q, g, x)
    print(f"message={message!r}")
    print(f"signature (e, s)={sig}")
    print(f"verify OK? {schnorr_verify(message, p, q, g, y, sig)}")
    print(f"verify on tampered message? {schnorr_verify(b'hello schnorr!', p, q, g, y, sig)}")
    print()

    print("=== Step 4: Nonce reuse leaks the private key ===")
    k_reused = 77
    m1 = b"pay bob 10"
    m2 = b"pay mallory 10"
    e1, s1 = schnorr_sign(m1, p, q, g, x, k=k_reused)
    e2, s2 = schnorr_sign(m2, p, q, g, x, k=k_reused)
    x_recovered = recover_x_from_nonce_reuse(q, e1, s1, e2, s2)
    print(f"reused k={k_reused}")
    print(f"sig1=(e={e1}, s={s1}) on {m1!r}")
    print(f"sig2=(e={e2}, s={s2}) on {m2!r}")
    print(f"recovered x={x_recovered} (matches? {x_recovered == x % q})")


if __name__ == "__main__":
    main()
