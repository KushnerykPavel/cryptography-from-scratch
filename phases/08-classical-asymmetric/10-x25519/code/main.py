"""
X25519 (Curve25519 ECDH) educational implementation.

Run:
  python3 code/main.py

This script:
- Implements scalar clamping and u-coordinate encoding/decoding per RFC 7748.
- Implements the Montgomery ladder to compute X25519(k, u) scalar multiplication.
- Demonstrates an ECDH exchange and the "all-zero" shared-secret check.

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import hashlib
import hmac


X25519_P = 2**255 - 19
X25519_A24 = 121665
X25519_BASEPOINT_U = 9
X25519_BASEPOINT_BYTES = bytes([X25519_BASEPOINT_U] + [0] * 31)


def clamp_scalar(scalar: bytes) -> bytes:
    if len(scalar) != 32:
        raise ValueError("scalar must be 32 bytes")
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def decode_scalar_25519(scalar: bytes) -> int:
    return int.from_bytes(clamp_scalar(scalar), "little")


def decode_u_coordinate(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("u-coordinate must be 32 bytes")
    u_list = bytearray(u)
    u_list[31] &= 127
    return int.from_bytes(u_list, "little")


def encode_u_coordinate(u: int) -> bytes:
    if u < 0:
        raise ValueError("u-coordinate must be non-negative")
    out = (u % X25519_P).to_bytes(32, "little")
    out_list = bytearray(out)
    out_list[31] &= 127
    return bytes(out_list)


def cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    if swap & 1:
        return b, a
    return a, b


def x25519_int(k: int, u: int) -> int:
    if k < 0:
        raise ValueError("scalar must be non-negative")
    if u < 0:
        raise ValueError("u-coordinate must be non-negative")

    x1 = u % X25519_P
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0

    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = kt

        a = (x2 + z2) % X25519_P
        aa = (a * a) % X25519_P
        b = (x2 - z2) % X25519_P
        bb = (b * b) % X25519_P
        e = (aa - bb) % X25519_P
        c = (x3 + z3) % X25519_P
        d = (x3 - z3) % X25519_P
        da = (d * a) % X25519_P
        cb = (c * b) % X25519_P
        x3 = ((da + cb) % X25519_P) ** 2 % X25519_P
        z3 = (x1 * (((da - cb) % X25519_P) ** 2 % X25519_P)) % X25519_P
        x2 = (aa * bb) % X25519_P
        z2 = (e * ((aa + X25519_A24 * e) % X25519_P)) % X25519_P

    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    z2_inv = pow(z2, X25519_P - 2, X25519_P)
    return (x2 * z2_inv) % X25519_P


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    k = decode_scalar_25519(scalar)
    u = decode_u_coordinate(u_coordinate)
    return encode_u_coordinate(x25519_int(k, u))


def x25519_base(scalar: bytes) -> bytes:
    return x25519(scalar, X25519_BASEPOINT_BYTES)


def is_all_zero(b: bytes) -> bool:
    acc = 0
    for x in b:
        acc |= x
    return acc == 0


def hkdf_sha256(*, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("length must be positive")

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
        if counter > 255:
            raise ValueError("length too large for HKDF")
    return okm[:length]


def ecdh_shared_secret(*, private_scalar: bytes, peer_public_key: bytes) -> bytes:
    shared = x25519(private_scalar, peer_public_key)
    if is_all_zero(shared):
        raise ValueError("all-zero shared secret (possible small-order/invalid input)")
    return shared


def x25519_iterated(*, iterations: int, k: bytes, u: bytes) -> bytes:
    if iterations < 0:
        raise ValueError("iterations must be non-negative")
    if len(k) != 32 or len(u) != 32:
        raise ValueError("k and u must be 32 bytes")
    k_i = k
    u_i = u
    for _ in range(iterations):
        k_next = x25519(k_i, u_i)
        u_i, k_i = k_i, k_next
    return k_i


def main() -> None:
    def print_step(title: str) -> None:
        print(f"=== {title} ===")

    print_step("Step 1: Clamp scalars + decode/encode u-coordinates")
    raw = bytes.fromhex("ff" * 32)
    print("raw scalar:   ", raw.hex())
    print("clamped:      ", clamp_scalar(raw).hex())
    print("basepoint (u):", X25519_BASEPOINT_BYTES.hex())

    print_step("Step 2: Conditional swap (cswap)")
    left, right = 111, 222
    print("cswap(0, left, right):", cswap(0, left, right))
    print("cswap(1, left, right):", cswap(1, left, right))

    print_step("Step 3: The Montgomery ladder (u-coordinate scalar multiplication)")
    tv_scalar = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    )
    tv_u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
    tv_out = x25519(tv_scalar, tv_u)
    print("scalar:", tv_scalar.hex())
    print("u:     ", tv_u.hex())
    print("out:   ", tv_out.hex())

    print_step("Step 4: Byte-level API + ECDH + all-zero check + HKDF")
    alice_sk = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    bob_sk = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    alice_pk = x25519_base(alice_sk)
    bob_pk = x25519_base(bob_sk)
    print("alice_pk:", alice_pk.hex())
    print("bob_pk:  ", bob_pk.hex())
    shared_a = ecdh_shared_secret(private_scalar=alice_sk, peer_public_key=bob_pk)
    shared_b = ecdh_shared_secret(private_scalar=bob_sk, peer_public_key=alice_pk)
    print("shared (alice):", shared_a.hex())
    print("shared (bob):  ", shared_b.hex())

    session_key = hkdf_sha256(
        ikm=shared_a,
        salt=b"x25519-demo-salt",
        info=alice_pk + bob_pk,
        length=32,
    )
    print("HKDF-SHA256 session key:", session_key.hex())


if __name__ == "__main__":
    main()
