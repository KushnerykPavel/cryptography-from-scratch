from __future__ import annotations

import os

P25519 = 2**255 - 19
CURVE25519_A = 486662
CURVE25519_A24 = 121665


def decode_u_coordinate(u: bytes) -> int:
    if len(u) != 32:
        raise ValueError("u must be 32 bytes")
    u_masked = bytearray(u)
    u_masked[31] &= 0x7F
    return int.from_bytes(u_masked, "little") % P25519


def encode_u_coordinate(u: int) -> bytes:
    u %= P25519
    out = bytearray(u.to_bytes(32, "little"))
    out[31] &= 0x7F
    return bytes(out)


def clamp_scalar25519(s: bytes) -> int:
    if len(s) != 32:
        raise ValueError("scalar must be 32 bytes")
    k = bytearray(s)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse does not exist")
    return pow(a, p - 2, p)


def cswap(swap: int, a: int, b: int) -> tuple[int, int]:
    if swap not in (0, 1):
        raise ValueError("swap must be 0 or 1")
    mask = -swap
    t = mask & (a ^ b)
    return a ^ t, b ^ t


def x25519_int(k: int, u: int) -> int:
    x1 = u % P25519
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        x2, x3 = cswap(swap, x2, x3)
        z2, z3 = cswap(swap, z2, z3)
        swap = k_t

        a = (x2 + z2) % P25519
        aa = (a * a) % P25519
        b = (x2 - z2) % P25519
        bb = (b * b) % P25519
        e = (aa - bb) % P25519
        c = (x3 + z3) % P25519
        d = (x3 - z3) % P25519
        da = (d * a) % P25519
        cb = (c * b) % P25519
        x3 = pow(da + cb, 2, P25519)
        z3 = (x1 * pow(da - cb, 2, P25519)) % P25519
        x2 = (aa * bb) % P25519
        z2 = (e * (aa + CURVE25519_A24 * e)) % P25519

    x2, x3 = cswap(swap, x2, x3)
    z2, z3 = cswap(swap, z2, z3)

    return (x2 * mod_inv(z2, P25519)) % P25519


def x25519(scalar32: bytes, u32: bytes) -> bytes:
    k = clamp_scalar25519(scalar32)
    u = decode_u_coordinate(u32)
    out = x25519_int(k, u)
    return encode_u_coordinate(out)


def x25519_basepoint(scalar32: bytes) -> bytes:
    return x25519(scalar32, b"\x09" + b"\x00" * 31)


def is_all_zero(value: bytes) -> bool:
    if not value:
        return True
    acc = 0
    for b in value:
        acc |= b
    return acc == 0


def generate_private_key() -> bytes:
    return os.urandom(32)


def generate_public_key(private_key32: bytes) -> bytes:
    return x25519_basepoint(private_key32)


def derive_shared_secret(private_key32: bytes, peer_public_key32: bytes) -> bytes:
    return x25519(private_key32, peer_public_key32)


def x25519_iterate(n: int) -> bytes:
    if n < 0:
        raise ValueError("n must be >= 0")
    k = b"\x09" + b"\x00" * 31
    u = b"\x09" + b"\x00" * 31
    for _ in range(n):
        old_k = k
        k = x25519(old_k, u)
        u = old_k
    return k


def main():
    a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    a_pub = x25519_basepoint(a)
    b_pub = x25519_basepoint(b)
    a_shared = x25519(a, b_pub)
    b_shared = x25519(b, a_pub)

    print("X25519 RFC 7748 example:")
    print("  Alice pub:", a_pub.hex())
    print("  Bob   pub:", b_pub.hex())
    print("  shared   :", a_shared.hex())
    print("  match    :", a_shared == b_shared)


if __name__ == "__main__":
    main()
