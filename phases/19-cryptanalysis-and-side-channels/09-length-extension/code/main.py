"""
Length extension attack demo (educational).

Run:
  python3 code/main.py

This lesson implements MD4 from scratch (stdlib-only) and demonstrates a length
extension attack against a secret-prefix MAC construction: MAC = MD4(key||msg).
"""

from __future__ import annotations

import struct
from typing import Tuple


def _rol32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _f(x: int, y: int, z: int) -> int:
    return (x & y) | (~x & z)


def _g(x: int, y: int, z: int) -> int:
    return (x & y) | (x & z) | (y & z)


def _h(x: int, y: int, z: int) -> int:
    return x ^ y ^ z


def md4_pad(message_len_bytes: int) -> bytes:
    bit_len = (message_len_bytes * 8) & 0xFFFFFFFFFFFFFFFF
    pad = b"\x80"
    while ((message_len_bytes + len(pad)) % 64) != 56:
        pad += b"\x00"
    pad += struct.pack("<Q", bit_len)
    return pad


def md4_compress(block: bytes, state: Tuple[int, int, int, int]) -> Tuple[int, int, int, int]:
    if len(block) != 64:
        raise ValueError("block must be 64 bytes")
    x = list(struct.unpack("<16I", block))
    a, b, c, d = state
    aa, bb, cc, dd = a, b, c, d

    def ff(a0: int, b0: int, c0: int, d0: int, k: int, s: int) -> int:
        return _rol32((a0 + _f(b0, c0, d0) + x[k]) & 0xFFFFFFFF, s)

    def gg(a0: int, b0: int, c0: int, d0: int, k: int, s: int) -> int:
        return _rol32((a0 + _g(b0, c0, d0) + x[k] + 0x5A827999) & 0xFFFFFFFF, s)

    def hh(a0: int, b0: int, c0: int, d0: int, k: int, s: int) -> int:
        return _rol32((a0 + _h(b0, c0, d0) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

    for i in range(0, 16, 4):
        a = ff(a, b, c, d, i + 0, 3)
        d = ff(d, a, b, c, i + 1, 7)
        c = ff(c, d, a, b, i + 2, 11)
        b = ff(b, c, d, a, i + 3, 19)

    order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    shifts2 = [3, 5, 9, 13]
    for i in range(0, 16, 4):
        a = gg(a, b, c, d, order2[i + 0], shifts2[0])
        d = gg(d, a, b, c, order2[i + 1], shifts2[1])
        c = gg(c, d, a, b, order2[i + 2], shifts2[2])
        b = gg(b, c, d, a, order2[i + 3], shifts2[3])

    order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    shifts3 = [3, 9, 11, 15]
    for i in range(0, 16, 4):
        a = hh(a, b, c, d, order3[i + 0], shifts3[0])
        d = hh(d, a, b, c, order3[i + 1], shifts3[1])
        c = hh(c, d, a, b, order3[i + 2], shifts3[2])
        b = hh(b, c, d, a, order3[i + 3], shifts3[3])

    a = (a + aa) & 0xFFFFFFFF
    b = (b + bb) & 0xFFFFFFFF
    c = (c + cc) & 0xFFFFFFFF
    d = (d + dd) & 0xFFFFFFFF
    return a, b, c, d


def md4_digest(message: bytes) -> bytes:
    state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    msg = message + md4_pad(len(message))
    for off in range(0, len(msg), 64):
        state = md4_compress(msg[off : off + 64], state)
    return struct.pack("<4I", *state)


def md4_state_from_digest(digest: bytes) -> Tuple[int, int, int, int]:
    if len(digest) != 16:
        raise ValueError("digest must be 16 bytes")
    return struct.unpack("<4I", digest)


def md4_digest_with_state(append: bytes, state: Tuple[int, int, int, int], message_len_so_far: int) -> bytes:
    msg = append + md4_pad(message_len_so_far + len(append))
    st = state
    for off in range(0, len(msg), 64):
        st = md4_compress(msg[off : off + 64], st)
    return struct.pack("<4I", *st)


def secret_prefix_mac_md4(key: bytes, msg: bytes) -> bytes:
    return md4_digest(key + msg)


def md4_length_extension_attack(
    mac: bytes, original_msg: bytes, suffix: bytes, key_len_guess: int
) -> Tuple[bytes, bytes]:
    glue = md4_pad(key_len_guess + len(original_msg))
    forged_msg = original_msg + glue + suffix
    state = md4_state_from_digest(mac)
    forged_mac = md4_digest_with_state(
        suffix, state, message_len_so_far=(key_len_guess + len(original_msg) + len(glue))
    )
    return forged_msg, forged_mac


def main():
    print("=== Step 1: Implement MD4 and validate a known digest ===")
    d0 = md4_digest(b"").hex()
    print("MD4(\"\"):", d0)

    print("=== Step 2: Build a secret-prefix MAC (insecure) ===")
    key = b"YELLOW_SUBMARINE"
    msg = b"comment=hello&admin=false"
    mac = secret_prefix_mac_md4(key, msg)
    print("mac:", mac.hex())

    print("=== Step 3: Forge a MAC via length extension ===")
    suffix = b"&admin=true"
    forged_msg, forged_mac = md4_length_extension_attack(mac, msg, suffix, key_len_guess=len(key))
    server_mac = secret_prefix_mac_md4(key, forged_msg)
    print("forged_mac_ok:", forged_mac == server_mac)
    print("forged_msg:", forged_msg)


if __name__ == "__main__":
    main()
