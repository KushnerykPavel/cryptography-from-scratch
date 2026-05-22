"""
Bleichenbacher-style padding oracle demo (educational).

Run:
  python3 code/main.py

This lesson implements RSA + PKCS#1 v1.5-style encoding, exposes a padding
validity oracle, then uses an adaptive chosen-ciphertext strategy to narrow the
plaintext until it is uniquely determined (for tiny toy parameters).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Tuple


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inv_mod(a: int, n: int) -> int:
    a %= n
    g, x, _ = egcd(a, n)
    if g != 1:
        raise ValueError("not invertible")
    return x % n


def i2osp(x: int, k: int) -> bytes:
    if x < 0 or x >= (1 << (8 * k)):
        raise ValueError("integer too large")
    return x.to_bytes(k, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


@dataclass(frozen=True)
class RSAKey:
    n: int
    e: int
    d: int

    @property
    def k(self) -> int:
        return (self.n.bit_length() + 7) // 8


def rsa_encrypt_int(m: int, n: int, e: int) -> int:
    if not (0 <= m < n):
        raise ValueError("m out of range")
    return pow(m, e, n)


def rsa_decrypt_int(c: int, n: int, d: int) -> int:
    if not (0 <= c < n):
        raise ValueError("c out of range")
    return pow(c, d, n)


def pkcs1v15_encode(message: bytes, k: int, ps: bytes) -> bytes:
    if len(message) > k - 11:
        raise ValueError("message too long")
    if len(ps) != k - 3 - len(message):
        raise ValueError("bad PS length")
    if any(x == 0 for x in ps):
        raise ValueError("PS must be non-zero bytes")
    return b"\x00\x02" + ps + b"\x00" + message


def pkcs1v15_is_conformant(em: bytes) -> bool:
    if len(em) < 11:
        return False
    if not (em[0] == 0 and em[1] == 2):
        return False
    try:
        sep = em.index(b"\x00", 2)
    except ValueError:
        return False
    if sep < 10:
        return False
    if any(x == 0 for x in em[2:sep]):
        return False
    return True


def pkcs1v15_decode_message(em: bytes) -> bytes:
    if not pkcs1v15_is_conformant(em):
        raise ValueError("not conformant")
    sep = em.index(b"\x00", 2)
    return em[sep + 1 :]


def header_oracle_factory(key: RSAKey, header_bits: int) -> Callable[[int], bool]:
    if header_bits <= 0 or header_bits > 16:
        raise ValueError("header_bits must be in 1..16 for this demo")

    def oracle(c: int) -> bool:
        k = key.k
        m = rsa_decrypt_int(c, key.n, key.d)
        top = m >> (8 * k - header_bits)
        return top == 2

    return oracle


def ceil_div(a: int, b: int) -> int:
    if b <= 0:
        raise ValueError("b must be positive")
    return -(-a // b)


def floor_div(a: int, b: int) -> int:
    if b <= 0:
        raise ValueError("b must be positive")
    return a // b


def _merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    if not intervals:
        return []
    intervals.sort()
    out = [intervals[0]]
    for a, b in intervals[1:]:
        la, lb = out[-1]
        if a <= lb + 1:
            out[-1] = (la, max(lb, b))
        else:
            out.append((a, b))
    return out


def bleichenbacher_recover_em(
    c: int,
    n: int,
    e: int,
    oracle: Callable[[int], bool],
    header_bits: int,
    max_oracle_calls: int = 250_000,
) -> Tuple[bytes, int]:
    k = (n.bit_length() + 7) // 8
    if header_bits <= 0 or header_bits > 16:
        raise ValueError("header_bits must be in 1..16 for this demo")
    B = 1 << (8 * k - header_bits)
    B2 = 2 * B
    B3m1 = 3 * B - 1

    calls = 0

    def ok(cand: int) -> bool:
        nonlocal calls
        calls += 1
        if calls > max_oracle_calls:
            raise RuntimeError("oracle call limit exceeded")
        return oracle(cand)

    c0 = c
    if not ok(c0):
        raise ValueError("ciphertext not conformant under oracle (demo expects conformant)")

    s = ceil_div(n, 3 * B)
    while not ok((c0 * pow(s, e, n)) % n):
        s += 1

    M: List[Tuple[int, int]] = [(B2, B3m1)]

    while True:
        new_M: List[Tuple[int, int]] = []
        for a, b in M:
            r_min = ceil_div(a * s - B3m1, n)
            r_max = floor_div(b * s - B2, n)
            for r in range(r_min, r_max + 1):
                lo = max(a, ceil_div(B2 + r * n, s))
                hi = min(b, floor_div(B3m1 + r * n, s))
                if lo <= hi:
                    new_M.append((lo, hi))
        M = _merge_intervals(new_M)

        if len(M) == 1 and M[0][0] == M[0][1]:
            m0 = M[0][0]
            return i2osp(m0, k), calls

        if len(M) > 1:
            s += 1
            while not ok((c0 * pow(s, e, n)) % n):
                s += 1
        else:
            a, b = M[0]
            r = ceil_div(2 * (b * s - B2), n)
            while True:
                left = ceil_div(B2 + r * n, b)
                right = floor_div(B3m1 + r * n, a)
                found = None
                for cand_s in range(left, right + 1):
                    if ok((c0 * pow(cand_s, e, n)) % n):
                        found = cand_s
                        break
                if found is not None:
                    s = found
                    break
                r += 1


def _toy_rsa_key() -> RSAKey:
    p = 251444687128489
    q = 274004257255073
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 5
    d = inv_mod(e, phi)
    return RSAKey(n=n, e=e, d=d)


def toy_prefix_encode(message: bytes, k: int, header_byte: int = 2) -> bytes:
    if not (0 <= header_byte <= 255):
        raise ValueError("bad header_byte")
    if len(message) > k - 1:
        raise ValueError("message too long")
    return bytes([header_byte]) + (b"\x00" * (k - 1 - len(message))) + message


def toy_prefix_decode(em: bytes, message_len: int) -> bytes:
    if message_len < 0 or message_len > len(em):
        raise ValueError("bad message_len")
    return em[-message_len:]


def main():
    key = _toy_rsa_key()
    msg = b"Z"

    print("=== Step 1: RSA primitives ===")
    print("k (bytes):", key.k)
    print("n (bits) :", key.n.bit_length())

    print("=== Step 2: PKCS#1 v1.5 encoding (format) ===")
    ps = bytes.fromhex("a1a2a3a4a5a6a7a8")
    pkcs_em = pkcs1v15_encode(msg, key.k, ps)
    print("pkcs_em:", pkcs_em.hex())
    print("pkcs_ok:", pkcs1v15_is_conformant(pkcs_em))

    print("=== Step 3: A fast header oracle (toy) ===")
    header_bits = 8
    oracle = header_oracle_factory(key, header_bits=header_bits)
    em = toy_prefix_encode(msg, key.k, header_byte=2)
    m = os2ip(em)
    c = rsa_encrypt_int(m, key.n, key.e)
    print("toy_em:", em.hex())
    print("oracle(c):", oracle(c))

    print("=== Step 4: Adaptive narrowing (Bleichenbacher-style, toy header) ===")
    B = 1 << (8 * key.k - header_bits)
    print("B bits:", B.bit_length())
    print("2B <= m < 3B ?", (2 * B) <= m < (3 * B))
    recovered_em, calls = bleichenbacher_recover_em(c, key.n, key.e, oracle, header_bits=header_bits)
    recovered_msg = toy_prefix_decode(recovered_em, len(msg))
    print("oracle_calls:", calls)
    print("recovered_em :", recovered_em.hex())
    print("recovered_msg:", recovered_msg)


if __name__ == "__main__":
    main()
