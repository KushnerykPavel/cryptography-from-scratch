"""
Deterministic nonces (RFC 6979) for DSA/ECDSA-style signatures.

This file implements:
- RFC 6979 deterministic nonce generation (HMAC-DRBG) from (x, H(m))
- DSA signing/verifying over a finite-field subgroup
- The classic nonce-reuse key-recovery attack for DSA

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Callable, Iterator


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


def int2octets(x: int, rolen: int) -> bytes:
    if x < 0:
        raise ValueError("x must be >= 0")
    return int_to_bytes(x, rolen)


def bits2octets(h1: bytes, q: int) -> bytes:
    qlen = q.bit_length()
    rolen = (qlen + 7) // 8
    z1 = bits2int(h1, qlen)
    z2 = z1 % q
    return int2octets(z2, rolen)


def hash_to_int(message: bytes, q: int, hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256) -> int:
    qlen = q.bit_length()
    h1 = hashfunc(message).digest()
    return bits2int(h1, qlen) % q


@dataclass
class Rfc6979NonceGenerator:
    q: int
    qlen: int
    rolen: int
    hashfunc: Callable[[], "hashlib._Hash"]
    v: bytes
    k: bytes

    @classmethod
    def from_key_and_hash(
        cls,
        *,
        x: int,
        q: int,
        h1: bytes,
        hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
    ) -> "Rfc6979NonceGenerator":
        qlen = q.bit_length()
        holen = hashfunc().digest_size
        rolen = (qlen + 7) // 8

        bx = int2octets(x % q, rolen) + bits2octets(h1, q)
        v = b"\x01" * holen
        k = b"\x00" * holen

        k = hmac.new(k, v + b"\x00" + bx, hashfunc).digest()
        v = hmac.new(k, v, hashfunc).digest()
        k = hmac.new(k, v + b"\x01" + bx, hashfunc).digest()
        v = hmac.new(k, v, hashfunc).digest()

        return cls(q=q, qlen=qlen, rolen=rolen, hashfunc=hashfunc, v=v, k=k)

    def next_k(self) -> int:
        while True:
            t = b""
            while len(t) < self.rolen:
                self.v = hmac.new(self.k, self.v, self.hashfunc).digest()
                t += self.v

            candidate = bits2int(t[: self.rolen], self.qlen)
            if 1 <= candidate < self.q:
                return candidate

            self.k = hmac.new(self.k, self.v + b"\x00", self.hashfunc).digest()
            self.v = hmac.new(self.k, self.v, self.hashfunc).digest()


def rfc6979_k_stream(
    *,
    x: int,
    q: int,
    message: bytes,
    hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> Iterator[int]:
    h1 = hashfunc(message).digest()
    gen = Rfc6979NonceGenerator.from_key_and_hash(x=x, q=q, h1=h1, hashfunc=hashfunc)
    while True:
        yield gen.next_k()


def rfc6979_generate_k(
    *,
    x: int,
    q: int,
    message: bytes,
    hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> int:
    return next(rfc6979_k_stream(x=x, q=q, message=message, hashfunc=hashfunc))


def dsa_sign(
    *,
    p: int,
    q: int,
    g: int,
    x: int,
    message: bytes,
    hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
    k: int | None = None,
) -> tuple[int, int, int]:
    if not (1 <= x < q):
        raise ValueError("private key x must be in 1..q-1")

    h = hash_to_int(message, q, hashfunc)

    if k is not None:
        k_candidates: Iterator[int] = iter([k])
    else:
        k_candidates = rfc6979_k_stream(x=x, q=q, message=message, hashfunc=hashfunc)

    for k_try in k_candidates:
        if not (1 <= k_try < q):
            raise ValueError("nonce k must be in 1..q-1")

        r = pow(g, k_try, p) % q
        if r == 0:
            continue

        s = (mod_inv(k_try, q) * (h + x * r)) % q
        if s == 0:
            continue

        return r, s, k_try

    raise ValueError("failed to produce non-zero (r,s)")


def dsa_verify(
    *,
    p: int,
    q: int,
    g: int,
    y: int,
    message: bytes,
    r: int,
    s: int,
    hashfunc: Callable[[], "hashlib._Hash"] = hashlib.sha256,
) -> bool:
    if not (1 <= r < q and 1 <= s < q):
        return False

    h = hash_to_int(message, q, hashfunc)
    w = mod_inv(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p
    v %= q
    return v == r


def recover_k_from_reused_dsa_nonce(*, q: int, h1: int, h2: int, s1: int, s2: int) -> int:
    if s1 == s2:
        raise ValueError("s1 must not equal s2 for reused-nonce recovery")
    return ((h1 - h2) * mod_inv((s1 - s2) % q, q)) % q


def recover_x_from_dsa_known_k(*, q: int, r: int, s: int, h: int, k: int) -> int:
    if r == 0:
        raise ValueError("r must be non-zero")
    return ((s * k - h) * mod_inv(r % q, q)) % q


def _hex_to_int(s: str) -> int:
    return int(s.replace(" ", "").replace("\n", ""), 16)


def _int_to_hex(x: int) -> str:
    return x.to_bytes((x.bit_length() + 7) // 8 or 1, "big").hex().upper()


RFC6979_DSA_1024 = {
    "p": _hex_to_int(
        "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447"
        "E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88"
        "73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C"
        "881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779"
    ),
    "q": _hex_to_int("996F967F6C8E388D9E28D01E205FBA957A5698B1"),
    "g": _hex_to_int(
        "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D"
        "89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD"
        "87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4"
        "17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD"
    ),
    "x": _hex_to_int("411602CB19A6CCC34494D79D98EF1E7ED5AF25F7"),
    "y": _hex_to_int(
        "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653"
        "92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D"
        "4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6"
        "82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B"
    ),
}


RFC6979_SHA256_VECTORS = {
    b"sample": {
        "k": _hex_to_int("519BA0546D0C39202A7D34D7DFA5E760B318BCFB"),
        "r": _hex_to_int("81F2F5850BE5BC123C43F71A3033E9384611C545"),
        "s": _hex_to_int("4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89"),
    },
    b"test": {
        "k": _hex_to_int("5A67592E8128E03A417B0484410FB72C0B630E1A"),
        "r": _hex_to_int("22518C127299B0F6FDC9872B282B9E70D0790812"),
        "s": _hex_to_int("6837EC18F150D55DE95B5E29BE7AF5D01E4FE160"),
    },
}


def main() -> None:
    p = RFC6979_DSA_1024["p"]
    q = RFC6979_DSA_1024["q"]
    g = RFC6979_DSA_1024["g"]
    x = RFC6979_DSA_1024["x"]
    y = RFC6979_DSA_1024["y"]

    print("=== Step 1: Hashes, integers, and octets ===")
    msg = b"sample"
    h1 = hashlib.sha256(msg).digest()
    print(f"SHA-256(message) = {h1.hex()}")
    print(f"bits2int(h1) mod q = {hash_to_int(msg, q):#x}")
    print(f"bits2octets(h1) = {bits2octets(h1, q).hex()}")

    print("\n=== Step 2: RFC 6979 deterministic nonce generation ===")
    k = rfc6979_generate_k(x=x, q=q, message=msg, hashfunc=hashlib.sha256)
    print(f"k(message={msg!r}) = 0x{_int_to_hex(k)}")
    print(f"k matches RFC 6979 vector: {k == RFC6979_SHA256_VECTORS[msg]['k']}")

    print("\n=== Step 3: Deterministic DSA sign/verify (RFC 6979) ===")
    for m in (b"sample", b"test"):
        r, s, k_used = dsa_sign(p=p, q=q, g=g, x=x, message=m, hashfunc=hashlib.sha256)
        ok = dsa_verify(p=p, q=q, g=g, y=y, message=m, r=r, s=s, hashfunc=hashlib.sha256)
        exp = RFC6979_SHA256_VECTORS[m]
        print(f"message={m!r}")
        print(f"  k = 0x{_int_to_hex(k_used)} (matches RFC: {k_used == exp['k']})")
        print(f"  r = 0x{_int_to_hex(r)} (matches RFC: {r == exp['r']})")
        print(f"  s = 0x{_int_to_hex(s)} (matches RFC: {s == exp['s']})")
        print(f"  verify: {ok}")

    print("\n=== Step 4: Nonce reuse breaks DSA (key recovery) ===")
    fixed_k = 42
    m1 = b"message one"
    m2 = b"message two"
    r1, s1, _ = dsa_sign(p=p, q=q, g=g, x=x, message=m1, hashfunc=hashlib.sha256, k=fixed_k)
    r2, s2, _ = dsa_sign(p=p, q=q, g=g, x=x, message=m2, hashfunc=hashlib.sha256, k=fixed_k)
    h_m1 = hash_to_int(m1, q, hashlib.sha256)
    h_m2 = hash_to_int(m2, q, hashlib.sha256)
    k_rec = recover_k_from_reused_dsa_nonce(q=q, h1=h_m1, h2=h_m2, s1=s1, s2=s2)
    x_rec = recover_x_from_dsa_known_k(q=q, r=r1, s=s1, h=h_m1, k=k_rec)
    print(f"r1 == r2 (same nonce) = {r1 == r2}")
    print(f"recovered k = {k_rec} (expected {fixed_k})")
    print(f"recovered x matches = {x_rec == x}")


if __name__ == "__main__":
    main()
