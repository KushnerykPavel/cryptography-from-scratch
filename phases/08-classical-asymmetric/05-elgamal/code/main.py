"""
ElGamal encryption from scratch (educational).

This script implements textbook ElGamal encryption over the multiplicative group
modulo a (small) safe prime, then demonstrates:

- key generation
- probabilistic encryption and correct decryption
- rerandomization (fresh randomness without the plaintext)
- malleability / multiplicative homomorphism
- a simple hybrid mode for bytes (KDF + XOR stream; still unauthenticated)

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import math
import secrets
from dataclasses import dataclass
from typing import Tuple


Ciphertext = Tuple[int, int]


def _is_prime_trial_division(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    limit = int(math.isqrt(n))
    f = 3
    while f <= limit:
        if n % f == 0:
            return False
        f += 2
    return True


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, modulus: int) -> int:
    a %= modulus
    g, x, _ = _egcd(a, modulus)
    if g != 1:
        raise ValueError("not invertible modulo modulus")
    return x % modulus


def int_to_bytes(n: int, length: int | None = None) -> bytes:
    if n < 0:
        raise ValueError("n must be non-negative")
    if length is None:
        if n == 0:
            return b"\x00"
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor requires equal-length buffers")
    return bytes(x ^ y for x, y in zip(a, b))


def sha256_stream(key_material: bytes, out_len: int, *, label: bytes = b"") -> bytes:
    if out_len < 0:
        raise ValueError("out_len must be non-negative")
    out = bytearray()
    counter = 0
    while len(out) < out_len:
        h = hashlib.sha256()
        h.update(label)
        h.update(counter.to_bytes(4, "big"))
        h.update(key_material)
        out.extend(h.digest())
        counter += 1
    return bytes(out[:out_len])


@dataclass(frozen=True)
class ElGamalParams:
    p: int
    g: int

    @property
    def q(self) -> int:
        return (self.p - 1) // 2


def validate_params(params: ElGamalParams) -> None:
    p, g = params.p, params.g
    if not _is_prime_trial_division(p):
        raise ValueError("p must be prime")
    if p <= 3:
        raise ValueError("p too small")
    if (p - 1) % 2 != 0:
        raise ValueError("p must be odd")
    q = (p - 1) // 2
    if not _is_prime_trial_division(q):
        raise ValueError("p must be a safe prime (q = (p-1)/2 prime)")
    if not (2 <= g <= p - 2):
        raise ValueError("g out of range")
    if pow(g, 2, p) == 1 or pow(g, q, p) == 1:
        raise ValueError("g must be a generator of Z_p* (order p-1)")


def demo_params() -> ElGamalParams:
    params = ElGamalParams(p=467, g=2)
    validate_params(params)
    return params


@dataclass(frozen=True)
class ElGamalPublicKey:
    params: ElGamalParams
    y: int


@dataclass(frozen=True)
class ElGamalPrivateKey:
    params: ElGamalParams
    x: int


def elgamal_keygen(params: ElGamalParams, *, x: int | None = None) -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
    validate_params(params)
    if x is None:
        x = secrets.randbelow(params.p - 2) + 1
    if not (1 <= x <= params.p - 2):
        raise ValueError("x out of range")
    y = pow(params.g, x, params.p)
    return ElGamalPublicKey(params=params, y=y), ElGamalPrivateKey(params=params, x=x)


def elgamal_encrypt_int(pub: ElGamalPublicKey, m: int, *, k: int | None = None) -> Ciphertext:
    p, g, y = pub.params.p, pub.params.g, pub.y
    if not (1 <= m <= p - 1):
        raise ValueError("message m must be in 1..p-1")
    if k is None:
        k = secrets.randbelow(p - 2) + 1
    if not (1 <= k <= p - 2):
        raise ValueError("k out of range")
    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p
    return c1, c2


def elgamal_decrypt_int(priv: ElGamalPrivateKey, ct: Ciphertext) -> int:
    p = priv.params.p
    c1, c2 = ct
    if not (1 <= c1 <= p - 1 and 0 <= c2 <= p - 1):
        raise ValueError("ciphertext components out of range")
    s = pow(c1, priv.x, p)
    return (c2 * modinv(s, p)) % p


def elgamal_rerandomize(pub: ElGamalPublicKey, ct: Ciphertext, *, r: int | None = None) -> Ciphertext:
    p, g, y = pub.params.p, pub.params.g, pub.y
    c1, c2 = ct
    if r is None:
        r = secrets.randbelow(p - 2) + 1
    if not (1 <= r <= p - 2):
        raise ValueError("r out of range")
    return (c1 * pow(g, r, p)) % p, (c2 * pow(y, r, p)) % p


def elgamal_mul_ciphertexts(params: ElGamalParams, a: Ciphertext, b: Ciphertext) -> Ciphertext:
    p = params.p
    return (a[0] * b[0]) % p, (a[1] * b[1]) % p


def elgamal_encrypt_bytes(pub: ElGamalPublicKey, plaintext: bytes, *, k: int | None = None, label: bytes = b"") -> Tuple[int, bytes]:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    p, g, y = pub.params.p, pub.params.g, pub.y
    if k is None:
        k = secrets.randbelow(p - 2) + 1
    if not (1 <= k <= p - 2):
        raise ValueError("k out of range")
    c1 = pow(g, k, p)
    shared = pow(y, k, p)
    key_material = int_to_bytes(shared)
    stream = sha256_stream(key_material, len(plaintext), label=label)
    return c1, xor_bytes(bytes(plaintext), stream)


def elgamal_decrypt_bytes(priv: ElGamalPrivateKey, c1: int, ciphertext: bytes, *, label: bytes = b"") -> bytes:
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes-like")
    p = priv.params.p
    if not (1 <= c1 <= p - 1):
        raise ValueError("c1 out of range")
    shared = pow(c1, priv.x, p)
    key_material = int_to_bytes(shared)
    stream = sha256_stream(key_material, len(ciphertext), label=label)
    return xor_bytes(bytes(ciphertext), stream)


def _fmt_pair(ct: Ciphertext) -> str:
    return f"(c1={ct[0]}, c2={ct[1]})"


def main() -> None:
    params = demo_params()

    print("=== Step 1: Parameters & helpers ===")
    print(f"p = {params.p} (safe prime), q = {params.q}, g = {params.g}")

    print("\n=== Step 2: Key generation ===")
    pub, priv = elgamal_keygen(params, x=37)
    print(f"private x = {priv.x}")
    print(f"public  y = g^x mod p = {pub.y}")

    print("\n=== Step 3: Encrypt/decrypt an integer mod p ===")
    m = 123
    ct = elgamal_encrypt_int(pub, m, k=81)
    m_dec = elgamal_decrypt_int(priv, ct)
    print(f"m = {m}")
    print(f"ct = {_fmt_pair(ct)}")
    print(f"dec(ct) = {m_dec}")

    print("\n=== Step 4: Rerandomize + homomorphism (and why it's a pitfall) ===")
    ct2 = elgamal_rerandomize(pub, ct, r=19)
    print(f"rerand(ct) = {_fmt_pair(ct2)}")
    print(f"dec(rerand(ct)) = {elgamal_decrypt_int(priv, ct2)}")

    a, b = 7, 11
    cta = elgamal_encrypt_int(pub, a, k=3)
    ctb = elgamal_encrypt_int(pub, b, k=5)
    ctab = elgamal_mul_ciphertexts(params, cta, ctb)
    ab_dec = elgamal_decrypt_int(priv, ctab)
    print(f"a = {a}, b = {b}")
    print(f"ct(a) = {_fmt_pair(cta)}")
    print(f"ct(b) = {_fmt_pair(ctb)}")
    print(f"ct(a)*ct(b) = {_fmt_pair(ctab)}")
    print(f"dec(ct(a)*ct(b)) = {ab_dec} (should equal a*b mod p)")

    t = 2
    tweaked = (ct[0], (ct[1] * t) % params.p)
    print(f"tweak: (c1, t*c2) with t={t} -> dec = {elgamal_decrypt_int(priv, tweaked)} (should equal t*m mod p)")

    print("\n=== Step 5: Hybrid bytes demo (KDF + XOR stream; unauthenticated) ===")
    msg = b"elgamal -> shared secret -> stream"
    c1, cbytes = elgamal_encrypt_bytes(pub, msg, k=9, label=b"demo")
    pbytes = elgamal_decrypt_bytes(priv, c1, cbytes, label=b"demo")
    print(f"plaintext = {msg!r}")
    print(f"c1 = {c1}, ciphertext = {cbytes.hex()}")
    print(f"decrypted = {pbytes!r}")


if __name__ == "__main__":
    main()
