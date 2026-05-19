"""
RSA from scratch (toy): key generation, encryption/decryption, and a simple attack.

Run:
  python3 code/main.py

This is an educational implementation. It is NOT constant-time and is NOT safe for production.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass


def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(a: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    a %= modulus
    g, x, _y = extended_gcd(a, modulus)
    if g != 1:
        raise ValueError("inverse does not exist (not coprime)")
    return x % modulus


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be non-negative")
    base %= modulus
    result = 1
    e = exponent
    b = base
    while e:
        if e & 1:
            result = (result * b) % modulus
        b = (b * b) % modulus
        e >>= 1
    return result


def _decompose_n_minus_1(n: int) -> tuple[int, int]:
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d


def is_probable_prime(n: int, rng: random.Random | None = None, rounds: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if n in small_primes:
        return True
    for p in small_primes:
        if n % p == 0:
            return False

    s, d = _decompose_n_minus_1(n)

    if n < (1 << 64):
        bases = (2, 325, 9375, 28178, 450775, 9780504, 1795265022)
    else:
        rng = rng or random.SystemRandom()
        bases = [rng.randrange(2, n - 1) for _ in range(max(1, rounds))]

    for a in bases:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def random_prime(bits: int, rng: random.Random) -> int:
    if bits < 8:
        raise ValueError("bits too small for this demo (need >= 8)")
    while True:
        candidate = rng.getrandbits(bits)
        candidate |= 1
        candidate |= 1 << (bits - 1)
        if is_probable_prime(candidate, rng=rng):
            return candidate


@dataclass(frozen=True)
class RSAKeypair:
    n: int
    e: int
    d: int
    p: int
    q: int


def rsa_keypair_from_primes(p: int, q: int, e: int = 65537) -> RSAKeypair:
    if p <= 1 or q <= 1:
        raise ValueError("p and q must be > 1")
    if p == q:
        raise ValueError("p and q must be distinct")
    if not is_probable_prime(p) or not is_probable_prime(q):
        raise ValueError("p and q must be prime")
    if e <= 1:
        raise ValueError("e must be > 1")

    n = p * q
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        raise ValueError("e must be coprime to phi(n)")
    d = mod_inverse(e, phi)
    return RSAKeypair(n=n, e=e, d=d, p=p, q=q)


def rsa_generate_keypair(bits: int, e: int = 65537, rng: random.Random | None = None) -> RSAKeypair:
    if bits < 16:
        raise ValueError("bits too small for this demo (need >= 16)")
    rng = rng or random.Random()
    while True:
        p = random_prime(bits // 2, rng)
        q = random_prime(bits - bits // 2, rng)
        if p == q:
            continue
        try:
            return rsa_keypair_from_primes(p, q, e=e)
        except ValueError:
            continue


def rsa_encrypt_int(m: int, n: int, e: int) -> int:
    if m < 0:
        raise ValueError("message representative must be non-negative")
    if m >= n:
        raise ValueError("message representative must be < n")
    return mod_pow(m, e, n)


def rsa_decrypt_int(c: int, n: int, d: int) -> int:
    if c < 0:
        raise ValueError("ciphertext representative must be non-negative")
    if c >= n:
        raise ValueError("ciphertext representative must be < n")
    return mod_pow(c, d, n)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big", signed=False)


def int_to_bytes(x: int, length: int) -> bytes:
    if x < 0:
        raise ValueError("x must be non-negative")
    if length < 0:
        raise ValueError("length must be non-negative")
    if length == 0:
        if x != 0:
            raise ValueError("x does not fit in the requested length")
        return b""
    if x >= (1 << (8 * length)):
        raise ValueError("x does not fit in the requested length")
    return x.to_bytes(length, byteorder="big", signed=False)


def rsa_encrypt_bytes_textbook(message: bytes, n: int, e: int) -> int:
    m = bytes_to_int(message)
    return rsa_encrypt_int(m, n, e)


def rsa_decrypt_bytes_textbook(ciphertext: int, n: int, d: int, out_len: int) -> bytes:
    m = rsa_decrypt_int(ciphertext, n, d)
    return int_to_bytes(m, out_len)


def factor_semiprime_trial(n: int) -> tuple[int, int]:
    if n <= 1:
        raise ValueError("n must be > 1")
    if n % 2 == 0:
        return 2, n // 2
    limit = int(math.isqrt(n))
    f = 3
    while f <= limit:
        if n % f == 0:
            return f, n // f
        f += 2
    raise ValueError("n does not look like a small semiprime (trial division failed)")


def recover_private_exponent_from_factoring(n: int, e: int) -> tuple[int, int, int]:
    p, q = factor_semiprime_trial(n)
    phi = (p - 1) * (q - 1)
    d = mod_inverse(e, phi)
    return p, q, d


def main():
    rng = random.Random(42)

    print("=== Step 1: Modular inverses (EEA) ===")
    a, m = 17, 3120
    inv = mod_inverse(a, m)
    print(f"a={a}, m={m}")
    print(f"inv={inv}")
    print(f"(a*inv) mod m = {(a*inv) % m}")
    print()

    print("=== Step 2: Primes (Miller–Rabin) ===")
    for x in (2, 3, 4, 5, 15, 17, 21, 97, 221):
        print(f"is_probable_prime({x}) = {is_probable_prime(x)}")
    print()
    p_demo = random_prime(16, rng)
    q_demo = random_prime(16, rng)
    print(f"example primes: p={p_demo}, q={q_demo}")
    print()

    print("=== Step 3: RSA key generation ===")
    key = rsa_keypair_from_primes(p=61, q=53, e=17)
    print(f"p={key.p}, q={key.q}")
    print(f"n={key.n}")
    print(f"e={key.e}")
    print(f"d={key.d}")
    print()

    print("=== Step 4: Textbook RSA encrypt/decrypt ===")
    m_int = 65
    c = rsa_encrypt_int(m_int, key.n, key.e)
    m_back = rsa_decrypt_int(c, key.n, key.d)
    print(f"m={m_int} -> c={c} -> m'={m_back}")
    msg = b"A"
    c2 = rsa_encrypt_bytes_textbook(msg, key.n, key.e)
    msg_back = rsa_decrypt_bytes_textbook(c2, key.n, key.d, out_len=len(msg))
    print(f"msg={msg!r} -> c={c2} -> msg'={msg_back!r}")
    print()

    print("=== Step 5: Break toy RSA by factoring n ===")
    p, q, d = recover_private_exponent_from_factoring(key.n, key.e)
    m_recovered = rsa_decrypt_int(c, key.n, d)
    print(f"factored n into p={p}, q={q}")
    print(f"recovered d={d}")
    print(f"decrypted with recovered d: m={m_recovered}")


if __name__ == "__main__":
    main()
