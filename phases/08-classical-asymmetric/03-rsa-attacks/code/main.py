"""
Textbook RSA attacks (demo-only).

This lesson implements three classic attacks that break *textbook* RSA when
systems violate key hygiene rules:

- Common modulus attack (same `n`, different exponents)
- Håstad broadcast attack (small `e`, same plaintext to multiple recipients)
- Wiener's attack (secret exponent `d` too small)

Run:
  python3 code/main.py
"""

from __future__ import annotations

import json
from math import gcd, isqrt
from pathlib import Path


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0 and b == 0:
        raise ValueError("at least one of a,b must be nonzero")

    x0, y0, x1, y1 = 1, 0, 0, 1
    aa, bb = a, b
    while bb != 0:
        q = aa // bb
        aa, bb = bb, aa - q * bb
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return aa, x0, y0


def modinv(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    aa = a % n
    g, x, _ = egcd(aa, n)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % n


def pow_mod_signed(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    b = base % modulus
    if exponent >= 0:
        return pow(b, exponent, modulus)
    inv = modinv(b, modulus)
    return pow(inv, -exponent, modulus)


def crt_combine(pairs: list[tuple[int, int]]) -> tuple[int, int]:
    if not pairs:
        raise ValueError("pairs must be non-empty")

    x = 0
    modulus = 1
    for a_i, n_i in pairs:
        if n_i <= 0:
            raise ValueError("modulus must be positive")
        if gcd(modulus, n_i) != 1:
            raise ValueError("moduli must be pairwise coprime")

        a_i %= n_i
        t = ((a_i - x) % n_i) * modinv(modulus % n_i, n_i) % n_i
        x = x + modulus * t
        modulus *= n_i
        x %= modulus

    return x, modulus


def integer_nth_root_floor(x: int, n: int) -> int:
    if x < 0:
        raise ValueError("x must be nonnegative")
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return x
    if x in (0, 1):
        return x
    if n == 2:
        return isqrt(x)

    hi = 1 << ((x.bit_length() + n - 1) // n)
    lo = 0
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**n <= x:
            lo = mid
        else:
            hi = mid
    return lo


def is_perfect_nth_power(x: int, n: int) -> int | None:
    r = integer_nth_root_floor(x, n)
    if r**n == x:
        return r
    return None


def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")
    if m < 0 or m >= n:
        raise ValueError("message representative out of range")
    if e <= 0:
        raise ValueError("e must be positive")
    return pow(m, e, n)


def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")
    if c < 0 or c >= n:
        raise ValueError("ciphertext representative out of range")
    if d <= 0:
        raise ValueError("d must be positive")
    return pow(c, d, n)


def common_modulus_attack(*, n: int, e1: int, e2: int, c1: int, c2: int) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")
    if e1 <= 0 or e2 <= 0:
        raise ValueError("exponents must be positive")
    if c1 < 0 or c1 >= n or c2 < 0 or c2 >= n:
        raise ValueError("ciphertexts out of range")

    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError("e1 and e2 must be coprime")

    part1 = pow_mod_signed(c1, a, n)
    part2 = pow_mod_signed(c2, b, n)
    return (part1 * part2) % n


def hastad_broadcast_attack(*, cs: list[int], ns: list[int], e: int) -> int:
    if e <= 1:
        raise ValueError("e must be > 1")
    if len(cs) != len(ns) or not cs:
        raise ValueError("cs and ns must have same nonzero length")

    x, _ = crt_combine(list(zip(cs, ns)))
    m = is_perfect_nth_power(x, e)
    if m is None:
        raise ValueError("combined value is not a perfect e-th power")
    return m


def continued_fraction(numer: int, denom: int) -> list[int]:
    if denom <= 0:
        raise ValueError("denom must be positive")
    if numer < 0:
        raise ValueError("numer must be nonnegative")

    out: list[int] = []
    n, d = numer, denom
    while d != 0:
        q = n // d
        out.append(q)
        n, d = d, n - q * d
    return out


def convergents(cf: list[int]) -> list[tuple[int, int]]:
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    out: list[tuple[int, int]] = []
    for a in cf:
        p = a * p1 + p0
        q = a * q1 + q0
        out.append((p, q))
        p0, p1 = p1, p
        q0, q1 = q1, q
    return out


def factor_from_phi(*, n: int, phi: int) -> tuple[int, int] | None:
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    r = isqrt(disc)
    if r * r != disc:
        return None
    if (s + r) % 2 != 0:
        return None
    p = (s + r) // 2
    q = (s - r) // 2
    if p * q != n:
        return None
    return (p, q) if p <= q else (q, p)


def wiener_attack_recover_key(*, e: int, n: int) -> tuple[int, int, int] | None:
    if n <= 1:
        raise ValueError("n must be > 1")
    if e <= 1 or e >= n:
        raise ValueError("e must satisfy 1 < e < n")

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        ed1 = e * d - 1
        if ed1 % k != 0:
            continue
        phi = ed1 // k
        factors = factor_from_phi(n=n, phi=phi)
        if factors is None:
            continue
        p, q = factors
        return p, q, d

    return None


def load_vectors_file(path: Path) -> dict:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("vectors file must be a JSON object")
    if "source" not in data or "vectors" not in data:
        raise ValueError("vectors file must include source and vectors")
    if not isinstance(data["source"], str):
        raise ValueError("source must be a string")
    if not isinstance(data["vectors"], list):
        raise ValueError("vectors must be a list")
    return data


def main() -> None:
    print("Textbook RSA attacks (demo-only)")
    print()

    print("=== Step 1: RSA math helpers ===")
    inv = modinv(17, 3120)
    print(f"modinv(17, 3120) = {inv}  (17*inv mod 3120 = {(17*inv)%3120})")

    x, mod = crt_combine([(2, 3), (3, 5)])
    print(f"CRT: x ≡ 2 (mod 3), x ≡ 3 (mod 5)  ->  x = {x} (mod {mod})")

    r = integer_nth_root_floor(28, 3)
    print(f"integer_nth_root_floor(28, 3) = {r}  (since {r}^3 <= 28 < {(r+1)}^3)")
    print()

    print("=== Step 2: Common modulus attack ===")
    n = 101 * 113
    m = 42
    e1, e2 = 17, 13
    c1 = rsa_encrypt_int(m, e1, n)
    c2 = rsa_encrypt_int(m, e2, n)
    recovered = common_modulus_attack(n=n, e1=e1, e2=e2, c1=c1, c2=c2)
    print(f"n = {n} (same modulus), exponents = ({e1}, {e2})")
    print(f"m = {m} -> c1 = m^e1 mod n = {c1}")
    print(f"m = {m} -> c2 = m^e2 mod n = {c2}")
    print(f"recovered m (no factoring) = {recovered}")
    print()

    print("=== Step 3: Håstad broadcast attack (e=3) ===")
    e = 3
    ns = [101 * 107, 113 * 131, 137 * 149]
    m = 1234
    cs = [rsa_encrypt_int(m, e, n_i) for n_i in ns]
    recovered = hastad_broadcast_attack(cs=cs, ns=ns, e=e)
    print(f"same plaintext m = {m}, public exponent e = {e}")
    for i, (n_i, c_i) in enumerate(zip(ns, cs), start=1):
        print(f"recipient {i}: n = {n_i}, c = m^e mod n = {c_i}")
    print(f"recovered m (CRT + integer root) = {recovered}")
    print()

    print("=== Step 4: Wiener's attack (small d) ===")
    p, q = 101, 107
    n = p * q
    phi = (p - 1) * (q - 1)
    d = 3
    e = modinv(d, phi)
    key = wiener_attack_recover_key(e=e, n=n)
    print(f"public key: (n={n}, e={e})")
    print(f"(unknown to attacker) secret d = {d}")
    print(f"wiener_attack_recover_key(...) = {key}")
    if key is None:
        raise AssertionError("expected Wiener recovery to succeed for this demo key")
    rp, rq, rd = key
    c = rsa_encrypt_int(99, e, n)
    m2 = rsa_decrypt_int(c, rd, n)
    print(f"decrypt with recovered d: c={c} -> m={m2}")


if __name__ == "__main__":
    main()
