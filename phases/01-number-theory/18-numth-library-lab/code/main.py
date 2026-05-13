from math import gcd as math_gcd
from math import isqrt, lcm, prod


class NumthError(ValueError):
    pass


class NoInverseError(NumthError):
    pass


class NoSquareRootError(NumthError):
    pass


MILLER_RABIN_BOUND = 3_317_044_064_679_887_385_961_981
MILLER_RABIN_BASES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
SMALL_PRIMES = [
    2,
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
]


def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0 and b == 0:
        return 0, 0, 0

    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    if a < 0:
        old_s = -old_s
    if b < 0:
        old_t = -old_t

    return old_r, old_s, old_t


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise NumthError("modulus must be positive")
    if exponent < 0:
        return mod_inverse(mod_pow(base, -exponent, modulus), modulus)
    return pow(base, exponent, modulus)


def mod_inverse(a: int, modulus: int) -> int:
    if modulus <= 0:
        raise NumthError("modulus must be positive")

    g, x, _ = extended_gcd(a, modulus)
    if g != 1:
        raise NoInverseError(f"{a} has no inverse modulo {modulus}")
    return x % modulus


def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    if len(residues) != len(moduli):
        raise NumthError("residues and moduli must have the same length")
    if not moduli:
        raise NumthError("CRT system must be non-empty")
    if any(modulus <= 0 for modulus in moduli):
        raise NumthError("all moduli must be positive")

    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise NumthError("moduli must be pairwise coprime")

    modulus = prod(moduli)
    total = 0
    for residue, n_i in zip(residues, moduli):
        partial = modulus // n_i
        total += (residue % n_i) * partial * mod_inverse(partial, n_i)
    return total % modulus, modulus


def decompose_n_minus_one(n: int) -> tuple[int, int]:
    if n < 3 or n % 2 == 0:
        raise NumthError("n must be an odd integer greater than 2")

    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    return s, d


def miller_rabin_witness(base: int, n: int) -> bool:
    if n < 3 or n % 2 == 0:
        raise NumthError("n must be an odd integer greater than 2")

    base %= n
    if base in (0, 1, n - 1):
        return False
    if gcd(base, n) != 1:
        return True

    s, d = decompose_n_minus_one(n)
    x = pow(base, d, n)
    if x in (1, n - 1):
        return False

    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    if n >= MILLER_RABIN_BOUND:
        raise NumthError("n exceeds this lesson's deterministic Miller-Rabin range")

    for base in MILLER_RABIN_BASES:
        if base >= n:
            continue
        if miller_rabin_witness(base, n):
            return False
    return True


def prime_sieve(limit: int) -> list[int]:
    if limit < 2:
        return []

    sieve = bytearray(b"\x01") * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for p in range(2, isqrt(limit) + 1):
        if sieve[p]:
            start = p * p
            sieve[start : limit + 1 : p] = b"\x00" * (((limit - start) // p) + 1)
    return [i for i in range(limit + 1) if sieve[i]]


def pollard_rho(n: int, max_rounds: int = 20_000) -> int | None:
    if n <= 1:
        raise NumthError("n must be greater than 1")
    if n % 2 == 0:
        return 2 if n != 2 else None
    if is_prime(n):
        return None

    for c in range(1, 8):
        x = 2
        y = 2
        factor = 1
        rounds = 0
        while factor == 1 and rounds < max_rounds:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            factor = math_gcd(abs(x - y), n)
            rounds += 1
        if 1 < factor < n:
            return factor
    return None


def pollard_p_minus_one(n: int, bound: int = 50) -> int | None:
    if n <= 1:
        raise NumthError("n must be greater than 1")
    if bound < 2:
        raise NumthError("bound must be at least 2")
    if n % 2 == 0:
        return 2 if n != 2 else None

    exponent = 1
    for value in range(2, bound + 1):
        exponent = lcm(exponent, value)

    factor = math_gcd(pow(2, exponent, n) - 1, n)
    if 1 < factor < n:
        return factor
    return None


def _factor_recursive(n: int, out: list[int], trial_bound: int, pm1_bound: int) -> None:
    if n == 1:
        return
    if is_prime(n):
        out.append(n)
        return

    for p in prime_sieve(min(trial_bound, isqrt(n))):
        while n % p == 0:
            out.append(p)
            n //= p
        if n == 1:
            return
        if is_prime(n):
            out.append(n)
            return

    factor = pollard_p_minus_one(n, pm1_bound)
    if factor is None:
        factor = pollard_rho(n)
    if factor is None:
        raise NumthError("failed to factor n with this lesson's toy algorithms")

    _factor_recursive(factor, out, trial_bound, pm1_bound)
    _factor_recursive(n // factor, out, trial_bound, pm1_bound)


def factor(n: int, trial_bound: int = 10_000, pm1_bound: int = 50) -> list[int]:
    if n == 0:
        raise NumthError("cannot factor zero")
    if abs(n) == 1:
        return []

    factors: list[int] = []
    if n < 0:
        factors.append(-1)
        n = -n

    _factor_recursive(n, factors, trial_bound, pm1_bound)
    return sorted(factors, key=lambda value: (value == -1, abs(value)))


def factor_counts(n: int) -> dict[int, int]:
    counts: dict[int, int] = {}
    for p in factor(n):
        if p == -1:
            continue
        counts[p] = counts.get(p, 0) + 1
    return counts


def phi(n: int) -> int:
    if n <= 0:
        raise NumthError("n must be positive")

    result = n
    for p in factor_counts(n):
        result = result // p * (p - 1)
    return result


def carmichael_lambda(n: int) -> int:
    if n <= 0:
        raise NumthError("n must be positive")

    values = []
    for p, exponent in factor_counts(n).items():
        if p == 2 and exponent >= 3:
            values.append(2 ** (exponent - 2))
        else:
            values.append((p - 1) * p ** (exponent - 1))
    return lcm(*values) if values else 1


def legendre_symbol(a: int, p: int) -> int:
    if p == 2 or not is_prime(p):
        raise NumthError("p must be an odd prime")

    a %= p
    if a == 0:
        return 0
    value = pow(a, (p - 1) // 2, p)
    return -1 if value == p - 1 else value


def jacobi_symbol(a: int, n: int) -> int:
    if n <= 0 or n % 2 == 0:
        raise NumthError("n must be a positive odd integer")

    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result
        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def _find_quadratic_non_residue(p: int) -> int:
    for z in range(2, p):
        if legendre_symbol(z, p) == -1:
            return z
    raise NoSquareRootError("no quadratic non-residue found")


def mod_sqrt(a: int, p: int) -> int:
    if p == 2:
        return a % 2
    if not is_prime(p):
        raise NumthError("p must be prime")

    a %= p
    if a == 0:
        return 0
    if legendre_symbol(a, p) != 1:
        raise NoSquareRootError(f"{a} is not a square modulo {p}")
    if p % 4 == 3:
        return min(pow(a, (p + 1) // 4, p), (-pow(a, (p + 1) // 4, p)) % p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = _find_quadratic_non_residue(p)
    c = pow(z, q, p)
    x = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s

    while t != 1:
        i = 1
        probe = (t * t) % p
        while i < m and probe != 1:
            probe = (probe * probe) % p
            i += 1
        if i == m:
            raise NoSquareRootError("Tonelli-Shanks failed to converge")
        b = pow(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i

    return min(x, (-x) % p)


def all_mod_sqrt(a: int, p: int) -> tuple[int, ...]:
    root = mod_sqrt(a, p)
    other = (-root) % p
    if root == other:
        return (root,)
    return tuple(sorted((root, other)))


def multiplicative_order(a: int, n: int) -> int:
    if n <= 1:
        raise NumthError("n must be greater than 1")
    if gcd(a, n) != 1:
        raise NumthError("a must be coprime to n")

    order = phi(n)
    for p in factor_counts(order):
        while order % p == 0 and pow(a, order // p, n) == 1:
            order //= p
    return order


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    if denominator == 0:
        raise NumthError("denominator must be non-zero")

    terms = []
    while denominator:
        q = numerator // denominator
        terms.append(q)
        numerator, denominator = denominator, numerator - q * denominator
    return terms


def main() -> None:
    print("numth library smoke test")
    print(f"gcd(240, 46) = {gcd(240, 46)}")
    print(f"mod_inverse(17, 3120) = {mod_inverse(17, 3120)}")
    print(f"crt([2, 3, 2], [3, 5, 7]) = {crt([2, 3, 2], [3, 5, 7])}")
    print(f"is_prime(2**61 - 1) = {is_prime(2**61 - 1)}")
    print(f"factor(8051) = {factor(8051)}")
    print(f"phi(36) = {phi(36)}")
    print(f"carmichael_lambda(36) = {carmichael_lambda(36)}")
    print(f"mod_sqrt(5, 41) = {mod_sqrt(5, 41)}")
    print(f"multiplicative_order(2, 101) = {multiplicative_order(2, 101)}")


if __name__ == "__main__":
    main()
