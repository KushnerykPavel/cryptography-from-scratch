from __future__ import annotations

from math import isqrt
from typing import Iterable


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for d in range(3, isqrt(n) + 1, 2):
        if n % d == 0:
            return False
    return True


def require_prime(p: int) -> None:
    if not is_prime(p):
        raise ValueError("p must be prime")


def prime_factors(n: int) -> list[int]:
    if n < 1:
        raise ValueError("n must be positive")
    factors: list[int] = []
    candidate = 2
    while candidate * candidate <= n:
        if n % candidate == 0:
            factors.append(candidate)
            while n % candidate == 0:
                n //= candidate
        candidate += 1 if candidate == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def divisors(n: int) -> list[int]:
    if n < 1:
        raise ValueError("n must be positive")
    result: list[int] = []
    for d in range(1, isqrt(n) + 1):
        if n % d == 0:
            result.append(d)
            if d != n // d:
                result.append(n // d)
    return sorted(result)


def euler_phi(n: int) -> int:
    if n < 1:
        raise ValueError("n must be positive")
    result = n
    for p in prime_factors(n):
        result = result // p * (p - 1)
    return result


def multiplicative_order(a: int, p: int) -> int:
    require_prime(p)
    a %= p
    if a == 0:
        raise ValueError("zero has no multiplicative order")
    order = p - 1
    for q in prime_factors(p - 1):
        while order % q == 0 and pow(a, order // q, p) == 1:
            order //= q
    return order


def is_primitive_nth_root(a: int, n: int, p: int) -> bool:
    require_prime(p)
    if n < 1:
        raise ValueError("n must be positive")
    a %= p
    if pow(a, n, p) != 1:
        return False
    for q in prime_factors(n):
        if pow(a, n // q, p) == 1:
            return False
    return True


def nth_roots_of_unity(n: int, p: int) -> list[int]:
    require_prime(p)
    if n < 1:
        raise ValueError("n must be positive")
    return sorted(a for a in range(p) if pow(a, n, p) == 1)


def primitive_nth_roots(n: int, p: int) -> list[int]:
    return [a for a in nth_roots_of_unity(n, p) if is_primitive_nth_root(a, n, p)]


def primitive_root(p: int) -> int:
    require_prime(p)
    if p == 2:
        return 1
    for g in range(2, p):
        if multiplicative_order(g, p) == p - 1:
            return g
    raise ValueError(f"no primitive root found for p={p}")


def find_primitive_nth_root(n: int, p: int) -> int:
    require_prime(p)
    if n < 1:
        raise ValueError("n must be positive")
    if (p - 1) % n != 0:
        raise ValueError(f"n={n} does not divide p-1={p - 1}, no primitive {n}-th root in F_{p}")
    g = primitive_root(p)
    return pow(g, (p - 1) // n, p)


def _int_poly_normalize(poly: list[int]) -> list[int]:
    result = list(poly)
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result or [0]


def _int_poly_mul(a: list[int], b: list[int]) -> list[int]:
    a = _int_poly_normalize(a)
    b = _int_poly_normalize(b)
    if a == [0] or b == [0]:
        return [0]
    result = [0] * (len(a) + len(b) - 1)
    for i, ac in enumerate(a):
        for j, bc in enumerate(b):
            result[i + j] += ac * bc
    return _int_poly_normalize(result)


def _int_poly_divexact(dividend: list[int], divisor: list[int]) -> list[int]:
    """Exact polynomial division over Z. Assumes remainder is zero."""
    remainder = list(_int_poly_normalize(dividend))
    d = _int_poly_normalize(divisor)
    if d == [0]:
        raise ValueError("division by zero polynomial")

    deg_rem = len(remainder) - 1
    deg_div = len(d) - 1

    if deg_rem < deg_div:
        raise ValueError("dividend degree less than divisor degree")

    result_len = deg_rem - deg_div + 1
    quotient = [0] * result_len

    for i in range(deg_rem - deg_div, -1, -1):
        q = remainder[i + deg_div] // d[deg_div]
        quotient[i] = q
        for j in range(deg_div + 1):
            remainder[i + j] -= q * d[j]

    return _int_poly_normalize(quotient)


def cyclotomic_poly_z(n: int) -> list[int]:
    """Cyclotomic polynomial Phi_n(x) with integer coefficients (low-to-high)."""
    if n < 1:
        raise ValueError("n must be positive")

    xn_minus_1 = [0] * (n + 1)
    xn_minus_1[0] = -1
    xn_minus_1[n] = 1

    result = list(xn_minus_1)
    for d in divisors(n)[:-1]:
        result = _int_poly_divexact(result, cyclotomic_poly_z(d))

    return result


def cyclotomic_poly(n: int, p: int) -> list[int]:
    """Cyclotomic polynomial Phi_n(x) reduced mod p (low-to-high coefficients)."""
    require_prime(p)
    poly_z = cyclotomic_poly_z(n)
    reduced = [c % p for c in poly_z]
    return _int_poly_normalize(reduced)


def cyclotomic_roots(n: int, p: int) -> list[int]:
    """All roots of Phi_n(x) in F_p. These are the primitive n-th roots of unity in F_p."""
    return primitive_nth_roots(n, p)


def ntt_check(n: int, p: int) -> dict[str, object]:
    """Check whether F_p supports an n-point NTT and return key parameters."""
    require_prime(p)
    if n < 1:
        raise ValueError("n must be positive")
    suitable = (p - 1) % n == 0
    result: dict[str, object] = {
        "n": n,
        "p": p,
        "p_minus_1": p - 1,
        "n_divides_p_minus_1": suitable,
        "primitive_root_omega": None,
    }
    if suitable:
        result["primitive_root_omega"] = find_primitive_nth_root(n, p)
    return result


def main() -> None:
    p = 17

    print("=== Roots of unity in F_17 ===")
    for n in [2, 4, 8, 16]:
        roots = nth_roots_of_unity(n, p)
        prim = primitive_nth_roots(n, p)
        print(f"  {n}-th roots: {roots}")
        print(f"  primitive {n}-th roots: {prim}")

    print()
    print("=== Cyclotomic polynomials ===")
    for n in [1, 2, 3, 4, 6, 8]:
        phi = cyclotomic_poly_z(n)
        print(f"  Phi_{n}(x) over Z: {phi}")

    print()
    print("=== NTT-readiness check ===")
    for n, prime in [(8, 17), (4, 5), (6, 7), (8, 13)]:
        info = ntt_check(n, prime)
        print(f"  n={n}, p={prime}: {info}")

    print()
    print("=== Primitive roots ===")
    for prime in [5, 7, 11, 13, 17]:
        g = primitive_root(prime)
        print(f"  primitive root mod {prime}: {g}")


if __name__ == "__main__":
    main()
