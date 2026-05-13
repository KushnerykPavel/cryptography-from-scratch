from dataclasses import dataclass
from math import gcd, isqrt


@dataclass(frozen=True)
class WienerResult:
    d: int
    p: int
    q: int
    phi: int


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    if denominator == 0:
        raise ValueError("denominator must be non-zero")

    terms = []
    while denominator:
        quotient = numerator // denominator
        terms.append(quotient)
        numerator, denominator = denominator, numerator - quotient * denominator
    return terms


def rational_from_continued_fraction(terms: list[int]) -> tuple[int, int]:
    if not terms:
        raise ValueError("terms must be non-empty")

    numerator = 1
    denominator = 0
    for term in reversed(terms):
        numerator, denominator = term * numerator + denominator, numerator
    return numerator, denominator


def convergents(terms: list[int]) -> list[tuple[int, int]]:
    if not terms:
        raise ValueError("terms must be non-empty")

    previous_p, current_p = 0, 1
    previous_q, current_q = 1, 0
    result = []

    for term in terms:
        previous_p, current_p = current_p, term * current_p + previous_p
        previous_q, current_q = current_q, term * current_q + previous_q
        result.append((current_p, current_q))

    return result


def sqrt_continued_fraction(n: int) -> tuple[int, list[int]]:
    if n < 0:
        raise ValueError("n must be non-negative")

    a0 = isqrt(n)
    if a0 * a0 == n:
        return a0, []

    m = 0
    d = 1
    a = a0
    period = []

    while True:
        m = d * a - m
        d = (n - m * m) // d
        a = (a0 + m) // d
        period.append(a)
        if a == 2 * a0:
            return a0, period


def sqrt_cf_terms(n: int, count: int) -> list[int]:
    if count <= 0:
        raise ValueError("count must be positive")

    a0, period = sqrt_continued_fraction(n)
    if not period:
        return [a0]

    terms = [a0]
    for index in range(count - 1):
        terms.append(period[index % len(period)])
    return terms


def best_rational_approximations(
    numerator: int, denominator: int
) -> list[tuple[int, int]]:
    return convergents(continued_fraction(numerator, denominator))


def solve_rsa_factors_from_phi(n: int, phi: int) -> tuple[int, int] | None:
    total = n - phi + 1
    discriminant = total * total - 4 * n
    if discriminant < 0:
        return None

    root = isqrt(discriminant)
    if root * root != discriminant:
        return None
    if (total + root) % 2:
        return None

    p = (total - root) // 2
    q = (total + root) // 2
    if p * q != n:
        return None
    return (p, q) if p <= q else (q, p)


def wiener_attack(e: int, n: int) -> WienerResult | None:
    if e <= 0 or n <= 1:
        raise ValueError("e and n must be positive")

    for k, d in best_rational_approximations(e, n):
        if k == 0 or d == 0:
            continue
        candidate = e * d - 1
        if candidate % k != 0:
            continue

        phi = candidate // k
        factors = solve_rsa_factors_from_phi(n, phi)
        if factors is None:
            continue

        p, q = factors
        if (e * d) % phi == 1:
            return WienerResult(d=d, p=p, q=q, phi=phi)

    return None


def sqrt_convergent_relations(n: int, count: int) -> list[dict[str, int]]:
    if n <= 1:
        raise ValueError("n must be greater than 1")

    terms = sqrt_cf_terms(n, count)
    relations = []
    for index, (p, q) in enumerate(convergents(terms), start=1):
        residue = p * p - n * q * q
        relations.append(
            {
                "index": index,
                "p": p,
                "q": q,
                "residue": residue,
                "abs_residue": abs(residue),
            }
        )
    return relations


def factor_over_base(value: int, base: list[int]) -> dict[int, int] | None:
    if value == 0:
        return None

    remaining = abs(value)
    exponents = {}
    for prime in base:
        exponent = 0
        while remaining % prime == 0:
            remaining //= prime
            exponent += 1
        if exponent:
            exponents[prime] = exponent

    if remaining != 1:
        return None
    return exponents


def smooth_cfrac_relations(n: int, count: int, base: list[int]) -> list[dict[str, object]]:
    smooth = []
    for relation in sqrt_convergent_relations(n, count):
        exponents = factor_over_base(int(relation["abs_residue"]), base)
        if exponents is not None:
            smooth.append({**relation, "exponents": exponents})
    return smooth


def main() -> None:
    print(f"7/22 CF: {continued_fraction(7, 22)}")
    print(f"7/22 convergents: {best_rational_approximations(7, 22)}")
    print(f"sqrt(23) CF: {sqrt_continued_fraction(23)}")

    result = wiener_attack(e=5755, n=8851)
    print(f"Wiener recovered: {result}")

    relations = smooth_cfrac_relations(n=1649, count=8, base=[2, 5, 7])
    print(f"CFRAC-style smooth relations: {relations}")


if __name__ == "__main__":
    main()
