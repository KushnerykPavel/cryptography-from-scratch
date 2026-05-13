from dataclasses import dataclass
from math import isqrt


@dataclass(frozen=True)
class Relation:
    exponent: int
    value: int
    exponents: list[int]


def primes_up_to(limit: int) -> list[int]:
    if limit < 2:
        return []

    sieve = [True] * (limit + 1)
    sieve[0] = False
    sieve[1] = False
    for p in range(2, isqrt(limit) + 1):
        if sieve[p]:
            for multiple in range(p * p, limit + 1, p):
                sieve[multiple] = False
    return [p for p, prime in enumerate(sieve) if prime]


def prime_factors(n: int) -> list[int]:
    if n <= 1:
        return []

    factors = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for d in range(3, isqrt(n) + 1, 2):
        if n % d == 0:
            return False
    return True


def mod_inverse(a: int, modulus: int) -> int:
    a %= modulus
    if modulus <= 1:
        raise ValueError("modulus must be greater than 1")

    old_r, r = a, modulus
    old_s, s = 1, 0
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    if old_r != 1:
        raise ValueError("inverse does not exist")
    return old_s % modulus


def primitive_root(p: int) -> int:
    if not is_prime(p):
        raise ValueError("p must be prime")

    factors = prime_factors(p - 1)
    for candidate in range(2, p):
        if all(pow(candidate, (p - 1) // factor, p) != 1 for factor in factors):
            return candidate
    raise ValueError("no primitive root found")


def subgroup_generator(p: int, q: int) -> int:
    if not is_prime(p) or not is_prime(q) or (p - 1) % q != 0:
        raise ValueError("q must be a prime divisor of p - 1")

    root = primitive_root(p)
    generator = pow(root, (p - 1) // q, p)
    if generator == 1 or pow(generator, q, p) != 1:
        raise ValueError("failed to construct subgroup generator")
    return generator


def factor_base_for_subgroup(p: int, q: int, bound: int) -> list[int]:
    if bound < 2:
        raise ValueError("bound must be at least 2")
    if not is_prime(p) or not is_prime(q) or (p - 1) % q != 0:
        raise ValueError("q must be a prime divisor of p - 1")

    base = []
    for candidate in primes_up_to(bound):
        if candidate < p and pow(candidate, q, p) == 1:
            base.append(candidate)
    return base


def factor_over_base(value: int, base: list[int]) -> list[int] | None:
    if value <= 0:
        return None

    remaining = value
    exponents = []
    for factor in base:
        exponent = 0
        while remaining % factor == 0:
            remaining //= factor
            exponent += 1
        exponents.append(exponent)

    if remaining != 1:
        return None
    return exponents


def collect_relations(
    p: int, g: int, q: int, base: list[int], needed: int | None = None
) -> list[Relation]:
    if needed is None:
        needed = len(base)
    if needed <= 0:
        raise ValueError("needed must be positive")
    if pow(g, q, p) != 1 or g == 1:
        raise ValueError("g must generate a subgroup of order q")

    relations = []
    for exponent in range(1, q):
        value = pow(g, exponent, p)
        exponents = factor_over_base(value, base)
        if exponents is not None:
            relations.append(Relation(exponent, value, exponents))
            if len(relations) >= needed:
                break
    return relations


def solve_linear_mod_prime(
    matrix: list[list[int]], rhs: list[int], modulus: int
) -> list[int]:
    if not is_prime(modulus):
        raise ValueError("modulus must be prime")
    if not matrix or len(matrix) != len(rhs):
        raise ValueError("matrix and rhs must be non-empty and aligned")

    row_count = len(matrix)
    col_count = len(matrix[0])
    rows = [
        [entry % modulus for entry in row] + [rhs_value % modulus]
        for row, rhs_value in zip(matrix, rhs)
    ]

    pivot_row = 0
    pivots = []
    for col in range(col_count):
        pivot = None
        for row in range(pivot_row, row_count):
            if rows[row][col] % modulus != 0:
                pivot = row
                break
        if pivot is None:
            continue

        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        inverse = mod_inverse(rows[pivot_row][col], modulus)
        rows[pivot_row] = [(value * inverse) % modulus for value in rows[pivot_row]]

        for row in range(row_count):
            if row == pivot_row:
                continue
            factor = rows[row][col] % modulus
            if factor:
                rows[row] = [
                    (rows[row][i] - factor * rows[pivot_row][i]) % modulus
                    for i in range(col_count + 1)
                ]

        pivots.append(col)
        pivot_row += 1
        if pivot_row == row_count:
            break

    for row in rows:
        if all(value % modulus == 0 for value in row[:col_count]) and row[-1] % modulus:
            raise ValueError("linear system is inconsistent")
    if len(pivots) < col_count:
        raise ValueError("linear system does not have full rank")

    solution = [0] * col_count
    for row_index, col in enumerate(pivots[:col_count]):
        solution[col] = rows[row_index][-1] % modulus
    return solution


def factor_base_logs(p: int, g: int, q: int, base: list[int]) -> dict[int, int]:
    relations = []
    for exponent in range(1, q):
        value = pow(g, exponent, p)
        exponents = factor_over_base(value, base)
        if exponents is None:
            continue
        relations.append(Relation(exponent, value, exponents))
        try:
            logs = solve_linear_mod_prime(
                [relation.exponents for relation in relations],
                [relation.exponent for relation in relations],
                q,
            )
            return dict(zip(base, logs))
        except ValueError:
            continue
    raise ValueError("not enough independent smooth relations")


def descend_target(
    p: int, g: int, q: int, h: int, base: list[int], logs: dict[int, int]
) -> tuple[int, int, list[int], int]:
    if pow(h, q, p) != 1:
        raise ValueError("target is not in the subgroup generated by g")

    for shift in range(q):
        value = (h * pow(g, shift, p)) % p
        exponents = factor_over_base(value, base)
        if exponents is None:
            continue

        log_value = 0
        for factor, exponent in zip(base, exponents):
            log_value = (log_value + exponent * logs[factor]) % q
        return shift, value, exponents, (log_value - shift) % q

    raise ValueError("target descent failed; increase the factor-base bound")


def index_calculus_log(p: int, g: int, q: int, h: int, bound: int = 50) -> int:
    base = factor_base_for_subgroup(p, q, bound)
    logs = factor_base_logs(p, g, q, base)
    _, _, _, result = descend_target(p, g, q, h, base, logs)
    return result


def main() -> None:
    p = 1019
    q = 509
    g = subgroup_generator(p, q)
    base = factor_base_for_subgroup(p, q, 50)
    logs = factor_base_logs(p, g, q, base)

    print(f"p={p}, q={q}, g={g}")
    print(f"factor base: {base}")
    print(f"factor-base logs: {logs}")

    for secret in (37, 123, 400):
        h = pow(g, secret, p)
        recovered = index_calculus_log(p, g, q, h, bound=50)
        print(f"log_g({h}) = {recovered}")


if __name__ == "__main__":
    main()
