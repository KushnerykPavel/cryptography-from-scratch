from dataclasses import dataclass
from math import gcd, isqrt


@dataclass(frozen=True)
class SmoothFactorization:
    value: int
    bound: int
    exponents: dict[int, int]
    remaining: int

    @property
    def is_smooth(self) -> bool:
        return self.remaining == 1


@dataclass(frozen=True)
class PeriodFactoringResult:
    n: int
    base: int
    period: int
    factors: tuple[int, int]


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


def factor_over_bound(value: int, bound: int) -> SmoothFactorization:
    if value <= 0:
        raise ValueError("value must be positive")
    if bound < 2:
        raise ValueError("bound must be at least 2")

    remaining = value
    exponents = {}
    for prime in primes_up_to(bound):
        exponent = 0
        while remaining % prime == 0:
            remaining //= prime
            exponent += 1
        if exponent:
            exponents[prime] = exponent

    return SmoothFactorization(value, bound, exponents, remaining)


def is_b_smooth(value: int, bound: int) -> bool:
    return factor_over_bound(value, bound).is_smooth


def smooth_values(limit: int, bound: int) -> list[int]:
    if limit < 1:
        raise ValueError("limit must be positive")
    return [value for value in range(1, limit + 1) if is_b_smooth(value, bound)]


def smooth_density(limit: int, bound: int) -> float:
    return len(smooth_values(limit, bound)) / limit


def hidden_period_table(group_size: int, period: int) -> list[int]:
    if group_size <= 0:
        raise ValueError("group_size must be positive")
    if period <= 0 or group_size % period != 0:
        raise ValueError("period must divide group_size")
    return [x % period for x in range(group_size)]


def is_hidden_subgroup_table(values: list[int], period: int) -> bool:
    if not values:
        raise ValueError("values must be non-empty")
    if period <= 0 or len(values) % period != 0:
        return False

    for x, value in enumerate(values):
        if values[(x + period) % len(values)] != value:
            return False
    return len({values[x] for x in range(period)}) == period


def recover_hidden_period(values: list[int]) -> int:
    if not values:
        raise ValueError("values must be non-empty")

    group_size = len(values)
    for candidate in range(1, group_size + 1):
        if group_size % candidate == 0 and is_hidden_subgroup_table(values, candidate):
            return candidate
    raise ValueError("no hidden period found")


def hidden_subgroup(group_size: int, period: int) -> list[int]:
    if period <= 0 or group_size % period != 0:
        raise ValueError("period must divide group_size")
    return list(range(0, group_size, period))


def multiplicative_order(base: int, modulus: int) -> int:
    if gcd(base, modulus) != 1:
        raise ValueError("base must be coprime to modulus")

    value = 1
    for exponent in range(1, modulus * modulus + 1):
        value = (value * base) % modulus
        if value == 1:
            return exponent
    raise ValueError("order search failed")


def factor_from_period(n: int, base: int, period: int) -> tuple[int, int]:
    if n <= 1:
        raise ValueError("n must be composite")
    if period % 2:
        raise ValueError("period must be even")

    root = pow(base, period // 2, n)
    if root in (1, n - 1):
        raise ValueError("period gives only trivial square roots")

    left = gcd(root - 1, n)
    right = gcd(root + 1, n)
    if left in (1, n) or right in (1, n):
        raise ValueError("period did not reveal non-trivial factors")
    return tuple(sorted((left, right)))


def shor_classical_postprocess(n: int, base: int) -> PeriodFactoringResult:
    if gcd(base, n) != 1:
        factor = gcd(base, n)
        return PeriodFactoringResult(n, base, 1, tuple(sorted((factor, n // factor))))

    period = multiplicative_order(base, n)
    factors = factor_from_period(n, base, period)
    return PeriodFactoringResult(n, base, period, factors)


def main() -> None:
    print(f"7-smooth values up to 100: {smooth_values(100, 7)}")
    print(f"7-smooth density up to 100: {smooth_density(100, 7):.2f}")

    values = hidden_period_table(group_size=12, period=4)
    period = recover_hidden_period(values)
    print(f"hidden period: {period}, hidden subgroup: {hidden_subgroup(12, period)}")

    result = shor_classical_postprocess(n=15, base=2)
    print(f"period of {result.base} mod {result.n}: {result.period}")
    print(f"factors from period: {result.factors}")


if __name__ == "__main__":
    main()
