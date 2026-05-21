"""
Toy, stdlib-only walkthrough of Shor's algorithm ideas:

- factoring reduces to finding the order r of a mod N
- the quantum part (phase estimation) returns a noisy fraction s/r
- continued fractions recover r from that fraction

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isqrt
from random import Random


def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b:
        a, b = b, a % b
    return a


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")

    result = 1
    base %= modulus
    e = exponent
    while e:
        if e & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        e >>= 1
    return result


def continued_fraction_rational(numerator: int, denominator: int) -> list[int]:
    if denominator == 0:
        raise ValueError("denominator must be nonzero")
    if numerator < 0 or denominator < 0:
        raise ValueError("numerator and denominator must be nonnegative")

    n = numerator
    d = denominator
    coefficients: list[int] = []
    while d:
        q = n // d
        coefficients.append(q)
        n, d = d, n - q * d
    return coefficients


def convergents(coefficients: list[int]) -> list[tuple[int, int]]:
    if not coefficients:
        raise ValueError("continued fraction must be non-empty")

    p0, q0 = 1, 0
    p1, q1 = coefficients[0], 1
    result: list[tuple[int, int]] = [(p1, q1)]
    for a in coefficients[1:]:
        p0, p1 = p1, a * p1 + p0
        q0, q1 = q1, a * q1 + q0
        result.append((p1, q1))
    return result


def multiplicative_order(a: int, n: int, max_r: int | None = None) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")

    base = a % n
    if gcd(base, n) != 1:
        raise ValueError("a must be coprime to n")

    limit = max_r if max_r is not None else n
    if limit <= 0:
        raise ValueError("max_r must be positive")

    x = 1
    for r in range(1, limit + 1):
        x = (x * base) % n
        if x == 1:
            return r
    raise ValueError("order not found within max_r")


def simulate_phase_measurement(s: int, r: int, Q: int) -> int:
    if r <= 0:
        raise ValueError("r must be positive")
    if Q <= 0:
        raise ValueError("Q must be positive")
    if not (0 <= s < r):
        raise ValueError("s must satisfy 0 <= s < r")

    return (s * Q + r // 2) // r


def recover_order_from_phase(
    *,
    measurement: int,
    Q: int,
    a: int,
    N: int,
    max_denominator: int | None = None,
    max_multiplier: int | None = None,
) -> int:
    if Q <= 0:
        raise ValueError("Q must be positive")
    if not (0 <= measurement < Q):
        raise ValueError("measurement must satisfy 0 <= measurement < Q")
    if N <= 1:
        raise ValueError("N must be > 1")
    if gcd(a, N) != 1:
        raise ValueError("a must be coprime to N")

    max_den = max_denominator if max_denominator is not None else N
    if max_den <= 0:
        raise ValueError("max_denominator must be positive")

    max_mult = max_multiplier if max_multiplier is not None else max(1, N)
    if max_mult <= 0:
        raise ValueError("max_multiplier must be positive")

    coeffs = continued_fraction_rational(measurement, Q)
    for _, q in convergents(coeffs):
        if q <= 0:
            continue
        if q > max_den:
            break

        for k in range(1, max_mult + 1):
            candidate = q * k
            if candidate > max_den:
                break
            if mod_pow(a, candidate, N) == 1:
                return multiplicative_order(a, N, max_r=candidate)

    raise ValueError("order not recovered from measurement")


def is_perfect_square(n: int) -> bool:
    if n < 0:
        return False
    r = isqrt(n)
    return r * r == n


def shor_factor_toy(N: int, *, seed: int = 0, max_attempts: int = 25) -> tuple[int, int]:
    if N <= 3:
        raise ValueError("N must be > 3")
    if N % 2 == 0:
        return 2, N // 2
    if is_perfect_square(N):
        root = isqrt(N)
        return root, root

    rng = Random(seed)
    for _ in range(max_attempts):
        a = rng.randrange(2, N - 1)
        g = gcd(a, N)
        if 1 < g < N:
            return min(g, N // g), max(g, N // g)

        try:
            r = multiplicative_order(a, N, max_r=N)
        except ValueError:
            continue

        if r % 2 == 1:
            continue

        x = mod_pow(a, r // 2, N)
        if x in (1, N - 1):
            continue

        p = gcd(x - 1, N)
        q = gcd(x + 1, N)
        if 1 < p < N and 1 < q < N and p * q == N:
            return min(p, q), max(p, q)

    raise ValueError("no nontrivial factors found (toy shor failed)")


@dataclass(frozen=True)
class StepResult:
    label: str
    lines: list[str]


def step_1_demo() -> StepResult:
    N = 15
    a = 7
    g = gcd(a, N)
    lines = [
        f"gcd({a}, {N}) = {g}",
        f"mod_pow({a}, 4, {N}) = {mod_pow(a, 4, N)}",
        f"mod_pow({a}, 8, {N}) = {mod_pow(a, 8, N)}",
    ]
    return StepResult("Modular primitives", lines)


def step_2_demo() -> StepResult:
    measurement = 32
    Q = 64
    coeffs = continued_fraction_rational(measurement, Q)
    convs = convergents(coeffs)[:6]
    lines = [
        f"measurement/Q = {measurement}/{Q}",
        f"continued_fraction = {coeffs}",
        "first convergents = " + ", ".join(f"{p}/{q}" for p, q in convs),
    ]
    return StepResult("Continued fractions", lines)


def step_3_demo() -> StepResult:
    N = 15
    a = 2
    r = multiplicative_order(a, N, max_r=N)
    Q = 64
    measurement = simulate_phase_measurement(2, r, Q)
    recovered = recover_order_from_phase(
        measurement=measurement,
        Q=Q,
        a=a,
        N=N,
        max_denominator=N,
        max_multiplier=10,
    )
    lines = [
        f"N = {N}, a = {a}, true order r = {r}",
        f"simulate_phase_measurement(s=2, r={r}, Q={Q}) -> measurement = {measurement}",
        f"recover_order_from_phase(measurement={measurement}, Q={Q}) -> r = {recovered}",
    ]
    return StepResult("Order finding from a phase", lines)


def step_4_demo() -> StepResult:
    N = 21
    p, q = shor_factor_toy(N, seed=1, max_attempts=50)
    lines = [f"shor_factor_toy({N}) -> ({p}, {q})"]
    return StepResult("Toy Shor factoring loop", lines)


def main() -> None:
    steps = [step_1_demo(), step_2_demo(), step_3_demo(), step_4_demo()]
    for i, step in enumerate(steps, start=1):
        print(f"=== Step {i}: {step.label} ===")
        for line in step.lines:
            print(line)
        print()


if __name__ == "__main__":
    main()
