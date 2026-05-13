from math import gcd, lcm


def rho_polynomial(x: int, n: int, c: int = 1) -> int:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    return (x * x + c) % n


def pollard_rho_floyd(
    n: int, x0: int = 2, c: int = 1, max_steps: int = 10_000
) -> tuple[int | None, int]:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")
    if n % 2 == 0:
        return (2 if n != 2 else None), 0

    tortoise = x0 % n
    hare = x0 % n

    for step in range(1, max_steps + 1):
        tortoise = rho_polynomial(tortoise, n, c)
        hare = rho_polynomial(rho_polynomial(hare, n, c), n, c)
        factor = gcd(abs(tortoise - hare), n)

        if 1 < factor < n:
            return factor, step
        if factor == n:
            return None, step

    return None, max_steps


def pollard_rho_brent(
    n: int, x0: int = 2, c: int = 1, batch_size: int = 32, max_steps: int = 10_000
) -> tuple[int | None, int]:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")
    if n % 2 == 0:
        return (2 if n != 2 else None), 0

    y = x0 % n
    r = 1
    q = 1
    factor = 1
    steps = 0
    saved_y = y

    while factor == 1 and steps < max_steps:
        x = y
        for _ in range(r):
            y = rho_polynomial(y, n, c)
            steps += 1
            if steps >= max_steps:
                break

        k = 0
        while k < r and factor == 1 and steps < max_steps:
            saved_y = y
            for _ in range(min(batch_size, r - k)):
                y = rho_polynomial(y, n, c)
                steps += 1
                q = (q * abs(x - y)) % n
                if steps >= max_steps:
                    break
            factor = gcd(q, n)
            k += batch_size
        r *= 2

    if factor == n:
        factor = 1
        while factor == 1 and steps < max_steps:
            saved_y = rho_polynomial(saved_y, n, c)
            steps += 1
            factor = gcd(abs(x - saved_y), n)
        if factor == n:
            return None, steps

    if 1 < factor < n:
        return factor, steps
    return None, steps


def lcm_upto(bound: int) -> int:
    if bound < 1:
        raise ValueError("bound must be at least 1")

    result = 1
    for value in range(2, bound + 1):
        result = lcm(result, value)
    return result


def is_b_smooth(value: int, bound: int) -> bool:
    if value <= 0:
        raise ValueError("value must be positive")
    if bound < 2:
        return value == 1

    remaining = value
    divisor = 2
    while divisor <= bound and remaining > 1:
        while remaining % divisor == 0:
            remaining //= divisor
        divisor = 3 if divisor == 2 else divisor + 2
    return remaining == 1


def pollard_p_minus_one(n: int, bound: int, a: int = 2) -> tuple[int | None, int]:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if bound < 2:
        raise ValueError("bound must be at least 2")
    if n % 2 == 0:
        return (2 if n != 2 else None), 0

    shared = gcd(a, n)
    if 1 < shared < n:
        return shared, 0
    if shared == n:
        return None, 0

    exponent = lcm_upto(bound)
    factor = gcd(pow(a, exponent, n) - 1, n)
    if 1 < factor < n:
        return factor, exponent
    return None, exponent


def factor_pair(n: int, factor: int | None) -> tuple[int, int] | None:
    if factor is None or factor <= 1 or n % factor != 0 or factor == n:
        return None
    other = n // factor
    return (factor, other) if factor <= other else (other, factor)


def factor_with_pollard(n: int, bound: int = 25) -> tuple[int, int] | None:
    factor, _ = pollard_p_minus_one(n, bound)
    pair = factor_pair(n, factor)
    if pair is not None:
        return pair

    factor, _ = pollard_rho_brent(n)
    return factor_pair(n, factor)


def main() -> None:
    n = 8051
    rho_factor, rho_steps = pollard_rho_floyd(n)
    print(f"rho({n}) found factor {rho_factor} in {rho_steps} Floyd steps")
    print(f"factor pair: {factor_pair(n, rho_factor)}")
    print()

    n = 101 * 107
    pm1_factor, exponent = pollard_p_minus_one(n, bound=25)
    print(f"p-1({n}, B=25) used exponent {exponent}")
    print(f"factor pair: {factor_pair(n, pm1_factor)}")
    print()

    for candidate in [8051, 10_807, 10403]:
        print(f"{candidate}: {factor_with_pollard(candidate)}")


if __name__ == "__main__":
    main()
