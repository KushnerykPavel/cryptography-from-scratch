def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def is_prime_naive(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    d = 3
    while d * d <= n:
        if n % d == 0:
            return False
        d += 2

    return True


def mod_pow(base: int, exp: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    if exp < 0:
        raise ValueError("negative exponent requires modular inverse")
    if n == 1:
        return 0

    result = 1
    base %= n

    while exp > 0:
        if exp & 1:
            result = (result * base) % n
        exp >>= 1
        base = (base * base) % n

    return result


def legendre_symbol(a: int, p: int) -> int:
    if not is_prime_naive(p) or p == 2:
        raise ValueError("p must be an odd prime")

    a %= p
    if a == 0:
        return 0

    value = mod_pow(a, (p - 1) // 2, p)
    if value == p - 1:
        return -1
    return value


def jacobi_symbol(a: int, n: int) -> int:
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")

    a %= n
    result = 1

    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result

        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n

    if n == 1:
        return result
    return 0


def jacobi_symbol_by_factorization(a: int, n: int) -> int:
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")

    remaining = n
    factor = 3
    result = 1

    if remaining == 1:
        return 1

    while factor * factor <= remaining:
        exponent = 0
        while remaining % factor == 0:
            remaining //= factor
            exponent += 1

        if exponent:
            value = legendre_symbol(a, factor)
            if value == 0:
                return 0
            if exponent % 2 == 1:
                result *= value
        factor += 2

    if remaining > 1:
        value = legendre_symbol(a, remaining)
        if value == 0:
            return 0
        result *= value

    return result


def is_quadratic_residue_bruteforce(a: int, n: int) -> bool:
    if n <= 0:
        raise ValueError("modulus must be positive")

    a %= n
    for x in range(n):
        if (x * x) % n == a:
            return True
    return False


def find_pseudosquares(n: int, limit: int | None = None) -> list[int]:
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")

    stop = n if limit is None else min(limit, n)
    values = []
    for a in range(1, stop):
        if gcd(a, n) != 1:
            continue
        if jacobi_symbol(a, n) == 1 and not is_quadratic_residue_bruteforce(a, n):
            values.append(a)
    return values


def solovay_strassen_witness(a: int, n: int) -> bool:
    if n < 3 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than 2")

    a %= n
    if a in (0, 1):
        return False
    if gcd(a, n) != 1:
        return True

    jacobi = jacobi_symbol(a, n)
    euler = mod_pow(a, (n - 1) // 2, n)
    return euler != jacobi % n


def solovay_strassen_primality_test(n: int, bases: list[int]) -> bool:
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    for a in bases:
        if solovay_strassen_witness(a, n):
            return False
    return True


def main() -> None:
    print("Legendre symbols")
    for a, p in [(2, 7), (3, 7), (5, 11)]:
        print(f"({a}/{p}) = {legendre_symbol(a, p)}")
    print()

    print("Jacobi symbols")
    for a, n in [(3, 35), (10, 21), (7, 21)]:
        print(f"({a}/{n}) = {jacobi_symbol(a, n)}")
    print()

    n = 21
    pseudosquares = find_pseudosquares(n)
    print(f"Jacobi +1 non-residues modulo {n}: {pseudosquares}")
    print(f"Solovay-Strassen says 561 is prime on base 2: {solovay_strassen_primality_test(561, [2])}")
    print(f"Solovay-Strassen says 561 is prime on bases [2, 3]: {solovay_strassen_primality_test(561, [2, 3])}")


if __name__ == "__main__":
    main()
