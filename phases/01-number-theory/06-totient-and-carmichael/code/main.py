from math import isqrt


def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return abs(a // gcd(a, b) * b)


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


def prime_factorization(n: int) -> list[tuple[int, int]]:
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return []

    factors: list[tuple[int, int]] = []
    exponent = 0
    while n % 2 == 0:
        n //= 2
        exponent += 1
    if exponent > 0:
        factors.append((2, exponent))

    p = 3
    while p * p <= n:
        exponent = 0
        while n % p == 0:
            n //= p
            exponent += 1
        if exponent > 0:
            factors.append((p, exponent))
        p += 2

    if n > 1:
        factors.append((n, 1))

    return factors


def euler_totient(n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return 1

    result = n
    for p, _ in prime_factorization(n):
        result -= result // p
    return result


def carmichael_prime_power(p: int, exponent: int) -> int:
    if exponent <= 0:
        raise ValueError("exponent must be positive")
    if not is_prime_naive(p):
        raise ValueError("p must be prime")

    if p == 2:
        if exponent == 1:
            return 1
        if exponent == 2:
            return 2
        return 1 << (exponent - 2)

    return (p - 1) * (p ** (exponent - 1))


def carmichael_lambda(n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return 1

    value = 1
    for p, exponent in prime_factorization(n):
        value = lcm(value, carmichael_prime_power(p, exponent))
    return value


def reduce_exponent_lambda(base: int, exp: int, n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if exp < 0:
        raise ValueError("negative exponent requires modular inverse")
    if gcd(base, n) != 1:
        raise ValueError("base must be coprime to n")
    return pow(base, exp % carmichael_lambda(n), n)


def rsa_private_exponent(e: int, p: int, q: int) -> int:
    if not is_prime_naive(p) or not is_prime_naive(q):
        raise ValueError("p and q must be prime")
    if p == q:
        raise ValueError("p and q must be distinct")

    lam = carmichael_lambda(p * q)
    if gcd(e, lam) != 1:
        raise ValueError("e must be coprime to lambda(n)")
    return pow(e, -1, lam)


def factor_semiprime_from_phi(n: int, phi_n: int) -> tuple[int, int]:
    if n <= 0 or phi_n <= 0:
        raise ValueError("n and phi(n) must be positive")

    s = n - phi_n + 1
    discriminant = s * s - 4 * n
    if discriminant < 0:
        raise ValueError("no integer factors match n and phi(n)")

    root = isqrt(discriminant)
    if root * root != discriminant:
        raise ValueError("no integer factors match n and phi(n)")
    if (s + root) % 2 != 0 or (s - root) % 2 != 0:
        raise ValueError("no integer factors match n and phi(n)")

    p = (s + root) // 2
    q = (s - root) // 2
    if p * q != n:
        raise ValueError("no integer factors match n and phi(n)")

    return max(p, q), min(p, q)


def is_carmichael_korselt(n: int) -> bool:
    if n < 3 or is_prime_naive(n):
        return False

    factors = prime_factorization(n)
    if any(exponent > 1 for _, exponent in factors):
        return False

    return all((n - 1) % (p - 1) == 0 for p, _ in factors)


def main() -> None:
    values = [1, 8, 12, 36, 45, 77]
    print("Totient and Carmichael values")
    for n in values:
        print(f"n={n:2d}  phi(n)={euler_totient(n):2d}  lambda(n)={carmichael_lambda(n):2d}")
    print()

    print("Exponent reduction with lambda(n)")
    print(f"7^222 mod 15 = {reduce_exponent_lambda(7, 222, 15)}")
    print(f"13^12345 mod 77 = {reduce_exponent_lambda(13, 12345, 77)}")
    print()

    p = 61
    q = 53
    n = p * q
    e = 17
    d = rsa_private_exponent(e, p, q)
    message = 65
    ciphertext = pow(message, e, n)
    recovered = pow(ciphertext, d, n)
    print("RSA sample")
    print(f"n={n}, phi(n)={euler_totient(n)}, lambda(n)={carmichael_lambda(n)}, d={d}")
    print(f"ciphertext={ciphertext}, recovered={recovered}")
    print()

    leaked_phi = euler_totient(n)
    factored_p, factored_q = factor_semiprime_from_phi(n, leaked_phi)
    print("Leak phi(n), lose the factorization")
    print(f"factored n={n} into p={factored_p}, q={factored_q}")
    print()

    for candidate in [15, 561, 1105]:
        print(f"{candidate} is Carmichael: {is_carmichael_korselt(candidate)}")


if __name__ == "__main__":
    main()
