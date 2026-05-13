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


def euler_totient_naive(n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    return sum(1 for k in range(1, n + 1) if gcd(k, n) == 1)


def fermat_residue(a: int, p: int) -> int:
    if not is_prime_naive(p):
        raise ValueError("p must be prime")
    return mod_pow(a, p - 1, p)


def fermat_holds(a: int, p: int) -> bool:
    if not is_prime_naive(p):
        return False
    if gcd(a, p) != 1:
        return False
    return fermat_residue(a, p) == 1


def euler_residue(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if gcd(a, n) != 1:
        raise ValueError("a must be coprime to n")
    return mod_pow(a, euler_totient_naive(n), n)


def euler_holds(a: int, n: int) -> bool:
    if gcd(a, n) != 1:
        return False
    return euler_residue(a, n) == 1


def reduce_exponent_prime(base: int, exp: int, p: int) -> int:
    if not is_prime_naive(p):
        raise ValueError("p must be prime")
    if gcd(base, p) != 1:
        raise ValueError("base must be coprime to p")
    return mod_pow(base, exp % (p - 1), p)


def reduce_exponent_euler(base: int, exp: int, n: int) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if gcd(base, n) != 1:
        raise ValueError("base must be coprime to n")
    return mod_pow(base, exp % euler_totient_naive(n), n)


def fermat_primality_test(n: int, bases: list[int]) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    for a in bases:
        a %= n
        if a in (0, 1):
            continue
        if gcd(a, n) != 1:
            return False
        if mod_pow(a, n - 1, n) != 1:
            return False

    return True


def is_carmichael_naive(n: int) -> bool:
    if n < 3 or is_prime_naive(n):
        return False

    for a in range(2, n):
        if gcd(a, n) == 1 and mod_pow(a, n - 1, n) != 1:
            return False
    return True


def main() -> None:
    print("Fermat examples")
    print(f"2^100 mod 13 = {reduce_exponent_prime(2, 100, 13)}")
    print(f"7^222 mod 11 = {reduce_exponent_prime(7, 222, 11)}")
    print()

    print("Euler examples")
    print(f"phi(10) = {euler_totient_naive(10)}")
    print(f"3^100 mod 10 = {reduce_exponent_euler(3, 100, 10)}")
    print(f"7^40 mod 15 = {reduce_exponent_euler(7, 40, 15)}")
    print()

    print("Fermat test")
    print(f"561 passes bases [2, 10, 50]: {fermat_primality_test(561, [2, 10, 50])}")
    print(f"561 is Carmichael: {is_carmichael_naive(561)}")


if __name__ == "__main__":
    main()
