def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0 and b == 0:
        return 0, 0, 0

    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    if a < 0:
        old_s = -old_s
    if b < 0:
        old_t = -old_t

    return old_r, old_s, old_t


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


def mod_inverse(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")

    g, s, _ = extended_gcd(a, n)
    if g != 1:
        raise ValueError("not invertible modulo n")
    return s % n


def mod_inverse_prime(a: int, p: int) -> int:
    if p <= 1:
        raise ValueError("prime modulus must be greater than 1")
    if a % p == 0:
        raise ValueError("zero has no inverse modulo p")
    return mod_pow(a, p - 2, p)


def main():
    samples = [(3, 11), (10, 17), (-3, 11), (7, 19)]
    for a, n in samples:
        inv = mod_inverse(a, n)
        print(f"a={a}, n={n}")
        print(f"  inverse = {inv}")
        print(f"  check: ({a} * {inv}) % {n} = {(a * inv) % n}")
        print()

    print(f"mod_pow(7, 128, 19) = {mod_pow(7, 128, 19)}")
    print(f"pow(7, 128, 19)     = {pow(7, 128, 19)}")
    print()
    print(f"mod_inverse_prime(5, 13) = {mod_inverse_prime(5, 13)}")


if __name__ == "__main__":
    main()
