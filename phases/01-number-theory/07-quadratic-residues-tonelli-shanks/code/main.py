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


def mod_pow(base: int, exp: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    if exp < 0:
        raise ValueError("negative exponent requires modular inverse")
    if modulus == 1:
        return 0

    result = 1
    base %= modulus
    while exp > 0:
        if exp & 1:
            result = (result * base) % modulus
        exp >>= 1
        base = (base * base) % modulus
    return result


def canonical_root(root: int, p: int) -> int:
    other = (-root) % p
    return min(root % p, other)


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


def is_quadratic_residue_prime(a: int, p: int) -> bool:
    return legendre_symbol(a, p) != -1


def quadratic_residues_prime(p: int) -> list[int]:
    if not is_prime_naive(p) or p == 2:
        raise ValueError("p must be an odd prime")

    residues = {0}
    for x in range(1, p):
        residues.add((x * x) % p)
    return sorted(residues)


def sqrt_mod_prime_3mod4(a: int, p: int) -> int:
    if not is_prime_naive(p) or p == 2:
        raise ValueError("p must be an odd prime")
    if p % 4 != 3:
        raise ValueError("p must satisfy p % 4 == 3")

    a %= p
    if a == 0:
        return 0
    if legendre_symbol(a, p) != 1:
        raise ValueError("a is not a quadratic residue mod p")

    return canonical_root(mod_pow(a, (p + 1) // 4, p), p)


def find_quadratic_non_residue(p: int) -> int:
    if not is_prime_naive(p) or p == 2:
        raise ValueError("p must be an odd prime")

    for z in range(2, p):
        if legendre_symbol(z, p) == -1:
            return z
    raise ValueError("no quadratic non-residue found")


def tonelli_shanks(a: int, p: int) -> int:
    if not is_prime_naive(p) or p == 2:
        raise ValueError("p must be an odd prime")

    a %= p
    if a == 0:
        return 0
    if legendre_symbol(a, p) != 1:
        raise ValueError("a is not a quadratic residue mod p")
    if p % 4 == 3:
        return sqrt_mod_prime_3mod4(a, p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = find_quadratic_non_residue(p)
    m = s
    c = mod_pow(z, q, p)
    t = mod_pow(a, q, p)
    r = mod_pow(a, (q + 1) // 2, p)

    while t != 1:
        i = 1
        t_power = (t * t) % p
        while i < m and t_power != 1:
            t_power = (t_power * t_power) % p
            i += 1
        if i == m:
            raise ValueError("Tonelli-Shanks failed to converge")

        b = mod_pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i

    return canonical_root(r, p)


def all_square_roots_prime(a: int, p: int) -> tuple[int, ...]:
    root = tonelli_shanks(a, p)
    if root == 0:
        return (0,)
    other = (-root) % p
    return tuple(sorted((root, other)))


def crt_two(a1: int, n1: int, a2: int, n2: int) -> int:
    if n1 <= 0 or n2 <= 0:
        raise ValueError("moduli must be positive")
    if gcd(n1, n2) != 1:
        raise ValueError("moduli must be coprime")

    inv = pow(n1, -1, n2)
    k = ((a2 - a1) * inv) % n2
    return a1 + k * n1


def sqrt_mod_semiprime_via_crt(a: int, p: int, q: int) -> tuple[int, int, int, int]:
    if not is_prime_naive(p) or not is_prime_naive(q) or p == 2 or q == 2:
        raise ValueError("p and q must be odd primes")
    if p == q:
        raise ValueError("p and q must be distinct")

    roots_p = all_square_roots_prime(a, p)
    roots_q = all_square_roots_prime(a, q)
    n = p * q
    roots = set()
    for rp in roots_p:
        for rq in roots_q:
            roots.add(crt_two(rp, p, rq, q) % n)
    return tuple(sorted(roots))


def recover_factor_from_roots(n: int, r: int, s: int) -> int:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if r % n == s % n or (r + s) % n == 0:
        raise ValueError("roots must be distinct and not negatives modulo n")

    factor = gcd(r - s, n)
    if factor in (1, n):
        raise ValueError("roots did not reveal a non-trivial factor")
    return factor


def main() -> None:
    p = 41
    a = 5
    root = tonelli_shanks(a, p)
    print("Prime-field square roots")
    print(f"a={a}, p={p}, root={root}, other={(-root) % p}")
    print(f"check: {root}^2 mod {p} = {mod_pow(root, 2, p)}")
    print()

    p = 7
    q = 11
    a = 9
    roots = sqrt_mod_semiprime_via_crt(a, p, q)
    print("Composite modulus roots via CRT")
    print(f"n={p*q}, a={a}, roots={roots}")
    factor = recover_factor_from_roots(p * q, roots[0], roots[1])
    print(f"recover factor from two distinct roots: gcd(r-s, n) = {factor}")


if __name__ == "__main__":
    main()
