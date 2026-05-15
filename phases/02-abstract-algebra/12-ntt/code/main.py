from __future__ import annotations

from math import isqrt


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for d in range(3, isqrt(n) + 1, 2):
        if n % d == 0:
            return False
    return True


def require_prime(p: int) -> None:
    if not is_prime(p):
        raise ValueError("p must be prime")


def prime_factors(n: int) -> list[int]:
    if n < 1:
        raise ValueError("n must be positive")
    factors: list[int] = []
    candidate = 2
    while candidate * candidate <= n:
        if n % candidate == 0:
            factors.append(candidate)
            while n % candidate == 0:
                n //= candidate
        candidate += 1 if candidate == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def multiplicative_order(a: int, p: int) -> int:
    require_prime(p)
    a %= p
    if a == 0:
        raise ValueError("zero has no multiplicative order")
    order = p - 1
    for q in prime_factors(p - 1):
        while order % q == 0 and pow(a, order // q, p) == 1:
            order //= q
    return order


def primitive_root(p: int) -> int:
    require_prime(p)
    if p == 2:
        return 1
    for g in range(2, p):
        if multiplicative_order(g, p) == p - 1:
            return g
    raise ValueError(f"no primitive root found for p={p}")


def find_primitive_nth_root(n: int, p: int) -> int:
    require_prime(p)
    if n < 1:
        raise ValueError("n must be positive")
    if (p - 1) % n != 0:
        raise ValueError(f"n={n} does not divide p-1={p - 1}, no primitive {n}-th root in F_{p}")
    g = primitive_root(p)
    return pow(g, (p - 1) // n, p)


def require_power_of_two(n: int) -> None:
    if n < 1 or (n & (n - 1)) != 0:
        raise ValueError("n must be a power of two")


def require_primitive_root_of_unity(omega: int, n: int, p: int) -> None:
    require_prime(p)
    if n < 1:
        raise ValueError("n must be positive")
    omega %= p
    if pow(omega, n, p) != 1:
        raise ValueError("omega is not an n-th root of unity")
    for q in prime_factors(n):
        if pow(omega, n // q, p) == 1:
            raise ValueError("omega is not a primitive n-th root of unity")


def ntt_slow(a: list[int], p: int, omega: int) -> list[int]:
    require_prime(p)
    n = len(a)
    if n < 1:
        raise ValueError("input must be non-empty")
    require_primitive_root_of_unity(omega, n, p)
    out = [0] * n
    for k in range(n):
        acc = 0
        for j, aj in enumerate(a):
            acc = (acc + (aj % p) * pow(omega, j * k, p)) % p
        out[k] = acc
    return out


def ntt_inplace(a: list[int], p: int, omega: int) -> None:
    require_prime(p)
    n = len(a)
    if n < 1:
        raise ValueError("input must be non-empty")
    require_power_of_two(n)
    require_primitive_root_of_unity(omega, n, p)

    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]

    length = 2
    while length <= n:
        wlen = pow(omega, n // length, p)
        for i in range(0, n, length):
            w = 1
            half = length // 2
            for j in range(half):
                u = a[i + j] % p
                v = (a[i + j + half] % p) * w % p
                a[i + j] = (u + v) % p
                a[i + j + half] = (u - v) % p
                w = w * wlen % p
        length *= 2


def ntt(a: list[int], p: int, omega: int) -> list[int]:
    out = list(a)
    ntt_inplace(out, p, omega)
    return out


def intt_inplace(a: list[int], p: int, omega: int) -> None:
    require_prime(p)
    n = len(a)
    if n < 1:
        raise ValueError("input must be non-empty")
    require_power_of_two(n)
    require_primitive_root_of_unity(omega, n, p)

    omega_inv = pow(omega, p - 2, p)
    ntt_inplace(a, p, omega_inv)
    n_inv = pow(n, p - 2, p)
    for i in range(n):
        a[i] = a[i] % p * n_inv % p


def intt(a: list[int], p: int, omega: int) -> list[int]:
    out = list(a)
    intt_inplace(out, p, omega)
    return out


def ntt_pointwise_mul(a_ntt: list[int], b_ntt: list[int], p: int) -> list[int]:
    if len(a_ntt) != len(b_ntt):
        raise ValueError("length mismatch")
    return [(x % p) * (y % p) % p for x, y in zip(a_ntt, b_ntt)]


def cyclic_convolution(a: list[int], b: list[int], p: int, omega: int) -> list[int]:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    n = len(a)
    require_power_of_two(n)
    a_ntt = ntt(a, p, omega)
    b_ntt = ntt(b, p, omega)
    c_ntt = ntt_pointwise_mul(a_ntt, b_ntt, p)
    return intt(c_ntt, p, omega)


def negacyclic_convolution(a: list[int], b: list[int], p: int, psi: int) -> list[int]:
    if len(a) != len(b):
        raise ValueError("length mismatch")
    n = len(a)
    require_power_of_two(n)
    require_primitive_root_of_unity(psi, 2 * n, p)
    omega = pow(psi, 2, p)
    require_primitive_root_of_unity(omega, n, p)

    psi_pow = 1
    a_twisted = [0] * n
    b_twisted = [0] * n
    for i in range(n):
        a_twisted[i] = (a[i] % p) * psi_pow % p
        b_twisted[i] = (b[i] % p) * psi_pow % p
        psi_pow = psi_pow * psi % p

    c_twisted = cyclic_convolution(a_twisted, b_twisted, p, omega)

    psi_inv = pow(psi, p - 2, p)
    psi_inv_pow = 1
    c = [0] * n
    for i in range(n):
        c[i] = (c_twisted[i] % p) * psi_inv_pow % p
        psi_inv_pow = psi_inv_pow * psi_inv % p
    return c


def main() -> None:
    p = 17
    n = 8
    omega = 9

    a = list(range(n))
    print("=== NTT demo (F_17, n=8, omega=9) ===")
    print(f"a: {a}")
    print(f"NTT(a): {ntt(a, p, omega)}")
    print(f"slow NTT(a): {ntt_slow(a, p, omega)}")
    print(f"iNTT(NTT(a)): {intt(ntt(a, p, omega), p, omega)}")

    b = [1, 0, 2, 0, 3, 0, 4, 0]
    print()
    print("=== Cyclic convolution (x^n - 1) ===")
    print(f"a: {a}")
    print(f"b: {b}")
    print(f"a * b (cyclic): {cyclic_convolution(a, b, p, omega)}")

    psi = 3
    print()
    print("=== Negacyclic convolution (x^n + 1) ===")
    print(f"psi (primitive 16th root): {psi}")
    print(f"a * b (negacyclic): {negacyclic_convolution(a, b, p, psi)}")


if __name__ == "__main__":
    main()
