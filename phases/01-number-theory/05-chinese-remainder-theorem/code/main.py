from math import prod


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


def mod_inverse(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")

    g, s, _ = extended_gcd(a, n)
    if g != 1:
        raise ValueError("not invertible modulo n")
    return s % n


def validate_crt_system(residues: list[int], moduli: list[int]) -> None:
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have the same length")
    if len(moduli) == 0:
        raise ValueError("CRT system must be non-empty")
    if any(n <= 0 for n in moduli):
        raise ValueError("all moduli must be positive")

    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError("moduli must be pairwise coprime")


def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    validate_crt_system(residues, moduli)

    n = prod(moduli)
    x = 0

    for residue, modulus in zip(residues, moduli):
        partial = n // modulus
        inverse = mod_inverse(partial, modulus)
        x += (residue % modulus) * partial * inverse

    return x % n, n


def garner(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    validate_crt_system(residues, moduli)

    coeffs = [residue % modulus for residue, modulus in zip(residues, moduli)]

    for i in range(len(moduli)):
        for j in range(i):
            coeffs[i] = (
                (coeffs[i] - coeffs[j]) * mod_inverse(moduli[j], moduli[i])
            ) % moduli[i]

    x = 0
    factor = 1
    for coeff, modulus in zip(coeffs, moduli):
        x += coeff * factor
        factor *= modulus

    return x % factor, factor


def rsa_crt_recombine(m_p: int, m_q: int, p: int, q: int) -> int:
    x, _ = crt([m_p, m_q], [p, q])
    return x


def rsa_crt_decrypt(ciphertext: int, d: int, p: int, q: int) -> int:
    if p <= 1 or q <= 1:
        raise ValueError("RSA primes must be greater than 1")

    m_p = pow(ciphertext, d % (p - 1), p)
    m_q = pow(ciphertext, d % (q - 1), q)
    return rsa_crt_recombine(m_p, m_q, p, q)


def main():
    systems = [
        ([2, 3], [3, 5]),
        ([1, 2], [5, 7]),
        ([2, 3, 2], [3, 5, 7]),
    ]

    for residues, moduli in systems:
        x_textbook, modulus = crt(residues, moduli)
        x_garner, _ = garner(residues, moduli)
        print(f"residues={residues}, moduli={moduli}")
        print(f"  textbook CRT -> x = {x_textbook} (mod {modulus})")
        print(f"  Garner       -> x = {x_garner} (mod {modulus})")
        print()

    p = 61
    q = 53
    n = p * q
    e = 17
    d = 2753
    message = 65
    ciphertext = pow(message, e, n)
    recovered = rsa_crt_decrypt(ciphertext, d, p, q)
    print(f"RSA sample: c={ciphertext}, recovered={recovered}")


if __name__ == "__main__":
    main()
