import secrets
from math import gcd


SORRENSON_WEBSTER_BOUND = 3_317_044_064_679_887_385_961_981
DETERMINISTIC_BASES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


def decompose_n_minus_one(n: int) -> tuple[int, int]:
    if n < 3 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than 2")

    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    return s, d


def strong_liar_sequence(a: int, n: int) -> list[int]:
    s, d = decompose_n_minus_one(n)
    a %= n
    values = [pow(a, d, n)]

    for _ in range(s - 1):
        values.append((values[-1] * values[-1]) % n)

    return values


def miller_rabin_witness(a: int, n: int) -> bool:
    if n < 3 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than 2")

    a %= n
    if a in (0, 1, n - 1):
        return False
    if gcd(a, n) != 1:
        return True

    values = strong_liar_sequence(a, n)
    if values[0] == 1:
        return False
    return all(value != n - 1 for value in values)


def is_probable_prime(n: int, bases: list[int]) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    for a in bases:
        if miller_rabin_witness(a, n):
            return False
    return True


def deterministic_bases_for(n: int) -> list[int]:
    if n < 2:
        return []
    if n >= SORRENSON_WEBSTER_BOUND:
        raise ValueError("n exceeds this lesson's deterministic fixed-base range")
    return [a for a in DETERMINISTIC_BASES if a < n]


def is_prime_deterministic(n: int) -> bool:
    if n < SORRENSON_WEBSTER_BOUND:
        return is_probable_prime(n, deterministic_bases_for(n))
    raise ValueError("n exceeds this lesson's deterministic fixed-base range")


def find_miller_rabin_liars(n: int) -> list[int]:
    if n < 3 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than 2")
    if is_prime_deterministic(n):
        return []

    return [a for a in range(2, n - 1) if not miller_rabin_witness(a, n)]


def normalize_odd_candidate(raw: int, bits: int) -> int:
    if bits < 2:
        raise ValueError("bits must be at least 2")

    mask = (1 << bits) - 1
    candidate = raw & mask
    candidate |= 1 << (bits - 1)
    candidate |= 1
    return candidate


def generate_probable_prime(bits: int, randbits=secrets.randbits) -> tuple[int, int]:
    if bits < 2:
        raise ValueError("bits must be at least 2")

    attempts = 0
    while True:
        attempts += 1
        candidate = normalize_odd_candidate(randbits(bits), bits)
        if is_prime_deterministic(candidate):
            return candidate, attempts


def main() -> None:
    n = 561
    print(f"{n} = composite")
    print(f"Fermat base 2 passes: {pow(2, n - 1, n) == 1}")
    print(f"Miller-Rabin base 2 witness: {miller_rabin_witness(2, n)}")
    print()

    for candidate in [97, 561, 1105, 2_305_843_009_213_693_951]:
        print(f"{candidate} prime: {is_prime_deterministic(candidate)}")
    print()

    prime, attempts = generate_probable_prime(16)
    print(f"Generated 16-bit probable prime {prime} after {attempts} attempts")


if __name__ == "__main__":
    main()
