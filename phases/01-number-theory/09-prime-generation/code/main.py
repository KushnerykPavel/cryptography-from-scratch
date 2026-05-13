import secrets
from math import isqrt


def trial_division_factor(n: int) -> int | None:
    if n < 2:
        return None
    if n % 2 == 0:
        return 2 if n != 2 else None

    d = 3
    limit = isqrt(n)
    while d <= limit:
        if n % d == 0:
            return d
        d += 2

    return None


def is_prime_trial(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    return trial_division_factor(n) is None


def sieve_primes_up_to(limit: int) -> list[int]:
    if limit < 2:
        return []

    sieve = [True] * (limit + 1)
    sieve[0] = False
    sieve[1] = False

    p = 2
    while p * p <= limit:
        if sieve[p]:
            start = p * p
            for multiple in range(start, limit + 1, p):
                sieve[multiple] = False
        p += 1

    return [n for n, is_prime in enumerate(sieve) if is_prime]


def prime_count(limit: int) -> int:
    return len(sieve_primes_up_to(limit))


def nth_prime(index: int) -> int:
    if index <= 0:
        raise ValueError("index must be positive")

    count = 0
    candidate = 1
    while count < index:
        candidate += 1
        if is_prime_trial(candidate):
            count += 1
    return candidate


def primes_in_segment(low: int, high: int) -> list[int]:
    if high < low:
        return []
    if high < 2:
        return []

    low = max(low, 2)
    width = high - low + 1
    segment = [True] * width
    base_primes = sieve_primes_up_to(isqrt(high))

    for p in base_primes:
        start = max(p * p, ((low + p - 1) // p) * p)
        for multiple in range(start, high + 1, p):
            segment[multiple - low] = False

    return [low + offset for offset, is_prime in enumerate(segment) if is_prime]


def next_prime(n: int) -> int:
    if n < 2:
        return 2

    candidate = n + 1
    if candidate % 2 == 0 and candidate != 2:
        candidate += 1

    while not is_prime_trial(candidate):
        candidate += 2

    return candidate


def normalize_odd_candidate(raw: int, bits: int) -> int:
    if bits < 2:
        raise ValueError("bits must be at least 2")

    mask = (1 << bits) - 1
    candidate = raw & mask
    candidate |= 1 << (bits - 1)
    candidate |= 1
    return candidate


def generate_prime_by_trial(bits: int, randbits=secrets.randbits) -> tuple[int, int]:
    if bits < 2:
        raise ValueError("bits must be at least 2")

    attempts = 0
    while True:
        attempts += 1
        candidate = normalize_odd_candidate(randbits(bits), bits)
        if is_prime_trial(candidate):
            return candidate, attempts


def main() -> None:
    print("Primes up to 50")
    print(sieve_primes_up_to(50))
    print()

    print("Primes in [10_000, 10_100]")
    print(primes_in_segment(10_000, 10_100))
    print()

    print(f"25th prime = {nth_prime(25)}")
    print(f"pi(1000) = {prime_count(1000)}")
    print()

    prime, attempts = generate_prime_by_trial(16)
    print(f"Generated 16-bit prime {prime} after {attempts} attempts")


if __name__ == "__main__":
    main()
