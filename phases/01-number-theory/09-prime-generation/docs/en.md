# Prime Generation — Trial Division to Sieves

> Prime generation is not one trick. It is a pipeline: reject easy composites fast, then spend expensive effort only where it matters.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 2, 3, 4, 6, 8
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why trial division is enough for toy examples but hopeless for 2048-bit RSA candidates.
- Implement trial-division primality testing, a full sieve, and a segmented sieve from scratch.
- Use sieving to enumerate primes in intervals and to pre-screen random odd candidates.
- Connect prime enumeration to practical key generation, where sieving is only the first filter.

## The Problem

RSA, Diffie-Hellman, DSA, and many zero-knowledge systems all start with one deceptively simple requirement: find primes. Not just any primes, but primes with the right size, shape, and randomness properties. If your prime generation is too slow, key generation becomes unusable. If your randomness is weak, the whole system can collapse even when the math is correct.

At first, prime finding sounds easy: try a number, divide by everything smaller than it, and see whether anything fits. That works for `29`. It even works for `104729`, the 10,000th prime, if you are patient. But it does not work for 2048-bit candidates. The search space is too large, and most of the work is wasted on obvious composites that could have been discarded much earlier.

This lesson builds the missing middle layer between "I can test tiny numbers" and "I can generate real key material." You will start with trial division, move to the Sieve of Eratosthenes, then adapt the idea into a segmented sieve that can search intervals without storing an impossibly large array. Next lesson, Miller-Rabin turns this into a realistic primality pipeline.

## The Concept

### Trial Division

If `n = a * b` is composite, then at least one factor is at most `sqrt(n)`.

```text
n composite
|
+-- n = a * b
    |
    +-- if a > sqrt(n) and b > sqrt(n), then a*b > n
    +-- impossible

So a composite number always has a factor <= sqrt(n).
```

That means we never need to test divisors above `sqrt(n)`. For an odd candidate, we can skip all even divisors too:

```text
2, 3, 5, 7, 9, 11, ...
^  ^  ^  ^  x  ^
```

This is perfect for single small numbers. It is terrible for "find all primes up to one million" because it repeats similar work for every candidate.

### Sieving

The Sieve of Eratosthenes flips the perspective. Instead of asking "is 91 prime?" over and over, it writes down every number up to `N` and crosses out multiples of each prime:

```text
2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 ...
P  P  x  P  x  P  x  x  x  P  x  P  x  x  x  P
```

The key optimization is to start crossing out from `p^2`. Any smaller multiple of `p` already had a smaller prime factor:

```text
for p = 5:
  10 = 2 * 5   already crossed out by 2
  15 = 3 * 5   already crossed out by 3
  20 = 4 * 5   already crossed out by 2
  25 = 5 * 5   first new multiple we must mark
```

The sieve finds every prime up to `N` in about `O(N log log N)` time with `O(N)` memory. Great for `N = 10^6`. Useless for `N = 2^2048`.

### Segmented Sieving

Suppose you want primes near `10^12`. You cannot allocate a boolean array from `0` to `10^12`, but you can allocate one for a window:

```text
[L, R] = [10^12, 10^12 + 10^6]
```

To sieve that window, you only need the primes up to `sqrt(R)`:

```text
base primes up to sqrt(R)  --->  cross out multiples inside [L, R]
```

This is the segmented sieve. Memory depends on the window width, not on `L`.

### Where Prime Generation Fits in Real Crypto

Real key generation usually looks like this:

1. Sample a random odd number with the target bit length.
2. Reject it if divisible by tiny primes like `3, 5, 7, 11, ...`.
3. Run a probabilistic primality test such as Miller-Rabin.
4. Optionally enforce extra structure, such as `gcd(e, p - 1) = 1` for RSA.

This lesson implements steps 1 and 2 completely, and gives the mental model for efficient rejection. Next lesson replaces full trial division with a much stronger primality filter.

## Build It

### Step 1: Trial division and smallest-factor search

Start with a helper that returns the first non-trivial factor it finds. If there is none, the number is prime.

```python
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
```

This already catches Carmichael numbers like `561`, because trial division proves compositeness instead of relying on a probabilistic congruence.

### Step 2: Build the full sieve

Now stop re-checking each number independently. Allocate an array, assume everything is prime, then cross out multiples.

```python
def sieve_primes_up_to(limit: int) -> list[int]:
    if limit < 2:
        return []

    sieve = [True] * (limit + 1)
    sieve[0] = False
    sieve[1] = False

    p = 2
    while p * p <= limit:
        if sieve[p]:
            for multiple in range(p * p, limit + 1, p):
                sieve[multiple] = False
        p += 1

    return [n for n, is_prime in enumerate(sieve) if is_prime]
```

With this one function you also get `pi(N)`, the prime-counting function:

```python
def prime_count(limit: int) -> int:
    return len(sieve_primes_up_to(limit))
```

And you can compute the `n`th prime by incrementally testing candidates:

```python
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
```

### Step 3: Segment the sieve

The full sieve is great when `N` fits in memory. To work near a huge `L`, sieve only the window `[L, R]`.

```python
from math import isqrt


def primes_in_segment(low: int, high: int) -> list[int]:
    if high < low or high < 2:
        return []

    low = max(low, 2)
    segment = [True] * (high - low + 1)
    base_primes = sieve_primes_up_to(isqrt(high))

    for p in base_primes:
        start = max(p * p, ((low + p - 1) // p) * p)
        for multiple in range(start, high + 1, p):
            segment[multiple - low] = False

    return [low + i for i, is_prime in enumerate(segment) if is_prime]
```

The `start` formula is the tricky part. It finds the first multiple of `p` inside the interval, but never goes below `p^2`.

### Step 4: Turn it into a tiny generation pipeline

Real generators sample odd candidates with the top bit set, then reject obvious composites quickly.

```python
import secrets


def normalize_odd_candidate(raw: int, bits: int) -> int:
    if bits < 2:
        raise ValueError("bits must be at least 2")

    mask = (1 << bits) - 1
    candidate = raw & mask
    candidate |= 1 << (bits - 1)
    candidate |= 1
    return candidate


def generate_prime_by_trial(bits: int, randbits=secrets.randbits) -> tuple[int, int]:
    attempts = 0
    while True:
        attempts += 1
        candidate = normalize_odd_candidate(randbits(bits), bits)
        if is_prime_trial(candidate):
            return candidate, attempts
```

This is educational, not practical for large cryptographic bit lengths. But it captures the control flow that real key generation uses.

Run it:

```
python3 code/main.py
```

## Use It

For prime enumeration in Python, `sympy.primerange(a, b)` and `sympy.randprime(a, b)` expose the same high-level tasks you just built: list primes in a range and pick a random prime from an interval. For actual key generation, libraries such as PyCryptodome do not rely on pure trial division for full-size candidates. They combine quick sieving with stronger primality tests and carefully designed randomness.

That is the right production lesson: your from-scratch code teaches the pipeline and the tradeoffs, but audited libraries provide the performance, edge-case handling, and security engineering.

## Attack It

Prime generation fails in two very different ways:

1. **Bad primality testing.** If you accept composites as primes, RSA moduli can become factorable immediately.
2. **Bad randomness.** Even perfect primality testing cannot save a generator that samples from a tiny candidate set.

The Debian OpenSSL bug is the classic example of the second failure mode. The problem was not "trial division versus Miller-Rabin." The problem was that the random-number generator had so little entropy that many users generated keys from the same tiny pool of primes. Attackers could collect public RSA moduli and compute pairwise `gcd`s. Shared prime factor in, full private key out.

That is why "prime generation" must always mean both:

- finding actual primes, and
- sampling them from a high-entropy, unpredictable distribution.

## Ship It

This lesson ships `outputs/skill-prime-generation-reviewer.md`, a small review skill for educational code that enumerates primes, sieves intervals, or screens random prime candidates before Miller-Rabin.

## Exercises

1. Extend `sieve_primes_up_to` so it also returns the smallest prime factor for every composite up to `N`.
2. Replace `nth_prime` with a bound-based sieve approach so you do not rely on repeated trial division.
3. Build a two-stage generator that first rejects candidates divisible by primes up to `1000`, then passes survivors to the Miller-Rabin lesson implementation.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| trial division | "just divide until it works" | Deterministic primality test up to `sqrt(n)` |
| sieve | "list primes fast" | Mark multiples in bulk instead of testing each number alone |
| segmented sieve | "sieve big ranges" | Sieve a window `[L, R]` using only primes up to `sqrt(R)` |
| prime-counting function `pi(N)` | "number of primes below N" | Exact count of primes less than or equal to `N` |
| candidate normalization | "make a random odd number" | Force the top bit and low bit so the number has the right size and parity |
| screening | "quick reject" | Throw away obvious composites before expensive tests |

## Test Vectors

Source: OEIS A000040 for exact prime values, OEIS A006880 for exact prime counts, plus project-internal composite examples checked by direct divisibility. Code must pass `tests/vectors.json`.

## Further Reading

- [Prime Number Theorem](https://en.wikipedia.org/wiki/Prime_number_theorem) — why primes thin out roughly like `1 / ln n`
- [Sieve of Eratosthenes](https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes) — the classic bulk-marking algorithm
- [Segmented sieve](https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes#Segmented_sieve) — how to search large intervals with bounded memory
- [PyCryptodome number utilities](https://pycryptodome.readthedocs.io/en/latest/src/util/util.html) — practical bigint and prime-generation helpers
