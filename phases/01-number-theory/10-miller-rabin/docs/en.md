# Miller-Rabin Primality Testing

> A prime test is useful only when composites have nowhere comfortable to hide.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 2, 3, 4, 6, 8, 9
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why Fermat's primality test is too weak for cryptographic prime generation.
- Decompose `n - 1` into `2^s * d` and use the squaring chain behind Miller-Rabin.
- Implement strong witnesses, fixed-base deterministic testing for bounded integers, and liar enumeration.
- Connect probable-prime testing to practical RSA-style prime generation.

## The Problem

The previous lesson could enumerate primes and screen candidates by trial division. That is useful for small numbers, but real cryptographic candidates are hundreds or thousands of bits long. Trial division up to `sqrt(n)` is hopeless there. We need a test that rejects composites quickly without trying to factor them.

Fermat's little theorem looks like the obvious tool: if `p` is prime and `gcd(a, p) = 1`, then `a^(p-1) = 1 mod p`. So maybe we can test whether `a^(n-1) = 1 mod n`. The catch is brutal: some composite numbers pass this test. Carmichael numbers such as `561` pass Fermat for every coprime base.

Miller-Rabin keeps the speed of modular exponentiation but asks a sharper question. Instead of checking only the final value `a^(n-1)`, it inspects the square-root chain that must exist if `n` is prime. Most composites reveal themselves quickly. After enough independent bases, a survivor is a probable prime with a tiny error probability. For common bounded integer ranges, carefully chosen fixed bases make the result deterministic.

## The Concept

### From Fermat to a Strong Test

For an odd prime `p`, write:

```text
p - 1 = 2^s * d      with d odd
```

Fermat says:

```text
a^(p-1) = a^(2^s * d) = 1 mod p
```

Miller-Rabin walks backward through the repeated squaring chain:

```text
a^d, a^(2d), a^(4d), ..., a^(2^(s-1)d), a^(2^s d)
```

If `p` is prime, the chain must reach `1` in one of two acceptable ways:

```text
a^d == 1 mod p
```

or

```text
a^(2^r d) == -1 mod p     for some r in [0, s - 1]
```

Why does `-1` matter? Because modulo an odd prime, the only square roots of `1` are `1` and `-1`. If the chain jumps into `1` from some value that is neither `1` nor `-1`, that exposes composite structure.

### Witnesses and Liars

For a composite `n`, a base `a` can behave in two ways:

| Base behavior | Meaning |
|---------------|---------|
| witness | The Miller-Rabin chain proves `n` is composite |
| strong liar | This base fails to expose the composite |

The crucial theorem is that for any odd composite `n`, at most one quarter of eligible bases are strong liars. With `k` independent random bases, the false-prime probability is at most `4^-k`.

```text
one round:   <= 1/4 error
two rounds:  <= 1/16 error
ten rounds:  <= 1/1,048,576 error
forty rounds: tiny enough for practical key generation
```

That is the jump from "Fermat is a neat theorem" to "Miller-Rabin is an engineering tool."

### Fixed Bases

Random bases give a probabilistic test. Fixed bases can give a deterministic test, but only under a stated numeric bound.

This lesson uses the Sorenson-Webster 2015 result:

```text
n < 3,317,044,064,679,887,385,961,981
bases = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37
```

Inside that range, passing all twelve bases proves primality. Outside that range, this lesson deliberately refuses to call the fixed-base result deterministic.

## Build It

### Step 1: Split `n - 1`

Start by extracting every factor of two from `n - 1`.

```python
def decompose_n_minus_one(n: int) -> tuple[int, int]:
    if n < 3 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than 2")

    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    return s, d
```

For `n = 13`, this returns `(2, 3)` because `12 = 2^2 * 3`. For `n = 561`, it returns `(4, 35)` because `560 = 2^4 * 35`.

### Step 2: Build the squaring chain

Now compute the values Miller-Rabin inspects.

```python
def strong_liar_sequence(a: int, n: int) -> list[int]:
    s, d = decompose_n_minus_one(n)
    a %= n
    values = [pow(a, d, n)]

    for _ in range(s - 1):
        values.append((values[-1] * values[-1]) % n)

    return values
```

For `n = 9` and `a = 2`, the sequence is:

```text
2^1 mod 9 = 2
2^2 mod 9 = 4
2^4 mod 9 = 7
```

No value is `1` at the start and no value is `-1 mod 9`, so base `2` is a witness that `9` is composite.

### Step 3: Decide whether a base is a witness

A witness exposes compositeness. A non-witness is either a valid prime behavior or a strong liar for that specific composite.

```python
from math import gcd


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
```

The `gcd` shortcut catches bases that share a factor with `n`. If `gcd(a, n) > 1`, then `n` is composite even before the squaring chain finishes.

### Step 4: Test probable primality

Wrap the witness check around a list of bases. Any witness means composite. No witnesses means probable prime for those bases.

```python
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
```

This function is intentionally honest about its name: probable prime. It is deterministic only when the base set and numeric range justify that stronger claim.

### Step 5: Add a deterministic bounded wrapper

Use the known fixed bases, but refuse inputs beyond the theorem's range.

```python
SORRENSON_WEBSTER_BOUND = 3_317_044_064_679_887_385_961_981
DETERMINISTIC_BASES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]


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
```

This is the kind of boundary that belongs in real APIs. "Works for all integers" and "works for integers below a proven bound" are very different promises.

### Step 6: Generate a toy probable prime

Reuse the candidate normalization from the previous lesson, then test with the deterministic wrapper.

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


def generate_probable_prime(bits: int, randbits=secrets.randbits) -> tuple[int, int]:
    attempts = 0
    while True:
        attempts += 1
        candidate = normalize_odd_candidate(randbits(bits), bits)
        if is_prime_deterministic(candidate):
            return candidate, attempts
```

This is still educational. Production key generation needs carefully reviewed randomness, side-channel discipline, prime-shape constraints, and library-level hardening.

Run it:

```
python3 code/main.py
```

## Use It

Python's `sympy.isprime(n)` offers a practical primality predicate for mathematical work. Crypto libraries such as PyCryptodome use probabilistic prime tests inside key-generation utilities instead of exposing raw toy Miller-Rabin loops as a security boundary.

The production lesson is not "copy this code into RSA." The production lesson is: combine small-prime screening, strong probable-prime tests, enough independent confidence, and audited randomness. If a library says "probable prime," read what probability and test strategy it means.

## Attack It

### Fermat liars

The plain Fermat test says `561` looks prime for base `2`:

```text
2^560 mod 561 = 1
```

But `561 = 3 * 11 * 17`. Fermat sees only the endpoint. Miller-Rabin sees the chain:

```text
561 - 1 = 2^4 * 35
2^35 mod 561 = 263
2^70 mod 561 = 166
2^140 mod 561 = 67
2^280 mod 561 = 1
```

The chain reaches `1` from a value that is not `-1 mod 561`, so base `2` exposes compositeness.

### Fixed-base overclaiming

The number `2047 = 23 * 89` passes Miller-Rabin for base `2`. It fails for base `3`. The number `3215031751` passes bases `2, 3, 5, 7` but fails when base `11` is included.

That is why "we tested a few bases" is not a proof unless the exact base set and input range are backed by a theorem.

## Ship It

This lesson ships `outputs/skill-miller-rabin-reviewer.md`, a review skill for educational Miller-Rabin code and prime-generation snippets.

## Exercises

1. Count the strong liars for every odd composite below `1000`. Which composite has the largest liar fraction?
2. Add random-base Miller-Rabin with `k` rounds, and report the bound `4^-k` next to the result.
3. Combine lesson 09's small-prime sieve with this lesson's Miller-Rabin test to build a faster toy prime generator.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| Fermat test | "fast prime test" | A necessary condition for primality that Carmichael composites can fool |
| Miller-Rabin | "probabilistic prime test" | A strong probable-prime test based on repeated squaring of `a^d` |
| witness | "a bad base" | A base that proves the tested number is composite |
| strong liar | "a lucky base" | A base that fails to expose a composite in Miller-Rabin |
| probable prime | "basically prime" | A number that passed the selected tests, with a claim limited by the base strategy |
| deterministic base set | "magic bases" | Fixed witnesses that prove primality only below a stated numeric bound |

## Test Vectors

Source: project-internal Miller-Rabin examples cross-checked with Python's `pow`, known pseudoprime examples `2047` and `3215031751`, and the Sorenson-Webster twelve-base deterministic range. Code must pass `tests/vectors.json`.

## Further Reading

- [Handbook of Applied Cryptography, Chapter 4](https://cacr.uwaterloo.ca/hac/about/chap4.pdf) - classic reference for probabilistic primality testing and number-theory algorithms.
- [Strong Pseudoprimes to Twelve Prime Bases](https://arxiv.org/abs/1509.00864) - Sorenson and Webster's fixed-base bound used in this lesson.
- [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) - modern digital-signature standard with primality-testing context for approved key generation.
