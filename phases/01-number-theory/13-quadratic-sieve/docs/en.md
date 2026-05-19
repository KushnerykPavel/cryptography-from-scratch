# Quadratic Sieve

> Smooth squares turn factoring into linear algebra.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 2, 3, 7, 9, 10, 12
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why factoring can be reduced to finding `x^2 ≡ y^2 (mod n)` with `x ≠ ±y`.
- Build a tiny Quadratic Sieve: factor base, smooth relations, parity matrix, dependency, gcd.
- Use Tonelli-Shanks to explain why only some primes belong in the factor base.
- Describe why QS is sub-exponential and where it sits between Pollard methods and NFS.

## The Problem

Pollard rho and Pollard p-1 are sharp tools, but each depends on a useful accident. Rho wants a birthday collision modulo a hidden factor. p-1 wants one prime factor whose `p - 1` is smooth. If a balanced semiprime has no small factor and no especially smooth group order, these methods start to feel unreliable.

The Quadratic Sieve is the first general-purpose factoring algorithm in this course that scales by collecting evidence. It does not try to guess a factor directly. Instead, it searches for many numbers near `sqrt(n)` whose squares are close to multiples of `n`, keeps the ones that factor over small primes, and lets linear algebra assemble them into a square.

This matters historically and cryptographically. QS factored many RSA challenge-size numbers before the Number Field Sieve became dominant. It also gives the template that keeps appearing in modern cryptanalysis: collect smooth relations, solve a sparse linear system, extract a hidden algebraic collision.

## The Concept

### Difference of squares

If you can find:

```text
x^2 ≡ y^2 (mod n)
x ≠  y (mod n)
x ≠ -y (mod n)
```

then:

```text
x^2 - y^2 ≡ 0 (mod n)
(x - y)(x + y) ≡ 0 (mod n)
```

For a composite `n = p*q`, there is a good chance one factor divides `x - y` while the other divides `x + y`. Then:

```text
gcd(x - y, n) = p
gcd(x + y, n) = q
```

Fermat factoring tries to find this by making `x^2 - n` a square directly. QS relaxes the demand: find many `x^2 - n` values that are made only of small primes, then multiply a subset whose prime exponents all become even.

### Smooth relations

Let:

```text
Q(x) = x^2 - n
```

Choose `x` near `ceil(sqrt(n))`, so `Q(x)` is much smaller than `n`. Smaller numbers are more likely to be smooth.

Example with `n = 1649 = 17 * 97`:

```text
x = 41    Q(x) = 41^2 - 1649 = 32  = 2^5
x = 43    Q(x) = 43^2 - 1649 = 200 = 2^3 * 5^2
```

Track only exponent parity:

```text
factor base:   2  5  7  23  29
Q(41) = 32     1  0  0   0   0
Q(43) = 200    1  0  0   0   0
xor:           0  0  0   0   0
```

The parity rows cancel, so `Q(41) * Q(43)` is a square:

```text
Q(41) * Q(43) = 32 * 200 = 6400 = 80^2
41 * 43 ≡ 114 (mod 1649)
114^2 ≡ 80^2 (mod 1649)
gcd(114 - 80, 1649) = 17
```

That is the whole algorithm in miniature.

### Factor base

The factor base is not every small prime. A prime `p` can divide `Q(x) = x^2 - n` only when:

```text
x^2 ≡ n (mod p)
```

So `n` must be a quadratic residue modulo `p`. Lesson 7's Tonelli-Shanks algorithm computes the roots. For each usable odd prime, the sieve would mark positions:

```text
x ≡  sqrt(n) (mod p)
x ≡ -sqrt(n) (mod p)
```

This lesson keeps the implementation simple by trial-factoring each nearby `Q(x)` over the factor base. Real QS uses logarithmic sieving over large intervals, large-prime variants, sparse matrices, and block Lanczos or Wiedemann linear algebra.

### Pipeline

```text
pick n, bound B
      |
      v
factor base = small p where n is QR mod p
      |
      v
scan x near sqrt(n), keep B-smooth Q(x)
      |
      v
rows = exponent parity vectors over F2
      |
      v
find row subset with xor = 0
      |
      v
product x_i^2 ≡ product Q(x_i) = y^2 (mod n)
      |
      v
gcd(x - y, n) or gcd(x + y, n)
```

## Build It

### Step 1: Square helpers and small primes

QS starts near `sqrt(n)` and needs a small-prime factor base.

```python
from math import gcd, isqrt


def ceil_sqrt(n: int) -> int:
    if n < 0:
        raise ValueError("n must be non-negative")
    root = isqrt(n)
    return root if root * root == n else root + 1


def primes_up_to(limit: int) -> list[int]:
    if limit < 2:
        return []

    sieve = [True] * (limit + 1)
    sieve[0] = False
    sieve[1] = False
    for p in range(2, isqrt(limit) + 1):
        if sieve[p]:
            for multiple in range(p * p, limit + 1, p):
                sieve[multiple] = False
    return [p for p, prime in enumerate(sieve) if prime]
```

### Step 2: Decide whether a prime belongs in the factor base

The Legendre symbol says whether `n` has a square root modulo an odd prime `p`. Tonelli-Shanks returns one actual root when it exists.

```python
def legendre_symbol(a: int, p: int) -> int:
    if p < 2:
        raise ValueError("p must be prime")
    if p == 2:
        return a % 2

    value = pow(a % p, (p - 1) // 2, p)
    if value == p - 1:
        return -1
    return value


def factor_base(n: int, bound: int) -> list[int]:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if bound < 2:
        raise ValueError("bound must be at least 2")

    base = []
    for p in primes_up_to(bound):
        if p == 2:
            base.append(p)
        elif n % p != 0 and legendre_symbol(n, p) == 1:
            base.append(p)
    return base
```

For `1649` and `B = 30`, the base is:

```text
[2, 5, 7, 23, 29]
```

### Step 3: Keep smooth `Q(x)` values

Factor each `Q(x) = x^2 - n` over the base. If anything remains, the relation is not smooth enough for this run.

```python
def factor_over_base(value: int, base: list[int]) -> list[int] | None:
    if value == 0:
        return None

    remaining = abs(value)
    exponents = []
    for p in base:
        exponent = 0
        while remaining % p == 0:
            remaining //= p
            exponent += 1
        exponents.append(exponent)

    if remaining != 1:
        return None
    return exponents


def parity_vector(exponents: list[int]) -> int:
    vector = 0
    for i, exponent in enumerate(exponents):
        if exponent % 2 == 1:
            vector |= 1 << i
    return vector
```

The bit vector is the row that enters the `F_2` matrix.

### Step 4: Collect relations

Start at `ceil(sqrt(n))`, scan a short interval, and keep only smooth values.

```python
def collect_relations(n: int, bound: int, interval: int) -> list[dict[str, object]]:
    if interval <= 0:
        raise ValueError("interval must be positive")

    base = factor_base(n, bound)
    start = ceil_sqrt(n)
    relations = []

    for x in range(start, start + interval):
        qx = x * x - n
        exponents = factor_over_base(qx, base)
        if exponents is None:
            continue
        relations.append(
            {
                "x": x,
                "qx": qx,
                "exponents": exponents,
                "parity": parity_vector(exponents),
            }
        )
    return relations
```

For `1649`, the first relations include:

```text
x=41, Q(x)=32,  exponents=[5, 0, 0, 0, 0], parity=1
x=42, Q(x)=115, exponents=[0, 1, 0, 1, 0], parity=10
x=43, Q(x)=200, exponents=[3, 2, 0, 0, 0], parity=1
```

### Step 5: Find a parity dependency

Gaussian elimination over `F_2` finds a subset of rows whose xor is zero. The code stores each row as an integer bitset and also stores the subset mask that produced it.

```python
def dependency_masks(vectors: list[int]) -> list[int]:
    basis: dict[int, tuple[int, int]] = {}
    masks = []

    for row, vector in enumerate(vectors):
        reduced = vector
        mask = 1 << row

        while reduced:
            pivot = reduced.bit_length() - 1
            if pivot not in basis:
                basis[pivot] = (reduced, mask)
                break
            basis_vector, basis_mask = basis[pivot]
            reduced ^= basis_vector
            mask ^= basis_mask

        if reduced == 0 and mask != 0:
            masks.append(mask)

    return masks
```

A zero xor means every prime exponent in the product is even, so the product is a square.

### Step 6: Build the congruence and take gcds

For the selected relation indices:

```text
X = product(x_i) mod n
Y = sqrt(product(Q(x_i))) mod n
```

Then test both gcds.

```python
def build_congruence(n: int, base: list[int], relations, indices) -> tuple[int, int]:
    x_value = 1
    exponent_sums = [0] * len(base)

    for index in indices:
        relation = relations[index]
        x_value = (x_value * int(relation["x"])) % n
        for i, exponent in enumerate(relation["exponents"]):
            exponent_sums[i] += int(exponent)

    y_value = 1
    for p, exponent in zip(base, exponent_sums):
        y_value = (y_value * pow(p, exponent // 2, n)) % n

    return x_value, y_value


def extract_factor(n: int, x_value: int, y_value: int) -> int | None:
    for candidate in (gcd(abs(x_value - y_value), n), gcd((x_value + y_value) % n, n)):
        if 1 < candidate < n:
            return candidate
    return None
```

### Step 7: Wrap the toy Quadratic Sieve

The wrapper handles easy cases, collects smooth relations, tries dependencies, and returns the first non-trivial factor pair.

```python
def quadratic_sieve(n: int, bound: int = 50, interval: int = 1_000) -> tuple[int, int] | None:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if n % 2 == 0:
        return (2, n // 2)

    base = factor_base(n, bound)
    relations = collect_relations(n, bound, interval)
    vectors = [int(relation["parity"]) for relation in relations]

    for mask in dependency_masks(vectors):
        indices = [i for i in range(mask.bit_length()) if (mask >> i) & 1]
        x_value, y_value = build_congruence(n, base, relations, indices)
        factor = extract_factor(n, x_value, y_value)
        if factor is not None:
            other = n // factor
            return (factor, other) if factor <= other else (other, factor)

    return None
```

Example output from `code/main.py`:

```text
91: (7, 13)
1649: (17, 97)
2491: (47, 53)
10403: (101, 103)
```

Run it:

```
python3 code/main.py
```

## Use It

In practice, you would use PARI/GP, SageMath, Magma, msieve, CADO-NFS, or a vetted computer-algebra package rather than this code. Those tools combine trial division, Pollard methods, ECM, QS variants, and NFS, then choose the method based on the size and shape of `n`.

The important engineering lesson is escalation. A real factorization stack does not say "QS forever." It uses cheap methods first, ECM for medium-size factors, MPQS/SIQS for suitable composite sizes, and GNFS for large general RSA-style moduli.

## Attack It

The "attack" in this lesson is the factorization itself. If an RSA modulus is small enough for QS, its security margin is gone. The difference from Pollard p-1 is that QS does not need a smooth `p - 1`; it only needs enough smooth values of `x^2 - n`.

For `n = 1649`:

```text
Q(41) = 32  = 2^5
Q(43) = 200 = 2^3 * 5^2

Q(41) * Q(43) = 80^2
41 * 43 ≡ 114 (mod 1649)
114^2 ≡ 80^2 (mod 1649)
gcd(114 - 80, 1649) = 17
```

That gives:

```text
1649 = 17 * 97
```

Real RSA moduli are chosen far beyond QS toy sizes. This implementation is for understanding the machinery, not for assessing production keys.

## Ship It

This lesson ships `outputs/skill-quadratic-sieve-reviewer.md`, a small review checklist for educational QS code. Use it to catch common conceptual bugs: using all primes instead of QR primes, forgetting the `x ≠ ±y` trivial dependency case, or treating one failed dependency as proof that `n` is prime.

## Exercises

1. Easy: For `n = 2491`, print the first ten smooth relations with `B = 50`. Which primes appear most often?
2. Medium: Replace trial-factoring in `collect_relations` with a logarithmic sieve that marks roots modulo each factor-base prime.
3. Hard: Add a single-large-prime variant: keep relations where one leftover prime is below a second bound, then merge pairs with the same leftover.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Quadratic Sieve | "A faster Fermat method" | A relation-collection algorithm that turns many smooth `x^2 - n` values into a square congruence |
| Factor base | "Small primes to try" | Small primes `p` for which `n` is a quadratic residue modulo `p`, so `Q(x)` can be divisible by `p` |
| Smooth relation | "A lucky `Q(x)`" | A value of `x^2 - n` whose prime factors all lie in the factor base |
| Parity vector | "The row in the matrix" | Exponents reduced modulo 2, because even exponents make a square |
| Dependency | "Rows cancel out" | A non-empty subset of parity vectors whose xor is zero |
| MPQS/SIQS | "Production QS" | Multiple-polynomial and self-initializing variants that keep sieve values small over many intervals |

## Test Vectors

Source: project-internal educational examples cross-checked with direct integer arithmetic. Algorithm reference: Carl Pomerance, "The Quadratic Sieve Factoring Algorithm," EUROCRYPT 1984.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Carl Pomerance, The Quadratic Sieve Factoring Algorithm](https://link.springer.com/chapter/10.1007/3-540-39757-4_17) — Original QS presentation.
- [Handbook of Applied Cryptography, Chapter 3](https://cacr.uwaterloo.ca/hac/about/chap3.pdf) — Broad reference for integer factorization algorithms.
- [msieve](https://github.com/radii/msieve) — Practical factoring codebase using QS/NFS techniques.
