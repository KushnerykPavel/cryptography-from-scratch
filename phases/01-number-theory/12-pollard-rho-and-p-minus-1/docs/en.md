# Pollard Rho & Pollard p-1 Factoring

> Factoring starts to feel different when collisions and smoothness become attack surfaces.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 2, 3, 4, 6, 9, 10
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why trial division is the wrong baseline once factors are larger than toy examples.
- Implement Pollard's rho algorithm with Floyd and Brent cycle detection.
- Implement Pollard's p-1 algorithm and connect it to smooth group orders.
- Explain why RSA primes should avoid easy smoothness structure in `p - 1`.

## The Problem

After Miller-Rabin, you can quickly say "this number is composite." That is not the same as finding its factors. Factoring is the harder problem that RSA relies on: given `n = p * q`, recover `p` and `q`. Trial division proves the concept, but it needs about `sqrt(p)` divisions to find the smaller prime factor. For a balanced RSA modulus, that is hopeless.

Pollard's algorithms are the first factoring methods that feel like cryptanalysis instead of brute force. Pollard rho uses the birthday paradox: a pseudo-random walk modulo `n` will collide modulo the hidden factor `p` long before it collides modulo `n`. Pollard p-1 uses group structure: if `p - 1` is made only of small prime powers, Fermat's theorem lets us manufacture a value that is `1 mod p` but not necessarily `1 mod q`.

This lesson gives you two compact attacks on weak composites. Neither breaks real RSA with well-generated primes. Both explain why "large" is not the only property a cryptographic prime needs.

## The Concept

### Pollard rho: collide modulo a factor

Pick a polynomial, usually:

```text
f(x) = x^2 + c mod n
```

Then iterate:

```text
x0 -> x1 -> x2 -> x3 -> ...
```

You cannot see the sequence modulo `p`, because `p` is the secret factor. But it is there:

```text
mod n:  x0, x1, x2, x3, x4, ...
mod p:  r0, r1, r2, r3, r4, ... eventually cycles
```

When two states become equal modulo `p`, their difference is divisible by `p`:

```text
xi ≡ xj (mod p)
xi - xj = k*p
gcd(|xi - xj|, n) = p        if q does not also divide the difference
```

The birthday paradox says that a collision modulo `p` is expected after about `sqrt(p)` samples. For a balanced semiprime `n = p*q`, that is around `n^(1/4)` iterations, much better than trial division's `n^(1/2)` scale.

### Floyd vs Brent

The naive way to find a repeated state is to store every previous value. That works, but memory grows with the walk. Cycle detection avoids the table.

| Method | Mental model | Tradeoff |
|--------|--------------|----------|
| Floyd | Tortoise moves one step; hare moves two steps | Simple and easy to teach |
| Brent | Power-of-two blocks and batched gcd checks | Same idea, usually fewer gcds |

Floyd is the clean first implementation. Brent is what you reach for when the cost of repeated gcd calls starts to matter.

### Pollard p-1: exploit smoothness

Fermat's theorem says that if `p` is prime and `gcd(a, p) = 1`, then:

```text
a^(p - 1) ≡ 1 (mod p)
```

If every prime-power factor of `p - 1` is small, then `p - 1` divides:

```text
M = lcm(1, 2, 3, ..., B)
```

So:

```text
a^M ≡ 1 (mod p)
```

Now compute:

```text
gcd(a^M - 1, n)
```

If `p - 1` is `B`-smooth but `q - 1` is not, the gcd reveals `p`. If both sides are smooth, the gcd can become `n` and the attempt fails. If neither side is smooth, the gcd is usually `1`.

## Build It

### Step 1: Build the rho walk

Start with the polynomial that drives the pseudo-random walk.

```python
from math import gcd, lcm


def rho_polynomial(x: int, n: int, c: int = 1) -> int:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    return (x * x + c) % n
```

Changing `c` changes the walk. That matters because Pollard rho is randomized in spirit: if one walk falls into an unhelpful cycle, retry with a different seed or polynomial.

### Step 2: Add Floyd cycle detection

Floyd's method keeps two states. If their difference shares a non-trivial gcd with `n`, you found a factor.

```python
def pollard_rho_floyd(
    n: int, x0: int = 2, c: int = 1, max_steps: int = 10_000
) -> tuple[int | None, int]:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")
    if n % 2 == 0:
        return (2 if n != 2 else None), 0

    tortoise = x0 % n
    hare = x0 % n

    for step in range(1, max_steps + 1):
        tortoise = rho_polynomial(tortoise, n, c)
        hare = rho_polynomial(rho_polynomial(hare, n, c), n, c)
        factor = gcd(abs(tortoise - hare), n)

        if 1 < factor < n:
            return factor, step
        if factor == n:
            return None, step

    return None, max_steps
```

For `8051`, this finds a factor quickly:

```text
8051 = 83 * 97
pollard_rho_floyd(8051) -> (97, 3)
```

### Step 3: Add Brent's variant

Brent's improvement batches work into power-of-two windows. It tends to perform fewer expensive gcd calls while preserving the same birthday-paradox intuition.

```python
def pollard_rho_brent(
    n: int, x0: int = 2, c: int = 1, batch_size: int = 32, max_steps: int = 10_000
) -> tuple[int | None, int]:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    if max_steps <= 0:
        raise ValueError("max_steps must be positive")
    if n % 2 == 0:
        return (2 if n != 2 else None), 0

    y = x0 % n
    r = 1
    q = 1
    factor = 1
    steps = 0
    saved_y = y

    while factor == 1 and steps < max_steps:
        x = y
        for _ in range(r):
            y = rho_polynomial(y, n, c)
            steps += 1
            if steps >= max_steps:
                break

        k = 0
        while k < r and factor == 1 and steps < max_steps:
            saved_y = y
            for _ in range(min(batch_size, r - k)):
                y = rho_polynomial(y, n, c)
                steps += 1
                q = (q * abs(x - y)) % n
                if steps >= max_steps:
                    break
            factor = gcd(q, n)
            k += batch_size
        r *= 2

    if factor == n:
        factor = 1
        while factor == 1 and steps < max_steps:
            saved_y = rho_polynomial(saved_y, n, c)
            steps += 1
            factor = gcd(abs(x - saved_y), n)
        if factor == n:
            return None, steps

    if 1 < factor < n:
        return factor, steps
    return None, steps
```

Brent's method is a performance improvement, not a different mathematical attack. Both methods still rely on a collision modulo a hidden factor.

### Step 4: Build `lcm(1..B)` and smoothness checks

Pollard p-1 needs an exponent divisible by many small prime powers. `lcm(1..B)` gives exactly that for the stage-one version.

```python
def lcm_upto(bound: int) -> int:
    if bound < 1:
        raise ValueError("bound must be at least 1")

    result = 1
    for value in range(2, bound + 1):
        result = lcm(result, value)
    return result


def is_b_smooth(value: int, bound: int) -> bool:
    if value <= 0:
        raise ValueError("value must be positive")
    if bound < 2:
        return value == 1

    remaining = value
    divisor = 2
    while divisor <= bound and remaining > 1:
        while remaining % divisor == 0:
            remaining //= divisor
        divisor = 3 if divisor == 2 else divisor + 2
    return remaining == 1
```

Examples:

```text
96 = 2^5 * 3       is 3-smooth
100 = 2^2 * 5^2    is 5-smooth
106 = 2 * 53       is not 25-smooth
```

### Step 5: Implement Pollard p-1

Compute `a^M - 1 mod n`, then take a gcd.

```python
def pollard_p_minus_one(n: int, bound: int, a: int = 2) -> tuple[int | None, int]:
    if n <= 1:
        raise ValueError("n must be greater than 1")
    if bound < 2:
        raise ValueError("bound must be at least 2")
    if n % 2 == 0:
        return (2 if n != 2 else None), 0

    shared = gcd(a, n)
    if 1 < shared < n:
        return shared, 0
    if shared == n:
        return None, 0

    exponent = lcm_upto(bound)
    factor = gcd(pow(a, exponent, n) - 1, n)
    if 1 < factor < n:
        return factor, exponent
    return None, exponent
```

For `n = 101 * 107`, `101 - 1 = 100` is `25`-smooth, while `107 - 1 = 106` has the larger factor `53`. That asymmetry reveals `101`.

### Step 6: Return clean factor pairs

Factoring code should make its output explicit. A non-trivial factor becomes a sorted pair; a failed attempt returns `None`.

```python
def factor_pair(n: int, factor: int | None) -> tuple[int, int] | None:
    if factor is None or factor <= 1 or n % factor != 0 or factor == n:
        return None
    other = n // factor
    return (factor, other) if factor <= other else (other, factor)


def factor_with_pollard(n: int, bound: int = 25) -> tuple[int, int] | None:
    factor, _ = pollard_p_minus_one(n, bound)
    pair = factor_pair(n, factor)
    if pair is not None:
        return pair

    factor, _ = pollard_rho_brent(n)
    return factor_pair(n, factor)
```

This is still a toy wrapper. A serious factoring tool would use many restarts, multiple polynomials, stage-two p-1, ECM, quadratic sieve, and eventually number field sieve.

Run it:

```
python3 code/main.py
```

## Use It

Mathematical software such as SageMath, PARI/GP, Magma, and SymPy includes integer factorization routines that combine many methods. They do not bet everything on one Pollard rho walk or one p-1 bound. They use cheap filters first, then escalate.

In security work, these algorithms show up as sanity checks. If a public RSA modulus falls to Pollard p-1, one prime had bad smoothness structure. If it falls to rho quickly, a small factor or malformed key-generation path is likely. Either result is a red-alert key-generation bug, not a clever optimization opportunity.

## Attack It

### Weak p-1 structure

Consider:

```text
n = 101 * 107 = 10807
101 - 1 = 100 = 2^2 * 5^2
107 - 1 = 106 = 2 * 53
```

With `B = 25`, `100` divides `lcm(1..25)`, but `106` does not. So:

```text
gcd(2^lcm(1..25) - 1, 10807) = 101
```

That is exactly the failure RSA prime-generation guidance tries to avoid: if a prime's `p - 1` is too smooth, group-order structure becomes a factoring shortcut.

### Rho against small factors

For:

```text
n = 8051 = 83 * 97
f(x) = x^2 + 1
x0 = 2
```

The Floyd rho walk finds a factor in a few iterations. The attack is not using special algebraic structure of `83` or `97`; it is exploiting the birthday collision inside the smaller hidden residue class.

## Ship It

This lesson ships `outputs/skill-pollard-factor-reviewer.md`, a review checklist for educational factoring code. Use it to catch common mistakes: forgetting the `gcd == n` failure case, treating one rho failure as proof of primality, or claiming p-1 works without a smoothness condition.

## Exercises

1. Easy: Try `pollard_rho_floyd` with `c = 2` and `c = 3` on `8051`. Compare the number of steps and the factor found.
2. Medium: Add a restart wrapper that tries several `(x0, c)` pairs before giving up.
3. Hard: Implement stage-two Pollard p-1 or compare this lesson's p-1 method with a small elliptic-curve method on numbers whose `p - 1` is not smooth.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Pollard rho | "Random factoring walk" | A pseudo-random iteration where collisions modulo a hidden factor reveal a gcd |
| Birthday bound | "Collisions happen around square root size" | In a set of size `N`, random samples collide with constant probability after about `sqrt(N)` draws |
| Brent cycle detection | "Faster rho" | A cycle-detection schedule that reduces gcd overhead compared with Floyd |
| B-smooth | "Made of small primes" | Every prime factor is at most `B`, including repeated prime powers through divisibility |
| Pollard p-1 | "Factor using Fermat" | A method that works when a prime factor `p` has `p - 1` dividing a smooth exponent |
| Strong RSA prime | "A safer-shaped prime" | A prime chosen to avoid simple smoothness attacks on `p - 1` and related structures |

## Test Vectors

Source: project-internal examples cross-checked with Python `math.gcd` and modular exponentiation. Algorithm references: Pollard 1975, Brent 1980, and *Handbook of Applied Cryptography*, section 3.2.

Code must pass all vectors in `tests/vectors.json`.

## Further Reading

- [Handbook of Applied Cryptography, Chapter 3](https://cacr.uwaterloo.ca/hac/about/chap3.pdf) — Classic reference for integer factorization algorithms.
- [John M. Pollard, A Monte Carlo Method for Factorization](https://doi.org/10.1007/BF01933667) — Original rho paper.
- [Richard P. Brent, An Improved Monte Carlo Factorization Algorithm](https://doi.org/10.1007/BF01933190) — Brent's cycle-detection improvement.
