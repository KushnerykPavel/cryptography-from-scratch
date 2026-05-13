# GCD, Bezout, Extended Euclidean Algorithm

> The gcd is not just a divisor. It is the integer combination that unlocks the whole system.

**Type:** Build
**Languages:** Python
**Prerequisites:** 01-modular-arithmetic
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

In lesson 01, modular arithmetic worked because we could reduce numbers and keep computing inside `Z/nZ`. But the moment you ask a harder question such as "does `a` have an inverse mod `n`?" or "can these two congruences be recombined?" reduction alone is not enough. You need a way to measure how tightly two integers are entangled.

That measurement is the greatest common divisor. If `gcd(a, n) = 1`, `a` is invertible mod `n`. If `gcd(e, phi(n)) != 1`, RSA key generation fails because the private exponent `d` does not exist. If two numbers share a hidden factor, `gcd` is the shortest path to recovering it.

Bezout's identity makes this more powerful: the gcd is not just something you compute, it is something you can *build* from `a` and `b` using integer coefficients. The Extended Euclidean Algorithm (EEA) finds those coefficients. That one fact will power modular inverse, CRT recombination, and several attacks later in the course.

## The Concept

The ordinary Euclidean algorithm repeatedly replaces a pair `(a, b)` with `(b, a mod b)`:

```text
gcd(a, b) = gcd(b, a mod b)
```

Why does that work? Because every common divisor of `a` and `b` also divides `a - q*b`, and `a mod b` is exactly `a - q*b` for some quotient `q`.

Think of it as controlled shrinking:

```text
(240, 46)
-> (46, 10)   because 240 = 5*46 + 10
-> (10, 6)    because 46  = 4*10 + 6
-> (6, 4)     because 10  = 1*6  + 4
-> (4, 2)     because 6   = 1*4  + 2
-> (2, 0)     because 4   = 2*2  + 0
```

The last non-zero remainder is the gcd, so `gcd(240, 46) = 2`.

Bezout's identity adds the deeper claim:

```text
There exist integers s, t such that

s*a + t*b = gcd(a, b)
```

That means the gcd is the smallest positive integer you can synthesize from `a` and `b` by taking integer linear combinations.

For `(240, 46)`, the remainder chain is:

```text
240 = 5*46 + 10
46  = 4*10 + 6
10  = 1*6  + 4
6   = 1*4  + 2
4   = 2*2  + 0
```

Now back-substitute:

```text
2 = 6 - 1*4
  = 6 - 1*(10 - 1*6)
  = 2*6 - 1*10
  = 2*(46 - 4*10) - 1*10
  = 2*46 - 9*10
  = 2*46 - 9*(240 - 5*46)
  = -9*240 + 47*46
```

So one valid Bezout pair is `s = -9`, `t = 47`:

```text
(-9)*240 + 47*46 = 2
```

The Extended Euclidean Algorithm is just the Euclidean algorithm with bookkeeping attached so you do not have to back-substitute by hand every time.

## Build It

### Step 1: Compute `gcd(a, b)`

Start with the plain Euclidean algorithm. The only design choice we need is sign normalization: cryptographic code usually wants the gcd to be non-negative, so we work with absolute values.

```python
def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a
```

This already handles zero cleanly:

```text
gcd(a, 0) = |a|
gcd(0, b) = |b|
gcd(0, 0) = 0
```

### Step 2: Track Bezout coefficients with `extended_gcd`

We keep two parallel stories:

- the current remainders
- how each remainder is written as a combination of the original inputs

```python
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
```

At the end:

- `old_r` is the gcd
- `old_s` and `old_t` satisfy `old_s*a + old_t*b = old_r`

### Step 3: Verify the identity directly

Never trust coefficient code by vibes. Check the invariant:

```python
g, s, t = extended_gcd(240, 46)
assert g == gcd(240, 46)
assert s * 240 + t * 46 == g
```

Try negatives too:

```python
g, s, t = extended_gcd(-240, 46)
assert g == 2
assert s * (-240) + t * 46 == 2
```

That is the real contract. The coefficients are not unique, but the identity must hold.

## Use It

Python already gives you `math.gcd(a, b)` for the plain gcd:

```python
import math

print(math.gcd(240, 46))  # 2
```

What Python's standard library does *not* expose directly is the full Bezout triple. That is why we build EEA ourselves here.

In real cryptographic libraries, EEA often appears one layer below the public API. A modular inverse helper typically calls EEA, checks that the gcd is 1, and then reduces the Bezout coefficient modulo `n`. We will build that explicitly in lesson 03 instead of smuggling it into this lesson.

The practical pattern is:

```text
1. Compute gcd(a, n)
2. If gcd != 1, no inverse exists
3. If gcd == 1, reuse the Bezout coefficient as the inverse
```

So this lesson supplies the engine; the next lesson turns it into the modular-inverse tool.

## Attack It

**RSA key-generation failure when `gcd(e, phi(n)) != 1`.**

RSA needs a private exponent `d` satisfying:

```text
e*d = 1 (mod phi(n))
```

That means `d` is the modular inverse of `e` modulo `phi(n)`. But an inverse exists only when:

```text
gcd(e, phi(n)) = 1
```

If an implementation picks `e = 65537` and forgets to check coprimality, it can generate a public key that looks normal but has no valid private key. Decryption and signing then fail because there is no integer `d` making the congruence true.

That is not a side issue. It is a key-generation gate:

```python
g, _, _ = extended_gcd(e, phi_n)
if g != 1:
    raise ValueError("public exponent is not invertible modulo phi(n)")
```

Later attacks will use EEA offensively too, but this is the first defensive lesson: some systems break not because the math is hard, but because a single gcd precondition was skipped.

## Ship It

This lesson's reusable artifact is conceptual rather than a new file in `outputs/`: a tiny, auditable `gcd` + `extended_gcd` module that every later number-theory lesson can lean on.

In this course, treat it as the foundation brick for:

- modular inverse
- Chinese Remainder Theorem recombination
- RSA key validation
- factor-recovery tricks based on shared divisors

No new artifact is added under `outputs/` in this lesson. The shipped value is the tested implementation itself.

## Exercises

1. **Easy.** Run the Euclidean algorithm by hand for `gcd(99, 78)` and identify the last non-zero remainder.
2. **Medium.** Compute one Bezout pair `(s, t)` for `(99, 78)` by back-substitution, then verify `s*99 + t*78 = gcd(99, 78)`.
3. **Hard.** Suppose two RSA public moduli share a prime factor `p`. Show how a single `gcd(n1, n2)` call recovers that shared factor, then explain why that instantly breaks both keys.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Greatest common divisor | "biggest shared factor" | The largest positive integer dividing both inputs |
| Coprime | "no common factors" | `gcd(a, b) = 1` |
| Bezout coefficients | "the inverse numbers" | Integers `s, t` with `s*a + t*b = gcd(a, b)` |
| Extended Euclidean Algorithm | "Euclid but longer" | Euclid's remainder loop plus coefficient tracking |

## Test Vectors

Source: project-internal integer examples grounded in the Euclidean algorithm and Bezout identity.
Code must pass `tests/vectors.json` for both `gcd` and `extended_gcd`.

## Further Reading

- [Python `math.gcd` documentation](https://docs.python.org/3/library/math.html#math.gcd) — Reference behavior for gcd edge cases.
- [Boneh and Shoup, *A Graduate Course in Applied Cryptography*](https://crypto.stanford.edu/~dabo/cryptobook/) — Free text with the number-theory background crypto actually uses.
- [Knuth, *The Art of Computer Programming*, Vol. 2](https://www-cs-faculty.stanford.edu/~knuth/taocp.html) — Classic treatment of Euclid and related algorithms.
