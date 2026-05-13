# AKS & Provable Primality

> Fast enough to guess is not the same thing as certain enough to prove.

**Type:** Learn
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 3, 4, 9, 10
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain what AKS proved that Miller-Rabin did not: unconditional, deterministic, polynomial-time primality testing.
- Understand the three structural steps of AKS: reject perfect powers, find a suitable `r`, then test a bounded family of polynomial congruences.
- Implement a toy AKS checker for small integers and see why it is mathematically beautiful but practically slow.
- Distinguish between "probable prime," "provable prime," and "prime with a short certificate."

## The Problem

Lesson 10 gave us Miller-Rabin, which is what real systems actually use during prime generation. That solves the engineering problem extremely well: screen candidates fast, drive the error probability down until it is negligible, and move on. But it leaves a theoretical gap. The output is "probable prime," not a proof that can never be wrong.

For a long time, that gap mattered. People knew many clever primality tests. Some were fast but randomized. Some were deterministic but only under unproved assumptions such as the Generalized Riemann Hypothesis. Some could certify primality in practice, but without the clean headline theorem computer scientists wanted: a deterministic polynomial-time algorithm for primality in the ordinary Turing-model sense.

AKS, published in 2002 by Agrawal, Kayal, and Saxena, closed that gap. It showed that primality is in `P`. That is a landmark result. It did not suddenly become the best practical way to generate RSA primes, but it changed what we know is possible. This lesson is about understanding that result at the right level: not every proof-of-primality tool is practical, and not every practical prime test is a proof.

## The Concept

### What AKS actually says

AKS is built on a prime-only identity. For prime `n`, the binomial coefficients in the expansion of `(X + a)^n` are all divisible by `n` except the first and last:

```text
(X + a)^n = X^n + (n choose 1) a X^(n-1) + ... + (n choose n-1) a^(n-1) X + a^n
```

If `n` is prime, then:

```text
(X + a)^n ≡ X^n + a (mod n)
```

That congruence alone is not enough, because checking full polynomials of degree `n` would be too expensive. AKS compresses the problem into the ring:

```text
Z_n[X] / (X^r - 1)
```

Now exponents wrap around modulo `r`, so the relevant identity becomes:

```text
(X + a)^n ≡ X^n + a (mod n, X^r - 1)
```

for enough small values of `a`.

### Why `r` matters

If `r` is chosen badly, composites can fake the polynomial identity. AKS therefore looks for the smallest `r` such that the multiplicative order of `n mod r` is large:

```text
ord_r(n) > log^2 n
```

That condition forces enough algebraic room that the polynomial check becomes meaningful.

Mental model:

```text
small r      -> too much wraparound, composites can hide
good r       -> enough distinct powers of n mod r, structure gets exposed
huge r       -> correct but expensive
```

So AKS is not "test one congruence and finish." It is a pipeline:

1. Reject perfect powers such as `64 = 2^6`.
2. Find a suitable `r`.
3. Check small gcds up to `r`.
4. Verify the polynomial congruence for enough `a`.

### Why this is not how production keygen works

Miller-Rabin answers the engineering question:

```text
Can I reject composites very fast with negligible risk?
```

AKS answers the theory question:

```text
Can I prove primality deterministically in polynomial time with no unproved assumptions?
```

Those are different wins. In practice, primality proving usually means ECPP or a similar certificate-producing method, because the prover is fast enough to be useful and the verifier can re-check a compact certificate. AKS is historically profound, but operationally heavy.

## Build It

### Step 1: Reject perfect powers

Every prime greater than `1` fails to be a perfect power. So AKS starts by eliminating numbers like:

```text
8 = 2^3
27 = 3^3
81 = 9^2
```

For small integers, a binary-search root plus exponent sweep is enough:

```python
def integer_nth_root(value: int, degree: int) -> int:
    low = 1
    high = value
    answer = 1
    while low <= high:
        mid = (low + high) // 2
        power = mid**degree
        if power == value:
            return mid
        if power < value:
            answer = mid
            low = mid + 1
        else:
            high = mid - 1
    return answer


def is_perfect_power(n: int) -> bool:
    for degree in range(2, n.bit_length() + 1):
        root = integer_nth_root(n, degree)
        if root**degree == n:
            return True
    return False
```

### Step 2: Find the first good `r`

We need the smallest `r` with:

```text
ord_r(n) > log^2 n
```

For a toy implementation, brute force is fine:

```python
from math import ceil, gcd, log2


def multiplicative_order_mod(n: int, r: int) -> int:
    value = n % r
    order = 1
    while value != 1:
        value = (value * n) % r
        order += 1
    return order


def find_smallest_r(n: int) -> int:
    threshold = ceil(log2(n) ** 2)
    r = 2
    while True:
        if gcd(n, r) == 1 and multiplicative_order_mod(n, r) > threshold:
            return r
        r += 1
```

This is not optimized AKS. It is the mathematically transparent version.

### Step 3: Multiply polynomials in `Z_n[X] / (X^r - 1)`

Inside the AKS ring, `X^r = 1`, so exponents wrap around:

```text
X^(r+2) = X^2
X^(2r+5) = X^5
```

Represent a polynomial as a length-`r` coefficient list. Then multiplication is just coefficient convolution with index wraparound:

```python
def poly_mul_mod(left: list[int], right: list[int], modulus: int, r: int) -> list[int]:
    result = [0] * r
    for i, left_coeff in enumerate(left[:r]):
        for j, right_coeff in enumerate(right[:r]):
            index = (i + j) % r
            result[index] = (result[index] + left_coeff * right_coeff) % modulus
    return result
```

Exponentiation uses repeated squaring exactly the same way integer modular exponentiation does.

### Step 4: Check the AKS congruence

The compressed identity is:

```text
(X + a)^n ≡ X^n + a (mod n, X^r - 1)
```

For a given `a`, compute the left side by polynomial exponentiation and compare it to the wrapped right side:

```python
def aks_target_polynomial(n: int, r: int, a: int) -> list[int]:
    target = [0] * r
    target[0] = a % n
    target[n % r] = (target[n % r] + 1) % n
    return target


def aks_congruence_holds(n: int, r: int, a: int) -> bool:
    base = [0] * r
    base[0] = a % n
    base[1 % r] = (base[1 % r] + 1) % n
    return poly_pow_mod(base, n, n, r) == aks_target_polynomial(n, r, a)
```

Then assemble the toy AKS pipeline:

```python
def aks_primality_test(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if is_perfect_power(n):
        return False

    r = find_smallest_r(n)
    factor = smallest_factor_up_to(n, r)
    if factor is not None and factor < n:
        return False
    if n <= r:
        return True

    limit = aks_witness_limit(n, r)
    for a in range(1, limit + 1):
        if not aks_congruence_holds(n, r, a):
            return False
    return True
```

This version is good for toy integers, testing, and understanding. It is not what you would run to make a 2048-bit RSA key.

## Use It

Real libraries usually do not expose AKS as the default primality path. They instead combine:

- small-prime sieving
- Miller-Rabin or Baillie-PSW style probable-prime screening
- certificate-producing provers such as ECPP when actual proof is required

In Python, `sympy.isprime` is a practical math-facing entry point. In systems code and crypto libraries, the common path is still "probable prime with overwhelming confidence," because that is the right performance/security tradeoff for key generation.

If you need a *provable* prime for a database, a standards artifact, or published parameters, the practical question becomes certificate generation and verification, not AKS purity.

## Attack It

AKS itself is not attacked the way Fermat or Miller-Rabin can be fooled by liars. Its value is exactly that it avoids that failure mode. The practical attack surface moves elsewhere:

1. Overclaiming certainty. If code runs Miller-Rabin and labels the result "provably prime," the bug is conceptual, not algebraic.
2. Forged certificates. If a system accepts an ECPP or Pratt certificate without recursively checking the claimed sub-proofs, an attacker can smuggle in a composite.
3. Resource exhaustion. A verifier that naively runs huge polynomial-ring checks on untrusted inputs can be turned into a denial-of-service target.

So the lesson here is different from Miller-Rabin. AKS is not "easy to fool." It is "easy to misuse as a systems component if you ignore cost, certificates, or terminology."

## Ship It

This lesson ships a review skill in `outputs/skill-primality-claim-reviewer.md`. It is for auditing educational code and docs that talk about primality. Its job is to catch overclaims such as:

- calling Miller-Rabin deterministic outside a proven bound
- calling a probable prime "proven"
- accepting a certificate without checking every recursive step
- using a toy AKS implementation as if it were practical production infrastructure

## Exercises

1. Replace the brute-force multiplicative-order search with a version that factors `phi(r)` and tests only divisors.
2. Count how many `a` values your toy AKS checks for each prime under `200`, and compare that cost to Miller-Rabin.
3. Implement a tiny Pratt-certificate verifier and compare its verification story with AKS.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| probable prime | "basically prime" | Passed a probabilistic test for chosen bases; still not a proof |
| deterministic primality test | "never uses randomness" | Returns the correct prime/composite answer for every input |
| primality certificate | "proof object" | A short artifact another verifier can check faster than rediscovering the proof |
| multiplicative order | "cycle length" | Smallest `k > 0` with `n^k ≡ 1 mod r` when `gcd(n, r) = 1` |
| perfect power | "obviously composite" | Integer of the form `a^b` with `a > 1` and `b > 1` |

## Test Vectors

Source: project-internal toy AKS examples cross-checked with Python arithmetic. The lesson code passes all vectors in `tests/vectors.json`.

## Further Reading

- Agrawal, Kayal, Saxena, "PRIMES is in P" — the original AKS result and proof structure.
- Crandall and Pomerance, *Prime Numbers: A Computational Perspective* — practical context for AKS, Miller-Rabin, and certificate-based proving.
- Bernstein, "Proving primality after Agrawal-Kayal-Saxena" — a concise map of where AKS fits among real-world proof systems.
