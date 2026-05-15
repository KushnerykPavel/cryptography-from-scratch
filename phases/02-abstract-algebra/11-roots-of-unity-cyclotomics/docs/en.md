# Roots of Unity & Cyclotomic Polynomials

> The element that cycles back: one rotation at a time.

**Type:** Build
**Languages:** Python
**Prerequisites:** 02-abstract-algebra/07-finite-fields-gf-p, 02-abstract-algebra/10-irreducible-polynomials
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

The Number Theoretic Transform — the backbone of fast polynomial multiplication in lattice cryptography and ZK proof systems — needs one special number: a primitive `n`-th root of unity in `F_p`.

Without knowing how to find that number, you cannot run an NTT. Without knowing when it exists, you cannot choose a suitable prime. And without the cyclotomic polynomial, you cannot understand why that primitive root splits the field in exactly the right way to make the transform work.

This lesson builds the machinery that sits between abstract algebra and the NTT: the tools for working with roots of unity over finite fields and computing the polynomials whose roots they are.

## The Concept

### What a root of unity is

An `n`-th root of unity in `F_p` is any element `ω` such that:

```text
ω^n = 1  in  F_p
```

The simplest root is always `1`. For `n = 2`, there is exactly one nontrivial root: `p - 1` (which is `-1 mod p`). For larger `n`, roots only exist when the group structure supports them.

### Order and the cyclic group

The multiplicative group `F_p*` is cyclic of order `p - 1`. Every element `a` in `F_p*` has a multiplicative order: the smallest positive `k` such that `a^k = 1`.

The `n`-th roots of unity form a subgroup of `F_p*`. That subgroup has exactly `n` elements when `n` divides `p - 1`, and only `gcd(n, p-1)` elements otherwise.

```text
n-th roots of unity exist in F_p  <=>  n | (p - 1)
```

### Primitive roots of unity

Among all `n`-th roots, the primitive ones have order exactly `n`. They are the generators of the cyclic subgroup of order `n`.

```text
primitive n-th roots of unity = elements with multiplicative order n
```

In `F_5` with `n = 4`: `p - 1 = 4`, so all of `F_5*` is the group of 4th roots. The elements `2` and `3` are primitive because `2^4 = 1` but `2^2 = 4 ≠ 1`.

### Finding a primitive n-th root

The cleanest method uses a generator of the full group `F_p*`, called a primitive root `g`:

```text
ω = g^((p-1)/n)
```

`ω` then has order exactly `n` because:

```text
ω^n = g^(p-1) = 1          (Fermat's little theorem)
ω^(n/q) = g^((p-1)/q) ≠ 1  (since g has full order p-1)
```

for every prime factor `q` of `n`.

### Cyclotomic polynomials

The `n`-th cyclotomic polynomial `Φ_n(x)` is the minimal polynomial whose roots are exactly the primitive `n`-th roots of unity in the complex numbers (and over any field where they live):

```text
Φ_n(x) = product of (x - ζ) over all primitive n-th roots ζ
```

Its degree is `φ(n)` — Euler's totient, the count of integers from `1` to `n` coprime to `n`.

The key identity connecting all cyclotomic polynomials:

```text
x^n - 1 = product of Φ_d(x)  for all d | n
```

This gives a recursive construction: divide `x^n - 1` by all `Φ_d` for proper divisors `d` of `n`.

Small examples:

```text
Φ_1(x) = x - 1
Φ_2(x) = x + 1
Φ_4(x) = x^2 + 1
Φ_6(x) = x^2 - x + 1
Φ_8(x) = x^4 + 1
```

Over `F_p`, `Φ_n(x)` may factor further. In `F_17`, `Φ_8(x) = x^4 + 1` splits into four linear factors because `17 ≡ 1 (mod 8)` — all primitive 8th roots live directly in `F_17`.

### Connection to NTT

The NTT over `F_p` on inputs of length `n` requires:

1. `n | (p - 1)` — so a primitive `n`-th root exists
2. A specific primitive `n`-th root `ω` — used as the twiddle factor
3. `n` invertible in `F_p` — so the inverse transform can divide by `n`

The split of `x^n - 1` into cyclotomic factors tells you exactly which roots the transform uses and how the DFT matrix factors. Lesson 12 builds the NTT on top of this foundation.

## Build It

### Step 1: Divisors and Euler's totient

Cyclotomic polynomials require divisors of `n` and degree counts:

```python
def divisors(n: int) -> list[int]:
    result = []
    for d in range(1, isqrt(n) + 1):
        if n % d == 0:
            result.append(d)
            if d != n // d:
                result.append(n // d)
    return sorted(result)

def euler_phi(n: int) -> int:
    result = n
    for p in prime_factors(n):
        result = result // p * (p - 1)
    return result
```

`euler_phi(n)` equals the degree of `Φ_n` and the count of primitive `n`-th roots.

### Step 2: Multiplicative order

The order of `a` in `F_p*` is the smallest positive `k` with `a^k = 1`. Since order divides `p - 1`, find it by dividing `p - 1` down by prime factors as long as `a^(order/q) = 1`:

```python
def multiplicative_order(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("zero has no multiplicative order")
    order = p - 1
    for q in prime_factors(p - 1):
        while order % q == 0 and pow(a, order // q, p) == 1:
            order //= q
    return order
```

Example:

```python
multiplicative_order(3, 7)   # 6  (3 generates F_7*)
multiplicative_order(2, 7)   # 3  (2^3 = 8 = 1 mod 7)
multiplicative_order(2, 17)  # 8
```

### Step 3: Primitive roots and n-th roots of unity

A primitive root `g` mod `p` generates the entire group `F_p*`:

```python
def primitive_root(p: int) -> int:
    for g in range(2, p):
        if multiplicative_order(g, p) == p - 1:
            return g
```

All `n`-th roots of unity and the primitive ones among them:

```python
def nth_roots_of_unity(n: int, p: int) -> list[int]:
    return sorted(a for a in range(p) if pow(a, n, p) == 1)

def is_primitive_nth_root(a: int, n: int, p: int) -> bool:
    if pow(a, n, p) != 1:
        return False
    for q in prime_factors(n):
        if pow(a, n // q, p) == 1:
            return False
    return True
```

In `F_17` with `n = 8`:

```python
nth_roots_of_unity(8, 17)    # [1, 2, 4, 8, 9, 13, 15, 16]
primitive_nth_roots(8, 17)   # [2, 8, 9, 15]
```

### Step 4: Find a canonical primitive n-th root

Given a prime `p` where `n | (p - 1)`, raise the primitive root to `(p-1)/n`:

```python
def find_primitive_nth_root(n: int, p: int) -> int:
    if (p - 1) % n != 0:
        raise ValueError(f"n={n} does not divide p-1={p-1}, ...")
    g = primitive_root(p)
    return pow(g, (p - 1) // n, p)
```

Example:

```python
find_primitive_nth_root(8, 17)  # 9
# 9^8 = 1 mod 17, 9^4 = 16 ≠ 1 mod 17
```

### Step 5: Build cyclotomic polynomials over Z

Use the product identity recursively. Integer polynomial division is exact here:

```python
def cyclotomic_poly_z(n: int) -> list[int]:
    xn_minus_1 = [0] * (n + 1)
    xn_minus_1[0] = -1
    xn_minus_1[n] = 1
    result = list(xn_minus_1)
    for d in divisors(n)[:-1]:          # all proper divisors
        result = _int_poly_divexact(result, cyclotomic_poly_z(d))
    return result
```

The `_int_poly_divexact` function does standard polynomial long division over the integers, trusting the remainder is zero:

```python
cyclotomic_poly_z(4)   # [1, 0, 1]  →  x^2 + 1
cyclotomic_poly_z(6)   # [1, -1, 1]  →  x^2 - x + 1
cyclotomic_poly_z(8)   # [1, 0, 0, 0, 1]  →  x^4 + 1
```

### Step 6: Reduce mod p

Reduce integer coefficients mod `p` for the finite-field version:

```python
def cyclotomic_poly(n: int, p: int) -> list[int]:
    poly_z = cyclotomic_poly_z(n)
    reduced = [c % p for c in poly_z]
    return _int_poly_normalize(reduced)
```

Over `F_7`, `Φ_6(x) = x^2 - x + 1` becomes:

```python
cyclotomic_poly(6, 7)   # [1, 6, 1]  →  x^2 + 6x + 1
```

(since `-1 mod 7 = 6`)

## Use It

Python's `sympy` library can confirm cyclotomic polynomials:

```python
from sympy import cyclotomic_poly as sympy_cyclo
from sympy import symbols

x = symbols("x")
print(sympy_cyclo(8, x))     # x**4 + 1
print(sympy_cyclo(6, x))     # x**2 - x + 1
```

The `galois` package provides finite-field NTT with automatic primitive root selection:

```python
import galois
GF = galois.GF(17)
# galois handles finding ω internally for NTT
```

Comparison:

| Task | This lesson | Library |
|------|-------------|---------|
| Roots of unity | brute-force search | algebraic structure |
| Primitive root | sequential scan | baby-step giant-step |
| Cyclotomic poly | recursive exact division | closed-form, memoized |
| NTT readiness | divisibility check | abstracted away |

## Attack It

Choosing a prime where `n` does not divide `p - 1` is a common NTT parameter mistake.

```text
n = 8,  p = 13
p - 1 = 12,  8 ∤ 12
```

There are only `gcd(8, 12) = 4` eighth roots of unity in `F_13`, not eight. An NTT on size-8 input fails silently: instead of a full basis of primitive roots, you get repeated twiddle factors and a singular transform matrix. Outputs are wrong with no error raised.

The lesson code exposes this:

```python
ntt_check(8, 13)
# {"n_divides_p_minus_1": False, "primitive_root_omega": None}
```

Always verify `n | (p - 1)` before selecting NTT parameters.

## Ship It

This lesson ships `outputs/skill-roots-of-unity-review.md`, a checklist for reviewing NTT parameters and roots-of-unity usage in cryptographic code.

Use it when evaluating code that performs NTTs, selects field parameters for lattice schemes, or constructs rings of the form `Z_p[x]/(x^n - 1)` or `Z_p[x]/(x^n + 1)`.

## Exercises

1. List all primitive 12th roots of unity in `F_13`. Confirm the count matches `φ(12)`.
2. Verify that `Φ_n(x)` has integer coefficients for `n = 12`. Compute it using the lesson code and check that `|coefficients| ≤ 1`.
3. Find the smallest prime `p > 100` such that `F_p` contains a primitive 16th root of unity. Confirm by computing `find_primitive_nth_root(16, p)`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| n-th root of unity | A special element | An element ω in F_p with ω^n = 1 |
| Primitive n-th root | The generator version | An n-th root with multiplicative order exactly n |
| Multiplicative order | How fast it cycles | Smallest k ≥ 1 such that a^k = 1 mod p |
| Primitive root mod p | Generator of F_p* | An element g with order p-1; every nonzero element is a power of g |
| Cyclotomic polynomial | Phi_n | Monic polynomial whose roots are exactly the primitive n-th roots |
| Euler's totient φ(n) | Phi of n | Count of integers from 1 to n coprime to n; degree of Φ_n |
| NTT prime | NTT-friendly prime | A prime p where n \| (p-1) for the desired transform length n |

## Test Vectors

Source: project-internal examples verified against known group orders, standard cyclotomic polynomial tables, and `sympy.cyclotomic_poly`.

Run:

```bash
python3 phases/02-abstract-algebra/11-roots-of-unity-cyclotomics/tests/test_vectors.py
```

## Further Reading

- [Washington, Introduction to Cyclotomic Fields](https://link.springer.com/book/10.1007/978-1-4612-1934-7) — classic reference on cyclotomic polynomials and their arithmetic.
- [SageMath cyclotomic polynomials](https://doc.sagemath.org/html/en/reference/rings_standard/sage/rings/polynomial/cyclotomic.html) — computable examples with verification.
- [NTT primer (GitHub: nayuki)](https://www.nayuki.io/page/number-theoretic-transform-integer-dft) — accessible walkthrough of NTT parameter selection connecting directly to this lesson.
