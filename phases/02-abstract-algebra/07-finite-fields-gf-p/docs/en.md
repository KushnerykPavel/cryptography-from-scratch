# Finite Fields GF(p)

> A prime modulus turns wraparound arithmetic into a world where every nonzero value can divide.

**Type:** Build
**Languages:** Python
**Prerequisites:** 01-number-theory/03-modular-inverse-and-fast-exp, 01-number-theory/04-fermat-and-euler, 02-abstract-algebra/06-fields-and-extensions
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Implement the four field operations (add, subtract, multiply, divide) in `GF(p)` with a prime-modulus guard on every function
- Explain why a composite modulus produces zero divisors that make division undefined for certain nonzero elements
- Compute the multiplicative order of an element and identify which elements are generators of `F_p*`
- Apply Lagrange interpolation over `GF(p)` to reconstruct a polynomial from field-valued points, connecting to Shamir secret sharing
- Distinguish the `Fp` value type from a raw integer and explain how carrying the field with the value prevents cross-field arithmetic bugs

## The Problem

Elliptic curves, Schnorr signatures, Reed-Solomon codes, Shamir secret sharing, and ZK circuits all do arithmetic in finite fields. The most common base case is `GF(p)`, also written `F_p`: integers modulo a prime.

If you treat "mod n" as automatically safe, you will build protocols on sand. `Z/15Z` has values such as `3` and `5` that are nonzero but multiply to zero. Division by those values is impossible. A signature formula, polynomial interpolation step, or elliptic-curve slope that assumes division exists can fail or leak structure.

The prime-field habit is simple: carry the modulus with every value, check that it is prime, reduce every operation, and refuse to divide by zero. This lesson turns that habit into a small reusable `GF(p)` toolkit.

## The Concept

A finite field with prime order has exactly `p` elements:

```text
F_p = {0, 1, 2, ..., p-1}
```

Addition, subtraction, and multiplication are ordinary integer operations followed by reduction:

```text
(a + b) mod p
(a - b) mod p
(a * b) mod p
```

For `p = 7`, the number line wraps:

```text
0 -- 1 -- 2 -- 3 -- 4 -- 5 -- 6 -- back to 0

5 + 4 = 9 = 2 mod 7
3 - 5 = -2 = 5 mod 7
```

The field property is about division. Every nonzero element must have an inverse:

```text
a * a^-1 = 1 mod p
```

When `p` is prime, every `1 <= a < p` is coprime to `p`, so Extended Euclid gives integers `x, y` such that:

```text
a*x + p*y = 1
```

Reducing both sides modulo `p` leaves:

```text
a*x = 1 mod p
```

So `x mod p` is the inverse.

### Why prime matters

Composite moduli have zero divisors:

```text
In Z/15Z:

3 != 0
5 != 0
3 * 5 = 15 = 0 mod 15
```

If `3` had an inverse, multiplying `3 * 5 = 0` by `3^-1` would imply `5 = 0`. That contradiction is why composite modular rings are not fields.

### Multiplicative group

The nonzero elements of `F_p` form a group of size `p - 1`:

```text
F_p^* = {1, 2, ..., p-1}
```

Some elements generate the whole group. In `F_7`, `3` is a generator:

```text
3^1 = 3
3^2 = 2
3^3 = 6
3^4 = 4
3^5 = 5
3^6 = 1
```

Generators matter later for Diffie-Hellman, discrete logs, roots of unity, NTTs, and polynomial commitments.

### Polynomials over GF(p)

Once coefficients live in `F_p`, polynomial arithmetic also wraps:

```text
f(x) = 7 + 3x + 2x^2 over F_17

f(4) = 7 + 12 + 32 = 51 = 0 mod 17
```

This is the arithmetic behind Shamir secret sharing and Reed-Solomon codes. Interpolation works because every nonzero denominator has an inverse in the field.

## Build It

This lesson builds a small prime-field toolkit: raw functions, an `Fp` value type, group helpers, and polynomial interpolation.

### Step 1: Check the modulus

For lesson-sized parameters, trial division is enough. Production systems use vetted prime-generation and primality-testing code.

```python
from math import isqrt


def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for d in range(3, isqrt(n) + 1, 2):
        if n % d == 0:
            return False
    return True
```

Every field operation calls `require_prime(p)` before trusting `p`.

### Step 2: Implement field operations

The arithmetic itself is short. The guardrails matter more than the formulas.

```python
def fp_add(a: int, b: int, p: int) -> int:
    require_prime(p)
    return (a + b) % p


def fp_mul(a: int, b: int, p: int) -> int:
    require_prime(p)
    return (a * b) % p
```

Division is multiplication by an inverse:

```python
def mod_inverse(a: int, p: int) -> int:
    require_prime(p)
    a %= p
    if a == 0:
        raise ValueError("zero has no multiplicative inverse")

    g, x, _ = egcd(a, p)
    if g != 1:
        raise ValueError("element is not invertible")
    return x % p
```

Negative exponents use the same inverse:

```python
def fp_pow(a: int, exponent: int, p: int) -> int:
    require_prime(p)
    if exponent < 0:
        return pow(mod_inverse(a, p), -exponent, p)
    return pow(a % p, exponent, p)
```

### Step 3: Carry the field with the value

Raw integers are easy to mix accidentally. A tiny value type prevents adding an element of `F_17` to an element of `F_19`.

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class Fp:
    value: int
    p: int

    def __post_init__(self) -> None:
        require_prime(self.p)
        object.__setattr__(self, "value", self.value % self.p)
```

Operations coerce plain integers into the same field and reject mismatched fields:

```python
def _coerce(self, other: int | Fp) -> Fp:
    if isinstance(other, Fp):
        if other.p != self.p:
            raise ValueError("cannot mix different prime fields")
        return other
    return Fp(other, self.p)
```

Now expressions read like algebra:

```python
a = Fp(29, 17)   # 12 in F_17
b = Fp(5, 17)

(a + b) * 4      # Fp(0, p=17)
a / b            # Fp(16, p=17)
```

### Step 4: Inspect the multiplicative group

The order of a nonzero element is the first positive `k` where `a^k = 1`.

```python
def multiplicative_order(a: int, p: int) -> int:
    require_prime(p)
    a %= p
    if a == 0:
        raise ValueError("zero has no multiplicative order")

    x = 1
    for k in range(1, p):
        x = (x * a) % p
        if x == 1:
            return k
```

An element is a generator when its order is `p - 1`.

```python
def generators(p: int) -> list[int]:
    require_prime(p)
    return [a for a in range(1, p) if multiplicative_order(a, p) == p - 1]
```

This brute-force version is fine for toy fields. Later phases use factorization of `p - 1` to test candidates efficiently.

### Step 5: Evaluate and interpolate polynomials

Horner's rule evaluates coefficients from highest degree to lowest:

```python
def poly_eval(coefficients, x: int, p: int) -> int:
    require_prime(p)
    result = 0
    for coefficient in reversed(list(coefficients)):
        result = (result * x + coefficient) % p
    return result
```

Lagrange interpolation reconstructs the unique degree `< n` polynomial through `n` points. To evaluate that polynomial at `x`:

```text
              x - x_j
f(x) = sum y_i * product -------
              x_i - x_j
```

Every denominator is nonzero when the `x_i` values are distinct, so every denominator is invertible in `F_p`.

```python
def lagrange_interpolate_at(points, x: int, p: int) -> int:
    require_prime(p)
    pts = [(px % p, py % p) for px, py in points]
    xs = [px for px, _ in pts]
    if len(set(xs)) != len(xs):
        raise ValueError("x coordinates must be distinct")

    total = 0
    for i, (xi, yi) in enumerate(pts):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(pts):
            if i == j:
                continue
            numerator = (numerator * (x - xj)) % p
            denominator = (denominator * (xi - xj)) % p
        total = (total + yi * numerator * mod_inverse(denominator, p)) % p

    return total
```

This is the core arithmetic in Shamir secret sharing:

```text
secret = f(0)
shares = (x_i, f(x_i))
recover secret by interpolating at x = 0
```

Run it:

```
python3 code/main.py
```

## Use It

Real crypto libraries do not expose "just an int mod p" as a casual integer. They encode the modulus and field rules into the type.

- `galois.GF(p)` creates a Python array type whose operations happen in `GF(p)`.
- `arkworks` and `halo2` use Rust field traits such as `PrimeField` for scalar fields in curves and proof systems.
- `py_ecc` carries curve and field parameters for Ethereum-related curves.
- `libsecp256k1` and `blst` use specialized constant-time field implementations for their fixed primes.

The lesson implementation is for learning. For real keys, signatures, proofs, commitments, or shares, use audited field arithmetic from the protocol's library.

## Attack It

The classic mistake is accepting a composite modulus and calling it a field.

Suppose a toy sharing scheme uses interpolation modulo `15`. Two different share x-coordinates can create a denominator that is nonzero but not invertible:

```text
x_1 = 1
x_2 = 6
x_1 - x_2 = -5 = 10 mod 15
gcd(10, 15) = 5
```

There is no `10^-1 mod 15`. Reconstruction either crashes, returns nonsense, or takes a dangerous shortcut such as "inverse failure means zero." That shortcut silently changes the polynomial and can leak or corrupt the secret.

The same issue appears anywhere a formula divides: elliptic-curve slopes, signature equations, barycentric interpolation, and polynomial commitments. If the modulus is not prime, you are not in `GF(p)`.

## Ship It

This lesson ships a short review checklist for prime-field code:

```text
outputs/skill-prime-field-review.md
```

Use it before implementing ECC scalar arithmetic, Reed-Solomon encoders, Shamir sharing, or ZK finite-field gadgets.

## Exercises

1. **Easy.** In `F_11`, compute `7 + 9`, `7 * 9`, `7^-1`, and `7 / 9`.
2. **Medium.** Find all generators of `F_11^*` and verify each has order `10`.
3. **Hard.** Implement `batch_inverse(values, p)` using one inversion and many multiplications. Reject zero inputs.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| `GF(p)` | "Numbers mod p" | The finite field with `p` elements, valid when `p` is prime |
| Characteristic | "The modulus" | The smallest positive count of `1 + 1 + ... + 1` that equals zero |
| Field element | "A wrapped integer" | A residue class with arithmetic defined by the field |
| Inverse | "Division helper" | A value `a^-1` where `a * a^-1 = 1` |
| Zero divisor | "Weird composite case" | Nonzero `a` where some nonzero `b` gives `ab = 0` |
| Multiplicative group | "Nonzero field values" | `F_p^*`, the group of all nonzero elements under multiplication |
| Generator | "Primitive root" | An element whose powers enumerate every nonzero field element |
| Order | "Cycle length" | The smallest positive `k` where `a^k = 1` |
| Lagrange interpolation | "Recover the polynomial" | Formula for reconstructing a polynomial from field-valued points |

## Test Vectors

Source: project-internal finite-field examples derived from standard arithmetic in `F_p`. References: Victor Shoup, *A Computational Introduction to Number Theory and Algebra*, Chapter 7, and Handbook of Applied Cryptography, Chapter 2.

Run:

```bash
python phases/02-abstract-algebra/07-finite-fields-gf-p/tests/test_vectors.py
```

## Further Reading

- [A Computational Introduction to Number Theory and Algebra](https://shoup.net/ntb/) — finite fields, multiplicative groups, and algorithms.
- [Handbook of Applied Cryptography, Chapter 2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf) — mathematical background for finite fields in applied cryptography.
- [galois documentation](https://mhostetter.github.io/galois/latest/) — practical finite-field arrays in Python.
- [arkworks algebra](https://github.com/arkworks-rs/algebra) — Rust traits and implementations for prime and extension fields.
