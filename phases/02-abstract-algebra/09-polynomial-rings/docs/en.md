# Polynomial Rings — Add, Mul, Mod, Division

> Polynomial arithmetic is modular arithmetic with `x` allowed to move.

**Type:** Build
**Languages:** Python
**Prerequisites:** 02-abstract-algebra/05-rings-ideals-quotients, 02-abstract-algebra/06-fields-and-extensions, 02-abstract-algebra/07-finite-fields-gf-p, 02-abstract-algebra/08-finite-fields-gf-2n
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

You have already seen two versions of "reduce after every operation": integers modulo `n`, and binary polynomials modulo an irreducible polynomial for `GF(2^n)`. The next cryptographic objects need the general version: polynomials with coefficients in a finite field.

Reed-Solomon codes evaluate polynomials over `F_p`. Shamir secret sharing reconstructs secrets with polynomial interpolation. KZG commitments commit to a polynomial and later prove evaluations. NTTs multiply large polynomials by evaluating them at roots of unity. Lattice schemes such as Kyber and Dilithium work inside quotient rings like `Z_q[x]/(x^n + 1)`.

If polynomial division feels like a black box, these systems become a pile of recipes. If you can add, multiply, divide, and reduce polynomials over `F_p`, then quotient rings stop being mysterious. They become the same move as integer modular arithmetic:

```text
integer world:      29 mod 5
polynomial world:   (x^3 + 2x + 1) mod (x^2 + x + 4) over F_5
```

## The Concept

A polynomial over `F_p` is a finite list of coefficients:

```text
[1, 2, 0, 1] over F_5  =  1 + 2x + 0x^2 + x^3
                         =  x^3 + 2x + 1
```

This lesson uses low-to-high coefficient order because it makes multiplication natural:

```text
index:        0   1   2   3
coefficient:  1   2   0   1
term:         1  2x  0x^2 x^3
```

Every coefficient is reduced modulo `p`. Over `F_5`, the coefficient `-1` is stored as `4`, and `6` is stored as `1`.

### Addition

Add coefficients at matching powers:

```text
  (x^3 + 2x + 1)
+ (x^2 + x + 4)
----------------
   x^3 + x^2 + 3x        over F_5
```

In list form:

```text
[1, 2, 0, 1] + [4, 1, 1] = [0, 3, 1, 1]
```

The constant term is `1 + 4 = 0 mod 5`.

### Multiplication

Multiply every term in the left polynomial by every term in the right polynomial, then collect equal powers:

```text
(a_0 + a_1x + a_2x^2)(b_0 + b_1x)

constant: a_0 b_0
x:        a_0 b_1 + a_1 b_0
x^2:      a_1 b_1 + a_2 b_0
x^3:      a_2 b_1
```

Each bucket is reduced modulo `p`.

### Division

Polynomial long division works because the leading coefficient of a nonzero polynomial over a field has an inverse.

To divide:

```text
f(x) = x^3 + 2x + 1
g(x) = x^2 + x + 4
```

over `F_5`, cancel the leading `x^3` term by subtracting `x * g(x)`. Continue until the remainder has smaller degree than `g`.

```text
f = qg + r
q = x + 4
r = 4x
```

So:

```text
poly_divmod([1, 2, 0, 1], [4, 1, 1], 5)
# quotient [4, 1], remainder [0, 4]
```

### Quotient rings

Reduction by a modulus polynomial turns arbitrary polynomials into fixed-size representatives:

```text
F_p[x] / (m(x))
```

Every element is represented by a polynomial with degree `< deg(m)`.

For example, in:

```text
F_5[x] / (x^2 + 2)
```

every element looks like:

```text
a + bx
```

because any `x^2` term can be replaced by `-2 = 3 mod 5`.

```text
x^2 + 2 = 0
x^2 = -2 = 3
```

### Division inside a quotient

In `F_p[x]/(m(x))`, an element `a(x)` is invertible exactly when:

```text
gcd(a(x), m(x)) = 1
```

Extended Euclid finds:

```text
s(x)a(x) + t(x)m(x) = 1
```

Reducing modulo `m(x)` leaves:

```text
s(x)a(x) = 1
```

So `s(x)` is the inverse of `a(x)`.

If `m(x)` is irreducible, every nonzero representative has an inverse and the quotient is a field. If `m(x)` is reducible, the quotient is only a ring, and some nonzero elements are zero divisors.

## Build It

This lesson builds:

- normalized polynomial representation over `F_p`
- addition, subtraction, negation, scaling, multiplication
- long division with quotient and remainder
- gcd and extended gcd
- quotient-ring arithmetic modulo a polynomial
- a `Poly` wrapper and a `PolyMod` wrapper

### Step 1: Normalize coefficients

Keep exactly one spelling for each polynomial:

```python
def normalize(coefficients: Iterable[int], p: int) -> list[int]:
    require_prime(p)
    result = [c % p for c in coefficients]
    while len(result) > 1 and result[-1] == 0:
        result.pop()
    return result or [0]
```

The zero polynomial is always `[0]`. Trailing zero coefficients are removed:

```python
normalize([6, -1, 0, 10], 5)
# [1, 4]
```

### Step 2: Add and subtract

Addition pads the shorter polynomial with zeros, adds matching coefficients, and normalizes:

```python
def poly_add(a, b, p):
    left = normalize(a, p)
    right = normalize(b, p)
    length = max(len(left), len(right))
    result = (
        (left[i] if i < len(left) else 0) + (right[i] if i < len(right) else 0)
        for i in range(length)
    )
    return normalize(result, p)
```

Subtraction is addition with negated coefficients:

```python
def poly_neg(a, p):
    return normalize((-c for c in normalize(a, p)), p)


def poly_sub(a, b, p):
    return poly_add(a, poly_neg(b, p), p)
```

### Step 3: Multiply

Polynomial multiplication is coefficient convolution:

```python
def poly_mul(a, b, p):
    left = normalize(a, p)
    right = normalize(b, p)
    if left == [0] or right == [0]:
        return [0]

    result = [0] * (len(left) + len(right) - 1)
    for i, ac in enumerate(left):
        for j, bc in enumerate(right):
            result[i + j] = (result[i + j] + ac * bc) % p
    return normalize(result, p)
```

This is the direct `O(n^2)` version. Later NTT and FFT lessons replace this with faster algorithms.

### Step 4: Divide

Long division cancels the leading term of the remainder until the remainder is smaller than the divisor:

```python
def poly_divmod(dividend, divisor, p):
    remainder = normalize(dividend, p)
    divisor_poly = require_nonzero_poly(divisor, p)
    quotient = [0] * max(1, len(remainder) - len(divisor_poly) + 1)
    divisor_lead_inv = mod_inverse(divisor_poly[-1], p)

    while remainder != [0] and len(remainder) >= len(divisor_poly):
        shift = len(remainder) - len(divisor_poly)
        factor = (remainder[-1] * divisor_lead_inv) % p
        quotient[shift] = factor
        subtractor = [0] * shift + [(factor * c) % p for c in divisor_poly]
        remainder = poly_sub(remainder, subtractor, p)

    return normalize(quotient, p), remainder
```

The invariant is:

```text
dividend = quotient * divisor + remainder
```

with:

```text
degree(remainder) < degree(divisor)
```

### Step 5: Reduce modulo a polynomial

Reduction keeps only the remainder:

```python
def poly_mod(poly, modulus, p):
    return poly_divmod(poly, modulus, p)[1]
```

That one line is the polynomial version of integer `%`.

### Step 6: Use Euclid for gcd and inverses

The Euclidean algorithm works in `F_p[x]`:

```python
def poly_gcd(a, b, p):
    left = normalize(a, p)
    right = normalize(b, p)
    while right != [0]:
        left, right = right, poly_mod(left, right, p)
    return [0] if left == [0] else poly_monic(left, p)
```

The gcd is made monic so it has a stable representation. Over `F_5`, `x + 3` and `2x + 1` generate the same ideal after scaling by a unit, but monic gcds are easier to compare.

Extended Euclid carries Bezout coefficients:

```text
gcd(a, b) = s*a + t*b
```

Those coefficients power division in quotient rings.

### Step 7: Work in `F_p[x]/(m)`

Quotient multiplication is multiply then reduce:

```python
def quotient_mul(a, b, modulus, p):
    return poly_mod(poly_mul(a, b, p), modulus, p)
```

Quotient inversion uses extended gcd:

```python
def quotient_inverse(a, modulus, p):
    value = poly_mod(a, modulus, p)
    if value == [0]:
        raise ValueError("zero has no multiplicative inverse")

    gcd, x, _ = poly_extended_gcd(value, modulus, p)
    if gcd != [1]:
        raise ValueError("element is not invertible with this modulus")
    return poly_mod(x, modulus, p)
```

Example:

```python
quotient_inverse([2, 1], [2, 0, 1], 5)
# [2, 4]
```

That means `x + 2` has inverse `4x + 2` in `F_5[x]/(x^2 + 2)`.

### Step 8: Carry parameters with values

`Poly` carries the coefficient field. `PolyMod` carries both the coefficient field and the modulus polynomial:

```python
a = PolyMod([3, 4], [2, 0, 1], 5)
b = PolyMod([2, 1], [2, 0, 1], 5)

a * b
# PolyMod([3, 1], modulus=[2, 0, 1], p=5)
```

The wrapper rejects arithmetic between different quotient rings. This is a small habit with a large payoff: accidentally mixing polynomial moduli silently breaks crypto code.

## Use It

SymPy has polynomial arithmetic over finite fields:

```python
from sympy import Poly, symbols

x = symbols("x")
f = Poly(x**3 + 2*x + 1, x, modulus=5)
g = Poly(x**2 + x + 4, x, modulus=5)

q, r = divmod(f, g)
```

SymPy is built for symbolic algebra, factoring, resultants, Groebner bases, and exact manipulation. The lesson code is built for learning the arithmetic surface:

| Task | This lesson | SymPy |
|------|-------------|-------|
| Representation | low-to-high lists | symbolic expressions |
| Coefficient field | prime fields `F_p` | many exact domains |
| Division | explicit long division | library `divmod` |
| Quotients | small educational wrapper | use residues or algebra systems |
| Crypto safety | not production-safe | still not a crypto implementation |

For production cryptography, use a vetted implementation from the protocol ecosystem. For algebra experiments, SymPy or SageMath are better tools than hand-written course code.

## Attack It

The common mistake is treating every polynomial modulus like it creates a field.

Take:

```text
F_5[x] / (x^2)
```

The element `x` is nonzero, but:

```text
x * x = x^2 = 0 mod x^2
```

So `x` is a nonzero zero divisor. It has no inverse. Any protocol step that assumes division by arbitrary nonzero elements now has a trapdoor-shaped bug.

The lesson code can find this witness:

```python
zero_divisor_pair([0, 0, 1], 5)
# ([0, 1], [0, 1])
```

This is the same warning from binary fields, now in general form:

```text
irreducible modulus   -> quotient is a field
reducible modulus     -> quotient may contain zero divisors
```

## Ship It

This lesson ships `outputs/skill-polynomial-ring-review.md`, a checklist for reviewing polynomial arithmetic in cryptographic code.

Use it when reading code for KZG, Reed-Solomon, NTTs, or lattice-style quotient rings.

## Exercises

1. Change the examples from `F_5` to `F_7`, then recompute `poly_divmod([1, 2, 0, 1], [4, 1, 1], 7)`.
2. Add `poly_derivative(coefficients, p)` and test that repeated roots can make `gcd(f, f')` nontrivial.
3. Write a small `is_irreducible(poly, p)` by trying all monic divisors up to half the degree, then compare `F_5[x]/(x^2 + 2)` with `F_5[x]/(x^2)`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Coefficient field | The numbers inside the polynomial | The field, here `F_p`, where coefficients are added, multiplied, and inverted |
| Degree | The list length | The highest power with a nonzero coefficient; zero has degree `-1` in this code |
| Monic polynomial | A polynomial with a nice shape | A polynomial whose leading coefficient is `1` |
| Remainder | Whatever is left after division | The unique polynomial with degree smaller than the divisor in `f = qg + r` |
| Quotient ring | Polynomial modulo another polynomial | The ring `F_p[x]/(m)` whose elements are residue classes represented by degree `< deg(m)` polynomials |
| Zero divisor | A weird zero-like value | A nonzero element `a` with a nonzero `b` such that `ab = 0` |

## Test Vectors

Source: project-internal examples for arithmetic in `F_p[x]`, checked against standard polynomial long-division identities. The zero-divisor example uses `F_5[x]/(x^2)` to expose a reducible modulus.

Run:

```bash
python3 phases/02-abstract-algebra/09-polynomial-rings/tests/test_vectors.py
```

## Further Reading

- [SymPy polynomial manipulation](https://docs.sympy.org/latest/modules/polys/reference.html) — practical symbolic polynomial APIs.
- [SageMath polynomial rings](https://doc.sagemath.org/html/en/tutorial/tour_polynomial.html) — a richer computer-algebra environment for quotient rings and finite fields.
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM uses polynomial quotient rings in production cryptography.
