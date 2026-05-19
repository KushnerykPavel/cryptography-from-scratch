# Irreducible Polynomials & Field Construction

> A quotient becomes a field only when the modulus refuses to factor.

**Type:** Build
**Languages:** Python
**Prerequisites:** 02-abstract-algebra/06-fields-and-extensions, 02-abstract-algebra/08-finite-fields-gf-2n, 02-abstract-algebra/09-polynomial-rings
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain Rabin's irreducibility criterion and how it combines Frobenius power checks with gcd conditions to certify an irreducible polynomial
- Apply root testing to detect reducibility in quadratic and cubic polynomials over `F_p`, and explain why root absence is insufficient for higher degrees
- Implement `poly_pow_mod` to compute `x^(p^k) mod f(x)` efficiently using square-and-multiply on polynomials
- Identify a reducible-modulus witness by factoring a polynomial and constructing two nonzero elements whose product is zero in the quotient
- Distinguish the `ExtensionField` wrapper's validation step from unchecked quotient arithmetic and explain why the irreducibility check is the field-construction gate

## The Problem

The previous lesson built `F_p[x]/(m(x))`, but it left the most important question open: which `m(x)` are safe to use when you want a field?

This matters everywhere finite fields appear. AES chooses an irreducible binary polynomial. Reed-Solomon codes choose fields where every nonzero element can be divided by. Pairing-friendly curves and ZK systems live inside towers of extension fields built from irreducible polynomials. If the modulus factors, nonzero elements can multiply to zero, and division fails exactly when later code assumes it cannot.

The mistake is subtle because a reducible quotient still looks like it has the right number of representatives:

```text
F_5[x]/(x^2 + 4) has 25 representatives
F_5[x]/(x^2 + 2) has 25 representatives
```

Only the second one is a field. This lesson builds the checks and wrappers that make that difference explicit.

## The Concept

An irreducible polynomial over `F_p` is the polynomial version of a prime number. It cannot be split into lower-degree factors over the same coefficient field.

```text
integer world:       15 = 3 * 5          reducible
integer world:       17                  prime

polynomial world:    x^2 + 4 = (x+1)(x+4) over F_5
polynomial world:    x^2 + 2             irreducible over F_5
```

The field-construction rule is:

```text
F_p[x] / (m(x)) is a field  <=>  m(x) is irreducible over F_p
```

If `m(x)` factors as `a(x)b(x)`, then inside the quotient:

```text
a(x)b(x) = m(x) = 0
```

Both factors can be nonzero, but their product is zero. That is a zero divisor, and fields cannot have zero divisors.

### Roots are a good first test

If a polynomial has a root `r` in `F_p`, then `(x-r)` is a factor.

For quadratics and cubics, this is enough:

```text
degree 2 or 3 polynomial over F_p is reducible
<=> it has a root in F_p
```

Example over `F_5`:

```text
x^2 + 4 has roots 1 and 4
x^2 + 4 = (x + 1)(x + 4)
```

But roots are not enough for higher degree. A quartic can factor as two quadratics and have no linear root. To build fields reliably, you need a real irreducibility test.

### Frobenius is the field fingerprint

In a finite field with `p^n` elements, every element satisfies:

```text
a^(p^n) = a
```

For a polynomial modulus `f(x)` of degree `n`, test what happens to the symbol `x` in the quotient:

```text
x^(p^n) - x mod f(x)
```

If `f` is irreducible, that expression is `0`. But that alone is not enough: `f` could be a product of irreducibles whose degrees divide `n`. Rabin's irreducibility criterion adds gcd checks for every prime divisor `q` of `n`:

```text
gcd(x^(p^(n/q)) - x, f(x)) = 1
```

Together:

```text
1. For every prime q | n, gcd(x^(p^(n/q)) - x, f) = 1
2. x^(p^n) - x = 0 mod f
```

If both hold, `f` is irreducible.

### Construction pattern

Once an irreducible modulus is found, extension-field arithmetic is just quotient arithmetic with a stronger constructor:

```text
choose irreducible m(x) of degree n
represent values as polynomials of degree < n
add/multiply as polynomials over F_p
reduce modulo m(x)
invert with extended Euclid
```

The wrapper in this lesson refuses reducible moduli, so `ExtensionField([1], [4, 0, 1], 5)` fails because `x^2 + 4` factors over `F_5`.

## Build It

This lesson builds:

- root checks over `F_p`
- Rabin irreducibility testing
- irreducible-polynomial search
- factor witnesses for reducible moduli
- an `ExtensionField` wrapper that only accepts irreducible moduli

### Step 1: Reuse polynomial arithmetic

Keep the same low-to-high coefficient convention from the previous lesson:

```text
[2, 0, 1] over F_5 = x^2 + 2
```

The code includes normalization, addition, multiplication, long division, gcd, and extended gcd. Irreducibility sits on top of these operations.

### Step 2: Evaluate roots

A root test tries each element of `F_p`:

```python
def roots(poly: Iterable[int], p: int) -> list[int]:
    value = require_nonzero_poly(poly, p)
    return [x for x in range(p) if poly_eval(value, x, p) == 0]
```

For example:

```python
roots([4, 0, 1], 5)
# [1, 4]
```

So `x^2 + 4` is reducible over `F_5`.

### Step 3: Raise `x` modulo `f`

Rabin's test needs powers like `x^(p^k) mod f(x)`. Use repeated squaring:

```python
def poly_pow_mod(base, exponent, modulus, p):
    if exponent < 0:
        raise ValueError("exponent must be nonnegative")

    modulus_poly = require_nonzero_poly(modulus, p)
    result = [1]
    power = poly_mod(base, modulus_poly, p)
    while exponent:
        if exponent & 1:
            result = poly_mod(poly_mul(result, power, p), modulus_poly, p)
        power = poly_mod(poly_mul(power, power, p), modulus_poly, p)
        exponent >>= 1
    return result
```

The base `[0, 1]` is `x`.

### Step 4: Test irreducibility

Make the polynomial monic, handle degree `1`, then apply Rabin's criterion:

```python
def is_irreducible(poly: Iterable[int], p: int) -> bool:
    f = poly_monic(poly, p)
    degree = len(f) - 1
    if degree <= 0:
        return False
    if degree == 1:
        return True

    x_poly = [0, 1]
    for q in prime_factors(degree):
        frobenius = poly_pow_mod(x_poly, p ** (degree // q), f, p)
        if poly_gcd(poly_sub(frobenius, x_poly, p), f, p) != [1]:
            return False

    final = poly_pow_mod(x_poly, p**degree, f, p)
    return poly_sub(final, x_poly, p) == [0]
```

Examples:

```python
is_irreducible([2, 0, 1], 5)     # x^2 + 2
# True

is_irreducible([4, 0, 1], 5)     # x^2 + 4
# False
```

### Step 5: Find a modulus

Search monic polynomials of the target degree until one passes:

```python
def find_irreducible(degree: int, p: int) -> list[int]:
    require_prime(p)
    if degree < 1:
        raise ValueError("degree must be positive")

    for candidate in monic_polynomials(degree, p):
        if degree > 1 and candidate[0] == 0:
            continue
        if is_irreducible(candidate, p):
            return candidate
    raise ValueError("no irreducible polynomial found")
```

This direct search is fine for tiny educational fields. Real systems use published parameters or stronger generation procedures with more careful validation.

### Step 6: Produce a reducible witness

When a modulus fails, do not merely return `False`. Find a factor pair:

```python
def reducible_witness(poly, p):
    f = poly_monic(poly, p)
    factor = find_nontrivial_factor(f, p)
    if factor is None:
        return None
    cofactor, _ = poly_divmod(f, factor, p)
    return factor, poly_monic(cofactor, p)
```

For `x^2 + 4` over `F_5`:

```python
reducible_witness([4, 0, 1], 5)
# ([1, 1], [4, 1])
```

That means:

```text
(x + 1)(x + 4) = x^2 + 4
```

In the quotient by `x^2 + 4`, both factors are nonzero but their product is zero.

### Step 7: Construct the field wrapper

The wrapper accepts only irreducible moduli:

```python
class ExtensionField:
    def __init__(self, value, modulus, p):
        modulus_poly = poly_monic(modulus, p)
        if not is_irreducible(modulus_poly, p):
            raise ValueError("modulus polynomial must be irreducible")
        self.p = p
        self.modulus = tuple(modulus_poly)
        self.value = tuple(poly_mod(value, modulus_poly, p))
```

Then operations delegate to quotient arithmetic:

```python
a = ExtensionField([3, 4], [2, 0, 1], 5)
b = ExtensionField([2, 1], [2, 0, 1], 5)

a * b
# ExtensionField([3, 1], modulus=[2, 0, 1], p=5)

b.inverse()
# ExtensionField([2, 4], modulus=[2, 0, 1], p=5)
```

Run it:

```
python3 code/main.py
```

## Use It

SymPy can check irreducibility and factor polynomials over finite fields:

```python
from sympy import Poly, symbols

x = symbols("x")
f = Poly(x**2 + 2, x, modulus=5)

f.is_irreducible
# True
```

For richer finite-field construction, SageMath and the Python `galois` package provide higher-level APIs. The lesson code is smaller and more explicit:

| Task | This lesson | Library |
|------|-------------|---------|
| Representation | low-to-high coefficient lists | symbolic or array-backed field types |
| Irreducibility | Rabin criterion + tiny trial witnesses | optimized factoring and irreducibility algorithms |
| Field construction | educational `ExtensionField` wrapper | mature field classes |
| Parameter safety | rejects reducible moduli | broader validation and tested implementations |
| Crypto safety | not production-safe | still use protocol-vetted libraries |

For production cryptography, do not generate field parameters casually. Use standard parameters from the primitive or protocol specification.

## Attack It

The attack is choosing a modulus that looks field-shaped but factors.

Take:

```text
F_5[x] / (x^2 + 4)
```

Since:

```text
x^2 + 4 = (x + 1)(x + 4)
```

inside the quotient:

```text
(x + 1)(x + 4) = 0
```

Neither `x + 1` nor `x + 4` is zero as a representative. They are zero divisors. Any code that assumes every nonzero denominator has an inverse can now fail or leak structure.

The lesson code exposes this directly:

```python
field_report([4, 0, 1], 5)
# {
#   "irreducible": False,
#   "roots": [1, 4],
#   "reducible_witness": ([1, 1], [4, 1])
# }
```

This is why "degree `n` modulus" is not enough. Field construction needs irreducibility.

## Ship It

This lesson ships `outputs/skill-irreducible-field-review.md`, a checklist for reviewing extension-field parameters in cryptographic code.

Use it when you see code constructing `GF(p^n)`, binary fields, tower fields, pairing fields, or polynomial quotient rings that are meant to be fields.

## Exercises

1. Over `F_7`, test whether `x^2 + 1` is irreducible. Then compare its roots with `x^2 + 3`.
2. Write `all_irreducibles(degree, p)` and list every monic irreducible quadratic over `F_3`.
3. Find a reducible quartic over `F_5` with no roots in `F_5`, then use `factor_by_trial` to explain why root checks are insufficient.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Irreducible polynomial | A polynomial with no roots | A nonconstant polynomial that cannot be factored into lower-degree polynomials over the same field |
| Reducible polynomial | A bad modulus | A polynomial with a nontrivial factorization, which creates zero divisors in the quotient |
| Monic polynomial | A normalized polynomial | A polynomial whose leading coefficient is `1` |
| Frobenius map | Raising to `p` | The map `a -> a^p`, central to finite-field structure |
| Rabin criterion | A fast trick | A finite-field irreducibility test using Frobenius powers and gcd checks |
| Extension field | Bigger field | A field such as `F_p[x]/(m)` where `m` is irreducible |
| Zero divisor | A value that acts partly like zero | A nonzero element `a` with a nonzero `b` such that `ab = 0` |

## Test Vectors

Source: project-internal examples for irreducibility in `F_p[x]`, checked against Rabin's irreducibility criterion and direct factor witnesses over small finite fields.

Run:

```bash
python3 phases/02-abstract-algebra/10-irreducible-polynomials/tests/test_vectors.py
```

## Further Reading

- [SymPy finite fields and polynomials](https://docs.sympy.org/latest/modules/polys/domainsref.html) - practical APIs for polynomial domains over finite fields.
- [SageMath finite fields](https://doc.sagemath.org/html/en/constructions/finite_fields.html) - field construction with irreducible moduli and generators.
- [Victor Shoup, A Computational Introduction to Number Theory and Algebra](https://shoup.net/ntb/) - finite fields and polynomial arithmetic in a cryptography-friendly algebra text.
