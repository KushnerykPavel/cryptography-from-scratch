# Fields and Field Extensions

> A field is where division is legal; an extension field is where you add just enough new numbers to make new equations solvable.

**Type:** Learn
**Languages:** Python
**Prerequisites:** 01-number-theory/03-modular-inverse-and-fast-exp, 02-abstract-algebra/05-rings-ideals-quotients
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why `Z/pZ` is a field exactly when `p` is prime and why composite moduli produce zero divisors that prevent division
- Compute addition, multiplication, and inverses in a quadratic extension field `F_p[u]/(u^2 - beta)` using the norm-based inversion formula
- Apply the Legendre symbol to determine whether a given `beta` makes `u^2 - beta` irreducible, and hence whether the quotient is a field
- Identify zero divisors in a reducible quadratic extension by constructing a pair of nonzero elements whose product is zero
- Distinguish prime fields from extension fields and describe how tower constructions like `F_p -> F_p^2 -> F_p^6 -> F_p^12` are used in pairing-based cryptography

## The Problem

The previous lesson gave you quotient rings. That is the broad construction behind modular integers, polynomial remainders, AES bytes, NTT rings, and pairing fields. But cryptography often needs a stronger promise than "this is a ring." It needs division.

ECDSA divides by a nonce. SNARK arithmetic divides by nonzero field elements while building polynomials. Pairing-friendly curves work over towers such as `F_p^2`, `F_p^6`, and `F_p^12`. Reed-Solomon codes evaluate polynomials over finite fields. If the algebraic object has zero divisors, those divisions are not merely inconvenient; they are undefined.

Field extensions explain how cryptography safely creates new fields from old ones. You start with a base field `F`, pick an irreducible polynomial `f(x)`, and form `F[x] / (f(x))`. If `f` is irreducible, the quotient is a field. If `f` is reducible, the same-looking construction has zero divisors. That single test is the line between clean algebra and broken assumptions.

## The Concept

A **field** is a commutative ring with `0 != 1` where every nonzero element has a multiplicative inverse.

```text
Field checklist

addition:        abelian group
multiplication:  associative, commutative, identity 1
distributivity:  a(b + c) = ab + ac
division:        every a != 0 has a^-1
```

The familiar examples:

```text
Q, R, C          infinite fields
F_p = Z/pZ       finite field when p is prime
Z/nZ             field only when n is prime
```

### Why composite moduli fail

In `Z/6Z`, the nonzero elements `2` and `3` multiply to zero:

```text
2 * 3 = 6 = 0 mod 6
```

So neither `2` nor `3` can have a multiplicative inverse. If `2` had an inverse, multiplying both sides by it would turn `2 * 3 = 0` into `3 = 0`, which is false.

That is why `Z/pZ` is a field exactly when `p` is prime:

```text
p prime        every 1 <= a < p is coprime to p      -> inverse exists
n composite    some 1 <= a < n shares a factor with n -> zero divisor exists
```

### Extension fields

Sometimes the base field is too small. Over `F_5`, the equation

```text
x^2 = 2
```

has no solution because the squares are:

```text
0^2 = 0
1^2 = 1
2^2 = 4
3^2 = 4
4^2 = 1
```

So we adjoin a new symbol `u` with the rule `u^2 = 2`. Elements now look like:

```text
a + b u    where a, b in F_5
```

Addition is component-wise:

```text
(a + b u) + (c + d u) = (a + c) + (b + d)u
```

Multiplication uses `u^2 = beta`:

```text
(a + b u)(c + d u)
  = ac + adu + bcu + bd u^2
  = (ac + beta bd) + (ad + bc)u
```

For `beta = 2` in `F_5`, this gives a field with `5^2 = 25` elements:

```text
F_5[u] / (u^2 - 2)
```

### Irreducibility is the field gate

The quotient `F[x] / (f(x))` is a field exactly when `f(x)` is irreducible over `F`.

For quadratic extensions over an odd prime field, the rule is especially simple:

```text
F_p[u] / (u^2 - beta) is a field
iff beta is not a square in F_p
```

In `F_5`, `2` is not a square, so `u^2 - 2` is irreducible. But `4` is a square because `2^2 = 4`, so:

```text
F_5[u] / (u^2 - 4)
```

is not a field. It has zero divisors:

```text
(1 + 2u)(1 + 3u)
  = 1 + 5u + 6u^2
  = 1 + 0u + 6*4
  = 25
  = 0 mod 5
```

Both factors are nonzero. The quotient ring is valid as a ring, but invalid as a field.

### Norm and inverse in a quadratic extension

In `F_p[u] / (u^2 - beta)`, conjugation flips the sign of `u`:

```text
conj(a + bu) = a - bu
```

The norm lands back in the base field:

```text
N(a + bu) = (a + bu)(a - bu) = a^2 - beta b^2
```

If the norm is nonzero, the inverse is:

```text
(a + bu)^-1 = (a - bu) / (a^2 - beta b^2)
```

That is the same trick as complex division, but over a finite field instead of the real numbers.

### Field towers

Large cryptographic fields are often built in layers:

```text
F_p
  |
  +-- F_p^2   = F_p[u] / (u^2 - beta)
        |
        +-- F_p^6
              |
              +-- F_p^12
```

Pairing libraries use tower representations because arithmetic in a tower is faster and clearer than treating every element as a huge flat polynomial.

## Build It

This lesson builds a small field inspector and a quadratic extension arithmetic toolkit.

### Step 1: Prime-field arithmetic

Start with modular operations and inverses. The inverse exists only when `gcd(a, n) = 1`.

```python
def inv_mod(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    g, x, _ = egcd(a % n, n)
    if g != 1:
        raise ValueError("element is not invertible modulo n")
    return x % n
```

Then `F_p` is just `Z/pZ` with `p` checked for primality:

```python
def prime_field_elements(p: int) -> list[int]:
    if not is_prime(p):
        raise ValueError("p must be prime")
    return residues_mod(p)
```

### Step 2: Check the field axiom

Reuse the finite ring checks from lesson 05, then add the one extra field condition: every nonzero element must invert.

```python
def is_field(elements, add, mul):
    if not is_commutative_ring(elements, add, mul):
        return False

    zero = additive_identity(elements, add)
    one = multiplicative_identity(elements, mul)
    if one is None or one == zero:
        return False

    return all(
        inverse_of(element, elements, mul) is not None
        for element in elements
        if element != zero
    )
```

On toy rings this exhaustive check is useful:

```text
Z/5Z -> field
Z/6Z -> not a field, because 2 * 3 = 0
```

### Step 3: Represent extension elements

Represent `a + bu` as a pair `(a, b)`.

```python
Fp2 = tuple[int, int]


def fp2_elements(p: int) -> list[Fp2]:
    if not is_prime(p):
        raise ValueError("p must be prime")
    return [(a, b) for a in range(p) for b in range(p)]
```

This is the whole set of `p^2` possible coefficients.

### Step 4: Add and multiply with `u^2 = beta`

Addition is component-wise. Multiplication reduces every `u^2` to `beta`.

```python
def fp2_add(x: Fp2, y: Fp2, p: int) -> Fp2:
    return ((x[0] + y[0]) % p, (x[1] + y[1]) % p)


def fp2_mul(x: Fp2, y: Fp2, p: int, beta: int) -> Fp2:
    a, b = x
    c, d = y
    return ((a * c + beta * b * d) % p, (a * d + b * c) % p)
```

For `F_5[u] / (u^2 - 2)`:

```text
(3 + 4u)(1 + 2u)
  = (3*1 + 2*4*2) + (3*2 + 4*1)u
  = 19 + 10u
  = 4 + 0u
```

### Step 5: Invert with the norm

The norm decides whether an element is a unit.

```python
def fp2_norm(x: Fp2, p: int, beta: int) -> int:
    a, b = x
    return (a * a - beta * b * b) % p


def fp2_inv(x: Fp2, p: int, beta: int) -> Fp2:
    if x == (0, 0):
        raise ValueError("zero has no multiplicative inverse")
    denom = fp2_norm(x, p, beta)
    if denom == 0:
        raise ValueError("element is a zero divisor, not a unit")
    scale = inv_mod(denom, p)
    conj = fp2_conjugate(x, p)
    return ((conj[0] * scale) % p, (conj[1] * scale) % p)
```

For `x = 3 + 4u` in `F_5[u] / (u^2 - 2)`:

```text
N(x) = 3^2 - 2*4^2 = 2 mod 5
2^-1 = 3 mod 5
conj(x) = 3 - 4u = 3 + u
x^-1 = 3(3 + u) = 4 + 3u
```

Check:

```text
(3 + 4u)(4 + 3u) = 1
```

### Step 6: Detect reducible choices

For odd prime `p`, `u^2 - beta` is irreducible when `beta` is a quadratic non-residue.

```python
def legendre_symbol(a: int, p: int) -> int:
    if not is_prime(p) or p == 2:
        raise ValueError("p must be an odd prime")
    value = pow(a % p, (p - 1) // 2, p)
    if value == p - 1:
        return -1
    return value


def fp2_is_field(p: int, beta: int) -> bool:
    if not is_prime(p) or p == 2:
        return False
    return legendre_symbol(beta, p) == -1
```

Use this before assuming extension arithmetic is field arithmetic.

Run it:

```
python3 code/main.py
```

## Use It

Real libraries encode field structure in types:

- `galois.GF(p)` builds prime fields and `galois.GF(p**m)` builds extension fields from irreducible polynomials.
- `arkworks` represents `Fp`, `Fp2`, `Fp6`, and `Fp12` fields with parameter types that include the modulus and non-residue choices.
- Pairing libraries such as `blst`, `mcl`, and `arkworks` use tower fields for BLS12-381 and BN254.
- Reed-Solomon implementations choose fields large enough to hold evaluation points and coefficients without collisions.

The library lesson is not "trust magic." It is: check which base field, which irreducible polynomial, which extension degree, and which representation the library chose.

## Attack It

This is a Learn lesson, but there is a sharp failure mode.

If a construction says "work in `F_p[u] / (u^2 - beta)`" and `beta` is actually a square, the object is not a field. Nonzero elements can multiply to zero. Inverses fail. Any protocol step that divides by a nonzero-looking element can break.

Concrete example:

```text
F_5[u] / (u^2 - 4)

(1 + 2u)(1 + 3u) = 0
```

Both factors are nonzero. This is not a rare edge case; it is exactly what reducibility means in a quotient.

The engineering habit is simple: never accept extension parameters without checking irreducibility or relying on a library type that already encodes a vetted choice.

## Ship It

This lesson ships a checklist for reviewing field and extension-field parameters:

```text
outputs/skill-field-extension-review.md
```

Use it before later lessons that introduce AES fields, Reed-Solomon fields, pairing fields, or ZK scalar fields.

## Exercises

1. **Easy.** List the nonzero elements of `Z/7Z` and compute their multiplicative inverses.
2. **Medium.** In `F_7[u] / (u^2 - 3)`, decide whether the quotient is a field. Then multiply `(2 + 5u)(4 + u)`.
3. **Hard.** Extend the code to cubic extensions `F_p[u] / (u^3 - beta)`. Find a small `p` and `beta` where the quotient has zero divisors.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| Field | "You can divide" | Commutative ring with `0 != 1` where every nonzero element is a unit |
| Prime field | "Integers mod p" | `F_p = Z/pZ` for prime `p` |
| Extension field | "Bigger field" | Field containing a smaller base field as a subfield |
| Degree | "How much bigger" | Dimension of the extension as a vector space over the base field |
| Algebraic element | "Root you adjoin" | New symbol satisfying a polynomial equation over the base field |
| Irreducible polynomial | "Cannot factor" | Nonconstant polynomial with no nontrivial factorization over the base field |
| Quadratic non-residue | "Not a square" | Element of `F_p` that is not `x^2` for any `x in F_p` |
| Norm | "Product with conjugate" | Base-field value used to test and compute inverses in extensions |
| Trace | "Sum of conjugates" | Base-field value that records the linear part of conjugate sums |
| Zero divisor | "Nonzero thing that kills" | Nonzero `a` where some nonzero `b` has `ab = 0` |

## Test Vectors

Source: project-internal finite-field examples. Prime-field checks use the standard theorem that `Z/pZ` is a field exactly when `p` is prime. Quadratic extension vectors use `F_p[u] / (u^2 - beta)`, with reducible and irreducible examples over `F_5`.

Run:

```bash
python phases/02-abstract-algebra/06-fields-and-extensions/tests/test_vectors.py
```

## Further Reading

- [A Computational Introduction to Number Theory and Algebra](https://shoup.net/ntb/) — finite fields and polynomial quotient constructions.
- [Handbook of Applied Cryptography, Chapter 2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf) — finite fields used in applied cryptography.
- [Pairing-Friendly Curves, IETF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves) — real field towers for pairing-based cryptography.
- [galois documentation](https://mhostetter.github.io/galois/latest/) — practical Python finite-field arithmetic.
