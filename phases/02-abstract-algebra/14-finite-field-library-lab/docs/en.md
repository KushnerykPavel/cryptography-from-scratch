# Algebra Lab — Build a Finite Field Library

> A protocol is only as correct as the field arithmetic it assumes.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 2 Lessons 7–10 (and Phase 1 modular arithmetic basics)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Package `GF(p)` and `GF(p^m)` arithmetic behind one coherent API.
- Make invalid states unrepresentable: no mixing fields, no division by zero, no reducible moduli.
- Reuse polynomial arithmetic to construct extension fields as quotient rings `F_p[x]/(f(x))`.
- Represent AES bytes as elements of `GF(2^8)` and reproduce standard multiplication/inversion examples.
- Cross-check small results against a real library (`galois`) without claiming production safety.

## The Problem

In this phase you built field arithmetic three different ways: prime fields `GF(p)`, binary fields `GF(2^n)`, and general extension fields from irreducible polynomials. That is the right learning progression, but it is a bad way to build later lessons. An elliptic-curve lesson should not copy-paste three versions of “inverse”. A polynomial-commitment lesson should not wonder which representation a “field element” uses today. An attack lesson should not quietly accept a modulus polynomial that is reducible and then fail halfway through interpolation.

This lab turns the ingredients into a single small library: predictable constructors, predictable failure behavior, and a single “field element” experience across `GF(p)` and `GF(p^m)`. The goal is not speed. The goal is correctness and guardrails.

The guardrails matter because field mistakes are *silent* until they become catastrophic. If you accidentally compute in `Z/15Z` instead of `GF(15)` (which doesn’t exist), division fails. If you build `F_p[x]/(f(x))` with a reducible `f(x)`, you get zero divisors and “inverses” stop existing. If you mix elements from two different fields, algebraic identities you rely on (like cancellation) are no longer meaningful.

## The Concept

### Two Families You Actually Use

Most cryptographic code uses:

1. Prime fields:

```text
GF(p) = {0, 1, ..., p-1}  with p prime
```

2. Extension fields built from polynomials:

```text
GF(p^m) ≅ F_p[x] / (f(x))   where f(x) is irreducible and deg(f) = m
```

An element of `GF(p^m)` is a polynomial of degree `< m` with coefficients in `F_p`, with multiplication reduced modulo `f(x)`.

### Guardrails as API Design

A “finite field library” is mostly an API problem:

- Values carry their field, so mixing fields is rejected.
- Constructors normalize representations (reduce mod `p`, reduce mod `f(x)`).
- Division is multiplication by inverse, and inverse raises on zero.
- Extension fields reject reducible modulus polynomials.

These are not “nice-to-have”. They prevent writing later lessons on top of undefined math.

## Build It

The implementation lives in `code/main.py`.

### Step 1: Define errors and prime checks

Field failures must be explicit. This lab uses typed exceptions (`FiniteFieldError`, `NoInverseError`, `NotIrreducibleError`) and a small `is_prime()` guard for lesson-sized primes.

### Step 2: Prime fields as a value type

Prime fields are the base case. The key ergonomic improvement is a `PrimeField(p)` object that *creates* elements and ensures everything stays in that field:

```python
F17 = PrimeField(17)
a = F17(29)      # reduces to 12 in F_17
b = F17(5)
(a + b) * 4
```

This prevents a common footgun: adding an element of `F_17` to an element of `F_19`.

### Step 3: Polynomials over `F_p`

Extension fields need polynomial arithmetic over `F_p`:

- normalize coefficients modulo `p`
- add/sub/mul
- divmod and remainder
- extended GCD for inverses

The same routines also drive the irreducibility check used at field construction time.

### Step 4: Extension fields as quotient rings

The constructor `PolyField(p, f)` represents:

```text
F_p[x] / (f(x))
```

It normalizes `f` to monic form and rejects it if it is not irreducible. Field elements are reduced modulo `f(x)` automatically.

### Step 5: AES bytes as `GF(2^8)`

AES defines:

```text
GF(2^8) = F_2[x] / (x^8 + x^4 + x^3 + x + 1)
```

Interpreting a byte as a polynomial is just treating the bits as coefficients:

```text
0x53 = 01010011 = x^6 + x^4 + x + 1
```

The helpers `aes_mul(a, b)` and `aes_inverse(byte)` reproduce the standard examples (and raise on `0` inverse).

## Use It

For real work you should prefer a vetted library. In Python, the `galois` package is a convenient reference implementation for experiments and for cross-checking:

```python
import galois

GF256 = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
assert int(GF256(0x57) * GF256(0x83)) == 0xC1
```

This course code is still educational and not side-channel safe. Treat `galois` as a correctness aid, not a hardened crypto primitive.

## Attack It

The textbook failure mode is building an “extension field” with a reducible modulus polynomial.

Example over `F_5`:

```text
f(x) = x^2 + 1
```

But `x^2 + 1` has roots in `F_5` (since `2^2 = 4 = -1 mod 5`), so it factors. The quotient `F_5[x]/(x^2+1)` is **not** a field: it contains nonzero zero divisors, and some nonzero elements have no inverse.

That breaks algorithms that assume division exists (interpolation, slope formulas on curves, NTT roots-of-unity logic). In this lab, the constructor rejects reducible moduli up front (`NotIrreducibleError`) so you cannot accidentally build that broken structure.

## Ship It

This lesson ships a review checklist for finite-field APIs:

- `outputs/skill-finite-field-library-api-review.md`

## Exercises

1. Easy: Add a helper `field_summary()` that returns `{p, degree, order, modulus_terms}` for `PrimeField` and `PolyField`.
2. Medium: Implement a `from_int()` / `to_int()` pair for `PolyField(p=2)` that round-trips bytes (with explicit degree checks).
3. Hard: Add a generator search for `GF(p)` and `GF(p^m)^*` on toy sizes and use it to find an element of large multiplicative order.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| irreducible polynomial | “a polynomial that has no roots” | cannot be factored into lower-degree polynomials over the base field |
| extension field | “a bigger field” | a field built as `F_p[x]/(f(x))` for irreducible `f(x)` |
| quotient ring | “mod out by a polynomial” | treat `f(x)=0` and reduce every polynomial modulo `f(x)` |
| zero divisor | “nonzero value that behaves like zero” | nonzero `a, b` with `a*b = 0`, which prevents division |

## Test Vectors

Vectors are project-internal arithmetic checks plus AES `GF(2^8)` examples from NIST FIPS 197. Code must pass `tests/vectors.json`.

## Further Reading

- NIST FIPS 197 — AES field definition and examples
- Victor Shoup, *A Computational Introduction to Number Theory and Algebra* — finite fields and polynomial constructions
- `galois` documentation — practical Python field arithmetic (for experiments, not production)
