# Legendre & Jacobi Symbols

> A square test can be cheap, but over composites it can also be a trap.

**Type:** Build
**Languages:** Python
**Prerequisites:** 03-modular-inverse-and-fast-exp, 04-fermat-and-euler, 07-quadratic-residues-tonelli-shanks
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

In the previous lesson, you learned how to compute modular square roots over a prime field. Before taking a square root, though, you need to know whether a root exists. Over an odd prime `p`, that question has a compact answer: the Legendre symbol `(a/p)`.

Composite moduli make the story more useful and more dangerous. In RSA-style settings, you often know `n = p*q` but not the factors. You still want a fast sign-like test that says something about whether `a` behaves like a square. The Jacobi symbol `(a/n)` gives that test without factoring `n`.

The catch is the entire lesson: Jacobi `+1` does not mean "square." Some values have Jacobi symbol `+1` and still have no square root modulo `n`. Those values, called pseudosquares here, are the core hardness behind the Quadratic Residuosity Problem and the Goldwasser-Micali cryptosystem.

## The Concept

### Legendre is the prime-field square sign

For an odd prime `p`, the Legendre symbol is:

```text
(1)  if a is a non-zero square modulo p
 0   if p divides a
-(1) if a is not a square modulo p
```

Euler's criterion computes it:

```text
(1): a^((p - 1)/2) ≡  1 (mod p)
-(1): a^((p - 1)/2) ≡ -1 (mod p)
 0 : a                  ≡  0 (mod p)
```

Example modulo `7`:

```text
Squares: 1^2 = 1, 2^2 = 4, 3^2 = 2, 4^2 = 2, 5^2 = 4, 6^2 = 1

Residues:     {1, 2, 4}
Non-residues: {3, 5, 6}

(2/7) = +1
(3/7) = -1
```

### Jacobi multiplies Legendre symbols

For odd positive `n` with prime factorization:

```text
n = p1^e1 * p2^e2 * ... * pk^ek
```

the Jacobi symbol is:

```text
(a/n) = (a/p1)^e1 * (a/p2)^e2 * ... * (a/pk)^ek
```

So for `35 = 5 * 7`:

```text
(3/35) = (3/5) * (3/7)
       =  -1   *  -1
       =  +1
```

That `+1` is only a parity-like product of prime-field answers. It does not prove that `3` has a square root modulo `35`.

### Reciprocity avoids factoring

The direct definition uses the factors of `n`, which defeats the point for RSA-style moduli. The efficient Jacobi algorithm is a cousin of Euclid's algorithm. It repeatedly uses:

```text
(2/n) = +1 if n ≡ 1 or 7 (mod 8)
(2/n) = -1 if n ≡ 3 or 5 (mod 8)
```

and quadratic reciprocity:

```text
(a/n) = -(n/a) if a ≡ 3 (mod 4) and n ≡ 3 (mod 4)
(a/n) =  (n/a) otherwise
```

Then it reduces the top modulo the bottom, just like the Euclidean algorithm.

```text
(a/n)
  remove factors of 2 from a
  maybe flip the sign
  swap a and n
  maybe flip the sign again
  reduce a modulo n
```

This is why Jacobi is fast even when `n` is a large composite whose factors are unknown.

### The meaning of each output

| Jacobi value | What it guarantees | What it does not guarantee |
|--------------|--------------------|----------------------------|
| `0` | `gcd(a, n) > 1` | That `a` is useless; it may reveal a factor |
| `-1` | `a` is not a square modulo `n` | Which prime factor rejects it |
| `+1` | The Legendre signs multiply to `+1` | That `a` is a square modulo `n` |

The last row is the sharp edge. For `n = 21`, the value `5` has Jacobi symbol `+1`, but no `x` satisfies:

```text
x^2 ≡ 5 (mod 21)
```

## Build It

### Step 1: Keep the basic number theory helpers

Use the same small helpers from earlier lessons: Euclid for `gcd`, a naive prime check for educational inputs, and square-and-multiply for modular exponentiation.

```python
def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b != 0:
        a, b = b, a % b
    return a
```

### Step 2: Implement Legendre with Euler's criterion

The raw exponentiation result is `1`, `0`, or `p - 1`. Convert `p - 1` into the mathematical value `-1`.

```python
def legendre_symbol(a: int, p: int) -> int:
    if not is_prime_naive(p) or p == 2:
        raise ValueError("p must be an odd prime")

    a %= p
    if a == 0:
        return 0

    value = mod_pow(a, (p - 1) // 2, p)
    if value == p - 1:
        return -1
    return value
```

### Step 3: Implement Jacobi without factoring

This is the useful version. It only requires that `n` is positive and odd.

```python
def jacobi_symbol(a: int, n: int) -> int:
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")

    a %= n
    result = 1

    while a != 0:
        while a % 2 == 0:
            a //= 2
            if n % 8 in (3, 5):
                result = -result

        a, n = n, a
        if a % 4 == 3 and n % 4 == 3:
            result = -result
        a %= n

    if n == 1:
        return result
    return 0
```

When the loop ends with `n != 1`, the original `a` and `n` were not coprime, so the symbol is `0`.

### Step 4: Cross-check against the definition

For small `n`, factorization is fine. Use it to test that the reciprocity algorithm matches the definition.

```python
def jacobi_symbol_by_factorization(a: int, n: int) -> int:
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")

    remaining = n
    factor = 3
    result = 1

    if remaining == 1:
        return 1

    while factor * factor <= remaining:
        exponent = 0
        while remaining % factor == 0:
            remaining //= factor
            exponent += 1

        if exponent:
            value = legendre_symbol(a, factor)
            if value == 0:
                return 0
            if exponent % 2 == 1:
                result *= value
        factor += 2

    if remaining > 1:
        value = legendre_symbol(a, remaining)
        if value == 0:
            return 0
        result *= value

    return result
```

### Step 5: Find pseudosquares

The Jacobi symbol gets interesting when it says `+1` but brute-force square enumeration says "no root."

```python
def find_pseudosquares(n: int, limit: int | None = None) -> list[int]:
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer")

    stop = n if limit is None else min(limit, n)
    values = []
    for a in range(1, stop):
        if gcd(a, n) != 1:
            continue
        if jacobi_symbol(a, n) == 1 and not is_quadratic_residue_bruteforce(a, n):
            values.append(a)
    return values
```

For `n = 21`, this returns:

```text
[5, 17, 20]
```

Those are exactly the values that look square-like to Jacobi but are not true quadratic residues.

### Step 6: Use Jacobi in Solovay-Strassen

If `n` is prime, Euler's criterion and the Jacobi symbol agree for every base `a` coprime to `n`:

```text
a^((n - 1)/2) ≡ (a/n) (mod n)
```

If they disagree, `n` is composite.

```python
def solovay_strassen_witness(a: int, n: int) -> bool:
    if n < 3 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than 2")

    a %= n
    if a in (0, 1):
        return False
    if gcd(a, n) != 1:
        return True

    jacobi = jacobi_symbol(a, n)
    euler = mod_pow(a, (n - 1) // 2, n)
    return euler != jacobi % n
```

This is a probabilistic primality test. One base can miss a composite; several independent bases reduce the error.

## Use It

Python's standard library has `pow(a, e, n)` for modular exponentiation, but it does not include Legendre or Jacobi symbols directly. In practical Python math work, use a maintained library rather than a hand-rolled implementation:

```python
from sympy.functions.combinatorial.numbers import jacobi_symbol
from sympy.ntheory.residue_ntheory import legendre_symbol

print(legendre_symbol(3, 7))
print(jacobi_symbol(3, 35))
```

For production cryptography, these routines usually live inside a larger protocol implementation. They must be paired with constant-time arithmetic and carefully specified input validation when secrets are involved.

## Attack It

The bug is treating Jacobi `+1` as "definitely a square."

Suppose a toy protocol says:

```text
accept a if jacobi_symbol(a, n) == 1
```

For `n = 21`, the value `5` passes:

```text
(5/21) = +1
```

But direct enumeration shows there is no square root:

```text
x^2 mod 21 produces {0, 1, 4, 7, 9, 15, 16, 18}
```

So an attacker can send `5` as a "square-looking" value that is not actually a square. This is not a failure of Jacobi; it is exactly what Jacobi means. The protocol was asking it the wrong question.

Goldwasser-Micali turns this distinction into a cryptosystem. Bit `0` is a true square modulo `n`; bit `1` is a non-square with Jacobi `+1`. Without the factorization of `n`, distinguishing those two cases is believed hard.

## Ship It

This lesson ships a checklist in:

```text
outputs/skill-legendre-jacobi-auditor.md
```

Use it when reviewing code that applies quadratic-residue tests, Solovay-Strassen, or RSA-style composite moduli.

## Exercises

1. Easy: list the non-zero quadratic residues modulo `11`, then compute `(a/11)` for every `a` from `1` to `10`.
2. Medium: trace the reciprocity-based Jacobi algorithm by hand for `(19/45)`.
3. Hard: find all values `a` modulo `35` with Jacobi `+1` that are not quadratic residues, then explain why checking Jacobi alone would be unsafe.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| Legendre symbol | "A square test" | A three-valued symbol `(a/p)` for an odd prime modulus `p` |
| Euler's criterion | "Raise to half the group order" | The theorem computing `(a/p)` as `a^((p - 1)/2) mod p` |
| Jacobi symbol | "Legendre for composites" | A multiplicative product of Legendre symbols over the odd prime factors of `n` |
| Quadratic reciprocity | "Flip the fraction" | The sign rule that lets `(a/n)` become `(n/a)` during the Jacobi algorithm |
| Pseudosquare | "A fake square" | A non-residue modulo composite `n` whose Jacobi symbol is `+1` |
| Solovay-Strassen witness | "A base that proves composite" | A base `a` where Euler's criterion disagrees with the Jacobi symbol |

## Test Vectors

Source: project-internal theorem examples cross-checked against Euler's criterion, quadratic reciprocity, and direct square enumeration for small composite moduli. See `tests/vectors.json`.

## Further Reading

- [Handbook of Applied Cryptography, Chapter 2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf) — Background number theory, including Legendre and Jacobi symbols
- [Handbook of Applied Cryptography, Chapter 3](https://cacr.uwaterloo.ca/hac/about/chap3.pdf) — Quadratic residues and computational number theory in cryptography
- [Solovay and Strassen, 1977](https://doi.org/10.1137/0206006) — The original randomized primality-test paper
