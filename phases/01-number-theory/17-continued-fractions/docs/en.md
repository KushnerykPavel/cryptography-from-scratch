# Continued Fractions for Cryptanalysis

> Good rational guesses are not luck; Euclid gives them to you in order.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 2, 3, 6, 12, 13, 16; Phase 8 Lesson 1
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Expand a rational number into a finite continued fraction.
- Compute convergents and explain why they are unusually good rational approximations.
- Compute the periodic continued fraction of `sqrt(n)` for non-square `n`.
- Use convergents of `e/n` to recover a dangerously small RSA private exponent with Wiener's attack.
- Recognize how convergents of `sqrt(n)` produce small residues for CFRAC-style factoring.

## The Problem

Several attacks in number theory start with the same strange move: replace a hard unknown with a very good rational approximation. If you can guess the right fraction, the rest of the attack becomes ordinary algebra.

RSA with a tiny private exponent is the cleanest warning. The public key gives `(n, e)`. The secret key satisfies:

```text
e*d - k*phi(n) = 1
```

Rearranged, that says `e/n` is close to `k/d` when `d` is small. Continued fractions are the machine that lists the best candidates for `k/d`. Try the convergents, test the implied `phi(n)`, and the private key falls out.

The same tool also explains an older factoring method: continued fraction factorization, or CFRAC. Convergents of `sqrt(n)` give values where `p^2 - n*q^2` is small. Small values are more likely to be smooth, and smooth relations are the fuel for square-finding attacks such as Quadratic Sieve.

## The Concept

### Euclid as a fraction printer

A continued fraction writes a number as nested integer parts:

```text
7/22 = [0; 3, 7]

        1
0 + ---------
          1
    3 + -----
          7
```

The terms are just Euclidean quotients:

```text
22 = 3*7 + 1
 7 = 7*1 + 0
```

For `415/93`:

```text
415/93 = [4; 2, 6, 7]

415 = 4*93 + 43
 93 = 2*43 + 7
 43 = 6*7  + 1
  7 = 7*1  + 0
```

### Convergents

Truncate the continued fraction after each term. Each truncation is a convergent.

```text
[4]          = 4/1
[4; 2]       = 9/2
[4; 2, 6]    = 58/13
[4; 2, 6, 7] = 415/93
```

The recurrence keeps the arithmetic small and exact:

```text
p_i = a_i*p_(i-1) + p_(i-2)
q_i = a_i*q_(i-1) + q_(i-2)

p_-2 = 0, p_-1 = 1
q_-2 = 1, q_-1 = 0
```

Convergents are not merely decent approximations. They are best approximations in a denominator-bounded sense. Legendre's theorem gives the cryptanalytic trigger:

```text
If |x - p/q| < 1/(2*q^2), then p/q is a convergent of x.
```

That is why small-secret attacks can be finite searches instead of guesswork.

### Square roots repeat

Rational numbers have finite continued fractions. Quadratic irrationals have eventually periodic continued fractions. For non-square `n`, `sqrt(n)` has a repeating tail:

```text
sqrt(23) = [4; 1, 3, 1, 8, 1, 3, 1, 8, ...]
period   = [1, 3, 1, 8]
```

The exact integer recurrence avoids floating point:

```text
m_next = d*a - m
d_next = (n - m_next^2) / d
a_next = floor((a0 + m_next) / d_next)
```

The period stops when `a_next = 2*a0`.

### Wiener's RSA attack shape

RSA key generation chooses `e*d = 1 mod phi(n)`, so:

```text
e*d - k*phi(n) = 1
```

Divide by `d*phi(n)`:

```text
e/phi(n) - k/d = 1/(d*phi(n))
```

Attackers do not know `phi(n)`, but `phi(n)` is close to `n` for balanced RSA primes. When `d` is very small, `k/d` becomes a convergent of `e/n`.

Attack loop:

```text
for each convergent k/d of e/n:
    phi_candidate = (e*d - 1) / k
    solve x^2 - (n - phi_candidate + 1)*x + n = 0
    if the roots multiply to n:
        recovered p, q, d
```

Wiener's theorem proves recovery when roughly:

```text
d < n^(1/4) / 3
```

Modern RSA does not make `d` tiny. A small public exponent such as `65537` is normal; a tiny private exponent is not.

### CFRAC intuition

If `p/q` approximates `sqrt(n)`, then:

```text
p^2 / q^2 ~= n
p^2 - n*q^2 ~= 0
```

The residue `p^2 - n*q^2` is often much smaller than a random number of comparable size. CFRAC collects residues that factor over a small base:

```text
p_i^2 - n*q_i^2 = +/- 2^a * 3^b * 5^c * ...
```

Once enough exponent vectors are collected, linear algebra finds a product whose exponents are all even. That gives:

```text
X^2 = Y^2 mod n
gcd(X - Y, n)
```

Quadratic Sieve improves the relation collection, but the square-finding idea is the same.

## Build It

The implementation is pure Python and exact integer arithmetic. No floating point is needed.

### Step 1: Expand a rational number

Repeated division gives the continued-fraction terms.

```python
def continued_fraction(numerator: int, denominator: int) -> list[int]:
    terms = []
    while denominator:
        quotient = numerator // denominator
        terms.append(quotient)
        numerator, denominator = denominator, numerator - quotient * denominator
    return terms
```

Example:

```text
continued_fraction(7, 22) = [0, 3, 7]
```

### Step 2: Build convergents

Use the recurrence for numerator and denominator pairs.

```python
def convergents(terms: list[int]) -> list[tuple[int, int]]:
    previous_p, current_p = 0, 1
    previous_q, current_q = 1, 0
    result = []
    for term in terms:
        previous_p, current_p = current_p, term * current_p + previous_p
        previous_q, current_q = current_q, term * current_q + previous_q
        result.append((current_p, current_q))
    return result
```

For `[4, 2, 6, 7]`, the result is:

```text
4/1, 9/2, 58/13, 415/93
```

### Step 3: Compute `sqrt(n)` periods

The integer recurrence returns the leading term and the repeating period.

```python
def sqrt_continued_fraction(n: int) -> tuple[int, list[int]]:
    a0 = isqrt(n)
    if a0 * a0 == n:
        return a0, []

    m = 0
    d = 1
    a = a0
    period = []
    while True:
        m = d * a - m
        d = (n - m * m) // d
        a = (a0 + m) // d
        period.append(a)
        if a == 2 * a0:
            return a0, period
```

Example:

```text
sqrt_continued_fraction(23) = (4, [1, 3, 1, 8])
```

### Step 4: Recover RSA `d` with Wiener's attack

Walk the convergents of `e/n`. For each candidate `k/d`, derive `phi(n)` and test whether it splits `n`.

```python
def wiener_attack(e: int, n: int) -> WienerResult | None:
    for k, d in best_rational_approximations(e, n):
        if k == 0 or d == 0:
            continue
        candidate = e * d - 1
        if candidate % k != 0:
            continue
        phi = candidate // k
        factors = solve_rsa_factors_from_phi(n, phi)
        if factors is not None and (e * d) % phi == 1:
            p, q = factors
            return WienerResult(d=d, p=p, q=q, phi=phi)
    return None
```

Tiny vulnerable example:

```text
p = 53, q = 167
n = 8851, phi(n) = 8632
d = 3, e = 5755

wiener_attack(e=5755, n=8851) recovers d = 3
```

### Step 5: Collect CFRAC-style relations

For each convergent `p/q` of `sqrt(n)`, record:

```text
residue = p^2 - n*q^2
```

For `n = 1649`, early relations include:

```text
40^2 - 1649*1^2 = -49 = -7^2
81^2 - 1649*2^2 = -35 = -5*7
203^2 - 1649*5^2 = -16 = -2^4
```

These are exactly the kind of small smooth residues a square-finding attack wants.

Run it:

```
python3 code/main.py
```

## Use It

Python's standard library has `fractions.Fraction` for exact rational arithmetic, and SymPy has `continued_fraction`, `continued_fraction_convergents`, and tools for quadratic irrationals. SageMath and PARI/GP are stronger choices for serious computational number theory.

Do not use this lesson code for production cryptography. Its job is to make the attack mechanics visible. Real RSA key generation must use audited libraries, strong randomness, padding schemes such as RSA-OAEP or RSA-PSS, and sane private-exponent generation.

## Attack It

This lesson's main attack is Wiener's RSA attack. The from-scratch code demonstrates why "make decryption faster by choosing tiny `d`" is catastrophic.

The attack does not decrypt a ciphertext directly. It recovers the private exponent and factors:

```text
public:  n = 8851, e = 5755
search:  convergents of e/n
hit:     k/d = 2/3
derive:  phi(n) = (e*d - 1)/k = 8632
split:   x^2 - (n - phi(n) + 1)x + n = 0
result:  p = 53, q = 167, d = 3
```

The lesson also shows the first step of CFRAC: find smooth residues from convergents of `sqrt(n)`. Full CFRAC continues with linear algebra over parity vectors, which you already saw in the Quadratic Sieve lesson.

## Ship It

This lesson ships `outputs/prompt-rsa-small-d-review.md`, a compact review prompt for checking RSA key generation or key import code for small-private-exponent risk.

## Exercises

1. Easy: Compute the continued fraction and convergents for `355/113`. Which convergent is the famous approximation to pi?
2. Medium: Compute the period for `sqrt(94)` and compare its length with `sqrt(61)`.
3. Hard: Generate a toy RSA key with `d = 5`, recover it with `wiener_attack`, then change `d` until the attack stops finding it.
4. Hard: For `n = 1649`, collect smooth CFRAC-style relations over base `[2, 5, 7]` and try to combine them into a square congruence.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Continued fraction | "A weird nested fraction" | A sequence of integer quotients produced by Euclid; finite for rationals and periodic for quadratic irrationals. |
| Partial quotient | "One term of the list" | The integer floor chosen at one continued-fraction step. |
| Convergent | "A good approximation" | A rational obtained by truncating a continued fraction; often the best approximation for its denominator size. |
| Legendre's theorem | "Close enough means convergent" | If `|x - p/q| < 1/(2*q^2)`, then `p/q` must appear among the convergents of `x`. |
| Wiener attack | "RSA with small d is broken" | A continued-fraction attack that recovers RSA `d` when `d` is below about `n^(1/4)/3`. |
| CFRAC | "Old Quadratic Sieve" | A factoring method that collects smooth residues from convergents of `sqrt(n)` and combines them into square congruences. |

## Test Vectors

The vectors in `tests/vectors.json` are deterministic textbook examples:

- finite continued fractions for `7/22` and `415/93`;
- periodic square-root continued fractions for `sqrt(23)` and `sqrt(61)`;
- a vulnerable RSA key where Wiener's attack recovers `d = 3`;
- CFRAC-style smooth residue examples for `n = 1649`.

They are not RFC or NIST primitive vectors because this lesson implements educational number-theory tooling and attacks, not a production primitive.

## Further Reading

- A. Ya. Khinchin, *Continued Fractions* - classic mathematical treatment of continued fractions and convergents.
- Michael J. Wiener, "Cryptanalysis of Short RSA Secret Exponents" (1990) - the original small-`d` RSA attack.
- Morrison and Brillhart, "A Method of Factoring and the Factorization of F7" (1975) - the continued fraction factorization method.
- Boneh, "Twenty Years of Attacks on the RSA Cryptosystem" - readable survey connecting Wiener, low-exponent issues, and later RSA attacks.
