# Number Theory Lab — Build a numth Library

> A crypto primitive is only as solid as the tiny arithmetic functions it trusts.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 1 Lessons 1-17
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Package the Phase 1 number-theory primitives behind a small coherent API.
- Define typed failure behavior for non-invertible values, invalid moduli, and non-residues.
- Combine trial division, Miller-Rabin, Pollard p-1, and Pollard rho into a toy factorization pipeline.
- Use factorization to compute `phi(n)`, Carmichael's `lambda(n)`, and multiplicative order.
- Expose CRT and modular square roots with explicit precondition checks.
- Explain why this library is useful for lessons and still unsuitable for production cryptography.

## The Problem

By the end of Phase 1, you have a drawer full of powerful tools: Euclid, modular inversion, CRT, prime tests, factoring, Legendre and Jacobi symbols, Tonelli-Shanks, continued fractions, and discrete-log attack helpers. That is useful, but it is not yet a library. A later RSA lesson should not have to re-implement `mod_inverse`. A later elliptic-curve lesson should not quietly copy a broken `gcd`. A later attack lesson should not wonder whether `factor(n)` returns one factor, all factors, or a pair.

This lab turns the drawer into a small module called `numth`: predictable names, predictable return types, and predictable errors. The main skill is not typing code faster. The main skill is drawing boundaries. Does `mod_sqrt(a, p)` handle composite moduli? No: it handles prime moduli and says so. Does `crt` accept non-coprime moduli? No: this version rejects them instead of silently computing nonsense. Does `is_prime` prove primality for arbitrary huge integers? No: this lesson uses deterministic fixed-base Miller-Rabin only in its documented range.

That honesty matters. Crypto failures often begin with a helper routine whose behavior is vague. A single `0` returned from a failed inverse can become a broken RSA key. A Fermat-only prime test can accept a Carmichael number. A factorization demo can be mistaken for a key-recovery tool. Good educational code is clear about both what it does and where it stops.

## The Concept

### Library Layers

The `numth` library has four layers:

```text
foundation
  gcd, extended_gcd, mod_pow, mod_inverse

composition
  crt, prime_sieve, is_prime, factor

derived arithmetic
  phi, carmichael_lambda, legendre_symbol, jacobi_symbol, mod_sqrt

lesson helpers
  multiplicative_order, continued_fraction
```

Each layer depends only on lower layers. That makes the module easy to test and easy to reuse.

```text
mod_inverse  -> extended_gcd
crt          -> mod_inverse + gcd
is_prime     -> Miller-Rabin witness test
factor       -> is_prime + sieve + Pollard methods
phi/lambda   -> factor
mod_sqrt     -> legendre_symbol + Tonelli-Shanks
order        -> phi + factor_counts
```

### Fail Loudly

The most important API rule is simple: broken preconditions raise errors.

| Operation | Precondition | Failure |
|-----------|--------------|---------|
| `mod_inverse(a, n)` | `n > 0` and `gcd(a, n) = 1` | `NoInverseError` |
| `crt(residues, moduli)` | non-empty, same length, positive pairwise-coprime moduli | `NumthError` |
| `is_prime(n)` | `n` inside the deterministic Miller-Rabin range | `NumthError` outside range |
| `mod_sqrt(a, p)` | `p` prime and `a` a quadratic residue | `NoSquareRootError` |
| `multiplicative_order(a, n)` | `gcd(a, n) = 1` | `NumthError` |

Returning sentinel values such as `0`, `None`, or `-1` from arithmetic routines is tempting, but dangerous. Many residues are valid values. An inverse modulo `1` would be nonsense, but a square root of `0` is real. Typed exceptions keep mistakes visible.

### Factoring Pipeline

This library is for toy and lesson-sized inputs. The factorization chain is cost-ordered:

```text
1. handle signs and small cases
2. detect prime with Miller-Rabin
3. trial divide by small primes
4. try Pollard p-1
5. try Pollard rho
6. recurse on discovered factors
```

This is enough for Phase 1 examples and later toy RSA demonstrations. It is not a general-purpose integer factorization package. It does not implement Quadratic Sieve or GNFS, and it should not be advertised as breaking real keys.

### Prime Testing Boundary

Fermat's test is not enough:

```text
2^560 mod 561 = 1
561 = 3 * 11 * 17
```

The composite `561` passes Fermat base `2`. It is a Carmichael number. Miller-Rabin uses a stronger sequence:

```text
n - 1 = 2^s * d
a^d, a^(2d), a^(4d), ..., a^(2^(s-1)d) mod n
```

For odd composite `n`, at most a quarter of bases are strong liars. For the input range in this lesson, a fixed base set gives deterministic answers. That is good enough for curriculum code; production systems still rely on audited libraries and standards-defined key-generation procedures.

### Square Root Boundary

For prime `p`, `mod_sqrt(a, p)` has a clean shape:

```text
if a == 0:
    return 0
if Legendre(a, p) == -1:
    raise NoSquareRootError
if p == 3 mod 4:
    return a^((p + 1) / 4) mod p
else:
    run Tonelli-Shanks
```

For composite moduli, square roots become a factoring problem. If you know `n = p*q`, you can compute roots modulo `p` and `q`, then combine them with CRT. If you do not know the factorization, a square-root oracle can reveal factors. That is an attack surface, not a convenience API.

## Build It

The implementation lives in `code/main.py`. It intentionally stays pure Python and exact integer arithmetic.

### Step 1: Foundation API

Start with total, boring arithmetic:

```python
def gcd(a: int, b: int) -> int:
    a = abs(a)
    b = abs(b)
    while b:
        a, b = b, a % b
    return a
```

Then expose `extended_gcd`, `mod_pow`, and `mod_inverse`. `mod_inverse` raises `NoInverseError` when `gcd(a, n) != 1`.

```python
def mod_inverse(a: int, modulus: int) -> int:
    if modulus <= 0:
        raise NumthError("modulus must be positive")

    g, x, _ = extended_gcd(a, modulus)
    if g != 1:
        raise NoInverseError(f"{a} has no inverse modulo {modulus}")
    return x % modulus
```

### Step 2: CRT

CRT is a composition test for the library. It depends on validation, `gcd`, and `mod_inverse`.

```python
def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    # validate lengths, positivity, and pairwise coprimality
    modulus = prod(moduli)
    total = 0
    for residue, n_i in zip(residues, moduli):
        partial = modulus // n_i
        total += (residue % n_i) * partial * mod_inverse(partial, n_i)
    return total % modulus, modulus
```

The return value is `(x, N)`, meaning:

```text
x mod N
```

For example:

```text
x = 2 mod 3
x = 3 mod 5
x = 2 mod 7

crt(...) = (23, 105)
```

### Step 3: Prime Testing

Use Miller-Rabin, not Fermat. The exported `is_prime(n)` uses fixed bases for the lesson's documented deterministic range.

```python
def miller_rabin_witness(base: int, n: int) -> bool:
    s, d = decompose_n_minus_one(n)
    x = pow(base, d, n)
    if x in (1, n - 1):
        return False
    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return False
    return True
```

`True` means "this base proves compositeness." That naming is worth getting right: witnesses prove composite; liars fail to reveal it.

### Step 4: Factoring

The factoring API returns all prime factors with multiplicity:

```text
factor(8051) = [83, 97]
factor(360)  = [2, 2, 2, 3, 3, 5]
```

It recursively splits `n` using trial division, Pollard p-1, and Pollard rho.

```python
def factor(n: int, trial_bound: int = 10_000, pm1_bound: int = 50) -> list[int]:
    if n == 0:
        raise NumthError("cannot factor zero")
    if abs(n) == 1:
        return []

    factors = []
    if n < 0:
        factors.append(-1)
        n = -n

    _factor_recursive(n, factors, trial_bound, pm1_bound)
    return sorted(factors, key=lambda value: (value == -1, abs(value)))
```

The `-1` convention keeps negative-input behavior explicit while leaving prime factors positive.

### Step 5: Derived Functions

Once factors are reliable, derived number-theory functions become compact:

```python
def phi(n: int) -> int:
    result = n
    for p in factor_counts(n):
        result = result // p * (p - 1)
    return result
```

For Carmichael's function:

```text
lambda(p^k) = phi(p^k)                 for odd p, or p = 2 and k <= 2
lambda(2^k) = 2^(k-2)                  for k >= 3
lambda(n)   = lcm(lambda(p_i^k_i))
```

This is the exponent that often matters for RSA-style modular arithmetic because it is the group exponent of `(Z/nZ)*`.

### Step 6: Residues and Square Roots

Expose both Legendre and Jacobi symbols:

```text
legendre_symbol(a, p) -> -1, 0, 1 for odd prime p
jacobi_symbol(a, n)   -> -1, 0, 1 for odd positive n
```

Then implement `mod_sqrt(a, p)` for prime moduli with the fast `p % 4 == 3` case and Tonelli-Shanks for the general odd-prime case.

```text
mod_sqrt(5, 41) = 13
all_mod_sqrt(9, 43) = (3, 40)
```

Returning the canonical smaller root keeps tests deterministic. `all_mod_sqrt` exposes both roots when the caller needs them.

Run it:

```
python3 code/main.py
```

## Use It

For real work, use a maintained math or cryptography library:

| Need | Use |
|------|-----|
| Modular exponentiation / inverse in Python | built-in `pow(a, e, n)` and `pow(a, -1, n)` |
| Symbolic number theory | SymPy `ntheory` |
| Fast arbitrary-precision arithmetic | GMP / gmpy2 |
| Serious computational number theory | SageMath or PARI/GP |
| Cryptographic key generation | PyCryptodome, cryptography.io, libsodium, OpenSSL-backed APIs |

This lesson's `numth` module is a bridge between hand derivations and later course code. It is not hardened against timing leakage, malformed adversarial inputs, resource exhaustion, or huge semiprimes.

## Attack It

### Attack 1: Fermat-Only Prime Testing

If a library exposes this:

```python
def is_prime_bad(n):
    return pow(2, n - 1, n) == 1
```

then `561` is accepted as prime:

```text
561 = 3 * 11 * 17
2^560 mod 561 = 1
```

Any later RSA keygen that trusts this can build keys from composite "primes." The fix is not more confidence in Fermat. The fix is Miller-Rabin with documented bases, or a production library's approved primality routine.

### Attack 2: Square Roots Modulo a Composite Reveal Factors

Suppose `n = p*q` and an attacker obtains two different square roots of the same value:

```text
r^2 = s^2 mod n
r != +/-s mod n
```

Then:

```text
r^2 - s^2 = 0 mod n
(r - s)(r + s) = 0 mod n
gcd(r - s, n)
```

usually gives a non-trivial factor. That is why `mod_sqrt(a, p)` says `p` must be prime. A casual "sqrt modulo n" helper is not harmless.

### Attack 3: Silent Inverse Failure

RSA needs `d = e^-1 mod lambda(n)` or `mod phi(n)`. If `gcd(e, lambda(n)) != 1`, no inverse exists. A bad helper that returns `0` on failure can produce a key object that looks initialized but cannot decrypt correctly. `NoInverseError` is a safety feature.

## Ship It

This lesson ships `outputs/skill-numth-api-review.md`, a reusable review checklist for any small number-theory helper library used by later lessons. It focuses on API contracts: range limits, exception behavior, factorization claims, and production-safety wording.

## Exercises

1. Easy: Add `is_coprime(a, b)` and use it inside `multiplicative_order`.
2. Medium: Add generalized CRT for non-coprime moduli. It should accept systems when residues agree modulo each shared gcd, and reject inconsistent systems.
3. Hard: Add `sqrt_mod_composite_known_factorization(a, factors)` and show how two distinct roots can recover a factor of a semiprime.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|------------------------|
| API contract | "Function behavior" | Inputs, outputs, errors, and documented range |
| Typed exception | "Custom error" | A failure mode callers can catch without parsing strings |
| Deterministic Miller-Rabin range | "Fixed bases work" | A proven input interval where selected bases identify all composites |
| Strong witness | "Miller-Rabin base" | A base that proves an odd number is composite |
| Pollard rho | "Random-looking factor search" | Cycle-finding over a polynomial map modulo `n` |
| Pollard p-1 | "Smooth factor method" | Factoring method that works when some prime factor has smooth `p - 1` |
| Carmichael lambda | "Like phi" | The exponent of the multiplicative group modulo `n` |
| Tonelli-Shanks | "Modular square root algorithm" | General algorithm for square roots modulo odd primes |

## Test Vectors

The vector file is `tests/vectors.json`. It includes:

- Phase 1 textbook examples for gcd, EEA, CRT, modular exponentiation, and inverses.
- Miller-Rabin checks for the Mersenne prime `2^61 - 1` and Carmichael composite `561`.
- Pollard-style factor smoke tests such as `8051 = 83 * 97`.
- Euler phi and Carmichael lambda examples for `36`.
- Legendre, Jacobi, and Tonelli-Shanks square-root cases.
- Error vectors for non-invertible values, non-coprime CRT moduli, and non-residues.

Sources: Phase 1 lesson examples; Menezes, van Oorschot, and Vanstone, *Handbook of Applied Cryptography*, Chapter 2; Crandall and Pomerance, *Prime Numbers: A Computational Perspective*; Sorenson and Webster fixed-base Miller-Rabin bounds used by Lesson 10.

## Further Reading

- [Handbook of Applied Cryptography, Chapter 2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf) — Number-theory algorithms used throughout classical cryptography.
- [Python `pow` documentation](https://docs.python.org/3/library/functions.html#pow) — Built-in modular exponentiation and modular inverse behavior.
- [SymPy ntheory documentation](https://docs.sympy.org/latest/modules/ntheory.html) — Practical maintained number-theory helpers for Python experiments.
- [PARI/GP](https://pari.math.u-bordeaux.fr/) — Serious computational number theory toolkit.
