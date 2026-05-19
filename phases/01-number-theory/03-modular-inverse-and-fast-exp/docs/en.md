# Modular Inverse & Fast Exponentiation

> In cryptography, division becomes inversion, and exponentiation only works if you stay small while you climb.

**Type:** Build
**Languages:** Python
**Prerequisites:** 01-modular-arithmetic, 02-gcd-bezout-eea
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how the Bezout coefficient of a becomes its modular inverse when gcd(a, n) = 1
- Compute modular inverses using both the Extended Euclidean Algorithm and the Fermat shortcut a^(p-2) mod p
- Implement square-and-multiply exponentiation with per-step reduction to keep operands bounded by n
- Distinguish when the Fermat inverse shortcut applies (prime modulus) from when EEA is required (general modulus)
- Identify timing side-channel leakage in branching square-and-multiply and explain why constant-time variants are necessary

## The Problem

Lesson 01 let us add, subtract, multiply, and exponentiate inside `Z/nZ`. Lesson 02 explained when an inverse exists and how Bezout coefficients reveal it. This lesson turns those facts into the two operations that show up everywhere in cryptography: modular inversion and fast exponentiation.

Without modular inverse, RSA key generation cannot compute `d = e^(-1) mod phi(n)`, elliptic-curve formulas cannot divide by slope denominators, and finite-field arithmetic is missing half the structure that makes it useful. Without fast exponentiation, even a toy RSA decrypt would explode into an integer too large to hold in memory before you ever reduced it.

These are not side helpers. They are the workhorses behind public-key cryptography. The goal here is to make both tools feel inevitable: inverse comes from Bezout, and fast exponentiation comes from reading the exponent in binary and reducing at every step.

## The Concept

In ordinary arithmetic, division by `a` means multiply by `1 / a`. In modular arithmetic, division by `a` means multiply by an element `a^(-1)` satisfying:

```text
a · a^(-1) ≡ 1 (mod n)
```

That inverse exists exactly when `gcd(a, n) = 1`.

Lesson 02 gave the key identity:

```text
s·a + t·n = gcd(a, n)
```

So if `gcd(a, n) = 1`, then:

```text
s·a + t·n = 1
```

Reduce both sides mod `n`:

```text
s·a ≡ 1 (mod n)
```

That means `s` is the modular inverse.

Fast exponentiation uses a different idea: do not build `a^k` directly. Read `k` in binary.

Example:

```text
13 = 1101_2 = 8 + 4 + 1
```

So:

```text
a^13 = a^(8+4+1) = a^8 · a^4 · a
```

If you keep squaring:

```text
a^1, a^2, a^4, a^8, ...
```

then every exponent bit tells you whether to multiply that power into the running result.

That gives the classic square-and-multiply loop:

| Exponent bit | Action |
|--------------|--------|
| `0` | square base, shift exponent |
| `1` | multiply result by base, then square and shift |

The crucial rule is the same as lesson 01: reduce mod `n` after every multiply. That keeps intermediate values bounded.

## Build It

### Step 1: Turn Bezout into `mod_inverse`

Start by reusing the Extended Euclidean Algorithm. If `gcd(a, n) != 1`, no inverse exists. If the gcd is 1, the Bezout coefficient of `a` is the inverse, up to reduction back into `[0, n)`.

```python
def mod_inverse(a: int, n: int) -> int:
    g, s, _ = extended_gcd(a, n)
    if g != 1:
        raise ValueError("not invertible modulo n")
    return s % n
```

Check it by multiplying back:

```python
inv = mod_inverse(3, 11)
assert inv == 4
assert (3 * inv) % 11 == 1
```

The `% n` at the end matters because Bezout coefficients are often negative.

### Step 2: Implement `mod_pow`

We already saw square-and-multiply in lesson 01. Here it becomes part of the same story because exponentiation and inversion are the two primitive operations you need most often in multiplicative groups.

```python
def mod_pow(base: int, exp: int, n: int) -> int:
    result = 1
    base %= n
    while exp > 0:
        if exp & 1:
            result = (result * base) % n
        exp >>= 1
        base = (base * base) % n
    return result
```

For an exponent with `b` bits, the loop runs `O(b)` times instead of `O(exp)`.

### Step 3: Compute inverse via Fermat when the modulus is prime

If `p` is prime and `a` is not divisible by `p`, Fermat's little theorem says:

```text
a^(p−1) ≡ 1 (mod p)
```

Multiply both sides by `a^(-1)`:

```text
a^(p−2) ≡ a^(-1) (mod p)
```

So with a prime modulus:

```python
def mod_inverse_prime(a: int, p: int) -> int:
    if a % p == 0:
        raise ValueError("zero has no inverse modulo p")
    return mod_pow(a, p - 2, p)
```

This does not replace EEA in general. It is a special shortcut for prime fields.

### Step 4: Cross-check both inverse methods

For prime moduli, both routes should agree:

```python
for a in range(1, 13):
    assert mod_inverse(a, 13) == mod_inverse_prime(a, 13)
```

That is a great sanity check because the algorithms come from different ideas:

- EEA uses Bezout coefficients
- Fermat uses group order

When they match, your implementation is probably sound.

Run it:

```
python3 code/main.py
```

## Use It

Python's built-in `pow(a, exp, n)` is the real-world replacement for hand-rolled `mod_pow`:

```python
pow(7, 128, 19)
```

Python also supports modular inverse directly:

```python
pow(3, -1, 11)
```

That returns `4`, raising `ValueError` when the inverse does not exist.

In larger ecosystems:

- `gmpy2.invert(a, n)` gives modular inverse with big-int acceleration
- finite-field libraries such as `galois.GF(p)` overload inversion and exponentiation on field elements
- cryptographic libraries usually expose constant-time exponentiation or ladder-style routines instead of textbook branching code

So this lesson's code is the transparent reference model. Production code uses the same math, but with hardened implementations.

## Attack It

**Timing leakage in naive square-and-multiply.**

A textbook implementation often does this:

```text
if current exponent bit is 1:
    multiply
always:
    square
```

If the multiply path takes measurably longer than the zero-bit path, an attacker observing many decryptions or signatures can learn the bit pattern of the secret exponent `d`.

That is the shape of a timing side channel:

- bit `0` means "square only"
- bit `1` means "square and multiply"
- runtime differences leak private-key structure

This is why educational `mod_pow` is correct but unsafe for secret exponents. Real libraries use constant-time variants such as always-multiply schedules, fixed windows, or Montgomery ladder style routines.

The lesson: mathematical correctness is not enough. In cryptography, control flow can be part of the attack surface.

## Ship It

Output: `outputs/skill-modular-inverse-auditor.md` — a review skill for spotting incorrect modular inverse usage, missing coprimality checks, and unsafe hand-rolled exponentiation in educational code.

## Exercises

1. **Easy.** Compute `7^(-1) mod 19` by hand using a Bezout identity or trial multiplication.
2. **Medium.** Compare `mod_inverse(a, p)` and `mod_inverse_prime(a, p)` for every `a` in `1..p-1` when `p = 101`. Confirm they always match.
3. **Hard.** Implement RSA key setup for small toy primes: choose `p, q`, compute `n`, `phi(n)`, pick `e`, derive `d = mod_inverse(e, phi(n))`, and verify `pow(pow(m, e, n), d, n) == m`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Modular inverse | "division mod n" | An element `a^(-1)` with `a · a^(-1) ≡ 1 (mod n)` |
| Coprime | "shares nothing important" | `gcd(a, n) = 1`, the exact condition for invertibility |
| Square-and-multiply | "fast power trick" | Binary exponentiation with repeated squaring and selective multiplies |
| Fermat inverse | "prime field shortcut" | `a^(p−2) mod p`, valid only when `p` is prime and `a != 0 mod p` |

## Test Vectors

Source: project-internal inverse examples plus cross-checks against Python's modular arithmetic semantics for exponentiation and inversion.

Code must pass all cases in `tests/vectors.json`.

## Further Reading

- Boneh & Shoup, *A Graduate Course in Applied Cryptography* — clean treatment of modular arithmetic and inverses in the early chapters.
- Menezes, van Oorschot, Vanstone, *Handbook of Applied Cryptography* — standard reference for modular arithmetic algorithms and implementation concerns.
- Python documentation for [`pow`](https://docs.python.org/3/library/functions.html#pow) — concise practical reference for modular exponentiation and inversion.
