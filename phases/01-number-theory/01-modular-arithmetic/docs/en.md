# Modular Arithmetic from Scratch

> Crypto lives in finite worlds. Modular arithmetic is the air it breathes.

**Type:** Build
**Languages:** Python
**Prerequisites:** None
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why modular reduction is a ring homomorphism from Z to Z/nZ and when Z/nZ becomes a field
- Compute modular addition, subtraction, multiplication, and exponentiation by hand on small examples
- Implement square-and-multiply exponentiation that keeps intermediate values bounded by n
- Distinguish between a ring modulo a composite and a field modulo a prime in terms of invertibility
- Identify how the common-modulus RSA attack exploits shared n by recovering m via Bezout coefficients

## The Problem

Every cryptographic primitive you'll meet — RSA, Diffie-Hellman, ECDSA, AES key schedule, Kyber, Bulletproofs — operates on integers reduced modulo something: a prime, a composite, or a polynomial. If `5 + 4 = 2 (mod 7)` doesn't feel as natural as `5 + 4 = 9`, every later lesson will be a fight.

Worse: when you read RSA decryption as `m = c^d mod n`, you might mentally hand-wave the `mod n` part. That hand-wave is exactly where attacks live. Common-modulus attack, Wiener's attack, lattice attacks on biased nonces — all exploit the modular structure most readers never internalize.

This lesson builds modular arithmetic from arithmetic axioms, then makes the structure visceral with a clock visualization and concrete reductions.

## The Concept

Think of integers wrapping around a clock face of size `n`:

```
        0
   11       1
 10           2
9        n=12   3
 8            4
   7        5
        6
```

**Definition.** `a ≡ b (mod n)` iff `n | (a − b)`.

Equivalently: `a` and `b` produce the same remainder when divided by `n`.

The set `Z/nZ = {0, 1, ..., n−1}` with operations `+`, `−`, `·` (all reduced mod `n`) forms a *commutative ring*. When `n` is prime, every non-zero element has a multiplicative inverse, and `Z/pZ` becomes a *field* — denoted `F_p` or `GF(p)`.

| Operation | Z/nZ Result |
|-----------|-------------|
| `(a + b) mod n` | sum, possibly wrapped |
| `(a − b) mod n` | wrap into `[0, n)` |
| `(a · b) mod n` | product, then reduce |
| `a^k mod n` | repeated multiplication |
| `a^(-1) mod n` | inverse — exists iff `gcd(a, n) = 1` |

The deep idea: **modular reduction is a homomorphism** from `Z` to `Z/nZ`. You can reduce *as you compute* — you don't have to wait until the end. This is what makes 4096-bit RSA tractable.

## Build It

### Step 1: Define `mod_add`, `mod_sub`, `mod_mul`

```python
def mod_add(a: int, b: int, n: int) -> int:
    return (a + b) % n


def mod_sub(a: int, b: int, n: int) -> int:
    return (a - b) % n


def mod_mul(a: int, b: int, n: int) -> int:
    return (a * b) % n
```

Python's `%` always returns a non-negative result for positive `n`. C's `%` does not. Cryptographic code in C must normalize.

### Step 2: Modular Exponentiation by Square-and-Multiply

Computing `a^k mod n` by `pow(a, k) % n` is fine for tiny `k`. For RSA, `k ≈ 2^2048`, so the intermediate result has 10^617 digits. You need to reduce *as you go*.

```python
def mod_pow(base: int, exp: int, n: int) -> int:
    result = 1
    base = base % n
    while exp > 0:
        if exp & 1:
            result = (result * base) % n
        exp >>= 1
        base = (base * base) % n
    return result
```

`O(log exp)` multiplications, each on numbers ≤ `n`. RSA decryption fits in milliseconds.

### Step 3: Verify Against Python's `pow(a, k, n)`

```python
import secrets

n = 2**256 - 189
for _ in range(1000):
    a = secrets.randbelow(n)
    k = secrets.randbelow(n)
    assert mod_pow(a, k, n) == pow(a, k, n)
```

If `mod_pow` agrees with `pow(a, k, n)` for 1000 random inputs, the implementation is correct with overwhelming probability.

### Step 4: The Clock Visualization

```python
def clock(n: int, marks: list[int]) -> None:
    for i in range(n):
        marker = "●" if i in {m % n for m in marks} else "·"
        print(f"  {i:2d}: {marker}")
```

Watch what `7 + 5 mod 12` looks like: start at 7, walk 5 steps, land at 0.

Run it:

```
python3 code/main.py
```

## Use It

Python's built-in `pow(base, exp, mod)` is a C-optimized GMP-backed equivalent of `mod_pow`. The `galois` package gives you a Sage-like field interface in pure Python:

```python
import galois

GF12 = galois.GF(12, irreducible_poly=None)  # use prime modulus for fields
GF13 = galois.GF(13)
a, b = GF13(7), GF13(5)
print(a + b)  # 12
print(a ** 100)  # auto-reduces mod 13
```

For performance-critical big-int work use `gmpy2.powmod(a, k, n)`.

## Attack It

**Common-modulus pitfall.** If two parties share the same `n` but different `e1, e2` with `gcd(e1, e2) = 1`, an attacker who sees `c1 = m^e1 mod n` and `c2 = m^e2 mod n` recovers `m` via Bezout coefficients:

```python
def common_modulus_attack(c1, e1, c2, e2, n):
    g, s, t = ext_gcd(e1, e2)
    assert g == 1
    if s < 0:
        c1 = mod_pow(c1, -1, n); s = -s
    if t < 0:
        c2 = mod_pow(c2, -1, n); t = -t
    return (mod_pow(c1, s, n) * mod_pow(c2, t, n)) % n
```

(`ext_gcd` arrives in lesson 02. Lesson: textbook RSA fails when `n` is reused.)

## Ship It

Output: `outputs/skill-modular-arithmetic-checker.md` — Claude Code skill that audits Python code for unsafe modular operations (e.g. `%` with negative operands, missing `n != 0` checks, modular ops on non-finite-field types).

## Exercises

1. **Easy.** Compute `2^100 mod 13` by hand using Fermat's little theorem.
2. **Medium.** Implement `mod_pow` without the `% n` inside the loop — only at the end. Measure runtime for `a, k ≈ 2^256`. Compare.
3. **Hard.** Given two 1024-bit primes `p, q` and `n = p·q`, write a function that performs RSA decryption via CRT (compute `m_p = c^d mod p`, `m_q = c^d mod q`, recombine). Measure speedup vs raw `mod_pow(c, d, n)`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| `mod` | "remainder" | Equivalence class in Z/nZ |
| `≡` | "equals" | Equivalent mod n — same coset |
| Field | "number system" | Ring where every non-zero has an inverse |
| Reduction | "the % thing" | Homomorphism Z → Z/nZ |

## Test Vectors

Source: project-internal random + RFC 8017 §C examples.
Code must pass `tests/vectors.json` cases for `mod_pow`.

## Further Reading

- Boneh & Shoup, *A Graduate Course in Applied Cryptography*, §1 — clearest free resource.
- Knuth, *TAOCP Vol 2* §4.3 — historical and algorithmic depth.
- Python docs, `int.__pow__` — what `pow(a, k, n)` actually invokes.
