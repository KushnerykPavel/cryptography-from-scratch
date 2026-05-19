# Fermat's Little Theorem & Euler's Theorem

> Group size turns huge exponents into short cycles.

**Type:** Learn
**Languages:** Python
**Prerequisites:** 01-modular-arithmetic, 02-gcd-bezout-eea, 03-modular-inverse-and-fast-exp
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why multiplication by a non-zero element permutes all non-zero residues modulo a prime, forcing a^(p-1) ≡ 1
- Compute large modular exponentiations efficiently by reducing the exponent modulo p-1 or phi(n) before calling mod_pow
- Implement fermat_holds and euler_holds helpers that encode the coprimality precondition directly in code
- Distinguish Fermat's Little Theorem (prime modulus) from Euler's generalization (any modulus with gcd(a, n) = 1)
- Identify Carmichael numbers as composites that satisfy a^(n-1) ≡ 1 for every coprime base, defeating naive Fermat primality tests

## The Problem

Lesson 03 gave us fast exponentiation, which makes `a^k mod n` computable. But computable is not the same as understandable. If you stare at `2^100 mod 13` or `m^(ed) mod n` in RSA without a theorem about how exponents cycle, you are reduced to blind calculation.

Cryptography depends on exactly those cycles. RSA works because exponentiation eventually comes back to the starting point on invertible residues. Prime-field tricks work because the multiplicative group modulo a prime has a fixed size. Primality tests work because composites often fail the same cycle identities that primes satisfy.

This lesson gives you the first big compression theorem in number theory: in the right modular world, giant exponents can be reduced to much smaller ones. Fermat handles prime moduli. Euler generalizes the same idea to any modulus once you restrict to elements coprime to it.

## The Concept

### The multiplicative world modulo `n`

Inside `Z/nZ`, not every element is invertible. The good elements are the residues coprime to `n`:

```text
U(n) = { a in {1, 2, ..., n-1} : gcd(a, n) = 1 }
```

These elements form a multiplicative group. That means:

- multiplying two members stays inside the set
- there is an identity element `1`
- every member has an inverse

The size of this group is Euler's totient:

```text
|U(n)| = phi(n)
```

For a prime `p`, every non-zero residue is invertible, so:

```text
U(p) = {1, 2, ..., p-1}
phi(p) = p - 1
```

That is why Fermat's Little Theorem is really the prime-modulus special case of Euler's theorem.

### Fermat's Little Theorem

If `p` is prime and `gcd(a, p) = 1`, then:

```text
a^(p-1) ≡ 1 (mod p)
```

Mental model:

```text
a, 2a, 3a, ..., (p-1)a   mod p
```

When `a` is non-zero mod prime `p`, multiplication by `a` just permutes the non-zero residues. The product of the permuted list must equal the product of the original list, which forces one factor of `a^(p-1)` to behave like `1`.

That immediately reduces exponents:

```text
2^100 mod 13
100 = 8*(12) + 4
2^100 ≡ (2^12)^8 * 2^4 ≡ 1^8 * 16 ≡ 3 (mod 13)
```

### Euler's theorem

If `gcd(a, n) = 1`, then:

```text
a^phi(n) ≡ 1 (mod n)
```

The idea is the same, but now you only permute the invertible residues in `U(n)`, not all residues modulo `n`.

Example with `n = 10`:

```text
U(10) = {1, 3, 7, 9}
phi(10) = 4
3^4 = 81 ≡ 1 (mod 10)
7^4 = 2401 ≡ 1 (mod 10)
9^4 = 6561 ≡ 1 (mod 10)
```

So:

```text
3^100 mod 10
100 mod 4 = 0
3^100 ≡ (3^4)^25 ≡ 1 (mod 10)
```

### Why RSA cares

RSA chooses `d` so that:

```text
e*d ≡ 1 (mod phi(n))
```

So for some integer `k`:

```text
e*d = 1 + k*phi(n)
```

Then:

```text
m^(ed) = m^(1 + k*phi(n)) = m * (m^phi(n))^k ≡ m (mod n)
```

for residues coprime to `n`. This is the algebraic heart of RSA decryption and signing.

### Where the theorem can fail

The coprimality condition is not cosmetic.

Example:

```text
2^4 mod 8 = 0
phi(8) = 4
```

Euler's theorem would predict `1`, but `gcd(2, 8) != 1`, so the theorem does not apply.

That is the recurring rule for this phase:

| Statement | Required condition |
|-----------|--------------------|
| Fermat | `p` prime and `gcd(a, p) = 1` |
| Euler | `gcd(a, n) = 1` |
| Exponent reduction | same condition as the theorem you use |

## Build It

### Step 1: Reuse `mod_pow`

The theorem is not a replacement for fast exponentiation. It tells you *which* exponent you can safely reduce before calling `mod_pow`.

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

### Step 2: Count `phi(n)` naively

Lesson 06 is where you will build efficient totient code. Here we only need the definition:

```python
def euler_totient_naive(n: int) -> int:
    return sum(1 for k in range(1, n + 1) if gcd(k, n) == 1)
```

That is enough to experiment with Euler's theorem on small moduli and see the group size directly.

### Step 3: Turn the theorems into checks

```python
def fermat_holds(a: int, p: int) -> bool:
    return gcd(a, p) == 1 and mod_pow(a, p - 1, p) == 1


def euler_holds(a: int, n: int) -> bool:
    return gcd(a, n) == 1 and mod_pow(a, euler_totient_naive(n), n) == 1
```

These helpers are not profound, but they force the preconditions into code instead of leaving them as vague mathematical memory.

### Step 4: Reduce exponents before computing

```python
def reduce_exponent_prime(base: int, exp: int, p: int) -> int:
    return mod_pow(base, exp % (p - 1), p)


def reduce_exponent_euler(base: int, exp: int, n: int) -> int:
    phi_n = euler_totient_naive(n)
    return mod_pow(base, exp % phi_n, n)
```

These are the practical payoffs:

- prime modulus: reduce exponent mod `p - 1`
- general modulus with `gcd(base, n) = 1`: reduce exponent mod `phi(n)`

Run it:

```
python3 code/main.py
```

## Use It

In Python, the real production-adjacent primitive is still:

```python
pow(base, exp, modulus)
```

The theorem helps you simplify the exponent *before* you call it, or reason about why a library routine works.

In actual cryptographic systems:

- RSA key generation uses `phi(n)` or the Carmichael function `lambda(n)` to compute the private exponent
- finite-field libraries rely on the same group-order facts when computing inverses as `a^(p-2) mod p`
- primality-testing libraries use stronger descendants of Fermat, especially Miller-Rabin, because plain Fermat is too easy to fool

So the theorem is not usually an API you call. It is the proof layer under the APIs you trust.

## Attack It

**The Fermat primality test has liars.**

If `n` is prime and `gcd(a, n) = 1`, then Fermat guarantees:

```text
a^(n-1) ≡ 1 (mod n)
```

That suggests a primality test:

1. pick a base `a`
2. compute `a^(n-1) mod n`
3. if the answer is not `1`, `n` is composite

This is a valid *compositeness* test, but not a reliable *primality* test. Some composites pass for many bases. The worst offenders are Carmichael numbers such as:

```text
561 = 3 * 11 * 17
1105 = 5 * 13 * 17
1729 = 7 * 13 * 19
```

For every base coprime to `561`:

```text
a^560 ≡ 1 (mod 561)
```

So naive Fermat testing says "probably prime" even though `561` is obviously composite.

That is why later lessons move to Miller-Rabin. Fermat explains the structure. Miller-Rabin turns that structure into an actually useful test.

## Ship It

Output: `outputs/skill-fermat-euler-screener.md` — a small audit skill for spotting unsafe uses of Fermat reduction, missing coprimality checks, and bogus primality claims based on plain Fermat testing.

## Exercises

1. **Easy.** Compute `5^96 mod 17` by reducing the exponent with Fermat's Little Theorem.
2. **Medium.** List `U(12)` and verify Euler's theorem for every element in that set.
3. **Hard.** Write a script that searches for composites below 10,000 that pass the Fermat test for bases `2`, `3`, and `5`. How many false positives do you find?

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Fermat's Little Theorem | "prime-number magic" | The statement that `a^(p-1) ≡ 1 (mod p)` for `a` coprime to prime `p` |
| Euler's theorem | "Fermat but bigger" | The generalization `a^phi(n) ≡ 1 (mod n)` for `gcd(a, n) = 1` |
| Euler totient `phi(n)` | "count of numbers below `n`" | The number of residues in `{1, ..., n}` coprime to `n` |
| Unit group `U(n)` | "the invertible residues" | The multiplicative group of elements modulo `n` with inverses |
| Carmichael number | "fake prime for Fermat" | A composite number that satisfies Fermat's congruence for every coprime base |

## Test Vectors

Source: project-internal theorem examples, textbook RSA-style exponent reductions, and known Carmichael-number counterexamples cross-checked with Python's `pow`.

Code must pass all cases in `tests/vectors.json`.

## Further Reading

- Boneh & Shoup, *A Graduate Course in Applied Cryptography* — early chapters give the cleanest cryptography-first presentation of FLT and Euler's theorem.
- Menezes, van Oorschot, Vanstone, *Handbook of Applied Cryptography* — standard reference for modular groups, RSA algebra, and primality testing.
- [Python `pow` documentation](https://docs.python.org/3/library/functions.html#pow) — practical reference for modular exponentiation in the standard library.
