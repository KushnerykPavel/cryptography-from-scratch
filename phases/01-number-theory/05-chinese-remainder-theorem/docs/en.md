# Chinese Remainder Theorem

> Split one hard modular world into smaller ones, solve locally, then stitch the answer back together.

**Type:** Build
**Languages:** Python
**Prerequisites:** 02-gcd-bezout-eea, 03-modular-inverse-and-fast-exp
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

One congruence is usually easy. Many congruences at once look messy. Suppose you know a value leaves remainder `2` mod `3`, remainder `3` mod `5`, and remainder `2` mod `7`. Brute force works for toy numbers, but it does not scale. In cryptography, the toy version becomes "compute mod `p` and mod `q`, then reconstruct mod `n = p*q`" where `p` and `q` are hundreds or thousands of bits long.

That reconstruction step is not decorative. RSA implementations use it to turn one expensive exponentiation mod `n` into two cheaper exponentiations mod `p` and mod `q`, then recombine. Broadcast attacks use the same theorem offensively: if the same RSA plaintext is sent to enough recipients with a small public exponent, CRT lets an attacker glue the ciphertext equations together and recover `m^e` over the integers.

So CRT is both a speed trick and an attack surface. You need to know how to recombine correctly, when the theorem applies, and why "just use CRT" is safe only if the algebraic preconditions really hold.

## The Concept

CRT is a statement about compatibility between one big clock and several smaller clocks.

If the moduli are pairwise coprime, then each value mod the product corresponds to exactly one tuple of residues:

```text
Z / (n1*n2*...*nk) Z  <->  Z/n1Z × Z/n2Z × ... × Z/nkZ
```

For `n1 = 3`, `n2 = 5`, `n3 = 7`, the big clock has size `105`. Every number mod `105` has one residue triple:

```text
x = 23
23 mod 3 = 2
23 mod 5 = 3
23 mod 7 = 2
```

CRT says the reverse direction also works:

```text
(2 mod 3, 3 mod 5, 2 mod 7)  ->  unique x mod 105
```

Why does coprimality matter? Because the smaller clocks must not contradict each other. This system is impossible:

```text
x ≡ 1 (mod 2)
x ≡ 0 (mod 4)
```

The second congruence forces `x` to be even, the first forces `x` to be odd. Shared factors let those constraints collide.

There are two practical reconstruction views:

1. **Textbook CRT formula.**
   Build a weighted sum using the total product `N = n1*...*nk`, partial products `Ni = N/ni`, and inverses of `Ni mod ni`.
2. **Garner's algorithm.**
   Reconstruct incrementally in mixed-radix form so you do not need the full giant product up front.

The textbook formula is the clean proof. Garner is the implementation mindset that shows up in RSA-CRT code.

## Build It

### Step 1: Reuse EEA to build modular inverses

CRT needs inverses. If `Ni = N / ni`, then we want a number `ui` such that:

```text
Ni * ui ≡ 1 (mod ni)
```

That inverse exists exactly because `Ni` and `ni` are coprime. So lesson 02 and lesson 03 are the engine under the hood:

```python
def mod_inverse(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")

    g, s, _ = extended_gcd(a, n)
    if g != 1:
        raise ValueError("not invertible modulo n")
    return s % n
```

### Step 2: Validate the CRT precondition

Do not silently accept broken systems. In this course, CRT means pairwise-coprime moduli:

```python
def validate_crt_system(residues: list[int], moduli: list[int]) -> None:
    if len(residues) != len(moduli):
        raise ValueError("residues and moduli must have the same length")
    if len(moduli) == 0:
        raise ValueError("CRT system must be non-empty")
    if any(n <= 0 for n in moduli):
        raise ValueError("all moduli must be positive")

    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd(moduli[i], moduli[j]) != 1:
                raise ValueError("moduli must be pairwise coprime")
```

That one guardrail prevents a lot of later pain.

### Step 3: Implement the textbook CRT formula

Let `N = n1*n2*...*nk`. For each congruence:

- `Ni = N / ni`
- `ui = Ni^(-1) mod ni`
- `Ni * ui` is `1 mod ni` and `0 mod nj` for every `j != i`

So the weighted sum isolates each residue in the right coordinate:

```python
from math import prod


def crt(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    validate_crt_system(residues, moduli)

    n = prod(moduli)
    x = 0

    for residue, modulus in zip(residues, moduli):
        partial = n // modulus
        inverse = mod_inverse(partial, modulus)
        x += (residue % modulus) * partial * inverse

    return x % n, n
```

Example:

```python
x, n = crt([2, 3, 2], [3, 5, 7])
assert (x, n) == (23, 105)
```

### Step 4: Reconstruct with Garner's algorithm

The textbook formula computes the full product first. Garner reconstructs incrementally:

```text
x = c0 + c1*n0 + c2*n0*n1 + ...
```

Each new coefficient is chosen so the current partial sum matches the next residue class.

```python
def garner(residues: list[int], moduli: list[int]) -> tuple[int, int]:
    validate_crt_system(residues, moduli)

    coeffs = [residue % modulus for residue, modulus in zip(residues, moduli)]

    for i in range(len(moduli)):
        for j in range(i):
            coeffs[i] = (
                (coeffs[i] - coeffs[j]) * mod_inverse(moduli[j], moduli[i])
            ) % moduli[i]

    x = 0
    factor = 1
    for coeff, modulus in zip(coeffs, moduli):
        x += coeff * factor
        factor *= modulus

    return x % factor, factor
```

It gives the same answer:

```python
x, n = garner([2, 3, 2], [3, 5, 7])
assert (x, n) == (23, 105)
```

### Step 5: Apply CRT to RSA recombination

RSA-CRT computes the message separately mod `p` and mod `q`, then recombines:

```python
def rsa_crt_recombine(m_p: int, m_q: int, p: int, q: int) -> int:
    x, _ = crt([m_p, m_q], [p, q])
    return x


def rsa_crt_decrypt(ciphertext: int, d: int, p: int, q: int) -> int:
    m_p = pow(ciphertext, d % (p - 1), p)
    m_q = pow(ciphertext, d % (q - 1), q)
    return rsa_crt_recombine(m_p, m_q, p, q)
```

That is the performance win: two half-size exponentiations plus one recombination.

## Use It

Python's built-in `pow(base, exp, mod)` already gives you fast modular exponentiation, and production RSA implementations use CRT internally when the private key contains `p` and `q`.

In PyCryptodome, for example, RSA private keys store the prime factors and CRT coefficients because decryption/signing is faster that way. The difference from our lesson code is not the theorem. The difference is engineering:

- constant-time arithmetic
- blinded exponentiation
- fault checks after CRT recombination
- hardened key parsing and validation

So the real-world lesson is:

```text
same algebra, much stricter implementation discipline
```

## Attack It

### Hastad's broadcast attack

If the same plaintext `m` is sent to `e` recipients using the same small exponent `e` and different pairwise-coprime moduli `n1, ..., ne`, then each ciphertext satisfies:

```text
ci ≡ m^e (mod ni)
```

CRT recombines these into one congruence mod `N = n1*...*ne`. If `m^e < N`, then this is not just a modular statement anymore. It is the exact integer `m^e`. The attacker takes the ordinary integer `e`-th root and recovers `m`.

Defense: randomized padding such as OAEP. Never textbook RSA.

### Bellcore fault attack on RSA-CRT

CRT also increases the blast radius of a fault. If a signer computes the `mod p` branch correctly but a hardware glitch corrupts the `mod q` branch, the recombined signature can leak a factor:

```text
gcd(s^e - m, n) = p    or    q
```

One faulty signature can factor the RSA modulus.

Defense: verify the CRT result before releasing it, or recompute and compare.

## Ship It

This lesson ships a reusable checklist in `outputs/skill-crt-sanity-check.md`. The idea is simple: before you use CRT in code or in an argument, verify three things:

1. the moduli are pairwise coprime
2. every inverse you rely on really exists
3. if this is RSA-CRT, recombination is followed by fault-aware validation

That artifact is meant to be reused later in RSA, Pohlig-Hellman, and broadcast-attack lessons.

## Exercises

1. **Easy.** Solve `x ≡ 4 (mod 9)` and `x ≡ 2 (mod 5)` with your `crt` function. Verify the result directly.
2. **Medium.** Write a helper that returns the residue tuple of `x` for a list of moduli, then check that `crt(residues(x), moduli)` returns `x mod N`.
3. **Hard.** Simulate Hastad's attack with `e = 3`: encrypt the same small message for three different RSA moduli, CRT-combine the ciphertexts, and recover the message by integer cube root.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Pairwise coprime | "All the moduli are unrelated" | Every pair has gcd 1, so inverse-based recombination works cleanly |
| CRT recombination | "Glue the answers together" | Recover the unique residue class mod the product from local residue classes |
| Partial product `Ni` | "Everything except one modulus" | `N / ni`, used to isolate the `i`-th congruence |
| Garner's algorithm | "An optimized CRT" | Incremental mixed-radix reconstruction without relying on one giant sum |
| RSA-CRT | "Fast RSA" | Compute mod `p` and mod `q` separately, then recombine mod `n = p*q` |
| Broadcast attack | "CRT breaks RSA" | CRT enables recovery only when RSA is misused without padding |

## Test Vectors

Source: project-internal CRT examples cross-checked against direct congruence arithmetic and the standard small RSA classroom example `p=61`, `q=53`, `e=17`, `d=2753`.

## Further Reading

- [Handbook of Applied Cryptography, Chapter 2](https://cacr.uwaterloo.ca/hac/about/toc/toc2.html) — concise number-theory background and modular arithmetic tools
- [Handbook of Applied Cryptography, Chapter 8](https://cacr.uwaterloo.ca/hac/about/toc/toc8.html) — RSA implementation details, including CRT motivation and caveats
