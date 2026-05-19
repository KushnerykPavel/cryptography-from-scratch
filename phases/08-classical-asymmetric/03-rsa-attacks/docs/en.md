# Attacking Textbook RSA — Common Modulus, Håstad, Wiener
> Reuse the modulus, reuse the plaintext, or shrink `d` — and RSA unravels.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 08, Lesson 01 (RSA from Scratch), Lesson 02 (RSA Padding); Phase 00, Lesson 03 (Big Integers), Lesson 04 (Test Vectors)  
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why “textbook RSA” is fragile under key hygiene failures
- Compute plaintext recovery in the common modulus setting using Bézout coefficients
- Implement Håstad’s broadcast attack with CRT + an integer `e`-th root
- Distinguish which failures are solved by padding (OAEP/PSS) vs key generation/hygiene
- Apply a practical checklist to spot these attack preconditions in real systems

## The Problem

RSA is a math trapdoor: if you don’t know the factors of `n = p*q`, inverting `c = m^e mod n` should be hard. That *only* holds when systems respect the “boring” rules around RSA: each key must have a unique modulus, encryption must be randomized (OAEP), and the secret exponent `d` must not be “too small”.

Real systems fail in boring ways. A PKI service accidentally reuses the same modulus `n` while issuing different public exponents to different users. A backend broadcasts the same (deterministic) token to multiple recipients using a small public exponent `e=3`. A performance “optimization” picks a tiny `d` to speed decryption. None of these require factoring `n` — but they can still let an attacker recover plaintexts (or even the private key).

This lesson gives you an attacker’s mental model: *what public information is enough to break RSA when someone violates the rules?* You’ll implement three classic attacks and see the exact preconditions where they work.

## The Concept

Textbook RSA treats messages as integers:

- public key: `(n, e)`
- secret key: `d` such that `e*d ≡ 1 (mod φ(n))`
- encrypt: `c = m^e mod n`
- decrypt: `m = c^d mod n`

The attacks in this lesson are “algebra wins” attacks. They don’t rely on advanced factoring — they rely on *reused structure*.

### Common modulus attack (same `n`)

If the same plaintext `m` is encrypted under the *same modulus* `n` but two different exponents `e1, e2`, you observe:

```
c1 = m^e1 mod n
c2 = m^e2 mod n
```

If `gcd(e1, e2) = 1`, there exist integers `a, b` such that:

```
a*e1 + b*e2 = 1
```

Then:

```
(m^e1)^a * (m^e2)^b = m^(a*e1 + b*e2) = m  (mod n)
```

Negative exponents mean modular inverses.

### Håstad broadcast attack (same `m`, small `e`)

If the same plaintext is sent to multiple recipients using the same small exponent `e` and different coprime moduli `n_i`, you observe:

```
c_i = m^e mod n_i
```

Using the Chinese Remainder Theorem (CRT), you can combine the congruences into a single value `x` such that:

```
x ≡ m^e (mod n_1 * n_2 * ... * n_k)
```

If `m^e` is smaller than the product modulus, then that congruence is actually equality: `x = m^e` as an integer, and you can recover `m` by taking an integer `e`-th root.

### Wiener’s attack (small `d`)

If the private exponent `d` is too small (roughly `d < n^(1/4)/3`), you can recover it from public data `(e, n)` using continued fractions. The key observation is that `e/φ(n)` is close to `k/d` for some integer `k`, and continued fractions find “best” rational approximations.

## Build It

### Step 1: RSA math helpers

We’ll build a small set of helpers you’ll reuse across all three attacks:

- extended GCD + modular inverse (including negative exponents)
- CRT combiner for pairwise coprime moduli
- integer `n`-th root (floor + perfect-power check)
- “RSA as integers” encrypt/decrypt wrappers for demos and tests

```python
from __future__ import annotations

import json
from math import gcd, isqrt
from pathlib import Path


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0 and b == 0:
        raise ValueError("at least one of a,b must be nonzero")

    x0, y0, x1, y1 = 1, 0, 0, 1
    aa, bb = a, b
    while bb != 0:
        q = aa // bb
        aa, bb = bb, aa - q * bb
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return aa, x0, y0


def modinv(a: int, n: int) -> int:
    if n <= 0:
        raise ValueError("modulus must be positive")
    aa = a % n
    g, x, _ = egcd(aa, n)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % n


def pow_mod_signed(base: int, exponent: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    b = base % modulus
    if exponent >= 0:
        return pow(b, exponent, modulus)
    inv = modinv(b, modulus)
    return pow(inv, -exponent, modulus)


def crt_combine(pairs: list[tuple[int, int]]) -> tuple[int, int]:
    if not pairs:
        raise ValueError("pairs must be non-empty")

    x = 0
    modulus = 1
    for a_i, n_i in pairs:
        if n_i <= 0:
            raise ValueError("modulus must be positive")
        if gcd(modulus, n_i) != 1:
            raise ValueError("moduli must be pairwise coprime")

        a_i %= n_i
        t = ((a_i - x) % n_i) * modinv(modulus % n_i, n_i) % n_i
        x = x + modulus * t
        modulus *= n_i
        x %= modulus

    return x, modulus


def integer_nth_root_floor(x: int, n: int) -> int:
    if x < 0:
        raise ValueError("x must be nonnegative")
    if n <= 0:
        raise ValueError("n must be positive")
    if n == 1:
        return x
    if x in (0, 1):
        return x
    if n == 2:
        return isqrt(x)

    hi = 1 << ((x.bit_length() + n - 1) // n)
    lo = 0
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if mid**n <= x:
            lo = mid
        else:
            hi = mid
    return lo


def is_perfect_nth_power(x: int, n: int) -> int | None:
    r = integer_nth_root_floor(x, n)
    if r**n == x:
        return r
    return None


def rsa_encrypt_int(m: int, e: int, n: int) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")
    if m < 0 or m >= n:
        raise ValueError("message representative out of range")
    if e <= 0:
        raise ValueError("e must be positive")
    return pow(m, e, n)


def rsa_decrypt_int(c: int, d: int, n: int) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")
    if c < 0 or c >= n:
        raise ValueError("ciphertext representative out of range")
    if d <= 0:
        raise ValueError("d must be positive")
    return pow(c, d, n)
```

### Step 2: Common modulus attack

This attack recovers `m` from `(n, e1, e2, c1, c2)` without factoring when the modulus is reused and `gcd(e1, e2) = 1`.

```python
def common_modulus_attack(*, n: int, e1: int, e2: int, c1: int, c2: int) -> int:
    if n <= 1:
        raise ValueError("n must be > 1")
    if e1 <= 0 or e2 <= 0:
        raise ValueError("exponents must be positive")
    if c1 < 0 or c1 >= n or c2 < 0 or c2 >= n:
        raise ValueError("ciphertexts out of range")

    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError("e1 and e2 must be coprime")

    part1 = pow_mod_signed(c1, a, n)
    part2 = pow_mod_signed(c2, b, n)
    return (part1 * part2) % n
```

### Step 3: Håstad broadcast attack (e=3)

This attack recovers a plaintext `m` that was sent to multiple recipients with the same small `e` and no padding, by combining ciphertexts with CRT and taking an integer `e`-th root.

```python
def hastad_broadcast_attack(*, cs: list[int], ns: list[int], e: int) -> int:
    if e <= 1:
        raise ValueError("e must be > 1")
    if len(cs) != len(ns) or not cs:
        raise ValueError("cs and ns must have same nonzero length")

    x, _ = crt_combine(list(zip(cs, ns)))
    m = is_perfect_nth_power(x, e)
    if m is None:
        raise ValueError("combined value is not a perfect e-th power")
    return m
```

### Step 4: Wiener’s attack (small d)

Wiener’s attack uses continued fractions to recover a too-small secret exponent `d` from the public key `(e, n)`. Once you can compute `φ(n)` from a candidate `(k, d)`, you can solve for `(p, q)` by turning:

```
φ(n) = (p-1)(q-1) = pq - (p+q) + 1
```

into a quadratic with discriminant check.

```python
def continued_fraction(numer: int, denom: int) -> list[int]:
    if denom <= 0:
        raise ValueError("denom must be positive")
    if numer < 0:
        raise ValueError("numer must be nonnegative")

    out: list[int] = []
    n, d = numer, denom
    while d != 0:
        q = n // d
        out.append(q)
        n, d = d, n - q * d
    return out


def convergents(cf: list[int]) -> list[tuple[int, int]]:
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    out: list[tuple[int, int]] = []
    for a in cf:
        p = a * p1 + p0
        q = a * q1 + q0
        out.append((p, q))
        p0, p1 = p1, p
        q0, q1 = q1, q
    return out


def factor_from_phi(*, n: int, phi: int) -> tuple[int, int] | None:
    s = n - phi + 1
    disc = s * s - 4 * n
    if disc < 0:
        return None
    r = isqrt(disc)
    if r * r != disc:
        return None
    if (s + r) % 2 != 0:
        return None
    p = (s + r) // 2
    q = (s - r) // 2
    if p * q != n:
        return None
    return (p, q) if p <= q else (q, p)


def wiener_attack_recover_key(*, e: int, n: int) -> tuple[int, int, int] | None:
    if n <= 1:
        raise ValueError("n must be > 1")
    if e <= 1 or e >= n:
        raise ValueError("e must satisfy 1 < e < n")

    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        ed1 = e * d - 1
        if ed1 % k != 0:
            continue
        phi = ed1 // k
        factors = factor_from_phi(n=n, phi=phi)
        if factors is None:
            continue
        p, q = factors
        return p, q, d

    return None
```

Run it:
python3 code/main.py

## Use It

In production, you almost never want “textbook RSA”.

- **Python `cryptography`**: uses OAEP for encryption and PSS for signatures; keys are generated with safe parameters and validated.
- **OpenSSL**: exposes RSA-OAEP and RSA-PSS; has guardrails around key generation.
- **Hardware-backed keys (TPM/HSM)**: reduce key-exfiltration risk, but *do not* fix protocol mistakes like deterministic plaintext broadcast.

The “use it” rule of thumb:

- **Encryption**: RSA-OAEP (or better: hybrid KEM+DEM like X25519+AEAD, or RSA-KEM).
- **Signatures**: RSA-PSS (or better: Ed25519 / ECDSA / BLS depending on needs).

## Pitfalls

- Reusing the same RSA modulus `n` across multiple public keys (common modulus attack).
- Sending the same deterministic plaintext under multiple RSA public keys with small `e` (broadcast attacks).
- Treating RSA as a “hashless transform”: `c = m^e mod n` with no padding/encoding (malleability + structural leaks).
- Choosing `d` to be “small for speed” (Wiener/Boneh–Durfee style attacks).
- Forgetting to enforce message representative bounds (`0 <= m < n`) and key sanity checks (`1 < e < n`, coprime conditions).

## Ship It

This lesson ships a reusable RSA attack triage checklist you can paste into a PR review or security assessment.

- File: `outputs/prompt-rsa-attack-triage.md`
- Use it when reviewing systems that claim “we use RSA” — it forces you to ask “which RSA, with which padding, and are any of the textbook-attack preconditions present?”

## Exercises

1. Easy: Run `python3 code/main.py`. Observe how each attack recovers `m` (and Wiener recovers `(p, q, d)`) without factoring in the usual sense.
2. Medium: Modify the broadcast demo so that `m^e` is *not* smaller than `n1*n2*n3` (e.g. increase `m`). Confirm `hastad_broadcast_attack` rejects because the combined value is no longer a perfect `e`-th power.
3. Hard: Take a real codebase that uses RSA (or a TLS stack wrapper), and use `outputs/prompt-rsa-attack-triage.md` to produce a 1-page risk assessment: what is safe, what is ambiguous, and what you would change.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Textbook RSA | “RSA encryption” | Raw modular exponentiation with no randomized padding; almost never safe |
| Common modulus | “Same key, different exponent” | Reusing `n` lets an attacker algebraically combine ciphertexts to recover `m` |
| CRT | “Combine congruences” | A deterministic way to glue `(x mod n_i)` into one `x mod Π n_i` |
| Håstad broadcast | “Small exponent break” | If the same `m` is sent to enough recipients, you can recover `m` by CRT + root |
| Wiener’s attack | “Small d break” | Continued fractions recover `d` when the private exponent is too small |

## Further Reading

- Menezes, van Oorschot, Vanstone, *Handbook of Applied Cryptography* (1996) — Chapter 8: RSA attacks (common modulus, broadcast, small `d`).
- Wiener, *Cryptanalysis of Short RSA Secret Exponents* (1990) — the original continued-fraction attack on small `d`.
- Boneh & Shoup, *A Graduate Course in Applied Cryptography* (ongoing) — clear RSA chapter with attacks and mitigations.
- RFC 8017, *PKCS #1 v2.2* (2016) — defines RSA-OAEP and RSA-PSS (the “don’t use textbook RSA” standard).
