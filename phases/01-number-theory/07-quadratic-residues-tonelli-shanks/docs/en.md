# Quadratic Residues & Tonelli-Shanks

> Squaring is easy. Unsquaring is where the field structure starts to matter.

**Type:** Build
**Languages:** Python
**Prerequisites:** 03-modular-inverse-and-fast-exp, 04-fermat-and-euler, 05-chinese-remainder-theorem, 06-totient-and-carmichael
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain why exactly half of the non-zero residues modulo an odd prime are quadratic residues
- Apply Euler's criterion a^((p-1)/2) mod p to decide whether a square root exists before attempting extraction
- Implement Tonelli-Shanks by factoring p-1 into q·2^s and iteratively reducing the order of the auxiliary element t
- Distinguish the closed-form shortcut a^((p+1)/4) mod p (valid when p ≡ 3 mod 4) from the general Tonelli-Shanks algorithm
- Identify how obtaining two non-negated square roots modulo a composite n = p·q via gcd(r − s, n) reveals a prime factor

## The Problem

Suppose an elliptic-curve point arrives compressed: you get the `x` coordinate and one extra parity bit, and you need to recover `y`. That recovery step is a modular square root. If you cannot compute square roots modulo a prime efficiently, point decompression is impossible.

The same issue appears in probabilistic cryptosystems and zero-knowledge protocols. A verifier may need to check whether a value is a square modulo a prime, or a prover may need to construct one deliberately. Brute-force search works for `p = 11`. It is useless once the modulus is large.

This lesson gives you the decision procedure and the construction algorithm. First you learn how to tell whether `a` is a square modulo an odd prime `p`. Then you learn how to actually recover the root with Tonelli-Shanks, the standard all-primes algorithm behind many real cryptographic implementations.

## The Concept

### What a quadratic residue is

For an odd prime `p`, a residue `a mod p` is a quadratic residue if some `x` satisfies:

```text
x^2 ≡ a (mod p)
```

Examples modulo `7`:

```text
0^2 ≡ 0
1^2 ≡ 1
2^2 ≡ 4
3^2 ≡ 2
4^2 ≡ 2
5^2 ≡ 4
6^2 ≡ 1
```

So the residues are:

```text
{0, 1, 2, 4}
```

Among the non-zero residues, exactly half are squares. That is because `x` and `-x` have the same square, so squaring is a 2-to-1 map on `(Z/pZ)*`.

### Euler's criterion

Lesson 04 told you that exponentiation can test structure. Here it tests whether a square root exists:

```text
a^((p - 1)/2) ≡ 1   (mod p)   if a is a non-zero quadratic residue
a^((p - 1)/2) ≡ -1  (mod p)   if a is a quadratic non-residue
```

That value is the Legendre symbol in exponentiation form:

```text
(a / p) = a^((p - 1)/2) mod p
```

with the convention that the result is interpreted as `1`, `-1`, or `0`.

### The easy case: `p ≡ 3 (mod 4)`

When the prime has the form `p = 4k + 3`, a square root drops out directly:

```text
x ≡ a^((p + 1)/4) (mod p)
```

Why it works:

```text
x^2 = a^((p + 1)/2) = a * a^((p - 1)/2) ≡ a * 1 ≡ a (mod p)
```

This covers many practical primes, but not all of them.

### Why Tonelli-Shanks is needed

For general odd primes, write:

```text
p - 1 = q * 2^s
```

with `q` odd. Tonelli-Shanks uses that factorization to peel off the awkward power-of-two part of the group order. The algorithm keeps an invariant:

```text
r^2 ≡ a * t (mod p)
```

and repeatedly shrinks the order of `t` until `t = 1`, at which point `r^2 ≡ a`.

The trick is to seed the process with a quadratic non-residue `z`. Since `z^q` lives in the 2-power torsion part of the group and is not `1`, it gives the algorithm a way to rotate `t` downward until it becomes trivial.

### Why composite moduli change the game

Modulo `n = p*q`, a square typically has four roots, not two. CRT combines `±rp mod p` with `±rq mod q` into four roots modulo `n`.

That matters because square-root oracles modulo composites can leak factors. If you ever obtain two different roots `r` and `s` of the same square modulo `n`, and they are not just negatives of each other, then:

```text
gcd(r - s, n)
```

reveals a non-trivial factor. This is the algebraic idea behind why square-root extraction modulo composite RSA-style moduli is factoring-sensitive.

## Build It

### Step 1: Test whether a root exists

Start with Euler's criterion in code. That gives you a fast yes/no answer for odd prime moduli.

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

Now `1` means residue, `-1` means non-residue, and `0` means the input was divisible by `p`.

### Step 2: Take the shortcut when `p % 4 == 3`

Do not run Tonelli-Shanks when a closed form exists.

```python
def sqrt_mod_prime_3mod4(a: int, p: int) -> int:
    if p % 4 != 3:
        raise ValueError("p must satisfy p % 4 == 3")
    if legendre_symbol(a, p) != 1:
        raise ValueError("a is not a quadratic residue mod p")

    return pow(a, (p + 1) // 4, p)
```

For deterministic tests, normalize to the smaller of the two roots `r` and `p - r`.

### Step 3: Find a quadratic non-residue

Tonelli-Shanks needs one witness `z` that is definitely not a square.

```python
def find_quadratic_non_residue(p: int) -> int:
    for z in range(2, p):
        if legendre_symbol(z, p) == -1:
            return z
    raise ValueError("no quadratic non-residue found")
```

Over a prime field this linear search is fine for educational-scale inputs.

### Step 4: Implement Tonelli-Shanks

Factor `p - 1` into `q * 2^s`, initialize the state, then keep reducing the order of `t`.

```python
def tonelli_shanks(a: int, p: int) -> int:
    a %= p
    if a == 0:
        return 0
    if legendre_symbol(a, p) != 1:
        raise ValueError("a is not a quadratic residue mod p")
    if p % 4 == 3:
        return sqrt_mod_prime_3mod4(a, p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = find_quadratic_non_residue(p)
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    while t != 1:
        i = 1
        t_power = (t * t) % p
        while i < m and t_power != 1:
            t_power = (t_power * t_power) % p
            i += 1

        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i

    return r
```

The algorithm returns one root. The other is always `-r mod p`.

### Step 5: Lift the prime roots to a composite with CRT

This is not the production target of Tonelli-Shanks, but it is the cryptographic consequence you should understand.

```python
def sqrt_mod_semiprime_via_crt(a: int, p: int, q: int) -> tuple[int, int, int, int]:
    roots_p = all_square_roots_prime(a, p)
    roots_q = all_square_roots_prime(a, q)
    roots = set()
    for rp in roots_p:
        for rq in roots_q:
            roots.add(crt_two(rp, p, rq, q) % (p * q))
    return tuple(sorted(roots))
```

That produces the four roots modulo `n = p*q`.

Run it:

```
python3 code/main.py
```

## Use It

Real libraries do not usually expose Tonelli-Shanks as a standalone teaching function, but the idea shows up everywhere:

- Elliptic-curve point decompression recovers `y` from `x` by solving a modular square-root problem in the field.
- Hash-to-curve implementations need residue tests and square-root extraction inside field arithmetic.
- Finite-field libraries often specialize the fast `p % 4 == 3` path and fall back to Tonelli-Shanks otherwise.

In production code, the root extraction is field-aware, constant-time where needed, and integrated with curve formulas. Your from-scratch version is for understanding the algebra, not for handling secrets safely.

## Attack It

The attack is not against Tonelli-Shanks over a prime field. The attack is against the idea of getting square roots modulo a composite for free.

Take `n = 77 = 7 * 11` and `a = 9`. The four roots modulo `77` are:

```text
3, 25, 52, 74
```

Check:

```text
3^2  ≡ 9 (mod 77)
25^2 ≡ 9 (mod 77)
52^2 ≡ 9 (mod 77)
74^2 ≡ 9 (mod 77)
```

Now use two roots that are not negatives of each other, say `3` and `25`:

```text
gcd(25 - 3, 77) = gcd(22, 77) = 11
```

One factor falls out immediately. That is why modular square roots over composites are tied to factoring hardness, why the Rabin cryptosystem needs care, and why Goldwasser-Micali is built around distinguishing residues from non-residues rather than handing out roots.

## Ship It

Save a reusable review artifact in `outputs/skill-tonelli-shanks-checklist.md`.

This lesson's shipped skill is a compact checklist for answering three questions:

1. Is the modulus actually an odd prime?
2. Does Euler's criterion say a root exists?
3. If this is a composite modulus, are we accidentally turning a root oracle into a factoring oracle?

## Exercises

1. Easy: list all quadratic residues modulo `13`, then verify Euler's criterion on each non-zero one.
2. Medium: modify the code to return both roots in prime fields and benchmark the `p % 4 == 3` shortcut against full Tonelli-Shanks.
3. Hard: implement the Jacobi symbol for odd composite moduli and find values with Jacobi symbol `+1` that are not true quadratic residues modulo `n = p*q`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Quadratic residue | "A square mod `p`" | A residue `a` for which some `x` satisfies `x^2 ≡ a (mod p)` |
| Quadratic non-residue | "Not a square" | A non-zero residue with no modular square root |
| Euler's criterion | "The residue test" | Exponentiation test `a^((p-1)/2) mod p` that returns `1` or `-1` over odd primes |
| Legendre symbol | "Residue sign" | Notation `(a/p)` encoding whether `a` is zero, a residue, or a non-residue mod prime `p` |
| Tonelli-Shanks | "The square-root algorithm" | General algorithm for solving `x^2 ≡ a (mod p)` over odd primes |
| Quadratic residuosity problem | "Residue or not?" | Decision problem of distinguishing squares from carefully chosen non-squares, especially over composites |

## Test Vectors

Source: project-internal theorem examples cross-checked with Python's built-in modular exponentiation and CRT identities. Code must pass `tests/vectors.json`.

## Further Reading

- [Handbook of Applied Cryptography, Chapter 3](https://cacr.uwaterloo.ca/hac/about/chap3.pdf) — Residues, Legendre/Jacobi symbols, and modular square roots
- [Tonelli-Shanks algorithm on Wikipedia](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm) — Compact algorithm summary with worked examples
- [SEC 1 v2.0](https://www.secg.org/sec1-v2.pdf) — Example of where modular square roots appear in elliptic-curve point encoding
