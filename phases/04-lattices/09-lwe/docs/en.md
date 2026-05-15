# LWE — Learning With Errors

> Noisy linear equations that stay hard even when everything is “just linear algebra”.

**Type:** Build
**Languages:** Python
**Prerequisites:** 01-what-is-a-lattice, 05-lll, 08-gaussian-sampling (intuition for noise)
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

Modern post-quantum cryptography is built on problems that look deceptively simple: systems of linear equations. The trick is that the equations are **noisy**.

If you only know “solve linear equations”, lattice-based crypto can feel like magic: where does the hardness come from if everything is linear? LWE is the clean answer: you publish many equations, but each one is perturbed by a small, secret error. That error is enough to make the underlying secret hard to recover at the right dimensions.

This lesson gives you a working mental model and a working toy implementation:

- generate LWE samples `(A, b = A·s + e mod q)`,
- build a tiny public-key encryption scheme on top (Regev-style),
- and see a textbook “attack” that works when parameters are tiny (brute force), which explains why real schemes need large dimensions.

## The Concept

An LWE sample is a noisy linear equation modulo `q`.

Pick:

- modulus `q` (a small-ish integer),
- secret vector `s ∈ Z^n` (often “small”, e.g. ternary),
- public matrix `A ∈ Z_q^{m×n}`,
- small error vector `e ∈ Z^m` (e.g. discrete Gaussian / ternary).

Publish:

```text
b = A·s + e   (mod q)
```

If `e = 0`, then this is just linear algebra: recover `s` from `A` and `b` (assuming enough equations and invertibility).

If `e` is small but nonzero, each equation is “almost correct”, and the set of all near-solutions forms a lattice-like search space. For the right parameter regimes, recovering `s` is believed to be hard (even for quantum computers).

Two standard problem variants:

- **Search-LWE:** given `(A, b)` recover `s`.
- **Decision-LWE:** distinguish LWE samples from uniform random pairs `(A, u)`.

## Build It

### Step 1: Modular linear algebra helpers

You need a small toolbox for vectors and matrices modulo `q`:

- `dot_mod(a, b, q)` and `mat_vec_mul_mod(A, s, q)`,
- transpose multiplication `A^T·r`,
- and a “center lift” that maps `x mod q` back into a small signed representative in `[-q/2, q/2]`.

```python
from main import dot_mod, mat_vec_mul_mod, mat_t_vec_mul_mod, center_lift
```

### Step 2: Generate LWE samples

Key generation for “LWE-as-a-public-key” is:

1. sample uniform `A`,
2. sample small secret `s` and error `e`,
3. set `b = A·s + e (mod q)`.

```python
from main import LWEParams, Sha256CtrRng, lwe_keygen

params = LWEParams(n=4, m=8, q=97, error_bound=1)
rng = Sha256CtrRng(b"demo")
pk, sk = lwe_keygen(rng, params)
```

### Step 3: Encrypt one bit (Regev-style toy PKE)

To encrypt a bit `μ ∈ {0,1}`, we hide it in the “phase” term `q/2`:

```text
choose r ∈ {0,1}^m, small e1 ∈ Z^n, small e2 ∈ Z
u = A^T·r + e1            (mod q)
v = b^T·r + e2 + μ·(q/2)  (mod q)
```

Decrypt by removing the `A·s` part:

```text
x = v - u^T·s   (mod q)  ≈ μ·(q/2) + (small noise)
```

Then decide whether `x` is closer to `0` or `q/2` on the circle modulo `q`.

```python
from main import lwe_encrypt_bit, lwe_decrypt_bit

ct = lwe_encrypt_bit(rng, params, pk, 1)
mu_hat = lwe_decrypt_bit(params, sk, ct)
```

## Use It

Real schemes almost never implement “plain LWE” directly. They use structured variants (MLWE/RLWE) to get efficiency, careful noise sampling, constant-time implementations, and tight parameter choices.

Educational takeaway: your toy code is useful to learn the algebra and the role of error, but production LWE-based cryptography is a full engineering discipline (sampling, side channels, serialization, proofs, performance).

## Attack It

For real parameters, the best known attacks are sophisticated and require a lot of math (lattice reduction, BKW-style combinatorics, hybrid methods, etc.). For a **toy** LWE instance you can break it with brute force:

1. enumerate all candidate secrets `s ∈ {-1,0,1}^n`,
2. compute `e = b - A·s (mod q)`,
3. “center lift” each error coordinate into a signed integer,
4. accept `s` if all errors are within the expected bound.

This is not an attack you’d run in real life; it’s an intuition pump:

- hardness comes from the combinatorics of hiding `s` behind lots of noisy equations,
- dimension `n` is what kills brute force (and makes lattice reduction hard).

## Ship It

You ship a quick checklist for “what makes LWE work” (parameter knobs, encryption shape, decryption thresholding, toy attack) in `outputs/skill-lwe.md`.

## Exercises

1. Easy: change `q` and watch when decryption begins to fail (too much wrap-around).
2. Medium: switch the secret from ternary to uniform mod `q`, and adjust the brute-force “attack” accordingly.
3. Hard: implement a tiny “no-error” solver (set `e=0`) and compare “linear algebra solves it instantly” vs “noise makes it hard”.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| LWE sample | “a random equation mod q” | `(A, b=A·s+e mod q)` where `e` is small |
| Search-LWE | “recover the secret” | given `(A,b)`, find `s` that makes errors small |
| Decision-LWE | “looks random” | distinguish LWE from uniform random |
| Center lift | “undo mod q” | map `x mod q` into a small signed representative |

## Test Vectors

Source: Regev (2005) defines LWE and the basic public-key encryption construction; Peikert (2016) surveys practical variants. Vectors are project-internal deterministic instances for a fixed toy parameter set and SHA-256 counter-mode RNG. Code must pass `tests/vectors.json`.

## Further Reading

- Regev (2005) — original LWE paper and a foundational PKE construction.
- Peikert (2016) — practical intuition: parameters, errors, and why LWE is useful.
