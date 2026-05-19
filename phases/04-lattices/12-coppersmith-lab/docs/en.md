# Lattice Lab — Break a Toy RSA with Coppersmith

> If part of an RSA plaintext is “fixed + small unknown”, you can turn decryption into “find a small root mod N” — and lattices can do that.

**Type:** Build
**Languages:** Python
**Prerequisites:** `04-lattices/05-lll` (LLL reduction). Comfort with textbook RSA (`c = m^e mod N`) and modular arithmetic.
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how a stereotyped RSA message (known prefix A, small unknown suffix x) reduces decryption to finding a small root of a polynomial congruence f(x) ≡ 0 mod N
- Implement the Howgrave–Graham polynomial basis: scale shifted copies of f(x)^i by powers of N and X to encode the root-size bound into the lattice
- Apply LLL to the coefficient-vector lattice and convert the short output vector back into a polynomial with an integer root
- Verify recovered roots by checking f(x₀) ≡ 0 mod N and reconstructing the plaintext m = A + x₀
- Identify the parameters m (power depth) and t (x-shifts) and explain how lattice dimension n = d·m + t trades off success probability against runtime

## The Problem

Textbook RSA (no padding) is brittle: it is not enough that “RSA is hard” in the abstract. Security depends on *how you encode and pad messages*.

In the real world, many plaintexts are structured:

- a protocol banner,
- a JSON prefix,
- a fixed header + a few unknown bytes,
- “the password today is: ____”.

If the unknown part is small enough (relative to `N` and `e`), then the attacker can recover it without factoring `N`.

This lesson teaches the lattice technique behind that break: **Coppersmith’s method (Howgrave–Graham form)** for finding **small integer roots of a polynomial congruence** modulo a composite.

## The Concept

### From RSA to “small root modulo N”

Suppose a plaintext has the form:

```text
m = A + x
```

where:

- `A` is known (the fixed prefix),
- `x` is unknown but bounded: `|x| < X`,
- ciphertext is `c ≡ m^e (mod N)`.

Then `x` satisfies:

```text
f(x) = (A + x)^e - c  ≡ 0  (mod N)
```

So breaking RSA in this setting becomes:

> Find an integer `x` with `|x| < X` such that `f(x) ≡ 0 (mod N)`.

### The key trick: “mod N root” → “integer root”

Howgrave–Graham’s viewpoint is:

1. Build many related polynomials that all vanish at `x0` modulo a large power of `N`.
2. Treat each polynomial as a coefficient vector (a lattice basis vector).
3. Run **LLL** to find a short integer combination.
4. That short combination corresponds to a polynomial `h(x)` with small coefficients.
5. If `h(x0)` is divisible by `N^m` *and* `|h(x0)| < N^m`, then `h(x0) = 0` over the integers.

That final step is the bridge: the modular condition plus a norm bound forces an exact integer equation.

### What the lattice encodes

For a monic univariate `f` of degree `d`, choose parameters `m, t` and build:

```text
g_{i,j}(x) = x^j * N^{m-i} * f(x)^i     for i = 0..m-1,  j = 0..d-1
g_{m,j}(x) = x^j * f(x)^m              for j = 0..t-1
```

Then scale by `X` so that “small roots” correspond to “small values”:

```text
g_{i,j}(xX)
```

The coefficient vectors of these scaled polynomials form a lattice basis. LLL finds a short vector, which maps back to a polynomial `h(x)` that (heuristically) has `x0` as an *integer* root.

## Build It

This lesson’s implementation lives in `code/main.py`.

Run the demo:

```bash
.venv/bin/python phases/04-lattices/12-coppersmith-lab/code/main.py
```

### Step 1: Model the “known prefix + unknown suffix” message

Build `f(x) = (A + x)^e - c (mod N)` with `|x| < X`:

```python
from main import stereotyped_rsa_polynomial

pol = stereotyped_rsa_polynomial(A=A, e=e, c=c, N=N)
```

The polynomial is monic (leading coefficient `1`), which is important for the standard univariate guarantee.

### Step 2: Construct the Howgrave–Graham polynomial set

Implement the standard basis set:

```python
from main import coppersmith_howgrave_univariate

roots = coppersmith_howgrave_univariate(pol, N, beta=1, m=3, t=0, X=2**kbits)
```

In this lab:

- `beta = 1` (we work modulo `N` itself),
- degree `d = e` (for `(A+x)^e - c`),
- `m` controls how many powers of `f` you include,
- `t` adds extra “x-shifts” at the highest power `f^m` (often `0` for the simplest `beta=1` demo).

### Step 3: Convert polynomials to a lattice basis

Each polynomial becomes one basis vector:

- column `k` holds the coefficient of `x^k` in the scaled polynomial,
- scaling by `X^k` is implemented by substituting `x → xX` before collecting coefficients.

The resulting basis is upper-triangular by construction (one polynomial per degree).

### Step 4: LLL-reduce the basis (exact rationals)

We reuse the “exact `Fraction` Gram–Schmidt” approach from the earlier LLL lesson:

- deterministic decisions,
- easy to reason about,
- good enough for small dimensions (this lab uses `n = d*m + t`).

### Step 5: Convert short vectors back to polynomials and extract integer roots

The LLL output vectors correspond to coefficient vectors of a polynomial `h(xX)`.

Divide each coefficient by `X^k` to recover `h(x)` and then find small integer roots:

- factor `h(x)` over the integers,
- keep integer roots `|x| < X`,
- verify `f(x) ≡ 0 (mod N)` (or equivalently `gcd(N, f(x)) = N` when `beta = 1`).

Run it:

```
python3 code/main.py
```

## Use It

In practice, you do not implement Coppersmith by hand.

Two common “real tool” paths:

1. **SageMath**: it has mature polynomial and lattice tooling, and its `small_roots(...)` helper is the usual one-liner for univariate Coppersmith demos.
2. **LLL libraries**: when you build the lattice yourself, you typically call an optimized LLL/BKZ implementation (e.g., `fplll`/`fpylll`) rather than exact `Fraction` arithmetic.

This lesson keeps everything in plain Python + SymPy so you can see the whole pipeline end-to-end.

## Attack It

This lab breaks **toy** textbook RSA in a stereotyped-message setting:

- RSA has *no padding* (this is the core vulnerability),
- the public exponent is small (we use `e = 3`),
- a large prefix `A` is known,
- only `k` low bits are unknown (`x < 2^k`).

The attacker:

1. forms `f(x) = (A + x)^3 - c (mod N)`,
2. runs the lattice construction + LLL,
3. recovers `x`,
4. reconstructs the plaintext `m = A + x`.

The lesson takeaway is not “RSA is broken”, but:

> Deterministic structure + missing padding turns RSA into a solvable algebra problem.

## Ship It

This lesson ships:

- `outputs/skill-coppersmith-stereotyped-rsa.md` — a checklist for “known prefix + small suffix” Coppersmith-style RSA breaks.

## Exercises

1. Easy: Change `kbits` (unknown suffix size). Find the largest `kbits` where the demo still reliably recovers `x` with your chosen `m,t`.
2. Medium: Keep `kbits` fixed and vary `m`. How does lattice dimension `n = d*m + t` affect success and runtime?
3. Hard: Replace the “known prefix” model with “known high bits of a prime factor” (`q = q0 + x`) by building `f(x) = x - q0 (mod N)` where the modulus root is modulo `q`. Use the `gcd(N, f(root))` check to recover a non-trivial factor.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Small root | “a root you can brute force” | An integer `x0` with `|x0| < X` where `X` is below a provable/heuristic threshold so lattice reduction can help |
| Coppersmith (univariate) | “find roots mod N” | Construct a lattice of shifted polynomials and use LLL to derive a polynomial that has the same root over the integers |
| Howgrave–Graham form | “Coppersmith revisited” | A simplified lattice construction and lemma that turns a modular multiple + norm bound into an exact integer root |
| Stereotyped message | “known prefix plaintext” | Plaintext `m = A + x` where `A` is known and `x` is short, enabling a polynomial congruence attack |
| LLL | “basis reduction” | A polynomial-time algorithm that finds short lattice vectors, used here to find a small-coefficient polynomial combination |

## Test Vectors

Source: the method is from Coppersmith (1997) and Howgrave–Graham (1997). This lesson’s test vector is a deterministic project-internal toy RSA instance designed for fast, deterministic reduction with exact `Fraction` arithmetic.

Your code must pass `tests/vectors.json`.

## Further Reading

- Don Coppersmith (1997). *Small Solutions to Polynomial Equations, and Low Exponent RSA Vulnerabilities* — the original small-root method and RSA applications
- Nick Howgrave-Graham (1997). *Finding Small Roots of Univariate Modular Equations Revisited* — practical reformulation used by most implementations
- Nguyen & Vallée (eds.). *The LLL Algorithm: Survey and Applications* — background for why the reduction step works
