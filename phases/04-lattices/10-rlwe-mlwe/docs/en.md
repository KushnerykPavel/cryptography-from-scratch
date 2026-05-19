# Ring-LWE & Module-LWE

> LWE, but your “vectors” are polynomials — structure buys speed, and you pay for it in assumptions.

**Type:** Build
**Languages:** Python
**Prerequisites:** 09-lwe
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how Ring-LWE replaces dense matrices with polynomial multiplication in Z_q[x]/(x^n + 1), reducing key sizes while preserving the noisy-equation hardness structure
- Implement cyclic polynomial multiplication using the relation x^n ≡ -1 for RLWE and x^n ≡ 1 for NTRU-style rings
- Distinguish RLWE (single polynomial, maximally structured) from MLWE (length-k vector of polynomials, tunable structure) and explain the security assumption tradeoff
- Apply Regev-style bit encryption and majority-vote decryption to toy RLWE and MLWE instances
- Identify why CRYSTALS-Kyber is based on MLWE and how module rank k tunes the structure-vs-assumption balance

## The Problem

Plain LWE is a beautiful definition, but it is expensive: it uses big dense matrices.

Real-world lattice cryptography needs to be fast and compact. To get there, almost every practical scheme adds **structure** to the public matrix so multiplication becomes polynomial arithmetic (and can use FFT/NTT-like speedups).

This lesson gives you a hands-on bridge from “matrix LWE” to the two workhorse variants used in modern post-quantum cryptography:

- **Ring-LWE (RLWE):** replace vectors with polynomials in a ring like `Z_q[x]/(x^n + 1)`.
- **Module-LWE (MLWE):** an in-between: vectors of polynomials (module rank `k`) to tune the structure/assumption tradeoff.

## The Concept

### From LWE to RLWE: pack n coordinates into one polynomial

In LWE you publish many noisy linear equations:

```text
b = A·s + e   (mod q)
```

In RLWE you keep the same idea (uniform “public” + small secret + small error), but you do it in a polynomial ring:

```text
R_q = Z_q[x] / (x^n + 1)

sample a ← R_q uniformly
sample s,e ← R (small)
publish b = a*s + e   in R_q
```

Intuition:

- A length-`n` vector becomes a degree-`< n` polynomial.
- Multiplying by a structured “matrix” becomes multiplying polynomials modulo `x^n + 1`.
- The “error” is still the whole point: without it, recovering the secret becomes easy.

### MLWE: tune structure with module rank k

RLWE is “maximally structured”. MLWE keeps the polynomial ring but reduces structure by using a small vector length `k`:

```text
a = (a1, ..., ak)   in R_q^k
s = (s1, ..., sk)   small in R^k
e small in R
publish b = <a, s> + e = a1*s1 + ... + ak*sk + e   in R_q
```

When `k=1`, MLWE looks like RLWE. When `k` grows, the structure is reduced.

## Build It

### Step 1: Polynomial arithmetic in Rq = Zq[x]/(x^n + 1)

Represent a polynomial as a length-`n` tuple of coefficients.

To multiply modulo `x^n + 1`, use the rule:

```text
x^n ≡ -1
```

So any term `c·x^{n+t}` “wraps” back to `-c·x^t`.

```python
from main import poly_mul_mod_xn_plus_1
```

### Step 2: RLWE toy public-key encryption (Regev-style, in a ring)

Key generation:

```text
pk = (a, b = a*s + e)   in R_q
sk = s (small)
```

Encrypt one bit `μ ∈ {0,1}` by hiding it at `q/2` (coefficient-wise):

```text
choose small r,e1,e2
u = a*r + e1
v = b*r + e2 + μ·(q/2)
ct = (u, v)
```

Decrypt:

```text
x = v - u*s  ≈ μ·(q/2) + noise
```

Then decide whether `x` is closer to `0` or `q/2` (we do a majority vote across coefficients in this toy).

```python
from main import RLWEParams, Sha256CtrRng, rlwe_keygen, rlwe_encrypt_bit, rlwe_decrypt_bit

params = RLWEParams(n=8, q=97, error_bound=1)
rng = Sha256CtrRng(b"demo")
pk, sk = rlwe_keygen(rng, params)
ct = rlwe_encrypt_bit(rng, params, pk, 1)
mu_hat = rlwe_decrypt_bit(params, sk, ct)
```

### Step 3: MLWE toy public-key encryption (module rank k)

MLWE is the same pattern, but the public key contains a vector of polynomials `a ∈ R_q^k` and the secret is `s ∈ R^k`:

```python
from main import MLWEParams, mlwe_keygen, mlwe_encrypt_bit, mlwe_decrypt_bit

params = MLWEParams(k=2, n=4, q=97, error_bound=1)
rng = Sha256CtrRng(b"demo")
pk, sk = mlwe_keygen(rng, params)
ct = mlwe_encrypt_bit(rng, params, pk, 1)
mu_hat = mlwe_decrypt_bit(params, sk, ct)
```

Run it:

```
python3 code/main.py
```

## Use It

In practice you usually don’t call “RLWE encryption” directly. Instead you use a full scheme whose security is based on MLWE/RLWE (plus careful sampling, compression, serialization, constant-time implementation, proofs, etc.).

Examples of where MLWE shows up:

- **CRYSTALS-Kyber (MLWE):** a standard KEM and a core building block for many PQ deployments.

Educational takeaway: your implementation is for learning the algebra and the noise story. Production systems require vetted parameters and constant-time libraries.

## Attack It

For real parameters, attacks are sophisticated and rely on lattice reduction and related techniques.

For **toy** parameters and a ternary secret, you can break both RLWE and MLWE by brute force:

1. enumerate all candidate secrets (RLWE: `s ∈ {-1,0,1}^n`, MLWE: `s ∈ {-1,0,1}^{k·n}`),
2. compute the implied error `e = b - a*s` (or `b - <a,s>`),
3. center-lift each coefficient and check it stays within the expected error bound.

This is not “real cryptanalysis”; it’s a sanity check that explains why real schemes need large dimensions.

## Ship It

`outputs/skill-rlwe-mlwe.md`: a quick checklist for implementing a deterministic toy RLWE/MLWE instance (ring arithmetic + bit encryption + tiny brute-force attack).

## Exercises

1. Easy: Change `n` (keep it a power of two) and confirm the test vectors still pass after regenerating them.
2. Medium: Replace majority-vote decoding with “decode only the constant coefficient” and compare failure rates for tiny `q`.
3. Hard: Implement polynomial multiplication using an NTT-friendly modulus (still toy parameters), then compare runtime vs. the naive `O(n^2)` method.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| RLWE | “LWE in a ring” | LWE where secrets/errors live in a polynomial ring and multiplication uses ring structure |
| MLWE | “in-between LWE and RLWE” | LWE over a module: short vectors of ring elements (module rank tunes structure) |
| `Z_q[x]/(x^n+1)` | “cyclotomic-ish ring” | polynomials modulo `q`, with the relation `x^n = -1` |
| center-lift | “map mod q to signed” | interpret a residue as a small signed integer in `[-q/2, q/2]` |

## Test Vectors

Source: RLWE is defined by Lyubashevsky–Peikert–Regev (2010). MLWE is a structured variant used in many modern lattice schemes.

Vectors in `tests/vectors.json` are deterministic toy instances generated by this lesson’s implementation so you can regression-test the algebra.

## Further Reading

- Lyubashevsky, Peikert, Regev (2010) — *On ideal lattices and learning with errors over rings*
- Peikert (2016) — *A Decade of Lattice Cryptography*
