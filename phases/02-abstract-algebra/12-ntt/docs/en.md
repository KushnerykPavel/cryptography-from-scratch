# NTT — Number Theoretic Transform

> FFT, but in a finite field: same butterflies, different numbers.

**Type:** Build
**Languages:** Python
**Prerequisites:** 02-abstract-algebra/09-polynomial-rings, 02-abstract-algebra/11-roots-of-unity-cyclotomics
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how the NTT evaluates a polynomial at powers of a primitive `n`-th root of unity in `F_p`, replacing complex exponentials with modular arithmetic
- Implement the Cooley-Tukey butterfly structure with bit-reversal permutation and verify that forward NTT followed by inverse NTT recovers the original coefficients
- Apply cyclic convolution via `iNTT(NTT(a) * NTT(b))` to multiply polynomials in `F_p[x]/(x^n - 1)` and confirm correctness against naive multiplication
- Distinguish cyclic convolution in `(x^n - 1)` from negacyclic convolution in `(x^n + 1)` and explain the `psi`-twist needed for the negacyclic case
- Verify that using a non-primitive `n`-th root as the twiddle base produces a non-invertible transform by exhibiting two distinct inputs that collide

## The Problem

Modern cryptography uses polynomial arithmetic everywhere: lattice schemes multiply polynomials in rings like `Z_q[x]/(x^n + 1)`, and many ZK proof systems rely on fast polynomial operations to keep prover time reasonable.

If you multiply two length-`n` polynomials naively, you do `O(n^2)` coefficient multiplications. That is fine for `n = 32` and painful for `n = 4096`. At the sizes used in practice, naive multiplication becomes the bottleneck.

The Number Theoretic Transform (NTT) is the finite-field analog of the FFT: it reduces polynomial multiplication to:

1. transform each polynomial (`O(n log n)`)
2. pointwise multiply (`O(n)`)
3. inverse transform (`O(n log n)`)

This lesson builds an NTT you can run and test, and shows how the same idea powers the “fast polynomial multiply” inside lattice crypto implementations.

## The Concept

### The DFT, but mod p

Pick a prime `p` and work in the field `F_p`. For a length-`n` vector `a = (a_0, ..., a_{n-1})`, define:

```text
NTT(a)[k] = Σ_{j=0}^{n-1} a_j * ω^{j*k}  (mod p)
```

This is the discrete Fourier transform matrix, just computed in `F_p` instead of in the complex numbers.

### When the NTT exists

To get an invertible transform you need a primitive `n`-th root of unity `ω` in `F_p`:

```text
ω^n = 1           (n-th root)
ω^(n/q) ≠ 1       for every prime factor q of n  (primitive)
```

Because `F_p*` is cyclic of order `p - 1`, a primitive `n`-th root exists iff:

```text
n | (p - 1)
```

That is the single most important “NTT parameter check”.

### Why it makes multiplication fast

In the polynomial ring `F_p[x]/(x^n - 1)`:

- cyclic convolution of coefficient vectors corresponds to polynomial multiplication mod `(x^n - 1)`
- the NTT diagonalizes cyclic convolution:

```text
NTT(a * b) = NTT(a) ⊙ NTT(b)
```

So multiplication becomes:

```text
c = iNTT( NTT(a) ⊙ NTT(b) )
```

### Butterflies (the FFT structure)

If `n` is a power of two, the NTT can be computed with the same Cooley–Tukey factorization as the FFT.

For `n = 8`, each stage combines pairs, then groups of 4, then groups of 8:

```text
len=2:  (0,1) (2,3) (4,5) (6,7)
len=4:  (0..3) (4..7)
len=8:  (0..7)
```

Each combination is a “butterfly”:

```text
u = a[i]
v = a[i+half] * w

a[i]      = u + v
a[i+half] = u - v
```

where `w` is a power of `ω` that changes across the butterfly.

### The negacyclic ring (x^n + 1)

Lattice schemes often work in `F_p[x]/(x^n + 1)` with `n` a power of two. This is negacyclic convolution:

```text
x^n ≡ -1
```

You can compute negacyclic multiplication using an NTT by introducing a primitive `2n`-th root `ψ` and “twisting” coefficients by powers of `ψ`. This is why lattice parameters often require `2n | (p - 1)`.

## Build It

### Step 1: Choose parameters (p, n, ω)

For a length-`n` NTT over `F_p`, you need:

- `p` prime
- `n` a power of two (for this lesson’s fast implementation)
- `n | (p - 1)` so a primitive `n`-th root exists

If `g` is a primitive root mod `p`, then:

```text
ω = g^((p-1)/n)   (mod p)
```

is a primitive `n`-th root of unity.

```python
def find_primitive_nth_root(n: int, p: int) -> int:
    if (p - 1) % n != 0:
        raise ValueError("no primitive n-th root in F_p")
    g = primitive_root(p)
    return pow(g, (p - 1) // n, p)
```

In the toy field `F_17`:

- `p - 1 = 16`
- for `n = 8`, a primitive 8th root exists
- one valid choice is `ω = 9`

### Step 2: Implement the forward NTT (Cooley–Tukey)

The fast NTT is the FFT structure with modular arithmetic:

1. bit-reversal permutation (so butterflies touch contiguous blocks)
2. stages of butterflies with `len = 2, 4, 8, ..., n`

```python
def ntt_inplace(a: list[int], p: int, omega: int) -> None:
    n = len(a)

    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            a[i], a[j] = a[j], a[i]

    length = 2
    while length <= n:
        wlen = pow(omega, n // length, p)
        for i in range(0, n, length):
            w = 1
            half = length // 2
            for j in range(half):
                u = a[i + j] % p
                v = (a[i + j + half] % p) * w % p
                a[i + j] = (u + v) % p
                a[i + j + half] = (u - v) % p
                w = w * wlen % p
        length *= 2
```

### Step 3: Implement the inverse NTT

The inverse uses:

- `ω^{-1}` instead of `ω`
- a final scale by `n^{-1} mod p`

```python
def intt_inplace(a: list[int], p: int, omega: int) -> None:
    n = len(a)
    omega_inv = pow(omega, p - 2, p)
    ntt_inplace(a, p, omega_inv)
    n_inv = pow(n, p - 2, p)
    for i in range(n):
        a[i] = a[i] % p * n_inv % p
```

### Step 4: Multiply polynomials (cyclic and negacyclic)

Cyclic convolution computes multiplication in `F_p[x]/(x^n - 1)`:

```python
def cyclic_convolution(a: list[int], b: list[int], p: int, omega: int) -> list[int]:
    a_ntt = ntt(a, p, omega)
    b_ntt = ntt(b, p, omega)
    c_ntt = [(x * y) % p for x, y in zip(a_ntt, b_ntt)]
    return intt(c_ntt, p, omega)
```

Negacyclic convolution computes multiplication in `F_p[x]/(x^n + 1)` using a primitive `2n`-th root `ψ`:

```text
ω = ψ^2   (an n-th root)
```

and a twist / untwist by powers of `ψ`.

Run it:

```
python3 code/main.py
```

## Use It

Real crypto implementations use an NTT, but with careful engineering:

- precomputed twiddle tables (no `pow` during the transform)
- constant-time modular reductions
- Montgomery / Barrett reduction for speed
- specialized NTTs for fixed parameters (e.g., Kyber’s `n=256`, `q=3329`)

In Python, you would almost never implement an NTT for performance. You use it to understand the structure, then rely on audited implementations in the relevant libraries.

What transfers from this lesson:

- the parameter checks (`n | (p - 1)`, primitive root order)
- the butterfly structure and where twiddles come from
- the difference between cyclic `(x^n - 1)` and negacyclic `(x^n + 1)` rings

## Attack It

The simplest NTT failure mode is using an `ω` that is an `n`-th root, but not *primitive*.

In `F_17` with `n = 8`, the element `4` is an 8th root of unity because `4^8 ≡ 1 (mod 17)`, but its order is only 4. That means `ω` repeats too early:

```text
4^0, 4^1, 4^2, 4^3, 4^4, ...   cycles every 4 steps
```

The transform is no longer invertible: two different inputs can map to the same output.

Concrete collision under the “NTT” defined with `ω = 4`:

```text
a  = [0,0,0,0,0,0,0,1]
a' = [0,0,0,1,0,0,0,0]

NTT_ω=4(a)  = [1,13,16,4,1,13,16,4]
NTT_ω=4(a') = [1,13,16,4,1,13,16,4]
```

If you cannot invert it, you cannot safely use it for multiplication. This is why “primitive” is not optional.

## Ship It

This lesson ships a review checklist for NTT implementations:

- `outputs/skill-ntt-review.md`

Use it when you see NTT code in lattice crypto, ZK tooling, or competitive-programming style NTT primes.

## Exercises

1. Easy: Using `p = 17`, list all primitive 8th roots of unity. Verify each candidate `ω` passes the “primitive” checks.
2. Medium: Implement a naive cyclic convolution (`O(n^2)`) and show it matches your `cyclic_convolution` output for random small vectors.
3. Hard: Implement a naive negacyclic convolution for `(x^n + 1)` and verify it matches `negacyclic_convolution`. Then explain why the `ψ` twist is needed.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| NTT | “FFT mod p” | A DFT over a finite field using a primitive root of unity |
| Twiddle factor | “The magic multipliers” | Powers of `ω` that appear inside butterflies |
| Primitive root of unity | “An n-th root” | An element of multiplicative order exactly `n` |
| Cyclic convolution | “Multiply mod x^n - 1” | Wrap-around multiplication where indices add mod `n` |
| Negacyclic convolution | “Multiply mod x^n + 1” | Wrap-around with a sign flip when indices exceed `n-1` |

## Test Vectors

Vectors in `tests/vectors.json` cover:

- forward NTT (fast and slow definitions agree)
- inverse roundtrip
- cyclic convolution in `F_17[x]/(x^8 - 1)`
- negacyclic convolution in `F_17[x]/(x^8 + 1)` using `ψ = 3` (a primitive 16th root)

## Further Reading

- https://cp-algorithms.com/algebra/fft.html — FFT structure and butterfly intuition (adapted to NTTs)
- https://cp-algorithms.com/algebra/fft-mod.html — Practical NTT notes and common NTT primes
- https://en.wikipedia.org/wiki/Number-theoretic_transform — Definition and variants (cyclic vs negacyclic)
