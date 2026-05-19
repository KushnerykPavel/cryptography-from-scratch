# FFT for Polynomial Multiplication

> Evaluate at roots of unity, multiply pointwise, then interpolate — fast.

**Type:** Build
**Languages:** Python
**Prerequisites:** 02-abstract-algebra/09-polynomial-rings, 02-abstract-algebra/11-roots-of-unity-cyclotomics, 02-abstract-algebra/12-ntt
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how the convolution theorem reduces polynomial multiplication to three steps: forward FFT, pointwise multiply, inverse FFT
- Implement the iterative Cooley-Tukey FFT with bit-reversal permutation and complex twiddle factors over the complex numbers
- Apply zero-padding to ensure linear convolution rather than circular convolution, and compute the required transform length
- Distinguish FFT-based polynomial multiplication over complex numbers from NTT-based multiplication in `F_p`, explaining the rounding and exact-arithmetic trade-off
- Identify the circular convolution bug caused by insufficient padding and construct a small counterexample where the wrapped output differs from the true product

## The Problem

Polynomial multiplication is the hidden workhorse in modern crypto and ZK:

- in lattice cryptography you multiply polynomials in rings like `Z_q[x]/(x^n + 1)`
- in proof systems you do massive batches of polynomial evaluations and products

The naive multiplication of two degree-`(n-1)` polynomials takes `O(n^2)` coefficient multiplies. That is fine for `n = 32` and painful for `n = 4096`.

The Fast Fourier Transform (FFT) reduces polynomial multiplication to:

1. transform each polynomial (`O(n log n)`)
2. pointwise multiply (`O(n)`)
3. inverse transform (`O(n log n)`)

This lesson builds a minimal FFT-based polynomial multiply over the complex numbers. It also explains why cryptographic code usually prefers the NTT (Lesson 12): the FFT’s floating-point arithmetic can silently round to the wrong integer.

## The Concept

### From coefficients to values

A polynomial is “the same object” in two coordinate systems:

- coefficient form: `a(x) = a_0 + a_1 x + ... + a_{n-1} x^{n-1}`
- value form: `a(α_0), a(α_1), ..., a(α_{n-1})` at chosen points `α_i`

If you choose `n` distinct points, you can recover the coefficients (interpolation). If you choose the points cleverly, evaluation and interpolation become fast.

### Roots of unity and the DFT

Pick `n` equally spaced points on the complex unit circle:

```text
ω = exp(2πi / n)
ω^0, ω^1, ω^2, ..., ω^(n-1)
```

These are the `n`-th roots of unity. The Discrete Fourier Transform (DFT) evaluates a polynomial (or vector) at these points:

```text
DFT(a)[k] = Σ_{j=0}^{n-1} a_j * ω^(j*k)
```

### Convolution theorem (the multiplication trick)

If `c = a * b` is polynomial multiplication (linear convolution of coefficient lists), then:

```text
DFT(c) = DFT(a) ⊙ DFT(b)
```

So to multiply polynomials, you can:

1. compute `A = DFT(a)` and `B = DFT(b)`
2. compute `C[k] = A[k] * B[k]` pointwise
3. compute `c = iDFT(C)`

### Linear vs circular convolution (padding matters)

The DFT is naturally “cyclic”: it corresponds to multiplication modulo `(x^n - 1)`, which wraps around:

```text
x^n ≡ 1
```

That is circular convolution. To get ordinary polynomial multiplication (linear convolution), you must pad with zeros so that no wrap-around happens:

```text
n >= len(a) + len(b) - 1
```

If you forget this, you will compute the wrong product — and the bug can look like “random coefficient noise”.

### Why the FFT is “fast”

For `n` a power of two, the DFT matrix factors recursively (Cooley–Tukey). The implementation becomes a sequence of “butterflies”:

```text
u = a[i]
v = a[i+half] * w

a[i]      = u + v
a[i+half] = u - v
```

where `w` is a power of `ω` (a “twiddle factor”) that changes across the stage.

## Build It

### Step 1: Pad to a power of two

We will implement the iterative FFT that expects the input length to be a power of two. For polynomial multiplication, we also need enough room for the full product:

- result length is `len(a) + len(b) - 1`
- choose `n` as the next power of two `>= result_length`
- pad both inputs to length `n` with zeros

```python
def next_power_of_two(n: int) -> int:
    if n < 1:
        raise ValueError("n must be positive")
    p = 1
    while p < n:
        p <<= 1
    return p
```

### Step 2: Bit-reversal permutation

The iterative FFT uses an in-place butterfly schedule. To make butterflies operate on contiguous blocks, we reorder the array in bit-reversed order.

```python
def bit_reverse_permute(a: list[complex]) -> None:
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
```

### Step 3: Forward FFT (Cooley–Tukey)

Each stage doubles the block size `length = 2, 4, 8, ...`. The per-stage twiddle base is the `length`-th root derived from the full `n`-th root:

```text
wlen = exp(±2πi / length)
```

```python
import math


def fft_inplace(a: list[complex], invert: bool) -> None:
    n = len(a)
    if n < 1 or (n & (n - 1)) != 0:
        raise ValueError("n must be a power of two")

    bit_reverse_permute(a)

    length = 2
    while length <= n:
        angle = 2.0 * math.pi / length
        if not invert:
            angle = -angle
        wlen = complex(math.cos(angle), math.sin(angle))
        half = length // 2
        for i in range(0, n, length):
            w = 1.0 + 0.0j
            for j in range(half):
                u = a[i + j]
                v = a[i + j + half] * w
                a[i + j] = u + v
                a[i + j + half] = u - v
                w *= wlen
        length *= 2
```

### Step 4: Inverse FFT (and scaling)

The inverse uses the opposite sign in the exponent, and a final scale by `1/n`.

```python
def ifft_inplace(a: list[complex]) -> None:
    n = len(a)
    fft_inplace(a, invert=True)
    inv_n = 1.0 / n
    for i in range(n):
        a[i] *= inv_n
```

### Step 5: Polynomial multiplication via FFT

Convert integer coefficients to complex numbers, pad, transform, multiply pointwise, invert, then round:

```python
def poly_mul_fft(a: list[int], b: list[int]) -> list[int]:
    if not a or not b:
        raise ValueError("inputs must be non-empty")

    out_len = len(a) + len(b) - 1
    n = next_power_of_two(out_len)

    fa = [complex(x, 0.0) for x in a] + [0.0j] * (n - len(a))
    fb = [complex(x, 0.0) for x in b] + [0.0j] * (n - len(b))

    fft_inplace(fa, invert=False)
    fft_inplace(fb, invert=False)
    for i in range(n):
        fa[i] *= fb[i]
    ifft_inplace(fa)

    return [int(round(fa[i].real)) for i in range(out_len)]
```

Run it:

```
python3 code/main.py
```

## Use It

In real systems, you typically use the FFT through a numerics library:

```python
import numpy as np

def poly_mul_numpy(a, b):
    out_len = len(a) + len(b) - 1
    n = 1 << (out_len - 1).bit_length()
    fa = np.fft.fft(np.array(a, dtype=np.float64), n=n)
    fb = np.fft.fft(np.array(b, dtype=np.float64), n=n)
    fc = fa * fb
    c = np.fft.ifft(fc)
    return np.rint(np.real(c[:out_len])).astype(np.int64).tolist()
```

For cryptography and proof systems, however, “FFT over complex numbers” is often the wrong tool:

- you usually need exact modular arithmetic, not floating-point approximations
- you want constant-time behavior and tight control over reductions

That is why lattice schemes (Kyber, Dilithium, NTRU variants) and many ZK stacks use the NTT (Lesson 12) over `F_p` or `Z_q`.

## Attack It

FFT-based integer polynomial multiplication fails in two common, reproducible ways.

### Attack 1: Forget padding → circular convolution bug

If you choose `n = next_power_of_two(max(len(a), len(b)))` instead of `len(a)+len(b)-1`, the FFT computes multiplication in:

```text
C[x] = A[x] * B[x]  mod (x^n - 1)
```

Coefficients wrap around and corrupt low-degree terms. This bug often survives simple spot-checks because the output still “looks polynomial-ish”.

### Attack 2: Adversarial magnitude → rounding errors

The FFT uses floating-point arithmetic. For large coefficients or large `n`, rounding can flip an integer by ±1 (or worse).

If you need exact results under adversarial inputs, do not use a complex FFT. Use an NTT (exact) or a multi-precision / split-coefficient technique designed for safe integer convolution.

## Ship It

Save a reusable review checklist:

- `outputs/skill-fft-poly-mul-review.md`

## Exercises

1. Easy: Multiply `(1 + 2x + 3x^2)` by `(4 + 5x)` by hand, then confirm your `poly_mul_fft` output matches.
2. Medium: Implement `poly_mul_naive` and compare it against `poly_mul_fft` for a few random small polynomials.
3. Hard: Write a “bad” multiplication that forgets padding (circular convolution). Find a small counterexample where it differs from the true product.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| DFT | “Fourier transform” | Evaluates a length-`n` sequence at `n`-th roots of unity |
| FFT | “Fast DFT” | An `O(n log n)` algorithm for the DFT when `n` has a smooth factorization (here: power of two) |
| Root of unity | “Point on the circle” | A complex number `ω` with `ω^n = 1` |
| Twiddle factor | “FFT constant” | A power of `ω` used inside butterflies |
| Linear convolution | “Normal polynomial multiply” | No wrap-around; result length is `len(a)+len(b)-1` |
| Circular convolution | “Modulo x^n-1 multiply” | Wrap-around because `x^n ≡ 1` |
| Numerical error | “Floating noise” | Rounding/precision loss that can change integer results |

## Test Vectors

Source: project-internal vectors cross-checked against naive polynomial multiplication.

## Further Reading

- https://cp-algorithms.com/algebra/fft.html — a practical FFT implementation and common pitfalls
- https://en.wikipedia.org/wiki/Convolution_theorem — why transforms turn convolution into pointwise multiplication
