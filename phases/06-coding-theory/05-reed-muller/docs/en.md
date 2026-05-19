# Reed-Muller Codes (RM) — Truth Tables of Low-Degree Polynomials

> A codeword is the truth table of a low-degree Boolean polynomial.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 6 Lesson 1 (Linear Codes), Phase 6 Lesson 2 (Hamming Distance), basic combinatorics (`C(m,i)`)  
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** how RM codes come from evaluating Boolean polynomials on all `2^m` inputs
- **Compute** `(n, k, d)` for `RM(r, m)` and interpret what those mean
- **Implement** an encoder using a generator matrix built from monomial truth tables
- **Distinguish** `RM(r, m)` (degree-`r` polynomials) from `RM(1, m)` (affine functions / Hadamard code)
- **Apply** Walsh-Hadamard decoding to correct errors for `RM(1, m)`

## The Problem

You need a small, fast, purely binary error-correcting code you can implement and reason about without heavy field arithmetic. Reed-Solomon is great for burst errors and storage, but it operates on **symbols** (like bytes) and needs finite-field multiplication. Sometimes you want “bit-level” structure you can decode with only XORs and additions.

Reed-Muller codes are a classic answer: they have a clean algebraic definition, simple encoders (linear codes), and for the important special case `RM(1, m)` they have a decoder that’s basically “compute correlations and pick the best match” — which can be implemented with a fast Walsh-Hadamard transform.

## The Concept

### RM(r, m) in one sentence

`RM(r, m)` is the set of truth tables you get by evaluating all Boolean polynomials in `m` variables of total degree ≤ `r` on every input `x ∈ {0,1}^m`.

### Parameters

- Length: `n = 2^m` (you list the polynomial’s output on every input)
- Dimension:  
  \[
  k = \sum_{i=0}^{r} \binom{m}{i}
  \]
  (one coefficient for each monomial of degree ≤ `r`)
- Minimum distance: `d = 2^{m-r}` (controls how many errors you can correct)

### Generator matrix as monomial truth tables

Fix an ordering of points `x` by integers `x = 0..2^m-1`, where bit `i` of `x` is variable `x_i`.

Each monomial (like `1`, `x0`, `x1*x3`) has a truth table: a length-`n` vector of 0/1 values over all points. Stack those truth tables as rows ⇒ a generator matrix `G`. Then:

- message bits = coefficients of monomials (same order as rows)
- codeword = `message · G (mod 2)`

### RM(1, m) and Walsh-Hadamard decoding

`RM(1, m)` are **affine functions**:
\[
f(x) = a_0 + a_1 x_0 + \cdots + a_m x_{m-1} \pmod 2
\]
The Walsh-Hadamard transform lets you compute, for every possible linear term vector `(a1..am)`, how well it correlates with your received word. The best correlation gives you the decoded affine function (and `a0` comes from the sign).

## Build It

### Step 1: Monomials as truth tables

We represent a monomial by the tuple of variable indices it multiplies: `()` is the constant `1`, `(0,)` is `x0`, `(1,3)` is `x1*x3`. Evaluating a monomial at a point `x` becomes “AND the selected bits of the integer `x`”.

```python
import itertools
import math


def assert_int(x: int, *, name: str = "x") -> None:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")


def assert_nonneg_int(x: int, *, name: str = "x") -> None:
    assert_int(x, name=name)
    if x < 0:
        raise ValueError(f"{name} must be >= 0")


def assert_bit(b: int, *, name: str = "b") -> None:
    assert_int(b, name=name)
    if b not in (0, 1):
        raise ValueError(f"{name} must be 0 or 1")


def assert_bits(v: list[int], *, name: str = "v") -> None:
    if not isinstance(v, list):
        raise TypeError(f"{name} must be a list[int]")
    for i, b in enumerate(v):
        assert_bit(b, name=f"{name}[{i}]")


def assert_rm_params(r: int, m: int) -> None:
    assert_int(r, name="r")
    assert_int(m, name="m")
    if m < 0:
        raise ValueError("m must be >= 0")
    if r < 0 or r > m:
        raise ValueError("require 0 <= r <= m")


def rm_monomials_upto_degree(r: int, m: int) -> list[tuple[int, ...]]:
    """
    Enumerate monomials in variables x0..x(m-1) of degree <= r.

    Representation:
      a monomial is a tuple of variable indices, e.g. () for 1, (0,) for x0,
      (1, 3) for x1*x3.

    Ordering:
      by increasing degree, then lexicographic by indices.
    """
    assert_rm_params(r, m)
    out: list[tuple[int, ...]] = [()]
    for deg in range(1, r + 1):
        out.extend(tuple(c) for c in itertools.combinations(range(m), deg))
    return out


def rm_eval_monomial(monomial: tuple[int, ...], x: int, *, m: int) -> int:
    assert_nonneg_int(x, name="x")
    assert_nonneg_int(m, name="m")
    if x >= (1 << m):
        raise ValueError("x out of range for m-bit point")
    if not isinstance(monomial, tuple):
        raise TypeError("monomial must be a tuple[int, ...]")
    v = 1
    for i in monomial:
        assert_int(i, name="var_index")
        if i < 0 or i >= m:
            raise ValueError("var_index out of range")
        v &= (x >> i) & 1
    return v
```

### Step 2: Generator matrix and parameters

Now we turn “monomials evaluated on all points” into a generator matrix. The key connection is: each row is a monomial truth table, and encoding is linear combination of rows (XOR) controlled by message bits.

```python
def rm_parameters(r: int, m: int) -> tuple[int, int, int]:
    """
    Return (n, k, d) for RM(r, m):
    - n = 2^m
    - k = sum_{i=0..r} C(m, i)
    - d = 2^(m-r)
    """
    assert_rm_params(r, m)
    n = 1 << m
    k = sum(math.comb(m, i) for i in range(r + 1))
    d = 1 << (m - r)
    return n, k, d


def rm_generator_matrix(r: int, m: int) -> list[list[int]]:
    assert_rm_params(r, m)
    n = 1 << m
    monomials = rm_monomials_upto_degree(r, m)
    G: list[list[int]] = []
    for mon in monomials:
        G.append([rm_eval_monomial(mon, x, m=m) for x in range(n)])
    return G
```

### Step 3: Encode over GF(2)

Given a message `message` (the monomial coefficients in the same order as the rows of `G`), encoding is just “XOR together the rows where the message bit is 1”.

```python
def xor_bits(a: list[int], b: list[int]) -> list[int]:
    assert_bits(a, name="a")
    assert_bits(b, name="b")
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return [x ^ y for x, y in zip(a, b)]


def rm_encode(message: list[int], r: int, m: int) -> list[int]:
    assert_bits(message, name="message")
    n, k, _ = rm_parameters(r, m)
    if len(message) != k:
        raise ValueError(f"message must have length k={k} for RM({r},{m})")

    G = rm_generator_matrix(r, m)
    codeword = [0] * n
    for bit, row in zip(message, G):
        if bit == 1:
            codeword = xor_bits(codeword, row)
    return codeword
```

### Step 4: Decode RM(1, m) with Walsh-Hadamard

For `RM(1, m)`, the codewords are affine functions. Decoding can be done by transforming the received word into `±1` values and computing all correlations at once via the fast Walsh-Hadamard transform.

```python
def rm1_affine_eval(coeffs: list[int], x: int, *, m: int) -> int:
    """
    Evaluate f(x) = a0 + a1*x0 + ... + am*x(m-1) over GF(2).
    Coeff ordering: [a0, a1, ..., am].
    """
    assert_bits(coeffs, name="coeffs")
    assert_nonneg_int(x, name="x")
    assert_nonneg_int(m, name="m")
    if len(coeffs) != m + 1:
        raise ValueError("coeffs must have length m+1")
    if x >= (1 << m):
        raise ValueError("x out of range for m-bit point")

    acc = coeffs[0]
    for i in range(m):
        if coeffs[i + 1] == 1:
            acc ^= (x >> i) & 1
    return acc


def fwht_inplace(a: list[int]) -> None:
    """
    In-place fast Walsh-Hadamard transform (Hadamard matrix with +/-1 entries).
    Length must be a power of two.
    """
    if not isinstance(a, list):
        raise TypeError("a must be a list[int]")
    n = len(a)
    if n == 0 or (n & (n - 1)) != 0:
        raise ValueError("length must be a power of two")
    for i, x in enumerate(a):
        assert_int(x, name=f"a[{i}]")

    h = 1
    while h < n:
        for i in range(0, n, 2 * h):
            for j in range(i, i + h):
                x = a[j]
                y = a[j + h]
                a[j] = x + y
                a[j + h] = x - y
        h *= 2


def rm1_decode_coeffs(received: list[int], *, m: int) -> list[int]:
    """
    Decode RM(1, m) (Hadamard code) via WHT.

    Returns coefficients [a0, a1, ..., am] of the closest affine function
    f(x) = a0 + sum_i a(i+1)*x_i over GF(2), under the assumption noise is
    within the unique decoding radius.
    """
    assert_bits(received, name="received")
    assert_nonneg_int(m, name="m")
    n = 1 << m
    if len(received) != n:
        raise ValueError(f"received must have length n=2^m={n}")

    spectrum = [1 - 2 * b for b in received]
    fwht_inplace(spectrum)

    best_u = 0
    best_abs = -1
    best_amp = 0
    for u, amp in enumerate(spectrum):
        a = abs(amp)
        if a > best_abs:
            best_abs = a
            best_u = u
            best_amp = amp

    linear = [(best_u >> i) & 1 for i in range(m)]
    a0 = 0 if best_amp >= 0 else 1
    return [a0] + linear


def rm1_encode_from_coeffs(coeffs: list[int], *, m: int) -> list[int]:
    assert_bits(coeffs, name="coeffs")
    assert_nonneg_int(m, name="m")
    if len(coeffs) != m + 1:
        raise ValueError("coeffs must have length m+1")
    n = 1 << m
    return [rm1_affine_eval(coeffs, x, m=m) for x in range(n)]


def rm1_correct(received: list[int], *, m: int) -> tuple[list[int], list[int]]:
    """
    Decode and return (decoded_message, corrected_codeword) for RM(1, m).
    The decoded message is [a0, a1, ..., am].
    """
    coeffs = rm1_decode_coeffs(received, m=m)
    corrected = rm1_encode_from_coeffs(coeffs, m=m)
    return coeffs, corrected


def hamming_distance(a: list[int], b: list[int]) -> int:
    assert_bits(a, name="a")
    assert_bits(b, name="b")
    if len(a) != len(b):
        raise ValueError("length mismatch")
    return sum((x ^ y) for x, y in zip(a, b))
```

Run it:

```bash
python3 phases/06-coding-theory/05-reed-muller/code/main.py
```

## Use It

Reed-Muller codes show up in practice mostly through the special case `RM(1,m)` (Hadamard) and as building blocks inside larger systems.

- **Walsh-Hadamard transform (WHT)**: used all over signal processing and coding; libraries in many languages expose a fast Hadamard transform you can reuse for `RM(1,m)` decoding.
- **Soft-decision decoding**: real decoders often work with “reliability” values (LLRs) rather than hard 0/1 bits; the same correlation idea generalizes.
- **Modern libraries**: for production-grade ECC, you usually reach for libraries that implement BCH / Reed-Solomon / LDPC / Polar codes rather than hand-rolling Reed-Muller. Reed-Muller is still a great conceptual bridge because the math is clean and the transform-based decoder is easy to audit.

## Pitfalls

- **Mismatched ordering**: if the encoder and decoder disagree on the ordering of points `x=0..2^m-1` (or which bit is `x0`), you’ll decode garbage.
- **Wrong monomial ordering**: message bits must align with the monomial list order used to build `G`.
- **Forgetting the constant term**: `RM(1,m)` has `m+1` coefficients (`a0` plus `m` linear bits).
- **“Best effort” decode beyond radius**: outside the unique decoding radius, a maximum-correlation decoder can silently output the wrong affine function; production systems must fail closed or add detection (e.g., CRC/authentication framing).
- **Treating course code as constant-time**: WHT-based decode here is not written to be constant-time; it’s for learning.

## Ship It

This lesson ships a reusable review prompt for `RM(1,m)` implementations.

1. Open `phases/06-coding-theory/05-reed-muller/outputs/prompt-rm1-audit.md`.
2. Paste it into your LLM (or use it as a human checklist) when reviewing a Reed-Muller / Hadamard encoder+decoder.
3. Use it to force conventions to be stated up front (ordering, bit mapping, failure behavior), then audit vectors + property tests.

## Exercises

1. Easy. Run `python3 phases/06-coding-theory/05-reed-muller/code/main.py`. Observe how each monomial becomes a truth-table row and how one flipped bit is corrected for `RM(1,3)`.
2. Medium. Change `m` in `main()` to `4` and update the demo message length (`k = m+1`). Verify the decoder still corrects up to `t = 2^{m-2}-1` errors by trying a few multi-bit flips.
3. Hard. Extend `rm1_decode_coeffs` to accept “soft” inputs (e.g., list of integers or floats representing confidence) and decode by correlating those values instead of hard 0/1 bits; add tests showing it improves robustness under biased noise.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| `RM(r,m)` | “Reed-Muller code” | All truth tables of degree-≤`r` Boolean polynomials in `m` variables |
| Monomial basis | “Terms like `x0*x2`” | One coefficient per subset of variables; basis vectors are monomial truth tables |
| Generator matrix `G` | “Matrix that generates codewords” | Rows are basis codewords; `message·G (mod 2)` encodes |
| Minimum distance `d` | “How separated codewords are” | Smallest Hamming distance between distinct codewords; sets correction radius |
| Walsh-Hadamard transform | “Fast Hadamard transform” | Computes all correlations with linear functions in `O(n log n)` time |

## Further Reading

- MacWilliams & Sloane, *The Theory of Error-Correcting Codes* (1977) — classic reference for Reed-Muller parameters and decoding ideas  
- Lin & Costello, *Error Control Coding* (2nd ed., 2004) — practical textbook treatment of RM codes and transform decoding  
- Odlyzko, “The First-Order Reed-Muller Code and the Walsh Transform” (notes) — short conceptual bridge between affine functions and WHT
