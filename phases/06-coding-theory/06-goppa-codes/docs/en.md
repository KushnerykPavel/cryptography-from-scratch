# Goppa Codes — McEliece’s Foundation

> Alternant structure that looks random (until you hold the secret).

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 06 Lessons 01–05 (Linear Codes → Reed–Muller), especially finite fields from Reed–Solomon
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain binary Goppa codes — what they are and why McEliece-style systems use them
- Compute the alternant parity-check matrix — over GF(2^m) and its binary expansion
- Implement GF(2^m) arithmetic — add, mul, inv (stdlib-only toy field)
- Distinguish matrix domains — `H_GF` over GF(2^m) vs `H_bin` over GF(2)
- Apply nullspace encoding — build a generator, verify syndromes, and toy-decode up to `t` errors

## The Problem

Modern code-based cryptography (notably Classic McEliece) hides structure inside what looks like a random binary linear code. If you can’t *construct* that structured code, you can’t reason about key generation, ciphertext structure (syndromes), or why decoding is fast for the secret key holder but hard for an attacker.

Goppa codes are the “workhorse” family here: they have high minimum distance for their rate, admit efficient decoding algorithms (e.g., Patterson-style decoders), and their public parity-check/generator matrices are designed to be indistinguishable from random in the threat models we care about.

This lesson builds a tiny, deterministic binary Goppa code end-to-end: finite-field arithmetic → Goppa parity-check matrix → binary expansion → generator (nullspace) → encode → syndrome check → toy decoding via brute force (only for small sizes).

## The Concept

### What you’re constructing

A **binary Goppa code** is specified by:

- An extension field **GF(2^m)**.
- A degree-`t` polynomial `g(x) ∈ GF(2^m)[x]` with `g(L_i) ≠ 0` on the support.
- A support list `L = (L_0, …, L_{n-1})` of **distinct** elements of GF(2^m) that are **not roots** of `g`.

The code is a **binary** linear code `C ⊆ {0,1}^n` defined as the kernel of a parity-check matrix derived from `(g, L)`.

### The alternant parity-check matrix

There’s a convenient “alternant” form for a parity-check matrix over GF(2^m):

Let `t = deg(g)`. Define the `t × n` matrix over GF(2^m):

- `V[i,j] = L_j^i`  (a Vandermonde-like matrix)
- `D[j,j] = 1 / g(L_j)` (a diagonal scaling)

Then:

```
H_GF = V * D
H_GF[i,j] = L_j^i / g(L_j)
```

This `H_GF` is not yet a binary matrix — its entries live in GF(2^m).

### Expanding to a binary matrix

To get a *binary* parity-check matrix, write each GF(2^m) element in a fixed polynomial basis:

```
a = a0 + a1·α + a2·α^2 + ... + a(m-1)·α^(m-1),  with ai ∈ {0,1}
```

Expanding each field element into its `m` coefficients turns a `t × n` matrix over GF(2^m) into an `(m·t) × n` matrix over GF(2). That’s the `H_bin` we’ll use for syndrome checks and nullspace encoding.

### What we do (and don’t) implement

- We **do** construct `H_bin` and encode by computing a **nullspace basis** of `H_bin`.
- We **do** demonstrate decoding by brute-forcing error patterns of weight ≤ `t` (only feasible for tiny `n`).
- We **do not** implement Patterson decoding — it’s polynomial-time but requires more polynomial machinery than fits in a stdlib-only toy lesson.

## Build It

### Step 1: GF(2^m) arithmetic in polynomial basis

We represent elements of GF(2^m) as `m`-bit integers, with addition as XOR and multiplication as polynomial multiplication reduced mod an irreducible polynomial.

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class GF2m:
    m: int
    irr_poly: int

    @property
    def size(self) -> int:
        return 1 << self.m

    @property
    def mask(self) -> int:
        return (1 << self.m) - 1

    def add(self, a: int, b: int) -> int:
        return (a ^ b) & self.mask

    def mul(self, a: int, b: int) -> int:
        a &= self.mask
        b &= self.mask
        out = 0
        top_bit = 1 << self.m
        while b:
            if b & 1:
                out ^= a
            b >>= 1
            a <<= 1
            if a & top_bit:
                a ^= self.irr_poly
            a &= self.mask
        return out & self.mask

    def pow(self, a: int, e: int) -> int:
        a &= self.mask
        if e < 0:
            raise ValueError("negative exponents require inv()")
        out = 1
        base = a
        exp = e
        while exp:
            if exp & 1:
                out = self.mul(out, base)
            base = self.mul(base, base)
            exp >>= 1
        return out

    def inv(self, a: int) -> int:
        a &= self.mask
        if a == 0:
            raise ZeroDivisionError("0 has no inverse in a field")
        return self.pow(a, (1 << self.m) - 2)

    def div(self, a: int, b: int) -> int:
        return self.mul(a, self.inv(b))

    def elem_to_bits(self, a: int) -> list[int]:
        a &= self.mask
        return [(a >> i) & 1 for i in range(self.m)]

    def bits_to_elem(self, bits: Iterable[int]) -> int:
        out = 0
        for i, bit in enumerate(bits):
            if bit & 1:
                out |= 1 << i
        return out & self.mask
```

### Step 2: pick g(x) and a support L with g(L_i) != 0

We’ll evaluate polynomials over GF(2^m) with Horner’s rule, then choose the first `n` field elements that are not roots of `g(x)`.

```python
def gf_poly_eval(field: GF2m, coeffs: list[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = field.add(field.mul(acc, x), c)
    return acc


def choose_support(field: GF2m, g_coeffs: list[int], n: int) -> list[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    out = []
    for a in range(field.size):
        if gf_poly_eval(field, g_coeffs, a) != 0:
            out.append(a)
            if len(out) == n:
                return out
    raise ValueError("could not find enough non-roots for the support")
```

### Step 3: build the binary parity-check matrix H_bin

First build `H_GF[i,j] = L_j^i / g(L_j)` over GF(2^m), then expand each element into `m` coefficient bits to get `H_bin`.

```python
def goppa_parity_check_gf(field: GF2m, g_coeffs: list[int], support: list[int]) -> list[list[int]]:
    if len(g_coeffs) < 2:
        raise ValueError("g(x) must have degree >= 1")
    t = len(g_coeffs) - 1
    n = len(support)
    inv_g = []
    for a in support:
        g_a = gf_poly_eval(field, g_coeffs, a)
        if g_a == 0:
            raise ValueError("support element is a root of g(x)")
        inv_g.append(field.inv(g_a))

    H = [[0] * n for _ in range(t)]
    for j, a in enumerate(support):
        a_pow = 1
        for i in range(t):
            H[i][j] = field.mul(a_pow, inv_g[j])
            a_pow = field.mul(a_pow, a)
    return H


def goppa_parity_check_bin(field: GF2m, g_coeffs: list[int], support: list[int]) -> list[list[int]]:
    H_gf = goppa_parity_check_gf(field, g_coeffs, support)
    t = len(H_gf)
    n = len(support)
    H_bin = [[0] * n for _ in range(t * field.m)]
    for i in range(t):
        for j in range(n):
            bits = field.elem_to_bits(H_gf[i][j])
            for b, bit in enumerate(bits):
                H_bin[i * field.m + b][j] = bit
    return H_bin
```

### Step 4: nullspace gives a generator; encode + toy decode t errors

Binary Goppa codewords satisfy `H_bin · c^T = 0` over GF(2). So any basis of the nullspace of `H_bin` can be used as a generator matrix. For a tiny toy code we can also brute-force decode within radius `t`.

```python
from itertools import combinations


def gf2_rref(matrix: list[list[int]]) -> tuple[list[list[int]], list[int]]:
    if not matrix:
        return [], []
    A = [row[:] for row in matrix]
    rows = len(A)
    cols = len(A[0])
    r = 0
    pivots = []
    for c in range(cols):
        pivot = None
        for i in range(r, rows):
            if A[i][c] & 1:
                pivot = i
                break
        if pivot is None:
            continue
        A[r], A[pivot] = A[pivot], A[r]
        pivots.append(c)
        for i in range(rows):
            if i != r and (A[i][c] & 1):
                row_r = A[r]
                A[i] = [(x ^ y) & 1 for x, y in zip(A[i], row_r)]
        r += 1
        if r == rows:
            break
    return A, pivots


def gf2_nullspace_basis(matrix: list[list[int]]) -> list[list[int]]:
    if not matrix:
        raise ValueError("matrix must be non-empty")
    rref, pivots = gf2_rref(matrix)
    rows = len(rref)
    cols = len(rref[0])
    pivot_set = set(pivots)
    free_cols = [c for c in range(cols) if c not in pivot_set]
    basis = []
    pivot_row_for_col = {p: i for i, p in enumerate(pivots)}
    for free in free_cols:
        v = [0] * cols
        v[free] = 1
        for p in pivots:
            r = pivot_row_for_col[p]
            v[p] = rref[r][free] & 1
        basis.append(v)
    return basis


def gf2_mat_vec_mul(matrix: list[list[int]], vec: list[int]) -> list[int]:
    out = []
    for row in matrix:
        s = 0
        for a, b in zip(row, vec):
            if b & 1:
                s ^= a & 1
        out.append(s & 1)
    return out


def gf2_vec_add(a: list[int], b: list[int]) -> list[int]:
    return [(x ^ y) & 1 for x, y in zip(a, b)]


def encode_from_generator(G: list[list[int]], msg: list[int]) -> list[int]:
    if not G:
        raise ValueError("G must be non-empty")
    if len(msg) != len(G):
        raise ValueError("msg length must equal number of generator rows")
    n = len(G[0])
    out = [0] * n
    for bit, row in zip(msg, G):
        if bit & 1:
            out = gf2_vec_add(out, row)
    return out


def brute_force_decode(H: list[list[int]], received: list[int], t: int) -> tuple[list[int], list[int]]:
    synd = gf2_mat_vec_mul(H, received)
    if all(x == 0 for x in synd):
        return received[:], [0] * len(received)

    n = len(received)
    for w in range(1, t + 1):
        for idxs in combinations(range(n), w):
            e = [0] * n
            for i in idxs:
                e[i] = 1
            cand = gf2_vec_add(received, e)
            if all(x == 0 for x in gf2_mat_vec_mul(H, cand)):
                return cand, e
    raise ValueError("no codeword within radius t of received")
```

Run it:
python3 code/main.py

## Use It

- **SageMath**: `sage.coding.goppa_code.GoppaCode` can construct Goppa codes, and can give generator/parity-check matrices for experimentation. This is the quickest way to sanity-check your own constructions. (See Sage’s `GoppaCode` docs.)
- **Classic McEliece (reference implementation/spec)**: Classic McEliece is built from binary Goppa codes (in Niederreiter form). The published reference implementation and spec describe key generation and matrix generation for these codes. (Start at the Classic McEliece project site.)
- **liboqs**: ships Classic McEliece KEMs and documents the underlying assumption as binary Goppa-code-based Niederreiter/McEliece.

## Pitfalls

1. **Including a root in the support**: if some `L_i` satisfies `g(L_i)=0`, then `1/g(L_i)` is undefined and the construction breaks.
2. **Mixing fields**: `H_GF` lives in GF(2^m); `H_bin` lives in GF(2). You can’t multiply them together interchangeably.
3. **Inconsistent basis choice**: expanding GF(2^m) elements to `m` bits depends on the chosen polynomial basis; different bases produce different binary matrices.
4. **Assuming brute force scales**: our decoder is exponential in `n`; real systems use polynomial-time decoders (Patterson-style) for secret decoding.
5. **Side channels in crypto contexts**: constant-time matters. Branching on secret-dependent values (like field inverses) leaks.

## Ship It

Save and reuse this outside the course:

- `outputs/goppa-codes-review-checklist.md` — a practical checklist for reviewing code-based crypto implementations and “Goppa-ish” matrix-generation code (support selection, field basis, parity-check expansion, and test strategy).

How to use it:

1. Paste the checklist into a PR review (or an audit doc) when you see “Classic McEliece”, “Goppa code”, “alternant code”, or “Niederreiter” in scope.
2. Use it to drive what you ask for: determinism, basis declarations, matrix-shape checks, and side-channel constraints.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that the encoded codeword has an all-zero syndrome and that the toy decoder recovers from 2 bit flips.
2. Medium: Change `g(x)` to a different monic degree-2 polynomial over GF(2^4) (change the `g = [...]` coefficients). Recompute `H_bin`, recompute `k`, and see how the nullspace size changes.
3. Hard: Recreate the same parity-check matrix in SageMath (or another CAS), and compare the binary-expanded `H_bin` against this lesson’s output (be explicit about the basis!). Document any differences and explain why they occur.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Goppa code | “The McEliece code” | A structured alternant/subfield-subcode defined by `(g(x), L)` over GF(2^m) with strong distance/decoding properties |
| Support `L` | “Evaluation points” | Distinct field elements where you evaluate structure; must avoid roots of `g` |
| Goppa polynomial `g(x)` | “The secret polynomial” | Degree-`t` polynomial over GF(2^m) that controls the code’s designed error-correction capability |
| Parity-check matrix `H` | “Constraints” | A matrix such that `H·c^T=0` for all codewords `c` |
| Alternant form | “Vandermonde times diagonal” | `H_GF = V·diag(y_j)` with `V[i,j]=L_j^i` and `y_j=1/g(L_j)` |
| Binary expansion | “Write field elements as bits” | Turn GF(2^m) entries into `m` GF(2) rows using a fixed basis |
| Syndrome | “The check result” | `s = H_bin·r^T`; zero means `r` is a codeword; nonzero indicates errors |
| Patterson decoding | “Efficient Goppa decoder” | A polynomial-time decoding algorithm for (square-free) binary Goppa codes correcting up to `t` errors |

## Further Reading

- Wikipedia, *Binary Goppa code* — definitions, parity-check matrix form, and binary expansion sketch
- V. D. Goppa, *A new class of linear error-correcting codes* (1970) — original construction
- Classic McEliece, *Intro / spec / implementation notes* — how Goppa codes appear in a modern KEM
- Bardet et al., *Understanding binary-Goppa decoding* (IACR ePrint 2022/473) — a decoder-focused walkthrough that’s friendlier than many older expositions
