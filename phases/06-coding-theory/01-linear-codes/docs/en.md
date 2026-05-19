# Linear Codes — Generator & Parity-Check Matrices

> A linear code is a subspace: `G` generates it, `H` checks it.

**Type:** Build
**Languages:** Python
**Prerequisites:** Basic linear algebra (vectors, matrices, dot products), binary arithmetic (XOR)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what it means for a code to be a linear subspace of `{0,1}^n`
- **Compute** Hamming weight, Hamming distance, and syndromes in GF(2)
- **Implement** encoding via `c = m·G (mod 2)` for a binary linear code
- **Distinguish** `G` (row space / codewords) from `H` (constraints / checks)
- **Apply** syndrome decoding to correct a single-bit error in Hamming(7,4)

## The Problem

You have bits you care about (a message), and a channel that flips bits you *don’t* control: radio noise, cosmic rays in RAM, packet loss + corruption, scratched QR codes, or a flaky NAND cell. If you transmit/store the raw bits, you get silent corruption — and in cryptography, silent corruption is often worse than a hard failure.

Error-correcting codes solve this by adding *structured redundancy*. But without a concrete model for “structured”, you can’t answer basic engineering questions: How many extra bits do I need? How do I detect an error? How do I correct one? How do I test that my encoder/decoder is even correct?

This lesson gives you the minimal linear-algebra toolkit: a generator matrix `G` to produce codewords, and a parity-check matrix `H` to verify them (and to locate single-bit errors via syndromes).

## The Concept

A **binary linear block code** is a set of `2^k` length-`n` bitstrings (called **codewords**) that forms a `k`-dimensional subspace of `{0,1}^n` under XOR. Concretely:

- Bits live in the field **GF(2)**: addition is XOR, multiplication is AND.
- A codeword is length `n`.
- A message is length `k` (the degrees of freedom).

There are two equivalent ways to describe the same linear code:

1. **Generator matrix `G`** (`k×n`): its rows are a basis of the code. Every message `m` maps to a codeword
   \[
   c = m\cdot G \pmod 2
   \]
   So `G` is “how we *make* codewords”.

2. **Parity-check matrix `H`** (`(n−k)×n`): it defines linear constraints that every codeword must satisfy:
   \[
   H\cdot c^T = 0 \pmod 2
   \]
   The vector `s = H·r^T` for a received word `r` is the **syndrome**. If `s=0`, `r` is a valid codeword; if `s≠0`, something is wrong.

For a **systematic** generator matrix `G = [I_k | P]`, you can build
`H = [P^T | I_{n-k}]` and get `G·H^T = 0` (the rows of `G` are orthogonal to the rows of `H`).

## Build It

### Step 1: Bits, weight, and Hamming distance

```python
def is_bit(x: int) -> bool:
    return x in (0, 1)


def assert_binary_vector(v: list[int], *, name: str = "vector") -> None:
    if not isinstance(v, list):
        raise TypeError(f"{name} must be a list[int]")
    if any(not isinstance(b, int) for b in v):
        raise TypeError(f"{name} must be a list[int]")
    if any(not is_bit(b) for b in v):
        raise ValueError(f"{name} must contain only 0/1")


def xor_vec(a: list[int], b: list[int]) -> list[int]:
    assert_binary_vector(a, name="a")
    assert_binary_vector(b, name="b")
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    return [x ^ y for x, y in zip(a, b)]


def hamming_weight(v: list[int]) -> int:
    assert_binary_vector(v, name="v")
    return sum(v)


def hamming_distance(a: list[int], b: list[int]) -> int:
    return hamming_weight(xor_vec(a, b))
```

Hamming weight counts 1s. Hamming distance is the number of bit flips needed to turn one word into another. In coding theory, distance is the “geometry” that tells you how many errors you can detect/correct.

### Step 2: Encoding with a generator matrix (G)

```python
def assert_binary_matrix(m: list[list[int]], *, name: str = "matrix") -> None:
    if not isinstance(m, list) or any(not isinstance(row, list) for row in m):
        raise TypeError(f"{name} must be a list[list[int]]")
    if len(m) == 0 or len(m[0]) == 0:
        raise ValueError(f"{name} must be non-empty")
    width = len(m[0])
    for row in m:
        if len(row) != width:
            raise ValueError(f"{name} must be rectangular")
        assert_binary_vector(row, name=name + " row")


def mul_vec_mat_mod2(v: list[int], m: list[list[int]]) -> list[int]:
    assert_binary_vector(v, name="v")
    assert_binary_matrix(m, name="m")
    rows = len(m)
    cols = len(m[0])
    if len(v) != rows:
        raise ValueError("vector length must match number of matrix rows")

    out: list[int] = []
    for j in range(cols):
        s = 0
        for i in range(rows):
            s ^= (v[i] & m[i][j])
        out.append(s)
    return out


def encode(message: list[int], g: list[list[int]]) -> list[int]:
    return mul_vec_mat_mod2(message, g)
```

`encode(m, G)` is the algebraic definition of a linear encoder: it takes a `k`-bit message and returns an `n`-bit codeword, with all arithmetic done mod 2 (XOR).

### Step 3: Checking codewords with a parity-check matrix (H)

```python
def mul_mat_vec_mod2(m: list[list[int]], v: list[int]) -> list[int]:
    assert_binary_matrix(m, name="m")
    assert_binary_vector(v, name="v")
    rows = len(m)
    cols = len(m[0])
    if len(v) != cols:
        raise ValueError("vector length must match number of matrix columns")

    out: list[int] = []
    for i in range(rows):
        s = 0
        for j in range(cols):
            s ^= (m[i][j] & v[j])
        out.append(s)
    return out


def parity_check_matrix_from_systematic_g(g: list[list[int]]) -> list[list[int]]:
    assert_binary_matrix(g, name="g")
    k = len(g)
    n = len(g[0])
    if n <= k:
        raise ValueError("need n > k to have parity symbols")

    for i in range(k):
        for j in range(k):
            expected = 1 if i == j else 0
            if g[i][j] != expected:
                raise ValueError("g is not systematic: expected left block to be identity")

    p = [row[k:] for row in g]
    r = n - k
    p_t = [list(col) for col in zip(*p)]
    i_r = [[1 if i == j else 0 for j in range(r)] for i in range(r)]
    return [p_t[i] + i_r[i] for i in range(r)]


def syndrome(received: list[int], h: list[list[int]]) -> list[int]:
    return mul_mat_vec_mod2(h, received)


def is_codeword(word: list[int], h: list[list[int]]) -> bool:
    return syndrome(word, h) == [0] * len(h)
```

`H` is a compact verifier: `syndrome(r, H) == 0` means “r satisfies every parity equation”. This is what you use in practice to *detect corruption* cheaply, even when you don’t plan to correct it.

### Step 4: Single-bit error correction (Hamming (7,4))

```python
def hamming74_matrices() -> tuple[list[list[int]], list[list[int]]]:
    g = [
        [1, 0, 0, 0, 1, 0, 1],
        [0, 1, 0, 0, 1, 1, 1],
        [0, 0, 1, 0, 1, 1, 0],
        [0, 0, 0, 1, 0, 1, 1],
    ]
    h = parity_check_matrix_from_systematic_g(g)
    return g, h


def correct_single_bit_error(received: list[int], h: list[list[int]]) -> tuple[list[int], int | None]:
    assert_binary_vector(received, name="received")
    assert_binary_matrix(h, name="h")
    if len(received) != len(h[0]):
        raise ValueError("received length must match number of columns of h")

    s = syndrome(received, h)
    if all(bit == 0 for bit in s):
        return received[:], None

    columns = [list(col) for col in zip(*h)]
    try:
        idx = columns.index(s)
    except ValueError as e:
        raise ValueError("syndrome does not match any single-bit error pattern") from e

    corrected = received[:]
    corrected[idx] ^= 1
    return corrected, idx


def decode_hamming74(received: list[int]) -> tuple[list[int], list[int], int | None]:
    g, h = hamming74_matrices()
    assert_binary_vector(received, name="received")
    if len(received) != 7:
        raise ValueError("expected 7-bit received word for Hamming(7,4)")

    corrected, flipped = correct_single_bit_error(received, h)
    message = corrected[:4]
    if encode(message, g) != corrected:
        raise ValueError("received word is not within 1 bit of a valid Hamming(7,4) codeword")
    return message, corrected, flipped
```

For Hamming(7,4), every non-zero syndrome matches *exactly one column* of `H`. That column index tells you which bit to flip. This corrects any single-bit error — but **not** two-bit errors (those can miscorrect into the wrong codeword).

Run it:

```bash
python3 code/main.py
```

## Use It

In real systems, you almost never hand-roll matrices. You pick a family and use a tested implementation:

| Goal | Typical tool/library | Notes |
|------|----------------------|------|
| Prototype / research linear codes | SageMath (`sage.coding`) | Full-featured coding theory toolkit |
| Classic algebraic codes | MATLAB/Octave (`hammgen`, `rsenc`, …) | Batteries-included for comms workflows |
| Storage ECC (SECDED, BCH, RS) | Hardware / firmware ECC engines | The “library” is often silicon |
| Code-based cryptography | `liboqs` (schemes like Classic McEliece) | Uses structured codes, but the math begins here |

The conceptual mapping stays the same: some representation of the code (often `G` and/or `H`), an encoder, a syndrome checker, and a decoder tuned to the code family.

## Pitfalls

- Mixing conventions: writing `c = G·m` in one place and `c = m·G` in another (row-vs-column vectors).
- Forgetting GF(2): replacing XOR/AND with integer addition/multiplication breaks everything silently.
- Assuming “syndrome correction detects two-bit errors”: for Hamming(7,4), correcting on a 2-bit error can flip a *third* bit and decode the wrong message.
- Treating a non-systematic `G` as if “the first k bits are the message” (not true unless `G=[I|P]`).
- Skipping dimension checks: `k×n` vs `n×k` mistakes are easy to make and hard to spot without tests.

## Ship It

This lesson ships a reusable audit prompt you can use to review linear-code implementations and matrix choices:

- Open `outputs/prompt-linear-code-audit.md`
- Paste it into your assistant or into a PR review
- Use it to check: dimensions, systematic form, `G·H^T=0`, syndrome logic, and edge cases

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that every encoded word has syndrome `000`, and that a 1-bit flip is corrected back to the original codeword.
2. Medium: Modify `main.py` to flip a different bit index (try 0, 4, 6). Confirm the syndrome changes and the reported flipped index matches the bit you changed.
3. Hard: Extend the lesson to an **extended Hamming(8,4)** SECDED code by adding one overall parity bit. Update `decode_hamming74` to *detect* (not miscorrect) 2-bit errors.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Linear code | “a set of codewords” | A `k`-dimensional subspace of `{0,1}^n` under XOR |
| Generator matrix (`G`) | “the encoder matrix” | A basis for the code (row space); `c=m·G` |
| Parity-check matrix (`H`) | “the parity matrix” | Constraints defining the code; `H·c^T=0` |
| Syndrome | “error signature” | `s=H·r^T`; zero means valid codeword |
| Hamming distance | “# of differing bits” | Metric that determines detect/correct capability |

## Further Reading

- MacWilliams & Sloane, *The Theory of Error-Correcting Codes* (1977) — classic reference for linear codes and beyond
- Huffman & Pless, *Fundamentals of Error-Correcting Codes* (2003) — clear foundations with many examples
- Wikipedia, “Hamming(7,4)” (online) — quick reference for the canonical worked example
