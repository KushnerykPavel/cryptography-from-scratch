# Syndrome Decoding (and why it gets hard fast)

> The syndrome tells you the *coset* — decoding is picking the most likely error inside it.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `06-coding-theory/01-linear-codes`, `06-coding-theory/03-hamming-codes`  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what a syndrome is and why it depends only on the error, not the sent codeword
- **Compute** syndromes `s = H·r^T (mod 2)` and interpret them as “which coset am I in?”
- **Implement** a syndrome table that maps each syndrome to a lowest-weight error pattern (coset leader)
- **Distinguish** “easy” syndrome decoding (e.g., Hamming single-bit) from “general decoding” (combinatorial / NP-hard)
- **Apply** syndrome decoding to correct a 1-bit error and to demonstrate miscorrection on 2-bit errors

## The Problem

In the previous lessons, you learned that `H·c^T = 0` is the definition of a valid codeword, and that `s = H·r^T` is a compact “something is wrong” signal for a received word `r`. But that only answers **detection**.

In real systems you often want **correction**: you don’t want to retransmit every time a bit flips. ECC memory, storage controllers, and low-latency links all need a decoder that can take a corrupted word and produce the most likely original codeword.

Syndrome decoding is the bridge from “I can compute a syndrome” to “I can correct errors”. It’s also the gateway to an uncomfortable truth: beyond special code families, decoding quickly turns into a **combinatorial search** problem.

## The Concept

Let `C` be a binary linear code with parity-check matrix `H` (`(n-k)×n`). A received word is:

\[
r = c \oplus e
\]

where `c` is the sent codeword and `e` is an error pattern (a sparse vector with 1s at flipped positions).

The syndrome is:

\[
s = H\cdot r^T = H\cdot(c \oplus e)^T = H\cdot c^T \oplus H\cdot e^T = 0 \oplus H\cdot e^T = H\cdot e^T
\]

So the syndrome depends **only** on the error pattern. That means:

- Every syndrome corresponds to a whole **coset** of possible received words.
- Decoding is: “given syndrome `s`, pick the *most likely* error `ê` with `H·ê^T = s`”.

For a binary symmetric channel (each bit flips with small probability `p`), lower-weight errors are exponentially more likely, so a common rule is:

- Pick the **lowest-weight** error pattern consistent with the syndrome.

This “find the minimum-weight `e` such that `H·e^T = s`” is the **general decoding problem**, and it is NP-hard for arbitrary linear codes. Hamming(7,4) is “easy” because every non-zero syndrome matches a single column of `H`, so the best error is always a single-bit flip.

## Build It

### Step 1: GF(2) vectors and syndromes

```python
from __future__ import annotations

from itertools import combinations


def is_bit(x: int) -> bool:
    return x in (0, 1)


def assert_binary_vector(v: list[int], *, name: str = "vector") -> None:
    if not isinstance(v, list):
        raise TypeError(f"{name} must be a list[int]")
    if any(not isinstance(b, int) for b in v):
        raise TypeError(f"{name} must be a list[int]")
    if any(not is_bit(b) for b in v):
        raise ValueError(f"{name} must contain only 0/1")


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


def format_bits(v: list[int]) -> str:
    assert_binary_vector(v, name="v")
    return "".join(str(b) for b in v)


def xor_vec(a: list[int], b: list[int]) -> list[int]:
    assert_binary_vector(a, name="a")
    assert_binary_vector(b, name="b")
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    return [x ^ y for x, y in zip(a, b)]


def hamming_weight(v: list[int]) -> int:
    assert_binary_vector(v, name="v")
    return sum(v)


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


def syndrome(received: list[int], h: list[list[int]]) -> list[int]:
    assert_binary_vector(received, name="received")
    assert_binary_matrix(h, name="h")
    if len(received) != len(h[0]):
        raise ValueError("received length must match number of columns of h")
    return mul_mat_vec_mod2(h, received)


def is_codeword(word: list[int], h: list[list[int]]) -> bool:
    return syndrome(word, h) == [0] * len(h)


def syndrome_to_int(s: list[int]) -> int:
    assert_binary_vector(s, name="s")
    out = 0
    for i, bit in enumerate(s):
        out += bit << i
    return out


def hamming74_parity_check_matrix() -> list[list[int]]:
    """
    Parity-check matrix H for Hamming(7,4) in the "bit position" convention.

    Columns correspond to positions 1..7, written in binary with three bits.
    The syndrome s = H·r^T (mod 2) equals the binary index of a single flipped bit.
    Syndrome bits are ordered as [1, 2, 4] (least-significant bit first).
    """

    return [
        [1, 0, 1, 0, 1, 0, 1],  # position bit 1 (LSB): 1,3,5,7
        [0, 1, 1, 0, 0, 1, 1],  # position bit 2:     2,3,6,7
        [0, 0, 0, 1, 1, 1, 1],  # position bit 4:     4,5,6,7
    ]
```

This is the “GF(2) plumbing”: XOR-based vector ops, `s = H·r^T`, and a concrete `H` for Hamming(7,4) so we can run a full end-to-end example.

### Step 2: A bit-flip becomes a syndrome

```python
def error_pattern(*, n: int, ones_at: list[int]) -> list[int]:
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if n <= 0:
        raise ValueError("n must be positive")
    if not isinstance(ones_at, list) or any(not isinstance(i, int) for i in ones_at):
        raise TypeError("ones_at must be a list[int]")
    if any(i < 0 or i >= n for i in ones_at):
        raise ValueError("ones_at contains an out-of-range index")
    if len(set(ones_at)) != len(ones_at):
        raise ValueError("ones_at must not contain duplicates")

    out = [0] * n
    for i in ones_at:
        out[i] = 1
    return out
```

We represent an error as a vector `e` with 1s at flipped positions. Then `r = c ⊕ e` and (crucially) `syndrome(r) == syndrome(e)`.

### Step 3: Build a syndrome table (coset leaders)

```python
def all_error_patterns(*, n: int, max_weight: int) -> list[list[int]]:
    if not isinstance(n, int):
        raise TypeError("n must be int")
    if not isinstance(max_weight, int):
        raise TypeError("max_weight must be int")
    if n <= 0:
        raise ValueError("n must be positive")
    if max_weight < 0:
        raise ValueError("max_weight must be >= 0")
    if max_weight > n:
        raise ValueError("max_weight must be <= n")

    out: list[list[int]] = []
    for w in range(max_weight + 1):
        for idxs in combinations(range(n), w):
            out.append(error_pattern(n=n, ones_at=list(idxs)))
    return out


def build_syndrome_table(h: list[list[int]], *, max_weight: int) -> dict[tuple[int, ...], list[int]]:
    """
    Build a syndrome table mapping each syndrome to a "coset leader":
    the first (lowest-weight) error pattern found with that syndrome.

    For a binary symmetric channel with small flip probability, picking the
    lowest-weight error is a maximum-likelihood rule.
    """

    assert_binary_matrix(h, name="h")
    n = len(h[0])
    patterns = all_error_patterns(n=n, max_weight=max_weight)

    table: dict[tuple[int, ...], list[int]] = {}
    for e in patterns:
        s = syndrome(e, h)
        key = tuple(s)
        if key not in table:
            table[key] = e
    return table
```

This is “general syndrome decoding” in its simplest form: enumerate likely errors up to a weight bound, compute their syndromes, and store the first pattern per syndrome. For Hamming(7,4), `max_weight=1` already covers every non-zero syndrome.

### Step 4: Syndrome decode (correct by XOR)

```python
def syndrome_decode(
    received: list[int],
    h: list[list[int]],
    *,
    table: dict[tuple[int, ...], list[int]],
) -> tuple[list[int], list[int], list[int]]:
    """
    Decode by computing s = H·r^T, looking up an estimated error ê(s),
    and returning r ⊕ ê(s).

    Returns (corrected, estimated_error, syndrome).
    """

    s = syndrome(received, h)
    key = tuple(s)
    if key not in table:
        raise ValueError("syndrome is not present in table (table is too small)")
    e_hat = table[key]
    corrected = xor_vec(received, e_hat)
    return corrected, e_hat, s
```

Decoding is literally “subtract the estimated error” — and in GF(2), subtraction is XOR.

### Step 5: Why decoding gets hard (and why miscorrection happens)

```python
def count_error_patterns(*, n: int, max_weight: int) -> int:
    return len(all_error_patterns(n=n, max_weight=max_weight))
```

The number of candidate errors of weight ≤ `t` is \(\sum_{i=0}^{t} \binom{n}{i}\), which explodes quickly. If you use a small table (e.g., `t=1`) and the true error has weight 2, the decoder will often “explain” it as a different 1-bit error with the same syndrome — producing a valid codeword that is *not* the original (miscorrection).

Run it:

```bash
python3 code/main.py
```

## Use It

Syndrome decoding in real systems is usually specialized:

| Where you see it | Typical implementation | Notes |
|---|---|---|
| Hamming/SECDED (memory, buses) | Hardware/firmware ECC | Syndrome points to a bit (or flags 2-bit errors) |
| BCH/RS (storage, Wi‑Fi, DVB) | Dedicated decoders (Berlekamp–Massey, Euclid) | Not “build a table”; algebraic decoding is faster |
| LDPC/Turbo (modern comms) | Iterative belief propagation | Soft information and many iterations |
| Code-based crypto (McEliece) | Specialized decoders for structured codes | Security relies on decoding being hard for random codes |

For “random linear codes”, the generic “find lowest-weight error matching a syndrome” is computationally hard — which is precisely why code-based cryptography exists.

## Pitfalls

- Building a syndrome table for large `n`: the table size grows like \(\sum_{i=0}^{t}\binom{n}{i}\), which becomes impossible fast.
- Overcorrecting: using a `t=1` decoder when the channel can produce 2-bit errors yields **miscorrections** (valid-but-wrong outputs).
- Mixing conventions: `s = H·r^T` vs `s = r·H^T`, bit order, or syndrome-bit ordering (LSB/MSB) — all silently break tables.
- Forgetting the error model: “lowest weight” is maximum-likelihood only under a simple BSC; with burst errors, the best coset leader differs.
- Treating decoding as non-adversarial: in adversarial settings, an attacker can craft error patterns that force miscorrection.

## Ship It

This lesson ships a reusable review prompt for syndrome decoders:

- Open `outputs/prompt-syndrome-decoding-review.md`
- Paste it into your assistant or into a PR review
- Use it to audit: parity-check conventions, table construction, decoding guarantees, and miscorrection risk

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that `syndrome(c)=000`, that a 1-bit flip is corrected, and that a 2-bit flip can miscorrect into a different codeword.
2. Medium: Change the `max_weight` used to build the table to `2`. Re-run and observe: does the decoder still pick a 1-bit error for Hamming(7,4)? Why?
3. Hard: Implement **SECDED** behavior for Hamming by adding one overall parity bit (extended Hamming(8,4)). Update the decoder to correct 1-bit errors but *detect* (reject) 2-bit errors.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Syndrome | “error signature” | `s = H·r^T`; it identifies the coset of the received word |
| Coset | “shifted code” | `C ⊕ e`: all words that differ from codewords by the same error pattern |
| Coset leader | “canonical error” | The chosen representative error pattern for a syndrome (often lowest-weight) |
| Minimum-weight decoding | “best correction” | Find `e` with `H·e^T=s` minimizing weight — hard in general |
| Miscorrection | “decoder made it worse” | Decoder outputs a valid codeword that is not the sent one |

## Further Reading

- Berlekamp, McEliece, van Tilborg, “On the inherent intractability of certain coding problems” (1978) — classic NP-hardness result for general decoding
- Huffman & Pless, *Fundamentals of Error-Correcting Codes* (2003) — clear presentation of syndromes, cosets, and decoding
- MacWilliams & Sloane, *The Theory of Error-Correcting Codes* (1977) — definitive reference for linear codes and decoding theory
