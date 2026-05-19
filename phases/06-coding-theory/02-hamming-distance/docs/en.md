# Hamming Distance & Minimum Distance

> Distance is your error budget: `d_min` tells you what you can detect and correct.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `phases/06-coding-theory/01-linear-codes` (binary vectors, XOR, basic GF(2) intuition)  
**Time:** ~50 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** Hamming distance as “how many symbols differ” for equal-length words
- **Compute** bit-level Hamming distance using `XOR` + popcount
- **Implement** `d_min` (minimum distance) for a finite set of codewords
- **Distinguish** detection (`d_min - 1`) from correction (`⌊(d_min-1)/2⌋`) guarantees
- **Apply** nearest-neighbor decoding and recognize when it becomes ambiguous

## The Problem

You’re storing or transmitting bits across a channel that flips some of them: flaky memory, noisy radio, scratched QR codes, or a corrupted packet. You add redundancy, but then you have to answer a hard engineering question: **how much corruption can I tolerate before the receiver gets confused?**

Without a concrete notion of “closeness” between two bitstrings, you can’t make (or audit) claims like “this code detects 2 errors” or “this decoder corrects 1 error”. You also can’t reason about failure modes like **miscorrection** (silently decoding to the wrong codeword) or **ambiguity** (two codewords are equally plausible).

This lesson gives you the geometry: **Hamming distance** (how many positions differ) and **minimum distance** `d_min` (how far apart the closest pair of valid codewords is). Those two numbers drive almost everything you say about a block code’s safety.

## The Concept

For two equal-length words (strings, vectors, bytes), the **Hamming distance** counts how many positions differ:

\[
d(x, y) = \#\{i \mid x_i \neq y_i\}
\]

For binary vectors, it’s useful to connect three related ideas:

- **Hamming weight** `w(x)` = number of 1s in `x`
- `x ⊕ y` (XOR) highlights which positions differ
- So `d(x, y) = w(x ⊕ y)`

Now suppose you have a block code `C` — a finite set of valid length-`n` codewords. Its **minimum distance** is:

\[
d_{\min}(C) = \min_{c_1 \neq c_2 \in C} d(c_1, c_2)
\]

Why you care: if the closest two codewords are `d_min` apart, then:

- **Detection guarantee:** up to `d_min - 1` flipped bits can’t turn one valid codeword into another valid codeword.
- **Correction guarantee (unique decoding):** up to `⌊(d_min - 1)/2⌋` flipped bits is small enough that the received word is closer to the original codeword than to any other.

The correction guarantee is about uniqueness: the “balls” of radius `t = ⌊(d_min - 1)/2⌋` around each codeword don’t overlap.

## Build It

### Step 1: Hamming weight & distance on bit vectors

```python
from __future__ import annotations


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

This is the core definition you’ll use everywhere in coding theory: distance is “how many bit flips it takes” to turn one word into another. The `xor_vec` trick makes that definition executable: XOR marks differences, and weight counts them.

### Step 2: Bit-level distance on bytes (XOR + popcount)

```python
def hamming_distance_bytes(a: bytes, b: bytes) -> int:
    if not isinstance(a, (bytes, bytearray)):
        raise TypeError("a must be bytes-like")
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("b must be bytes-like")
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def normalized_hamming_distance_bytes(a: bytes, b: bytes) -> float:
    if len(a) == 0:
        raise ValueError("cannot normalize distance for empty inputs")
    return hamming_distance_bytes(a, b) / len(a)
```

When your “symbols” are bytes, Hamming distance usually means **bit-level** distance: XOR the bytes and count the 1s (popcount). The normalized distance (bits per byte here) is a common scaling trick when comparing blocks of different sizes.

### Step 3: Minimum distance and what it guarantees

```python
def assert_codewords(codewords: list[list[int]], *, name: str = "codewords") -> None:
    if not isinstance(codewords, list):
        raise TypeError(f"{name} must be a list[list[int]]")
    if len(codewords) == 0:
        raise ValueError(f"{name} must be non-empty")
    if any(not isinstance(w, list) for w in codewords):
        raise TypeError(f"{name} must be a list[list[int]]")
    n = len(codewords[0])
    for i, w in enumerate(codewords):
        assert_binary_vector(w, name=f"{name}[{i}]")
        if len(w) != n:
            raise ValueError(f"{name} must contain words of equal length")


def minimum_distance(codewords: list[list[int]]) -> int:
    assert_codewords(codewords)
    if len(codewords) < 2:
        raise ValueError("need at least 2 codewords to define a minimum distance")

    best: int | None = None
    for i in range(len(codewords)):
        for j in range(i + 1, len(codewords)):
            d = hamming_distance(codewords[i], codewords[j])
            if best is None or d < best:
                best = d
    assert best is not None
    return best


def max_detectable_errors(d_min: int) -> int:
    if not isinstance(d_min, int):
        raise TypeError("d_min must be int")
    if d_min <= 0:
        raise ValueError("d_min must be positive")
    return d_min - 1


def max_correctable_errors(d_min: int) -> int:
    if not isinstance(d_min, int):
        raise TypeError("d_min must be int")
    if d_min <= 0:
        raise ValueError("d_min must be positive")
    return (d_min - 1) // 2
```

`minimum_distance` is the “single number summary” of a code’s robustness. Once you know `d_min`, you can translate it into honest statements about what the code can **always detect** and what it can **always correct** (under unique decoding).

### Step 4: Nearest-neighbor decoding (and when it fails)

```python
def nearest_neighbor_decode(received: list[int], codewords: list[list[int]]) -> tuple[list[int], int]:
    assert_binary_vector(received, name="received")
    assert_codewords(codewords, name="codewords")
    if len(received) != len(codewords[0]):
        raise ValueError("received length must match codeword length")

    best_idx: int | None = None
    best_dist: int | None = None
    tied = False

    for i, c in enumerate(codewords):
        d = hamming_distance(received, c)
        if best_dist is None or d < best_dist:
            best_idx = i
            best_dist = d
            tied = False
        elif d == best_dist:
            tied = True

    assert best_idx is not None
    assert best_dist is not None
    if tied:
        raise ValueError("nearest-neighbor decoding is ambiguous (tie for closest codeword)")
    return codewords[best_idx][:], best_dist


def format_bits(v: list[int]) -> str:
    return "".join(str(b) for b in v)


def main() -> int:
    print("\n=== Step 1: Hamming weight & distance on bit vectors ===\n")
    a = [1, 0, 1, 1, 0, 1]
    b = [1, 1, 0, 1, 0, 0]
    print(f"a = {format_bits(a)}  weight(a) = {hamming_weight(a)}")
    print(f"b = {format_bits(b)}  weight(b) = {hamming_weight(b)}")
    print(f"distance(a, b) = {hamming_distance(a, b)}")

    print("\n=== Step 2: Bit-level distance on bytes (XOR + popcount) ===\n")
    s1 = b"this is a test"
    s2 = b"wokka wokka!!!"
    d = hamming_distance_bytes(s1, s2)
    nd = normalized_hamming_distance_bytes(s1, s2)
    print(f"s1 = {s1!r}")
    print(f"s2 = {s2!r}")
    print(f"hamming_distance_bytes(s1, s2) = {d}")
    print(f"normalized_hamming_distance_bytes(s1, s2) = {nd:.6f} (bits per byte)")

    print("\n=== Step 3: Minimum distance and what it guarantees ===\n")
    repetition3 = [[0, 0, 0], [1, 1, 1]]
    d_min = minimum_distance(repetition3)
    print(f"repetition3 codewords = {[format_bits(w) for w in repetition3]}")
    print(f"d_min = {d_min}")
    print(f"detect up to {max_detectable_errors(d_min)} bit flips (guaranteed)")
    print(f"correct up to {max_correctable_errors(d_min)} bit flips (guaranteed)")

    print("\n=== Step 4: Nearest-neighbor decoding (and when it fails) ===\n")
    r_good = [0, 1, 0]
    decoded, dist = nearest_neighbor_decode(r_good, repetition3)
    print(f"received = {format_bits(r_good)}  -> decoded = {format_bits(decoded)}  (distance {dist})")

    code_00_11 = [[0, 0], [1, 1]]
    r_amb = [0, 1]
    print(f"\ncodewords = {[format_bits(w) for w in code_00_11]}")
    print(f"received  = {format_bits(r_amb)}")
    try:
        nearest_neighbor_decode(r_amb, code_00_11)
    except ValueError as e:
        print(f"decode failed: {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Nearest-neighbor decoding is the simplest possible decoder: pick the valid codeword closest to what you received. It’s exactly what the `d_min` correction guarantee is about — and the tie case is the failure mode you must not hide (ties mean your “correction” claim is false for that error pattern).

Run it:

```bash
python3 code/main.py
```

## Use It

In practice, you usually don’t compute distances between all codewords (there can be astronomically many). Instead you use algebraic structure:

- **Hamming codes / BCH / Reed–Solomon** use syndrome-based decoding (solve for the error pattern).
- **Modern storage/network stacks** use standardized ECC blocks with well-defined minimum distance and decoders.

Still, Hamming distance shows up constantly in “glue code” and debugging:

- Measuring “how corrupted” a received word is (distance to the nearest valid word)
- Comparing candidate decodings (which one is closer?)
- Normalized distances as heuristics (e.g., guessing key sizes in classical attacks)

## Pitfalls

- Confusing **symbol distance** (positions differ) with **bit distance** (bits differ inside bytes). For bytes, be explicit about whether you mean “bytes differ” or “bits differ”.
- Forgetting the **equal-length requirement**. Hamming distance is not edit distance (no insertions/deletions).
- Normalizing by the wrong unit: “bits per *byte*” vs “bits per *bit*”. Write the unit in the variable name or printed output.
- Over-claiming correction: `d_min = 2` can *detect* 1 error, but it cannot *uniquely correct* 1 error (ties happen).
- Hiding ambiguity by “just pick one” in a decoder. In adversarial settings, silent miscorrection is often worse than a hard failure.

## Ship It

This lesson ships a reusable review prompt: a checklist for auditing “distance-based” claims (detection/correction/decoding) in ECC code and specs.

1. Open `outputs/prompt-distance-claims-audit.md`.
2. Paste it into your LLM or a PR review comment.
3. Fill in the code’s codewords/parameters and force the author to justify every “detect/correct” claim from `d_min`.

## Exercises

1. Easy: run `python3 code/main.py`. Observe the ambiguous nearest-neighbor decode for the `{00, 11}` code.
2. Medium: extend `code/main.py` with a helper that computes `d_min` for the full Hamming(7,4) codebook (generate all codewords from `phases/06-coding-theory/01-linear-codes/code/main.py`) and verify `d_min = 3`.
3. Hard: integrate this lesson into a “decode-or-reject” policy: given a received word, decode only if it’s within `t = ⌊(d_min-1)/2⌋` of a unique codeword; otherwise reject (simulate adversarial corruption cases).

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Hamming distance | “How many bits differ” | For equal-length words: the number of positions (symbols) that differ (often applied at bit-level via XOR+popcount). |
| Hamming weight | “How many 1s” | The number of 1s in a binary vector. |
| Minimum distance (`d_min`) | “How strong the code is” | The smallest Hamming distance between any two distinct codewords in the code. |
| Detect `t` errors | “It catches corruption” | Any pattern of up to `t` flips will never map a valid codeword to another valid codeword. |
| Correct `t` errors | “It fixes corruption” | Up to `t` flips still leave a unique closest codeword (no overlap of decoding balls). |

## Further Reading

- Richard W. Hamming, *Error Detecting and Error Correcting Codes* (1950) — the original motivation and construction of Hamming codes.  
- NIST, *Dictionary of Algorithms and Data Structures: Hamming distance* (2006) — concise definition and references.  
- “Hamming distance” (Wikipedia) — includes the `d_min - 1` detection and `⌊(d_min-1)/2⌋` correction relationship.  
- The Cryptopals Crypto Challenges, Set 1 Challenge 6 — a practical place you’ll see normalized Hamming distance used as a heuristic.
