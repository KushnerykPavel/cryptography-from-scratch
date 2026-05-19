# Hamming Codes (7,4) from Scratch

> Redundancy that points to the exact flipped bit.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `06-coding-theory/01-linear-codes`, `06-coding-theory/02-hamming-distance`  
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why parity bits go at power-of-two positions (1, 2, 4, …)
- **Compute** a Hamming(7,4) syndrome and interpret it as a bit address
- **Implement** Hamming(7,4) encoding (4 data bits → 7 code bits)
- **Distinguish** error detection (“something broke”) from error correction (“fix it safely”)
- **Apply** syndrome decoding to correct any single-bit flip

## The Problem

You store or transmit bits, and something flips them: noisy links, flaky flash cells, radiation in RAM, or a scratched barcode. If you ship raw bits, you get silent corruption: “1011” becomes “1001” and nobody notices until it’s too late.

Checksums and hashes can *detect* corruption, but they don’t usually tell you **which bit** flipped. If your system needs to keep going (memory, storage, telemetry), you want the simplest possible mechanism that can **locate** a single-bit error and correct it automatically.

Hamming codes are the canonical answer: a small number of parity bits, placed carefully, give you enough information to pinpoint one bad bit — including when the bad bit is itself a parity bit.

## The Concept

A Hamming code is a **linear block code** that adds parity checks so that every single-bit error produces a unique **syndrome**.

For Hamming(7,4):

- 4 data bits become 7 transmitted bits.
- Parity bits sit at positions that are powers of two: **1, 2, 4**.
- Data bits fill the remaining positions: **3, 5, 6, 7**.

We’ll use this bit layout (1-indexed positions):

| Position | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
|---|---|---|---|---|---|---|---|
| Meaning | p1 | p2 | d1 | p4 | d2 | d3 | d4 |

The magic trick is: write each position number in binary (3 bits). The syndrome is computed so that, for a single flipped bit, the syndrome equals the **binary index of the flipped position**.

That’s why Hamming decoding can be “compute syndrome → flip that position”.

## Build It

### Step 1: Bit layout and parity-check matrix

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


def format_bits(v: list[int]) -> str:
    assert_binary_vector(v, name="v")
    return "".join(str(b) for b in v)


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


def mul_mat_vec_mod2(m: list[list[int]], v: list[int]) -> list[int]:
    if not isinstance(m, list) or any(not isinstance(row, list) for row in m):
        raise TypeError("m must be a list[list[int]]")
    if len(m) == 0:
        raise ValueError("m must be non-empty")
    width = len(m[0])
    if any(len(row) != width for row in m):
        raise ValueError("m must be rectangular")
    for row in m:
        assert_binary_vector(row, name="m row")

    assert_binary_vector(v, name="v")
    if len(v) != width:
        raise ValueError("vector length must match number of matrix columns")

    out: list[int] = []
    for row in m:
        s = 0
        for a, b in zip(row, v):
            s ^= (a & b)
        out.append(s)
    return out


def hamming74_syndrome(received: list[int]) -> list[int]:
    assert_binary_vector(received, name="received")
    if len(received) != 7:
        raise ValueError("expected 7 bits for Hamming(7,4)")
    h = hamming74_parity_check_matrix()
    return mul_mat_vec_mod2(h, received)


def syndrome_to_position(syndrome: list[int]) -> int:
    assert_binary_vector(syndrome, name="syndrome")
    if len(syndrome) != 3:
        raise ValueError("expected 3 syndrome bits for Hamming(7,4)")
    return syndrome[0] + 2 * syndrome[1] + 4 * syndrome[2]
```

This defines `H` and a syndrome computation `s = H·r^T (mod 2)`. With this convention, a single-bit flip at position `i` yields `syndrome_to_position(s) == i`.

### Step 2: Encode (4 bits -> 7 bits)

```python
def hamming74_encode(message: list[int]) -> list[int]:
    """
    Encode 4 message bits into a 7-bit Hamming(7,4) codeword (even parity).

    Bit layout by position (1-indexed):
      [p1, p2, d1, p4, d2, d3, d4]
    """

    assert_binary_vector(message, name="message")
    if len(message) != 4:
        raise ValueError("expected 4 message bits for Hamming(7,4)")

    d1, d2, d3, d4 = message
    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p4 = d2 ^ d3 ^ d4
    return [p1, p2, d1, p4, d2, d3, d4]


def hamming74_is_codeword(word: list[int]) -> bool:
    return hamming74_syndrome(word) == [0, 0, 0]
```

Encoding is “choose parity bits so all parity checks pass” (even parity). `hamming74_is_codeword` is a cheap validity check: syndrome all-zero means “no parity equation is violated”.

### Step 3: Syndrome (the error’s address)

```python
def flip_bit(word: list[int], *, position: int) -> list[int]:
    assert_binary_vector(word, name="word")
    if not isinstance(position, int):
        raise TypeError("position must be int")
    if position < 1 or position > len(word):
        raise ValueError("position out of range (1-indexed)")
    out = word[:]
    out[position - 1] ^= 1
    return out
```

If you flip one bit in a valid codeword, the syndrome becomes the (binary) index of that bit position. That’s the core ergonomic win of Hamming codes: “detect” and “locate” are the same operation.

### Step 4: Correct and decode

```python
def hamming74_correct_single_bit(received: list[int]) -> tuple[list[int], int | None]:
    """
    If syndrome is non-zero, flip the indicated bit position (1..7).

    Warning: if there are >=2 bit flips, this can "miscorrect" into a different
    valid codeword. Plain Hamming(7,4) cannot reliably detect that case.
    """

    s = hamming74_syndrome(received)
    pos = syndrome_to_position(s)
    if pos == 0:
        return received[:], None
    corrected = flip_bit(received, position=pos)
    return corrected, pos


def hamming74_decode(received: list[int]) -> tuple[list[int], list[int], int | None]:
    """
    Decode a 7-bit received word into (message, corrected_codeword, flipped_pos).

    `flipped_pos` is a 1-indexed bit position that was flipped, or None if no
    error was detected.
    """

    corrected, flipped_pos = hamming74_correct_single_bit(received)
    message = [corrected[2], corrected[4], corrected[5], corrected[6]]
    return message, corrected, flipped_pos
```

Correction is: `syndrome -> position -> flip`. Decoding then extracts the data-bit positions `(3,5,6,7)`.

### Step 5: Pitfall demo — two-bit errors can miscorrect

```python
def main() -> int:
    print("\n=== Step 1: Bit layout and parity-check matrix ===\n")
    h = hamming74_parity_check_matrix()
    print("Bit layout (positions 1..7): [p1, p2, d1, p4, d2, d3, d4]")
    print("Parity-check matrix H (rows correspond to syndrome bits [1,2,4]):")
    for row in h:
        print("  " + format_bits(row))

    print("\n=== Step 2: Encode (4 bits -> 7 bits) ===\n")
    m = [1, 0, 1, 1]
    c = hamming74_encode(m)
    print(f"message  m = {format_bits(m)}")
    print(f"codeword c = {format_bits(c)}")
    print(f"is_codeword(c) = {hamming74_is_codeword(c)}")

    print("\n=== Step 3: Syndrome (the error’s address) ===\n")
    s0 = hamming74_syndrome(c)
    print(f"syndrome(c) = {format_bits(s0)}  -> position {syndrome_to_position(s0)} (0 means no error)")

    r1 = flip_bit(c, position=5)
    s1 = hamming74_syndrome(r1)
    print(f"received r = {format_bits(r1)}  (flipped position 5)")
    print(f"syndrome(r) = {format_bits(s1)} -> position {syndrome_to_position(s1)}")

    print("\n=== Step 4: Correct and decode ===\n")
    m2, corrected, flipped = hamming74_decode(r1)
    print(f"corrected   = {format_bits(corrected)}  (flipped position {flipped})")
    print(f"decoded m   = {format_bits(m2)}")

    print("\n=== Step 5: Pitfall demo — two-bit errors can miscorrect ===\n")
    r2 = flip_bit(flip_bit(c, position=5), position=6)
    s2 = hamming74_syndrome(r2)
    m3, corrected2, flipped2 = hamming74_decode(r2)
    print(f"sent        = {format_bits(c)}")
    print(f"received    = {format_bits(r2)}  (flipped positions 5 and 6)")
    print(f"syndrome    = {format_bits(s2)} -> position {syndrome_to_position(s2)}")
    print(f"corrected   = {format_bits(corrected2)}  (decoder flips position {flipped2})")
    print(f"decoded m   = {format_bits(m3)}  (may be wrong!)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

This last step is the real-world gotcha: **plain Hamming(7,4) cannot tell “1 error” from “2 errors”**. If you “correct anyway”, you can silently decode the wrong message.

Run it:

```bash
python3 code/main.py
```

## Use It

Where Hamming-style ECC shows up in production:

- **ECC RAM / memory controllers:** commonly use *extended Hamming* (SECDED) variants: correct 1-bit errors, detect (but don’t correct) 2-bit errors per word.
- **Storage / flash controllers:** often use stronger families (BCH/LDPC), but the “syndrome → location” idea generalizes.
- **Hardware descriptions:** parity-check logic is typically implemented as XOR trees over selected bit positions.

Practical equivalents (what you’d use instead of rolling your own in Python):

- Hardware ECC engines (memory controller, FPGA IP, SoC peripherals)
- Standardized coding families for noisy channels: BCH, Reed–Solomon, LDPC, Polar

## Pitfalls

- **Bit ordering mismatches:** switching between 0-indexed code arrays and 1-indexed “bit positions” breaks syndrome decoding.
- **Parity convention drift:** “even parity” vs “odd parity” must match on encode and decode.
- **Over-correction:** applying single-error correction in a setting where 2-bit errors happen can silently corrupt data (miscorrection).
- **Wrong extraction of data bits:** decoding must pull out positions 3,5,6,7 for this layout (not “first 4 bits”).
- **No tests for every bit position:** skipping “flip each of the 7 bits and decode” is how bugs ship.

## Ship It

Save and reuse the checklist in `outputs/prompt-hamming74-audit.md` when reviewing:

- a Hamming(7,4) encoder/decoder
- “ECC RAM” logic in software or HDL
- any syndrome-based “flip a bit” correction code

Use it as a PR review prompt: paste it into your reviewer agent and ask for a go/no-go recommendation.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe how the syndrome becomes the binary address of the flipped bit.
2. Medium. Modify the demo to flip each position 1..7 once and print `(position, syndrome, corrected_position)` to confirm they match.
3. Hard. Add an **overall parity bit** (extended Hamming / SECDED) so the decoder can detect (but not correct) double-bit errors instead of miscorrecting them.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Hamming(7,4) | “7 bits with 3 parity bits” | A `[7,4,3]` linear code over GF(2): `k=4`, `n=7`, minimum distance `d_min=3` |
| Parity bit | “Extra check bit” | A bit chosen so a selected subset has even (or odd) parity |
| Parity-check matrix (H) | “The checker matrix” | A matrix defining constraints; `H·c^T = 0` for valid codewords |
| Syndrome | “Error pattern” | The vector `s = H·r^T`; for Hamming(7,4) it encodes the flipped position |
| Syndrome decoding | “Flip the bit syndrome says” | A decoder that maps `s` to the lowest-weight error consistent with it |
| Miscorrection | “It corrected, but wrong” | A decoder flips a bit and lands on a valid codeword that is not the original |

## Further Reading

- Richard W. Hamming, “Error Detecting and Error Correcting Codes” (1950) — the original idea and motivation.
- Any modern coding theory text, “Hamming codes” chapter — generalizes to `(2^r-1, 2^r-1-r)` constructions.
- “SECDED / extended Hamming” notes in computer architecture material — how real memory systems avoid silent miscorrection.
