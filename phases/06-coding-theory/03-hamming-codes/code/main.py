"""
Hamming(7,4) from scratch (even parity).

This script implements the classic Hamming(7,4) code using parity bits at
positions 1, 2, and 4 (1-indexed). It supports:
- encoding 4 data bits into 7 bits
- computing the syndrome (which identifies a single flipped bit)
- correcting a single-bit error and decoding the original 4 data bits

Run:
  python3 phases/06-coding-theory/03-hamming-codes/code/main.py
"""

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


def flip_bit(word: list[int], *, position: int) -> list[int]:
    assert_binary_vector(word, name="word")
    if not isinstance(position, int):
        raise TypeError("position must be int")
    if position < 1 or position > len(word):
        raise ValueError("position out of range (1-indexed)")
    out = word[:]
    out[position - 1] ^= 1
    return out


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
