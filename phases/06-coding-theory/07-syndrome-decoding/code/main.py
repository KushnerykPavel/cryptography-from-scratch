"""
Syndrome decoding (binary linear codes) from scratch.

This script shows how to:
  1) Compute syndromes s = H·r^T (mod 2)
  2) Build a syndrome table (syndrome -> lowest-weight error pattern)
  3) Decode by subtracting the estimated error (XOR in GF(2))
  4) See why general decoding becomes combinatorial (NP-hard in general)

Run:
  python3 code/main.py
"""

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


def count_error_patterns(*, n: int, max_weight: int) -> int:
    return len(all_error_patterns(n=n, max_weight=max_weight))


def main() -> int:
    h = hamming74_parity_check_matrix()
    n = len(h[0])

    print("\n=== Step 1: GF(2) vectors and syndromes ===\n")
    print("Parity-check matrix H for Hamming(7,4) (rows are syndrome bits [1,2,4]):")
    for row in h:
        print("  " + format_bits(row))

    c = [0, 1, 1, 0, 0, 1, 1]
    print(f"\nexample codeword c = {format_bits(c)}")
    print(f"syndrome(c)        = {format_bits(syndrome(c, h))}  (0 means 'valid codeword')")

    print("\n=== Step 2: A bit-flip becomes a syndrome ===\n")
    r1 = xor_vec(c, error_pattern(n=n, ones_at=[4]))  # flip position 5 (0-indexed 4)
    s1 = syndrome(r1, h)
    print(f"received r         = {format_bits(r1)}  (one flip at position 5)")
    print(f"syndrome(r)        = {format_bits(s1)}  -> int {syndrome_to_int(s1)}")

    print("\n=== Step 3: Build a syndrome table (coset leaders) ===\n")
    t = 1
    table = build_syndrome_table(h, max_weight=t)
    print(f"built table for max_weight={t}: {len(table)} syndromes covered")
    print("example lookups (syndrome -> error pattern -> bit position):")
    for s_bits in ([1, 0, 1], [1, 1, 1], [0, 0, 0]):
        e = table[tuple(s_bits)]
        positions = [i + 1 for i, b in enumerate(e) if b == 1]
        label = "none" if not positions else ",".join(str(p) for p in positions)
        print(f"  {format_bits(s_bits)} -> {format_bits(e)} -> {label}")

    print("\n=== Step 4: Syndrome decode (correct by XOR) ===\n")
    corrected, e_hat, s_hat = syndrome_decode(r1, h, table=table)
    print(f"syndrome            = {format_bits(s_hat)}")
    print(f"estimated error ê   = {format_bits(e_hat)}  (weight {hamming_weight(e_hat)})")
    print(f"corrected word ĉ    = {format_bits(corrected)}")
    print(f"is_codeword(ĉ)      = {is_codeword(corrected, h)}")
    print(f"ĉ == c              = {corrected == c}")

    print("\n=== Step 5: Why decoding gets hard (and why miscorrection happens) ===\n")
    r2 = xor_vec(c, error_pattern(n=n, ones_at=[4, 5]))  # flip positions 5 and 6
    s2 = syndrome(r2, h)
    corrected2, e_hat2, _ = syndrome_decode(r2, h, table=table)
    print(f"received r (2 flips) = {format_bits(r2)}  (positions 5 and 6)")
    print(f"syndrome(r)          = {format_bits(s2)}  (same as a 1-bit flip at position 3)")
    print(f"decoder uses ê       = {format_bits(e_hat2)}")
    print(f"corrected ĉ          = {format_bits(corrected2)}")
    print(f"ĉ is codeword        = {is_codeword(corrected2, h)}  (but it may be the wrong one!)")

    print("\nBrute-force table sizes (error patterns of weight <= t):")
    for n_show in (7, 15, 31, 63):
        sizes = [count_error_patterns(n=n_show, max_weight=t_show) for t_show in (1, 2, 3)]
        print(f"  n={n_show:>2}: t=1 -> {sizes[0]:>6}, t=2 -> {sizes[1]:>6}, t=3 -> {sizes[2]:>6}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
