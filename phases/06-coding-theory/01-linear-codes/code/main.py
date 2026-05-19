"""
Linear codes from scratch (binary, GF(2)).

This script implements a tiny toolkit for linear block codes:
- Hamming weight / distance
- Encoding with a generator matrix G
- Syndrome checking with a parity-check matrix H
- Single-bit error correction for the (7,4) Hamming code (systematic form)

Run:
  python3 phases/06-coding-theory/01-linear-codes/code/main.py
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


def encode(message: list[int], g: list[list[int]]) -> list[int]:
    return mul_vec_mat_mod2(message, g)


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


def all_binary_vectors(length: int) -> list[list[int]]:
    if length < 0:
        raise ValueError("length must be non-negative")
    if length == 0:
        return [[]]
    out: list[list[int]] = []
    for x in range(1 << length):
        out.append([(x >> (length - 1 - i)) & 1 for i in range(length)])
    return out


def format_bits(v: list[int]) -> str:
    return "".join(str(b) for b in v)


def main() -> int:
    print("\n=== Step 1: Bits, weight, and Hamming distance ===\n")
    a = [1, 0, 1, 1]
    b = [1, 1, 0, 1]
    print(f"a = {format_bits(a)}  weight(a) = {hamming_weight(a)}")
    print(f"b = {format_bits(b)}  weight(b) = {hamming_weight(b)}")
    print(f"distance(a, b) = {hamming_distance(a, b)}")

    print("\n=== Step 2: Encoding with a generator matrix (G) ===\n")
    g, _ = hamming74_matrices()
    m = [1, 0, 1, 1]
    c = encode(m, g)
    print(f"message m = {format_bits(m)}")
    print(f"codeword c = m·G (mod 2) = {format_bits(c)}")

    print("\n=== Step 3: Validity checking with a parity-check matrix (H) ===\n")
    _, h = hamming74_matrices()
    s0 = syndrome(c, h)
    print(f"syndrome(H·c^T) = {format_bits(s0)}  (all-zero means valid)")
    print(f"is_codeword(c) = {is_codeword(c, h)}")

    print("\n=== Step 4: Single-bit error correction (Hamming (7,4)) ===\n")
    received = c[:]
    received[2] ^= 1
    print(f"sent     = {format_bits(c)}")
    print(f"received = {format_bits(received)}  (bit 2 flipped)")
    s1 = syndrome(received, h)
    print(f"syndrome = {format_bits(s1)}")
    message2, corrected, flipped = decode_hamming74(received)
    print(f"corrected= {format_bits(corrected)}  (flipped bit index: {flipped})")
    print(f"decoded m= {format_bits(message2)}")

    print("\nEnumerating all 16 codewords (Hamming(7,4)):")
    codewords = [format_bits(encode(msg, g)) for msg in all_binary_vectors(4)]
    print(", ".join(codewords))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
