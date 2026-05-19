"""
Hamming distance and minimum distance (from scratch).

This script builds a small, stdlib-only toolkit for:
- Hamming weight and Hamming distance on binary vectors (list[int])
- Bit-level Hamming distance on equal-length byte strings
- Minimum distance of a block code (a finite set of codewords)
- Error detection/correction capability derived from minimum distance
- Nearest-neighbor (minimum-distance) decoding with tie detection

Run:
  python3 phases/06-coding-theory/02-hamming-distance/code/main.py
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
