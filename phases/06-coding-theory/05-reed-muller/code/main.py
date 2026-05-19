"""
Reed-Muller codes from scratch (focus: RM(1, m) / Hadamard code decoding).

This script implements:
- Reed-Muller parameters and monomial basis (RM(r, m))
- Generator matrix construction via monomial truth tables
- Encoding over GF(2) using the generator matrix
- Fast decoding for RM(1, m) using the Walsh-Hadamard transform (WHT)

Run:
  python3 phases/06-coding-theory/05-reed-muller/code/main.py
"""

from __future__ import annotations

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


def rm_generator_matrix(r: int, m: int) -> list[list[int]]:
    assert_rm_params(r, m)
    n = 1 << m
    monomials = rm_monomials_upto_degree(r, m)
    G: list[list[int]] = []
    for mon in monomials:
        G.append([rm_eval_monomial(mon, x, m=m) for x in range(n)])
    return G


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


def bits_from_int(x: int, *, width: int) -> list[int]:
    assert_nonneg_int(x, name="x")
    assert_nonneg_int(width, name="width")
    return [((x >> i) & 1) for i in range(width)]


def _pretty_monomial(mon: tuple[int, ...]) -> str:
    if len(mon) == 0:
        return "1"
    return "*".join(f"x{i}" for i in mon)


def main() -> None:
    m = 3
    r = 1

    print("=== Step 1: Monomials as truth tables ===")
    monomials = rm_monomials_upto_degree(r, m)
    print("monomials:", [_pretty_monomial(mon) for mon in monomials])
    for mon in monomials:
        row = [rm_eval_monomial(mon, x, m=m) for x in range(1 << m)]
        print(f"{_pretty_monomial(mon):>4}:", row)

    print("\n=== Step 2: Generator matrix and parameters ===")
    n, k, d = rm_parameters(r, m)
    print(f"RM({r},{m}) has n={n}, k={k}, d={d}")
    G = rm_generator_matrix(r, m)
    print("G (rows are monomials, columns are points x=0..n-1):")
    for row in G:
        print(row)

    print("\n=== Step 3: Encode with the generator matrix ===")
    message = [1, 0, 1, 1]
    codeword = rm_encode(message, r, m)
    print("message (coeffs for [1, x0, x1, x2]):", message)
    print("codeword:", codeword)

    print("\n=== Step 4: Decode RM(1,m) with Walsh-Hadamard ===")
    received = codeword[:]
    flip_pos = 5
    received[flip_pos] ^= 1
    decoded, corrected = rm1_correct(received, m=m)
    print("received (1-bit error at position 5):", received)
    print("decoded coeffs [a0,a1,a2,a3]:", decoded)
    print("corrected codeword:", corrected)
    print("distance(received, corrected):", hamming_distance(received, corrected))


if __name__ == "__main__":
    main()
