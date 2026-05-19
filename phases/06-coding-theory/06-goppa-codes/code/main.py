"""Binary Goppa codes (toy) — build parity checks, generator, and a tiny decoder.

Run: python3 code/main.py

This is an educational, from-scratch implementation over GF(2^m) using only the
Python standard library. It is not constant-time and not suitable for
production cryptography or error-correction systems.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
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


def _fmt_bits(bits: list[int]) -> str:
    return "".join(str(b & 1) for b in bits)


def main():
    field = GF2m(m=4, irr_poly=0b10011)
    g = [1, 1, 1]
    t = len(g) - 1
    n = 10
    support = choose_support(field, g, n)

    print("=== Step 1: GF(2^m) arithmetic in polynomial basis ===")
    a = 0b0011
    b = 0b0101
    print(f"  m={field.m}, irr_poly=0b{field.irr_poly:b}")
    print(f"  a=0b{a:04b}, b=0b{b:04b}")
    print(f"  a+b = 0b{field.add(a, b):04b} (xor)")
    print(f"  a*b = 0b{field.mul(a, b):04b} (mod irr_poly)")
    print(f"  inv(a) = 0b{field.inv(a):04b}; a*inv(a)=0b{field.mul(a, field.inv(a)):04b}")

    print()
    print("=== Step 2: pick g(x) and a support L with g(L_i) != 0 ===")
    print(f"  g(x) = x^2 + x + 1 over GF(2^{field.m})")
    print(f"  n={n}, support L (ints): {support}")
    print(f"  g(L_i) (ints): {[gf_poly_eval(field, g, x) for x in support]}")

    print()
    print("=== Step 3: build the binary parity-check matrix H_bin ===")
    H_bin = goppa_parity_check_bin(field, g, support)
    print(f"  H_bin shape: {len(H_bin)} x {len(H_bin[0])} (m*t x n with m={field.m}, t={t})")
    print("  first 4 rows (as bits):")
    for r in range(min(4, len(H_bin))):
        print(f"    {r:02d}: {_fmt_bits(H_bin[r])}")

    print()
    print("=== Step 4: nullspace gives a generator; encode + toy decode t errors ===")
    G = gf2_nullspace_basis(H_bin)
    k = len(G)
    print(f"  rank(H_bin) = {len(H_bin[0]) - k}, so code is [n={n}, k={k}] (toy size)")
    msg = [1] + [0] * (k - 1)
    codeword = encode_from_generator(G, msg)
    print(f"  msg (k bits): {_fmt_bits(msg)}")
    print(f"  codeword (n bits): {_fmt_bits(codeword)}")
    print(f"  syndrome(codeword) = {gf2_mat_vec_mul(H_bin, codeword)}")

    received = codeword[:]
    flip_idxs = (1, 7) if n > 7 else (0, 1)
    for i in flip_idxs:
        received[i] ^= 1
    decoded, err = brute_force_decode(H_bin, received, t=t)
    print(f"  received (with {len(flip_idxs)} flips): {_fmt_bits(received)}")
    print(f"  decoded: {_fmt_bits(decoded)}")
    print(f"  recovered error: {_fmt_bits(err)}")
    print(f"  decoded == codeword? {decoded == codeword}")


if __name__ == "__main__":
    main()
