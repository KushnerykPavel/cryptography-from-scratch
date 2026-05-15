from __future__ import annotations

import math
from dataclasses import dataclass
from fractions import Fraction
from itertools import product

Vec = tuple[int, ...]
Basis = tuple[Vec, ...]  # column vectors (b1, ..., bn), full rank in R^n


def _require_same_dim(*vs: Vec) -> int:
    if not vs:
        raise ValueError("expected at least one vector")
    n = len(vs[0])
    if n == 0:
        raise ValueError("vectors must be non-empty")
    for v in vs:
        if len(v) != n:
            raise ValueError("dimension mismatch")
    return n


def _require_full_rank_square_basis(basis: Basis) -> int:
    if not basis:
        raise ValueError("basis must be non-empty")
    n = len(basis)
    if any(len(b) != n for b in basis):
        raise ValueError("basis must be full rank in R^n (n vectors of length n)")
    if det_int_square(columns_to_rows(basis)) == 0:
        raise ValueError("basis must be full rank (det != 0)")
    return n


def vec_sub(a: Vec, b: Vec) -> Vec:
    _require_same_dim(a, b)
    return tuple(x - y for x, y in zip(a, b))


def norm2(v: Vec) -> int:
    _require_same_dim(v)
    return sum(x * x for x in v)


def lattice_vector(basis: Basis, z: Vec) -> Vec:
    n = _require_full_rank_square_basis(basis)
    if len(z) != n:
        raise ValueError("coefficient dimension mismatch")

    out = [0 for _ in range(n)]
    for coeff, col in zip(z, basis):
        for i in range(n):
            out[i] += coeff * col[i]
    return tuple(out)


def _require_square_int_matrix(A: list[list[int]]) -> int:
    n = len(A)
    if n == 0:
        raise ValueError("matrix must be non-empty")
    for row in A:
        if len(row) != n:
            raise ValueError("matrix must be square")
    return n


def det_int_square(A: list[list[int]]) -> int:
    n = _require_square_int_matrix(A)
    M = [row[:] for row in A]

    sign = 1
    prev_pivot = 1

    for k in range(n - 1):
        pivot_row = None
        for i in range(k, n):
            if M[i][k] != 0:
                pivot_row = i
                break

        if pivot_row is None:
            return 0

        if pivot_row != k:
            M[k], M[pivot_row] = M[pivot_row], M[k]
            sign *= -1

        pivot = M[k][k]
        if prev_pivot == 0:
            return _det_fraction_elimination(A)

        for i in range(k + 1, n):
            for j in range(k + 1, n):
                M[i][j] = pivot * M[i][j] - M[i][k] * M[k][j]
                if k > 0:
                    if M[i][j] % prev_pivot != 0:
                        return _det_fraction_elimination(A)
                    M[i][j] //= prev_pivot
        for i in range(k + 1, n):
            M[i][k] = 0

        prev_pivot = pivot

    return sign * M[n - 1][n - 1]


def _det_fraction_elimination(A: list[list[int]]) -> int:
    n = _require_square_int_matrix(A)
    M: list[list[Fraction]] = [[Fraction(x) for x in row] for row in A]

    sign = 1
    for k in range(n - 1):
        pivot_row = None
        for i in range(k, n):
            if M[i][k] != 0:
                pivot_row = i
                break
        if pivot_row is None:
            return 0
        if pivot_row != k:
            M[k], M[pivot_row] = M[pivot_row], M[k]
            sign *= -1

        pivot = M[k][k]
        for i in range(k + 1, n):
            factor = M[i][k] / pivot
            for j in range(k, n):
                M[i][j] -= factor * M[k][j]

    det = Fraction(sign, 1)
    for i in range(n):
        det *= M[i][i]
    if det.denominator != 1:
        raise ValueError("determinant should be integer for integer matrix")
    return int(det.numerator)


def columns_to_rows(basis: Basis) -> list[list[int]]:
    if not basis:
        raise ValueError("basis must be non-empty")
    n = len(basis)
    if any(len(b) != n for b in basis):
        raise ValueError("basis must be full rank in R^n (n vectors of length n)")
    return [[basis[j][i] for j in range(n)] for i in range(n)]


def candidate_count(coeff_bound: int, n: int) -> int:
    if coeff_bound < 0:
        raise ValueError("coeff_bound must be non-negative")
    if n <= 0:
        raise ValueError("n must be positive")
    return (2 * coeff_bound + 1) ** n


def iter_coeffs(n: int, coeff_bound: int):
    if n <= 0:
        raise ValueError("n must be positive")
    if coeff_bound < 0:
        raise ValueError("coeff_bound must be non-negative")
    rng = range(-coeff_bound, coeff_bound + 1)
    yield from product(rng, repeat=n)


@dataclass(frozen=True, slots=True)
class SVPResult:
    coeffs: Vec
    vector: Vec
    norm2: int


@dataclass(frozen=True, slots=True)
class CVPResult:
    coeffs: Vec
    vector: Vec
    dist2: int


def svp_bruteforce(basis: Basis, coeff_bound: int) -> SVPResult:
    n = _require_full_rank_square_basis(basis)
    if coeff_bound <= 0:
        raise ValueError("coeff_bound must be positive")

    best_key = None
    best = None
    for z in iter_coeffs(n, coeff_bound):
        if all(c == 0 for c in z):
            continue
        v = lattice_vector(basis, z)
        n2 = norm2(v)
        key = (n2, z, v)
        if best_key is None or key < best_key:
            best_key = key
            best = SVPResult(coeffs=tuple(z), vector=v, norm2=n2)

    if best is None:
        raise ValueError("no non-zero vectors in the given coefficient window")
    return best


def cvp_bruteforce(basis: Basis, target: Vec, coeff_bound: int) -> CVPResult:
    n = _require_full_rank_square_basis(basis)
    _require_same_dim(target)
    if len(target) != n:
        raise ValueError("target dimension mismatch")
    if coeff_bound < 0:
        raise ValueError("coeff_bound must be non-negative")

    best_key = None
    best = None
    for z in iter_coeffs(n, coeff_bound):
        v = lattice_vector(basis, z)
        d2 = norm2(vec_sub(v, target))
        key = (d2, z, v)
        if best_key is None or key < best_key:
            best_key = key
            best = CVPResult(coeffs=tuple(z), vector=v, dist2=d2)

    if best is None:
        raise ValueError("no candidates found")
    return best


def fmt_vec(v: Vec) -> str:
    return "(" + ", ".join(str(x) for x in v) + ")"


def fmt_coeffs(z: Vec) -> str:
    return "(" + ", ".join(str(x) for x in z) + ")"


def _demo_2d() -> None:
    B: Basis = ((2, 0), (1, 1))
    t: Vec = (3, 0)

    print("SVP (toy): shortest non-zero lattice vector in a bounded coefficient window")
    svp = svp_bruteforce(B, coeff_bound=8)
    print(f"basis B = {B}")
    print(f"window  = [-8,8]^2  candidates={candidate_count(8, 2)}")
    print(f"svp z   = {fmt_coeffs(svp.coeffs)}")
    print(f"svp v   = {fmt_vec(svp.vector)}  ||v||2={math.sqrt(svp.norm2):.6f}")
    print()

    print("CVP (toy): closest lattice vector to a target in a bounded coefficient window")
    cvp = cvp_bruteforce(B, target=t, coeff_bound=6)
    print(f"target t = {fmt_vec(t)}")
    print(f"window   = [-6,6]^2  candidates={candidate_count(6, 2)}")
    print(f"cvp z    = {fmt_coeffs(cvp.coeffs)}")
    print(f"cvp v    = {fmt_vec(cvp.vector)}  dist(t,L)={math.sqrt(cvp.dist2):.6f}")


def _demo_growth() -> None:
    print()
    print("Brute-force growth (candidate count)")
    for n in (2, 3, 4, 8, 16):
        k = 6 if n <= 4 else 3
        print(f"n={n:>2}  k={k}  (2k+1)^n = {candidate_count(k, n):,}")


def main() -> None:
    _demo_2d()
    _demo_growth()


if __name__ == "__main__":
    main()
