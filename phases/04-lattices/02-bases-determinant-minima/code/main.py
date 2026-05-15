from __future__ import annotations

import math
from fractions import Fraction

Vec = tuple[int, ...]
Basis = tuple[Vec, ...]  # column vectors (b1, ..., bn), full rank in R^n
Mat = tuple[tuple[int, ...], ...]  # row-major n×n


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


def rows_to_columns(M: list[list[int]]) -> Basis:
    n = _require_square_int_matrix(M)
    return tuple(tuple(M[i][j] for i in range(n)) for j in range(n))


def mat_mul_square(A: list[list[int]], B: list[list[int]]) -> list[list[int]]:
    n = _require_square_int_matrix(A)
    if _require_square_int_matrix(B) != n:
        raise ValueError("matrix dimension mismatch")
    out = [[0 for _ in range(n)] for _ in range(n)]
    for i in range(n):
        for k in range(n):
            aik = A[i][k]
            if aik == 0:
                continue
            for j in range(n):
                out[i][j] += aik * B[k][j]
    return out


def lattice_determinant(basis: Basis) -> int:
    B = columns_to_rows(basis)
    return abs(det_int_square(B))


def is_unimodular(U: Mat) -> bool:
    U_rows = [list(r) for r in U]
    return abs(det_int_square(U_rows)) == 1


def change_basis_unimodular(basis: Basis, U: Mat) -> Basis:
    if not is_unimodular(U):
        raise ValueError("U must be unimodular (det = ±1)")

    B_rows = columns_to_rows(basis)
    if det_int_square(B_rows) == 0:
        raise ValueError("basis must be full rank (det != 0)")

    BU = mat_mul_square(B_rows, [list(r) for r in U])
    return rows_to_columns(BU)


def lattice_vector(basis: Basis, z: Vec) -> Vec:
    if len(z) != len(basis):
        raise ValueError("coefficient dimension mismatch")
    n = len(basis)
    out = [0 for _ in range(n)]
    for coeff, col in zip(z, basis):
        for i in range(n):
            out[i] += coeff * col[i]
    return tuple(out)


def norm2(v: Vec) -> int:
    return sum(x * x for x in v)


def det_2d(v1: tuple[int, int], v2: tuple[int, int]) -> int:
    x1, y1 = v1
    x2, y2 = v2
    return x1 * y2 - y1 * x2


def successive_minima_sqnorm_bruteforce_2d(basis: Basis, coeff_bound: int) -> tuple[int, int]:
    if len(basis) != 2 or len(basis[0]) != 2 or len(basis[1]) != 2:
        raise ValueError("basis must be 2D (two vectors in R^2)")
    if coeff_bound <= 0:
        raise ValueError("coeff_bound must be positive")

    seen: dict[tuple[int, int], int] = {}
    for z1 in range(-coeff_bound, coeff_bound + 1):
        for z2 in range(-coeff_bound, coeff_bound + 1):
            if z1 == 0 and z2 == 0:
                continue
            v = lattice_vector(basis, (z1, z2))
            v2 = (int(v[0]), int(v[1]))
            n2 = norm2(v2)
            prev = seen.get(v2)
            if prev is None or n2 < prev:
                seen[v2] = n2

    items = sorted(((n2, v) for v, n2 in seen.items()), key=lambda t: (t[0], t[1]))
    if not items:
        raise ValueError("no non-zero vectors found")

    lambda1_sq = items[0][0]

    candidate_norm2 = sorted({n2 for n2, _ in items})
    for r2 in candidate_norm2:
        vectors = [v for n2, v in items if n2 <= r2]
        if len(vectors) < 2:
            continue
        v0 = vectors[0]
        for v in vectors[1:]:
            if det_2d(v0, v) != 0:
                return (lambda1_sq, r2)

    raise ValueError("failed to find two independent vectors in the coefficient window")


def fmt_vec(v: Vec) -> str:
    return "(" + ", ".join(str(x) for x in v) + ")"


def main() -> None:
    B: Basis = ((2, 0), (1, 1))
    U: Mat = ((1, 1), (0, 1))
    B2 = change_basis_unimodular(B, U)

    print("Determinant is a lattice invariant (full rank)")
    print(f"B  = {B}")
    print(f"det(L(B))  = {lattice_determinant(B)}")
    print(f"U  = {U}  unimodular={is_unimodular(U)}")
    print(f"BU = {B2}")
    print(f"det(L(BU)) = {lattice_determinant(B2)}")
    print()

    lam1_sq, lam2_sq = successive_minima_sqnorm_bruteforce_2d(B, coeff_bound=8)
    print("Toy successive minima (2D brute force, bounded coefficients)")
    print(f"λ1^2 = {lam1_sq}  λ1 ≈ {math.sqrt(lam1_sq):.6f}")
    print(f"λ2^2 = {lam2_sq}  λ2 ≈ {math.sqrt(lam2_sq):.6f}")
    print()

    skinny: Basis = ((1, 0), (0, 100))
    balanced: Basis = ((10, 0), (0, 10))
    s_l1_sq, _ = successive_minima_sqnorm_bruteforce_2d(skinny, coeff_bound=120)
    b_l1_sq, _ = successive_minima_sqnorm_bruteforce_2d(balanced, coeff_bound=20)
    print("Same determinant, different λ1 (det does not determine short vectors)")
    print(f"skinny  det={lattice_determinant(skinny):>3}  shortest={fmt_vec((1, 0))}  λ1={math.sqrt(s_l1_sq):.1f}")
    print(f"balanced det={lattice_determinant(balanced):>3}  shortest={fmt_vec((10, 0))} λ1={math.sqrt(b_l1_sq):.1f}")


if __name__ == "__main__":
    main()
