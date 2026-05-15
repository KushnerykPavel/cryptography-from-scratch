from __future__ import annotations

from fractions import Fraction

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


def dot(a: Vec, b: Vec) -> int:
    _require_same_dim(a, b)
    return sum(x * y for x, y in zip(a, b))


def norm2(v: Vec) -> int:
    _require_same_dim(v)
    return dot(v, v)


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


def _round_fraction_nearest(x: Fraction) -> int:
    if x < 0:
        return -_round_fraction_nearest(-x)
    p = x.numerator
    q = x.denominator
    return (2 * p + q) // (2 * q)


def _dot_frac_int(a: list[Fraction], b: list[int]) -> Fraction:
    return sum(x * y for x, y in zip(a, b))


def _dot_frac(a: list[Fraction], b: list[Fraction]) -> Fraction:
    return sum(x * y for x, y in zip(a, b))


def _gram_schmidt(basis: list[list[int]]):
    n = len(basis)
    b_star: list[list[Fraction]] = []
    mu: list[list[Fraction]] = [[Fraction(0) for _ in range(n)] for __ in range(n)]
    B: list[Fraction] = [Fraction(0) for _ in range(n)]

    for i in range(n):
        v = [Fraction(x) for x in basis[i]]
        for j in range(i):
            if B[j] == 0:
                raise ValueError("basis must be full rank (det != 0)")
            mu_ij = _dot_frac_int(b_star[j], basis[i]) / B[j]
            mu[i][j] = mu_ij
            if mu_ij:
                v = [vk - mu_ij * bjk for vk, bjk in zip(v, b_star[j])]
        b_star.append(v)
        B[i] = _dot_frac(v, v)
    return b_star, mu, B


def is_lll_reduced(basis: Basis, *, delta: Fraction = Fraction(3, 4)) -> bool:
    n = _require_full_rank_square_basis(basis)
    if not (Fraction(1, 4) < delta < 1):
        raise ValueError("delta must satisfy 1/4 < delta < 1")

    b_list = [list(b) for b in basis]
    _, mu, B = _gram_schmidt(b_list)

    half = Fraction(1, 2)
    for k in range(n):
        for j in range(k):
            if abs(mu[k][j]) > half:
                return False

    for k in range(1, n):
        lhs = B[k]
        rhs = (delta - mu[k][k - 1] * mu[k][k - 1]) * B[k - 1]
        if lhs < rhs:
            return False

    return True


def lll_reduce(
    basis: Basis,
    *,
    delta: Fraction = Fraction(3, 4),
    max_iters: int = 100_000,
) -> Basis:
    n = _require_full_rank_square_basis(basis)
    if not (Fraction(1, 4) < delta < 1):
        raise ValueError("delta must satisfy 1/4 < delta < 1")
    if max_iters <= 0:
        raise ValueError("max_iters must be positive")

    B = [list(b) for b in basis]
    _, mu, Bstar = _gram_schmidt(B)

    def recompute() -> None:
        nonlocal mu, Bstar
        _, mu, Bstar = _gram_schmidt(B)

    iters = 0
    k = 1
    while k < n:
        iters += 1
        if iters > max_iters:
            raise ValueError("did not converge (max_iters reached)")

        for j in range(k - 1, -1, -1):
            r = _round_fraction_nearest(mu[k][j])
            if r != 0:
                B[k] = [xk - r * xj for xk, xj in zip(B[k], B[j])]
                recompute()

        lhs = Bstar[k]
        rhs = (delta - mu[k][k - 1] * mu[k][k - 1]) * Bstar[k - 1]
        if lhs >= rhs:
            k += 1
            continue

        B[k], B[k - 1] = B[k - 1], B[k]
        recompute()
        k = max(k - 1, 1)

    return tuple(tuple(int(x) for x in col) for col in B)


def _fmt_vec(v: Vec) -> str:
    return "(" + ", ".join(str(x) for x in v) + ")"


def main() -> None:
    basis: Basis = ((1, 1, 1), (-1, 0, 2), (3, 5, 6))
    reduced = lll_reduce(basis)

    det0 = det_int_square(columns_to_rows(basis))
    det1 = det_int_square(columns_to_rows(reduced))

    print("LLL reduction (educational, exact Fraction arithmetic; delta=3/4)")
    print("input basis:")
    for b in basis:
        print(f"  {_fmt_vec(b)}  ||b||^2={norm2(b)}")
    print(f"det = {det0}   |det| = {abs(det0)}")
    print()

    print("LLL-reduced basis:")
    for b in reduced:
        print(f"  {_fmt_vec(b)}  ||b||^2={norm2(b)}")
    print(f"det = {det1}   |det| = {abs(det1)}")
    print(f"lll_reduced? {is_lll_reduced(reduced)}")

    try:
        from fpylll import IntegerMatrix, LLL  # type: ignore

        print()
        print("fpylll sanity check (if installed):")
        mat = IntegerMatrix.from_matrix(columns_to_rows(basis))
        LLL.reduction(mat)
        reduced_lll = [[int(mat[i, j]) for j in range(mat.ncols)] for i in range(mat.nrows)]
        print(reduced_lll)
    except Exception:
        pass


if __name__ == "__main__":
    main()
