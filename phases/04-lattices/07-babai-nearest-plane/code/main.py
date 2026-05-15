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


def dot(a: Vec, b: Vec) -> int:
    _require_same_dim(a, b)
    return sum(x * y for x, y in zip(a, b))


def norm2(v: Vec) -> int:
    _require_same_dim(v)
    return dot(v, v)


def lattice_vector(basis: Basis, z: tuple[int, ...]) -> Vec:
    n = _require_full_rank_square_basis(basis)
    if len(z) != n:
        raise ValueError("coefficient dimension mismatch")
    out = [0 for _ in range(n)]
    for coeff, b in zip(z, basis):
        if coeff == 0:
            continue
        for i in range(n):
            out[i] += coeff * b[i]
    return tuple(out)


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


@dataclass(frozen=True, slots=True)
class BabaiResult:
    coeffs: tuple[int, ...]
    vector: Vec
    residual: tuple[Fraction, ...]
    dist2: Fraction


def babai_nearest_plane(basis: Basis, target: Vec) -> BabaiResult:
    n = _require_full_rank_square_basis(basis)
    _require_same_dim(target)
    if len(target) != n:
        raise ValueError("target dimension mismatch")

    B = [list(b) for b in basis]
    b_star, _, Bsq = _gram_schmidt(B)

    residual = [Fraction(x) for x in target]
    coeffs = [0 for _ in range(n)]

    for i in range(n - 1, -1, -1):
        if Bsq[i] == 0:
            raise ValueError("basis must be full rank (det != 0)")
        ci = _dot_frac(residual, b_star[i]) / Bsq[i]
        ki = _round_fraction_nearest(ci)
        coeffs[i] = ki
        if ki != 0:
            residual = [ri - ki * bi for ri, bi in zip(residual, B[i])]

    v = lattice_vector(basis, tuple(coeffs))
    diff = [Fraction(v_i) - Fraction(t_i) for v_i, t_i in zip(v, target)]
    dist2 = _dot_frac(diff, diff)
    return BabaiResult(coeffs=tuple(coeffs), vector=v, residual=tuple(residual), dist2=dist2)


def iter_coeffs(n: int, coeff_bound: int):
    if n <= 0:
        raise ValueError("n must be positive")
    if coeff_bound < 0:
        raise ValueError("coeff_bound must be non-negative")
    rng = range(-coeff_bound, coeff_bound + 1)
    yield from product(rng, repeat=n)


@dataclass(frozen=True, slots=True)
class CVPResult:
    coeffs: tuple[int, ...]
    vector: Vec
    dist2: int


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


def babai_after_lll(
    basis: Basis,
    target: Vec,
    *,
    delta: Fraction = Fraction(3, 4),
    max_iters: int = 100_000,
) -> tuple[Basis, BabaiResult]:
    reduced = lll_reduce(basis, delta=delta, max_iters=max_iters)
    return reduced, babai_nearest_plane(reduced, target)


def _fmt_vec(v: Vec) -> str:
    return "(" + ", ".join(str(x) for x in v) + ")"


def _fmt_coeffs(z: tuple[int, ...]) -> str:
    return "(" + ", ".join(str(x) for x in z) + ")"


def _demo() -> None:
    B: Basis = ((1, 5), (6, 21))
    t: Vec = (10, 10)

    print("Babai nearest plane: approximate CVP relative to a chosen basis")
    print(f"basis B  = {B}")
    print(f"target t = {_fmt_vec(t)}")
    print()

    b0 = babai_nearest_plane(B, t)
    print(f"babai(B,t) coeffs = {_fmt_coeffs(b0.coeffs)}  v={_fmt_vec(b0.vector)}  dist={math.sqrt(float(b0.dist2)):.6f}")

    Bred, b1 = babai_after_lll(B, t)
    print(f"lll(B)            = {Bred}")
    print(
        f"babai(lll(B),t)   coeffs = {_fmt_coeffs(b1.coeffs)}  v={_fmt_vec(b1.vector)}  dist={math.sqrt(float(b1.dist2)):.6f}"
    )
    print()

    cvp = cvp_bruteforce(B, t, coeff_bound=20)
    print(
        f"cvp brute-force (window [-20,20]^2): v={_fmt_vec(cvp.vector)}  dist={math.sqrt(cvp.dist2):.6f}  coeffs={_fmt_coeffs(cvp.coeffs)}"
    )


if __name__ == "__main__":
    _demo()
