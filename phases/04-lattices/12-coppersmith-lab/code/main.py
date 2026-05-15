from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
from math import gcd

from sympy import Poly, Symbol, ZZ
from sympy.core.intfunc import integer_nthroot
from sympy.ntheory.generate import nextprime

x = Symbol("x")


Vec = tuple[int, ...]
Basis = tuple[Vec, ...]


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


def _require_full_rank_square_basis(basis: Basis) -> int:
    if not basis:
        raise ValueError("basis must be non-empty")
    n = len(basis)
    if any(len(b) != n for b in basis):
        raise ValueError("basis must be full rank in R^n (n vectors of length n)")
    if det_int_square([list(row) for row in basis]) == 0:
        raise ValueError("basis must be full rank (det != 0)")
    return n


def _round_fraction_nearest(v: Fraction) -> int:
    if v < 0:
        return -_round_fraction_nearest(-v)
    p = v.numerator
    q = v.denominator
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
        if lhs < rhs:
            B[k], B[k - 1] = B[k - 1], B[k]
            recompute()
            k = max(k - 1, 1)
        else:
            k += 1

    return tuple(tuple(v) for v in B)


def _poly_zz_coeffs_mod(poly: Poly, modulus: int) -> Poly:
    if modulus <= 1:
        raise ValueError("modulus must be > 1")
    if poly.gens != (x,):
        raise ValueError("polynomial must be univariate in x")

    deg = poly.degree()
    expr = 0
    for k in range(deg + 1):
        ck = int(poly.nth(k)) % modulus
        if ck:
            expr += ck * x**k
    return Poly(expr, x, domain=ZZ)


def stereotyped_rsa_polynomial(*, A: int, e: int, c: int, N: int) -> Poly:
    if N <= 1:
        raise ValueError("N must be > 1")
    if e <= 1:
        raise ValueError("e must be > 1")
    if not (0 <= c < N):
        raise ValueError("c must satisfy 0 <= c < N")
    if not (0 <= A < N):
        raise ValueError("A must satisfy 0 <= A < N")

    pol = Poly((A + x) ** e - c, x, domain=ZZ)
    return _poly_zz_coeffs_mod(pol, N)


def _floor_pow_int(n: int, beta: Fraction) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if not (Fraction(0, 1) < beta <= Fraction(1, 1)):
        raise ValueError("beta must be in (0, 1]")

    if beta == 1:
        return n

    a, b = beta.numerator, beta.denominator
    root, _ = integer_nthroot(pow(n, a), b)
    return int(root)


def coppersmith_howgrave_univariate(
    pol: Poly,
    modulus: int,
    beta: Fraction,
    m: int,
    t: int,
    X: int,
    *,
    max_lll_rows: int = 8,
    lll_delta: Fraction = Fraction(99, 100),
    lll_max_iters: int = 200_000,
) -> list[int]:
    if modulus <= 1:
        raise ValueError("modulus must be > 1")
    if X <= 0:
        raise ValueError("X must be positive")
    if m <= 0:
        raise ValueError("m must be positive")
    if t < 0:
        raise ValueError("t must be >= 0")
    if max_lll_rows <= 0:
        raise ValueError("max_lll_rows must be positive")
    if pol.gens != (x,):
        raise ValueError("polynomial must be univariate in x")

    beta = Fraction(beta)
    if not (Fraction(0, 1) < beta <= Fraction(1, 1)):
        raise ValueError("beta must be in (0, 1]")

    polZ = _poly_zz_coeffs_mod(pol, modulus)
    if polZ.LC() != 1:
        raise ValueError("polynomial must be monic")

    d = polZ.degree()
    n = d * m + t

    polZX_expr = polZ.as_expr().subs(x, x * X)
    xX = x * X

    gg: list[Poly] = []
    for i in range(m):
        pow_f = pow(polZX_expr, i)
        Ni = pow(modulus, m - i)
        for j in range(d):
            gg.append(Poly(pow(xX, j) * Ni * pow_f, x, domain=ZZ))

    pow_fm = pow(polZX_expr, m)
    for j in range(t):
        gg.append(Poly(pow(xX, j) * pow_fm, x, domain=ZZ))

    if len(gg) != n:
        raise ValueError("internal error: bad lattice dimension")

    rows: list[list[int]] = [[0 for _ in range(n)] for __ in range(n)]
    for row_i, g in enumerate(gg):
        for col_j in range(row_i + 1):
            rows[row_i][col_j] = int(g.nth(col_j))

    reduced = lll_reduce(tuple(tuple(r) for r in rows), delta=lll_delta, max_iters=lll_max_iters)

    min_gcd = _floor_pow_int(modulus, beta)
    roots: set[int] = set()

    rows_to_try = min(n, max_lll_rows)
    for row_i in range(rows_to_try):
        vec = reduced[row_i]
        h_expr = 0
        for k in range(n):
            vk = int(vec[k])
            denom = pow(X, k)
            q, r = divmod(vk, denom)
            if r != 0:
                h_expr = None
                break
            if q:
                h_expr += q * x**k
        if h_expr is None:
            continue

        h = Poly(h_expr, x, domain=ZZ)
        for r_sym in h.ground_roots().keys():
            r = int(r_sym)
            if abs(r) >= X:
                continue
            if gcd(modulus, int(polZ.eval(r))) >= min_gcd:
                roots.add(r)

    return sorted(roots)


@dataclass(frozen=True)
class RSAStereotypedInstance:
    N: int
    e: int
    A: int
    c: int
    X: int
    secret_x: int


def make_demo_instance(*, n_bits: int = 256, e: int = 3, kbits: int = 40) -> RSAStereotypedInstance:
    if n_bits < 64:
        raise ValueError("n_bits must be >= 64")
    if e <= 1:
        raise ValueError("e must be > 1")
    if kbits <= 0:
        raise ValueError("kbits must be positive")

    p = int(nextprime(2 ** (n_bits // 2 - 1) + 12345))
    q = int(nextprime(2 ** (n_bits // 2 - 1) + 67890))
    if p == q:
        q = int(nextprime(q + 2))
    N = p * q

    X = 1 << kbits
    A = (N // (4 * X)) * X
    if A + X >= N:
        raise ValueError("failed to build a safe (A + X) < N demo instance")

    secret_x = 424242 % X
    m = A + secret_x
    c = pow(m, e, N)
    return RSAStereotypedInstance(N=N, e=e, A=A, c=c, X=X, secret_x=secret_x)


def main() -> None:
    inst = make_demo_instance()
    pol = stereotyped_rsa_polynomial(A=inst.A, e=inst.e, c=inst.c, N=inst.N)

    roots = coppersmith_howgrave_univariate(pol, inst.N, Fraction(1, 1), m=3, t=0, X=inst.X)
    recovered = roots[0] if roots else None

    print("N_bits:", inst.N.bit_length())
    print("e:", inst.e)
    print("X_bits:", inst.X.bit_length() - 1)
    print("secret_x:", inst.secret_x)
    print("recovered_x:", recovered)
    print("ok:", recovered == inst.secret_x)


if __name__ == "__main__":
    main()
