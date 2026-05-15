from __future__ import annotations

import hashlib
from dataclasses import dataclass
from fractions import Fraction

Poly = tuple[int, ...]
Vec = tuple[int, ...]
Basis = tuple[Vec, ...]  # row vectors (b1, ..., bn), full rank in R^n


class Sha256CtrRng:
    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        if len(seed) == 0:
            raise ValueError("seed must be non-empty")
        self._seed = bytes(seed)
        self._ctr = 0
        self._buf = b""
        self._pos = 0

    def _refill(self) -> None:
        h = hashlib.sha256()
        h.update(self._seed)
        h.update(self._ctr.to_bytes(8, "big"))
        self._ctr += 1
        self._buf = h.digest()
        self._pos = 0

    def random_bytes(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        out = bytearray()
        while len(out) < n:
            if self._pos >= len(self._buf):
                self._refill()
            take = min(n - len(out), len(self._buf) - self._pos)
            out += self._buf[self._pos : self._pos + take]
            self._pos += take
        return bytes(out)

    def _randbits(self, k: int) -> int:
        if k < 0:
            raise ValueError("k must be non-negative")
        nbytes = (k + 7) // 8
        x = int.from_bytes(self.random_bytes(nbytes), "big")
        if k % 8:
            x &= (1 << k) - 1
        return x

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        k = n.bit_length()
        while True:
            x = self._randbits(k)
            if x < n:
                return x


def _require_positive_int(name: str, x: int) -> None:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")
    if x <= 0:
        raise ValueError(f"{name} must be positive")


def _require_poly_dim(p: Poly, n: int, *, name: str) -> None:
    if len(p) != n:
        raise ValueError(f"{name} dimension mismatch")


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


def center_lift(x: int, q: int) -> int:
    _require_positive_int("q", q)
    y = x % q
    half = q // 2
    if y > half:
        y -= q
    return y


def poly_mul_cyclic_mod(a: Poly, b: Poly, q: int) -> Poly:
    _require_positive_int("q", q)
    n = len(a)
    if n == 0:
        raise ValueError("polynomials must be non-empty")
    _require_poly_dim(b, n, name="b")

    out = [0] * n
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[(i + j) % n] += ai * bj
    return tuple(x % q for x in out)


def poly_mul_cyclic_int(a: Poly, b: Poly) -> Poly:
    n = len(a)
    if n == 0:
        raise ValueError("polynomials must be non-empty")
    _require_poly_dim(b, n, name="b")

    out = [0] * n
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[(i + j) % n] += ai * bj
    return tuple(out)


def cyclic_convolution_matrix(p: Poly, q: int) -> list[list[int]]:
    _require_positive_int("q", q)
    n = len(p)
    if n == 0:
        raise ValueError("polynomial must be non-empty")
    return [[p[(i - j) % n] % q for j in range(n)] for i in range(n)]


def mat_vec_mul_mod(A: list[list[int]], x: Vec, q: int) -> Vec:
    _require_positive_int("q", q)
    if not A:
        raise ValueError("A must be non-empty")
    n = len(A)
    if any(len(row) != n for row in A):
        raise ValueError("A must be square")
    _require_same_dim(x, tuple(0 for _ in range(n)))
    out = []
    for i in range(n):
        acc = 0
        for j in range(n):
            acc += A[i][j] * x[j]
        out.append(acc % q)
    return tuple(out)


def _inv_mod(a: int, q: int) -> int:
    a %= q
    if a == 0:
        raise ValueError("not invertible mod q")
    t0, t1 = 0, 1
    r0, r1 = q, a
    while r1:
        k = r0 // r1
        r0, r1 = r1, r0 - k * r1
        t0, t1 = t1, t0 - k * t1
    if r0 != 1:
        raise ValueError("not invertible mod q")
    return t0 % q


def solve_linear_mod(A: list[list[int]], b: Vec, q: int) -> Vec:
    _require_positive_int("q", q)
    n = len(A)
    if n == 0:
        raise ValueError("A must be non-empty")
    if any(len(row) != n for row in A):
        raise ValueError("A must be square")
    _require_same_dim(b, tuple(0 for _ in range(n)))

    M = [[A[i][j] % q for j in range(n)] + [b[i] % q] for i in range(n)]

    row = 0
    pivots = [-1] * n
    for col in range(n):
        pivot = None
        for r in range(row, n):
            if M[r][col] % q != 0:
                pivot = r
                break
        if pivot is None:
            continue
        if pivot != row:
            M[row], M[pivot] = M[pivot], M[row]
        inv = _inv_mod(M[row][col], q)
        for j in range(col, n + 1):
            M[row][j] = (M[row][j] * inv) % q
        for r in range(n):
            if r == row:
                continue
            factor = M[r][col] % q
            if factor == 0:
                continue
            for j in range(col, n + 1):
                M[r][j] = (M[r][j] - factor * M[row][j]) % q
        pivots[col] = row
        row += 1
        if row == n:
            break

    for col in range(n):
        if pivots[col] == -1:
            raise ValueError("system has no unique solution")

    x = [0] * n
    for col in range(n):
        x[col] = M[pivots[col]][n] % q
    return tuple(x)


def poly_inv_cyclic_mod_q(f: Poly, q: int) -> Poly:
    _require_positive_int("q", q)
    n = len(f)
    if n == 0:
        raise ValueError("f must be non-empty")
    A = cyclic_convolution_matrix(tuple(x % q for x in f), q)
    e0 = (1,) + (0,) * (n - 1)
    inv = solve_linear_mod(A, e0, q)
    if poly_mul_cyclic_mod(tuple(x % q for x in f), inv, q) != e0:
        raise ValueError("f is not invertible in R_q")
    return inv


def poly_norm2(p: Poly) -> int:
    return sum(x * x for x in p)


def norm2(v: Vec) -> int:
    _require_same_dim(v)
    return sum(x * x for x in v)


def _require_full_rank_square_basis_rows(basis: Basis) -> int:
    if not basis:
        raise ValueError("basis must be non-empty")
    n = len(basis)
    if any(len(b) != n for b in basis):
        raise ValueError("basis must be full rank in R^n (n vectors of length n)")
    if det_int_square([list(row) for row in basis]) == 0:
        raise ValueError("basis must be full rank (det != 0)")
    return n


def det_int_square(A: list[list[int]]) -> int:
    n = len(A)
    if n == 0:
        raise ValueError("matrix must be non-empty")
    for row in A:
        if len(row) != n:
            raise ValueError("matrix must be square")

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
    n = len(A)
    if n == 0:
        raise ValueError("matrix must be non-empty")
    for row in A:
        if len(row) != n:
            raise ValueError("matrix must be square")

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


def lll_reduce_rows(
    basis: Basis,
    *,
    delta: Fraction = Fraction(3, 4),
    max_iters: int = 200_000,
) -> Basis:
    n = _require_full_rank_square_basis_rows(basis)
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

    return tuple(tuple(int(x) for x in row) for row in B)


def _canonical_sign(v: Vec) -> Vec:
    for x in v:
        if x != 0:
            return v if x > 0 else tuple(-y for y in v)
    return v


@dataclass(frozen=True)
class NTRUParams:
    n: int
    q: int
    f_ones: int
    f_negs: int
    g_ones: int
    g_negs: int

    def validate(self) -> None:
        _require_positive_int("n", self.n)
        _require_positive_int("q", self.q)
        for name, v in (
            ("f_ones", self.f_ones),
            ("f_negs", self.f_negs),
            ("g_ones", self.g_ones),
            ("g_negs", self.g_negs),
        ):
            if not isinstance(v, int):
                raise TypeError(f"{name} must be int")
            if v < 0:
                raise ValueError(f"{name} must be non-negative")
        if self.f_ones + self.f_negs > self.n:
            raise ValueError("f weight exceeds n")
        if self.g_ones + self.g_negs > self.n:
            raise ValueError("g weight exceeds n")


def _sample_fixed_weight_ternary(rng: Sha256CtrRng, n: int, ones: int, negs: int) -> Poly:
    if ones < 0 or negs < 0:
        raise ValueError("weights must be non-negative")
    if ones + negs > n:
        raise ValueError("weight exceeds n")
    idxs = list(range(n))
    for i in range(n - 1, 0, -1):
        j = rng.randbelow(i + 1)
        idxs[i], idxs[j] = idxs[j], idxs[i]
    out = [0] * n
    for i in range(ones):
        out[idxs[i]] = 1
    for i in range(ones, ones + negs):
        out[idxs[i]] = -1
    return tuple(out)


@dataclass(frozen=True)
class NTRUPublicKey:
    h: Poly


@dataclass(frozen=True)
class NTRUSecretKey:
    f: Poly
    g: Poly


def ntru_keygen(rng: Sha256CtrRng, params: NTRUParams) -> tuple[NTRUPublicKey, NTRUSecretKey]:
    params.validate()
    tries = 0
    while True:
        tries += 1
        if tries > 10_000:
            raise ValueError("failed to sample invertible f")
        f = _sample_fixed_weight_ternary(rng, params.n, params.f_ones, params.f_negs)
        try:
            f_inv = poly_inv_cyclic_mod_q(tuple(x % params.q for x in f), params.q)
            break
        except ValueError:
            continue
    g = _sample_fixed_weight_ternary(rng, params.n, params.g_ones, params.g_negs)
    h = poly_mul_cyclic_mod(tuple(x % params.q for x in g), f_inv, params.q)
    return NTRUPublicKey(h=h), NTRUSecretKey(f=f, g=g)


def ntru_lattice_basis_rows(h: Poly, q: int) -> Basis:
    _require_positive_int("q", q)
    n = len(h)
    if n == 0:
        raise ValueError("h must be non-empty")
    H_col = cyclic_convolution_matrix(tuple(x % q for x in h), q)
    H = [list(row) for row in zip(*H_col)]
    rows: list[Vec] = []
    for i in range(n):
        e = [0] * n
        e[i] = 1
        rows.append(tuple(e + H[i]))
    for i in range(n):
        e = [0] * n
        eq = [0] * n
        eq[i] = q
        rows.append(tuple(e + eq))
    return tuple(rows)


def ntru_secret_is_in_lattice(sk: NTRUSecretKey, pk: NTRUPublicKey, q: int) -> bool:
    _require_positive_int("q", q)
    n = len(pk.h)
    _require_poly_dim(sk.f, n, name="sk.f")
    _require_poly_dim(sk.g, n, name="sk.g")
    g_from_f = poly_mul_cyclic_mod(tuple(x % q for x in sk.f), tuple(x % q for x in pk.h), q)
    return tuple(x % q for x in sk.g) == g_from_f


def recover_ntru_secret_via_lll(
    *,
    pk: NTRUPublicKey,
    q: int,
    delta: Fraction = Fraction(3, 4),
) -> NTRUSecretKey:
    _require_positive_int("q", q)
    basis = ntru_lattice_basis_rows(pk.h, q)
    reduced = lll_reduce_rows(basis, delta=delta)
    cand = min(reduced, key=norm2)
    cand = _canonical_sign(cand)
    n = len(pk.h)
    f = tuple(int(x) for x in cand[:n])
    g = tuple(int(x) for x in cand[n:])
    return NTRUSecretKey(f=f, g=g)


def main() -> None:
    print("NTRU lattice demo (educational, not constant-time, not production-safe)")

    params = NTRUParams(n=7, q=29, f_ones=2, f_negs=1, g_ones=2, g_negs=2)
    rng = Sha256CtrRng(b"04-lattices/11-ntru-lattices/demo")
    pk, sk = ntru_keygen(rng, params)

    print(f"params: n={params.n} q={params.q}")
    print(f"sk.f (ternary): {list(sk.f)}   ||f||^2={poly_norm2(sk.f)}")
    print(f"sk.g (ternary): {list(sk.g)}   ||g||^2={poly_norm2(sk.g)}")
    print(f"pk.h (mod q):   {list(pk.h)}")
    print(f"check: f*h == g (mod q)? {ntru_secret_is_in_lattice(sk, pk, params.q)}")
    print()

    rec = recover_ntru_secret_via_lll(pk=pk, q=params.q)
    print(f"LLL recovered f: {list(rec.f)}   ||f||^2={poly_norm2(rec.f)}")
    print(f"LLL recovered g: {list(rec.g)}   ||g||^2={poly_norm2(rec.g)}")

    try:
        from fpylll import IntegerMatrix, LLL  # type: ignore

        print()
        print("fpylll sanity check (if installed):")
        B = ntru_lattice_basis_rows(pk.h, params.q)
        mat = IntegerMatrix.from_matrix([list(r) for r in B])
        LLL.reduction(mat)
        short0 = [int(mat[0, j]) for j in range(mat.ncols)]
        print(f"first reduced vector: {short0}  ||v||^2={sum(x*x for x in short0)}")
    except Exception:
        pass


if __name__ == "__main__":
    main()
