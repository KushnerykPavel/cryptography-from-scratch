from __future__ import annotations

from typing import Iterable

Vec2 = tuple[int, int]
Basis2D = tuple[Vec2, Vec2]


def det_2d(basis: Basis2D) -> int:
    (x1, y1), (x2, y2) = basis
    return x1 * y2 - y1 * x2


def dot_2d(a: Vec2, b: Vec2) -> int:
    return a[0] * b[0] + a[1] * b[1]


def norm2_2d(v: Vec2) -> int:
    return v[0] * v[0] + v[1] * v[1]


def round_div_nearest(n: int, d: int) -> int:
    if d <= 0:
        raise ValueError("d must be positive")
    if n < 0:
        return -round_div_nearest(-n, d)
    return (n + d // 2) // d


def _lex_positive(v: Vec2) -> Vec2:
    x, y = v
    if x < 0 or (x == 0 and y < 0):
        return (-x, -y)
    return v


def is_gauss_reduced_2d(basis: Basis2D) -> bool:
    b1, b2 = basis
    n1 = norm2_2d(b1)
    n2 = norm2_2d(b2)
    if n1 == 0 or n2 == 0:
        return False
    if n1 > n2:
        return False
    return 2 * abs(dot_2d(b1, b2)) <= n1


def gauss_lagrange_reduce_2d(basis: Basis2D, *, max_iters: int = 10_000) -> Basis2D:
    if max_iters <= 0:
        raise ValueError("max_iters must be positive")
    if det_2d(basis) == 0:
        raise ValueError("basis must be linearly independent (det != 0)")

    b1, b2 = basis

    for _ in range(max_iters):
        if norm2_2d(b2) < norm2_2d(b1):
            b1, b2 = b2, b1

        m = round_div_nearest(dot_2d(b1, b2), norm2_2d(b1))
        if m == 0:
            out = (_lex_positive(b1), _lex_positive(b2))
            if norm2_2d(out[1]) < norm2_2d(out[0]):
                out = (out[1], out[0])
            return out

        b2 = (b2[0] - m * b1[0], b2[1] - m * b1[1])

    raise ValueError("did not converge (max_iters reached)")


def shortest_vector_gauss_2d(basis: Basis2D) -> Vec2:
    b1, _ = gauss_lagrange_reduce_2d(basis)
    return b1


def shortest_vector_bruteforce_2d(basis: Basis2D, coeff_bound: int) -> Vec2:
    if coeff_bound <= 0:
        raise ValueError("coeff_bound must be positive")
    if det_2d(basis) == 0:
        raise ValueError("basis must be linearly independent (det != 0)")

    (b1x, b1y), (b2x, b2y) = basis
    best: Vec2 | None = None
    best_norm2: int | None = None
    for z1 in range(-coeff_bound, coeff_bound + 1):
        for z2 in range(-coeff_bound, coeff_bound + 1):
            if z1 == 0 and z2 == 0:
                continue
            x = z1 * b1x + z2 * b2x
            y = z1 * b1y + z2 * b2y
            n2 = x * x + y * y
            if best_norm2 is None or n2 < best_norm2:
                best_norm2 = n2
                best = (x, y)
    if best is None:
        raise ValueError("no non-zero vectors in the given coefficient window")
    return _lex_positive(best)


def fmt_points(points: Iterable[Vec2], max_items: int = 12) -> str:
    items = list(points)
    shown = items[:max_items]
    suffix = "" if len(items) <= max_items else f" … (+{len(items) - max_items} more)"
    return f"{shown}{suffix}"


def main() -> None:
    basis: Basis2D = ((1, 5), (6, 21))
    reduced = gauss_lagrange_reduce_2d(basis)

    print("Gauss / Lagrange reduction in 2D (exact integer arithmetic)")
    print(f"basis    = {basis}   det={det_2d(basis)}")
    print(f"reduced  = {reduced} det={det_2d(reduced)}")
    print(f"reduced? = {is_gauss_reduced_2d(reduced)}")
    print()

    sv = shortest_vector_gauss_2d(basis)
    print(f"shortest via Gauss reduction: {sv}  ||sv||^2={norm2_2d(sv)}")

    sv_bf = shortest_vector_bruteforce_2d(basis, coeff_bound=12)
    print(f"shortest via brute force (toy): {sv_bf}  ||sv||^2={norm2_2d(sv_bf)}")

    try:
        from fpylll import IntegerMatrix, LLL

        print()
        print("fpylll sanity check (LLL on 2D basis)")
        mat = IntegerMatrix.from_matrix([[basis[0][0], basis[1][0]], [basis[0][1], basis[1][1]]])
        LLL.reduction(mat)
        reduced_lll = [[int(mat[i, j]) for j in range(mat.ncols)] for i in range(mat.nrows)]
        print(reduced_lll)
    except Exception:
        pass


if __name__ == "__main__":
    main()
