from __future__ import annotations

from typing import Iterable

Vec2 = tuple[int, int]
Basis2D = tuple[Vec2, Vec2]
Mat2 = tuple[tuple[int, int], tuple[int, int]]


def det_mat2(U: Mat2) -> int:
    (a, b), (c, d) = U
    return a * d - b * c


def det_2d(basis: Basis2D) -> int:
    (x1, y1), (x2, y2) = basis
    return x1 * y2 - y1 * x2


def lattice_point_2d(basis: Basis2D, z1: int, z2: int) -> Vec2:
    (x1, y1), (x2, y2) = basis
    return (z1 * x1 + z2 * x2, z1 * y1 + z2 * y2)


def lattice_points_in_box_2d(
    basis: Basis2D,
    coeff_bound: int,
    x_min: int,
    x_max: int,
    y_min: int,
    y_max: int,
) -> list[Vec2]:
    if coeff_bound < 0:
        raise ValueError("coeff_bound must be non-negative")
    if x_min > x_max or y_min > y_max:
        raise ValueError("invalid box bounds")
    if det_2d(basis) == 0:
        raise ValueError("basis must be linearly independent (det != 0)")

    points: set[Vec2] = set()
    for z1 in range(-coeff_bound, coeff_bound + 1):
        for z2 in range(-coeff_bound, coeff_bound + 1):
            x, y = lattice_point_2d(basis, z1, z2)
            if x_min <= x <= x_max and y_min <= y <= y_max:
                points.add((x, y))
    return sorted(points)


def is_in_lattice_2d(basis: Basis2D, v: Vec2) -> bool:
    if det_2d(basis) == 0:
        raise ValueError("basis must be linearly independent (det != 0)")

    (b1x, b1y), (b2x, b2y) = basis
    vx, vy = v
    detB = abs(det_2d(basis))

    z1_num = vx * b2y - vy * b2x
    z2_num = b1x * vy - b1y * vx
    return z1_num % detB == 0 and z2_num % detB == 0


def lattice_points_in_box_membership_2d(
    basis: Basis2D, x_min: int, x_max: int, y_min: int, y_max: int
) -> list[Vec2]:
    if x_min > x_max or y_min > y_max:
        raise ValueError("invalid box bounds")
    if det_2d(basis) == 0:
        raise ValueError("basis must be linearly independent (det != 0)")

    points: list[Vec2] = []
    for x in range(x_min, x_max + 1):
        for y in range(y_min, y_max + 1):
            if is_in_lattice_2d(basis, (x, y)):
                points.append((x, y))
    return points


def change_basis_unimodular_2d(basis: Basis2D, U: Mat2) -> Basis2D:
    if abs(det_mat2(U)) != 1:
        raise ValueError("U must be unimodular (det = ±1)")
    if det_2d(basis) == 0:
        raise ValueError("basis must be linearly independent (det != 0)")

    (b1x, b1y), (b2x, b2y) = basis
    (a, b), (c, d) = U

    new_b1 = (a * b1x + c * b2x, a * b1y + c * b2y)
    new_b2 = (b * b1x + d * b2x, b * b1y + d * b2y)
    return (new_b1, new_b2)


def shortest_vector_bruteforce_2d(basis: Basis2D, coeff_bound: int) -> Vec2:
    if coeff_bound <= 0:
        raise ValueError("coeff_bound must be positive")
    if det_2d(basis) == 0:
        raise ValueError("basis must be linearly independent (det != 0)")

    best: Vec2 | None = None
    best_norm2: int | None = None
    for z1 in range(-coeff_bound, coeff_bound + 1):
        for z2 in range(-coeff_bound, coeff_bound + 1):
            if z1 == 0 and z2 == 0:
                continue
            x, y = lattice_point_2d(basis, z1, z2)
            n2 = x * x + y * y
            if best_norm2 is None or n2 < best_norm2:
                best_norm2 = n2
                best = (x, y)
    if best is None:
        raise ValueError("no non-zero vectors in the given coefficient window")
    return best


def fmt_points(points: Iterable[Vec2], max_items: int = 12) -> str:
    items = list(points)
    shown = items[:max_items]
    suffix = "" if len(items) <= max_items else f" … (+{len(items) - max_items} more)"
    return f"{shown}{suffix}"


def main() -> None:
    basis: Basis2D = ((2, 0), (1, 1))
    U: Mat2 = ((1, 1), (0, 1))
    changed = change_basis_unimodular_2d(basis, U)

    print("Lattice = integer span of a basis")
    print(f"basis B = {basis}")
    print(f"det(B)  = {det_2d(basis)}")
    print()

    print("Change basis with a unimodular matrix (same lattice)")
    print(f"U       = {U}  det(U)={det_mat2(U)}")
    print(f"basis B'= {changed}")
    print(f"det(B') = {det_2d(changed)}")
    print()

    pts_B = lattice_points_in_box_2d(basis, coeff_bound=8, x_min=-6, x_max=6, y_min=-6, y_max=6)
    pts_Bp = lattice_points_in_box_2d(changed, coeff_bound=8, x_min=-6, x_max=6, y_min=-6, y_max=6)
    print("Points in a box (coefficient-window view; may differ across bases)")
    print(f"B  coeff-window: {fmt_points(pts_B)}")
    print(f"B' coeff-window: {fmt_points(pts_Bp)}")
    print()

    pts_Bm = lattice_points_in_box_membership_2d(basis, x_min=-6, x_max=6, y_min=-6, y_max=6)
    pts_Bpm = lattice_points_in_box_membership_2d(changed, x_min=-6, x_max=6, y_min=-6, y_max=6)
    print("Points in a box (membership view; must match across bases)")
    print(f"B  membership: {fmt_points(pts_Bm)}")
    print(f"B' membership: {fmt_points(pts_Bpm)}")
    print(f"equal: {pts_Bm == pts_Bpm}")
    print()

    sv_B = shortest_vector_bruteforce_2d(basis, coeff_bound=8)
    sv_Bp = shortest_vector_bruteforce_2d(changed, coeff_bound=8)
    print("Toy shortest-vector search (bounded coefficients)")
    print(f"shortest (B) : {sv_B}")
    print(f"shortest (B'): {sv_Bp}")

    try:
        from fpylll import IntegerMatrix, LLL

        print()
        print("fpylll sanity check (LLL reduction)")
        mat = IntegerMatrix.from_matrix([[basis[0][0], basis[1][0]], [basis[0][1], basis[1][1]]])
        LLL.reduction(mat)
        reduced = [[int(mat[i, j]) for j in range(mat.ncols)] for i in range(mat.nrows)]
        print(reduced)
    except Exception:
        pass


if __name__ == "__main__":
    main()
