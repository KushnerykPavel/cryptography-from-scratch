"""
Toy UOV + MAYO lesson code (stdlib-only).

This file implements:
- Finite-field arithmetic mod a small prime p
- Gaussian elimination over GF(p)
- A toy Oil-and-Vinegar (OV) quadratic map that vanishes on a secret oil subspace
- A toy UOV-style "hash-and-sign" using OV structure (when oil dimension == number of equations)
- A toy MAYO-style "whipped-up" map trick (when oil dimension < number of equations)

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple


def modp(value: int, p: int) -> int:
    return value % p


def inv_modp(a: int, p: int) -> int:
    a = a % p
    if a == 0:
        raise ZeroDivisionError("no inverse for 0 mod p")

    t, new_t = 0, 1
    r, new_r = p, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r

    if r != 1:
        raise ZeroDivisionError("a is not invertible mod p")
    return t % p


def vec_add(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("vector length mismatch")
    return [(x + y) % p for x, y in zip(a, b)]


def vec_sub(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    if len(a) != len(b):
        raise ValueError("vector length mismatch")
    return [(x - y) % p for x, y in zip(a, b)]


def mat_identity(n: int) -> List[List[int]]:
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def mat_vec_mul(matrix: Sequence[Sequence[int]], vector: Sequence[int], p: int) -> List[int]:
    if not matrix:
        return []
    cols = len(matrix[0])
    if len(vector) != cols:
        raise ValueError("dimension mismatch for mat-vec multiply")
    out: List[int] = []
    for row in matrix:
        if len(row) != cols:
            raise ValueError("ragged matrix")
        acc = 0
        for a, b in zip(row, vector):
            acc += a * b
        out.append(acc % p)
    return out


def mat_mul(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]], p: int) -> List[List[int]]:
    if not a or not b:
        return []
    a_cols = len(a[0])
    b_cols = len(b[0])
    if any(len(row) != a_cols for row in a) or any(len(row) != b_cols for row in b):
        raise ValueError("ragged matrix")
    if len(b) != a_cols:
        raise ValueError("dimension mismatch for mat-mat multiply")

    b_t = list(map(list, zip(*b)))
    out: List[List[int]] = []
    for row in a:
        out_row: List[int] = []
        for col in b_t:
            acc = 0
            for x, y in zip(row, col):
                acc += x * y
            out_row.append(acc % p)
        out.append(out_row)
    return out


def solve_linear_system_modp(
    matrix: Sequence[Sequence[int]], rhs: Sequence[int], p: int
) -> Optional[List[int]]:
    """
    Solve A x = b over GF(p) using Gaussian elimination.

    Returns one solution (free vars set to 0) or None if inconsistent.
    Works for rectangular A.
    """
    rows = len(matrix)
    if rows != len(rhs):
        raise ValueError("row count mismatch")
    cols = len(matrix[0]) if rows else 0
    if any(len(row) != cols for row in matrix):
        raise ValueError("ragged matrix")

    aug = [[matrix[i][j] % p for j in range(cols)] + [rhs[i] % p] for i in range(rows)]

    pivot_row = 0
    pivot_cols: List[int] = []
    for col in range(cols):
        pivot = None
        for r in range(pivot_row, rows):
            if aug[r][col] % p != 0:
                pivot = r
                break
        if pivot is None:
            continue
        aug[pivot_row], aug[pivot] = aug[pivot], aug[pivot_row]

        inv_pivot = inv_modp(aug[pivot_row][col], p)
        for j in range(col, cols + 1):
            aug[pivot_row][j] = (aug[pivot_row][j] * inv_pivot) % p

        for r in range(rows):
            if r == pivot_row:
                continue
            factor = aug[r][col] % p
            if factor == 0:
                continue
            for j in range(col, cols + 1):
                aug[r][j] = (aug[r][j] - factor * aug[pivot_row][j]) % p

        pivot_cols.append(col)
        pivot_row += 1
        if pivot_row == rows:
            break

    for r in range(rows):
        all_zero = all(aug[r][c] % p == 0 for c in range(cols))
        if all_zero and (aug[r][cols] % p != 0):
            return None

    solution = [0] * cols
    for r, c in enumerate(pivot_cols):
        solution[c] = aug[r][cols] % p
    return solution


def mat_inverse(matrix: Sequence[Sequence[int]], p: int) -> Optional[List[List[int]]]:
    n = len(matrix)
    if n == 0:
        return []
    if any(len(row) != n for row in matrix):
        raise ValueError("matrix must be square")

    aug = [[matrix[i][j] % p for j in range(n)] + mat_identity(n)[i] for i in range(n)]

    pivot_row = 0
    for col in range(n):
        pivot = None
        for r in range(pivot_row, n):
            if aug[r][col] % p != 0:
                pivot = r
                break
        if pivot is None:
            return None
        aug[pivot_row], aug[pivot] = aug[pivot], aug[pivot_row]

        inv_pivot = inv_modp(aug[pivot_row][col], p)
        for j in range(col, 2 * n):
            aug[pivot_row][j] = (aug[pivot_row][j] * inv_pivot) % p

        for r in range(n):
            if r == pivot_row:
                continue
            factor = aug[r][col] % p
            if factor == 0:
                continue
            for j in range(col, 2 * n):
                aug[r][j] = (aug[r][j] - factor * aug[pivot_row][j]) % p

        pivot_row += 1

    return [row[n:] for row in aug]


def hash_to_field_vec(message: bytes, p: int, length: int, domain: bytes = b"uov-mayo") -> List[int]:
    """
    Deterministic (toy) full-domain hash into F_p^length.

    Real MAYO/UOV use carefully specified XOF/FH and a salt; here we only need
    something stable and demo-friendly.
    """
    digest = hashlib.sha256(domain + b"\x00" + message).digest()
    out: List[int] = []
    counter = 0
    while len(out) < length:
        block = hashlib.sha256(digest + counter.to_bytes(4, "big")).digest()
        for byte in block:
            if len(out) == length:
                break
            out.append(byte % p)
        counter += 1
    return out


@dataclass(frozen=True)
class OVMap:
    """
    Oil-and-Vinegar quadratic map P: F_p^(v+o) -> F_p^m, with the trapdoor property:
    P(oil_only) = 0 for all vectors whose vinegar part is 0.

    That is ensured by construction: every term contains at least one vinegar variable.
    """

    p: int
    v: int
    o: int
    m: int
    vv: List[List[List[int]]]  # vv[poly][a][b] for 0<=a<=b<v, lower triangle is 0
    vo: List[List[List[int]]]  # vo[poly][a][k] for vinegar index a and oil index k
    lin_v: List[List[int]]  # lin_v[poly][a] for vinegar linear terms

    @property
    def n(self) -> int:
        return self.v + self.o


def ov_map_random(p: int, v: int, o: int, m: int, rng: random.Random) -> OVMap:
    vv: List[List[List[int]]] = []
    vo: List[List[List[int]]] = []
    lin_v: List[List[int]] = []
    for _ in range(m):
        vv_poly = [[0 for _ in range(v)] for _ in range(v)]
        for a in range(v):
            for b in range(a, v):
                vv_poly[a][b] = rng.randrange(p)
        vo_poly = [[rng.randrange(p) for _ in range(o)] for _ in range(v)]
        lin_v_poly = [rng.randrange(p) for _ in range(v)]
        vv.append(vv_poly)
        vo.append(vo_poly)
        lin_v.append(lin_v_poly)
    return OVMap(p=p, v=v, o=o, m=m, vv=vv, vo=vo, lin_v=lin_v)


def ov_eval(ov_map: OVMap, x: Sequence[int]) -> List[int]:
    if len(x) != ov_map.n:
        raise ValueError("input length mismatch")
    p = ov_map.p
    vinegar = x[: ov_map.v]
    oil = x[ov_map.v :]
    out: List[int] = []
    for poly_index in range(ov_map.m):
        acc = 0
        vv_poly = ov_map.vv[poly_index]
        vo_poly = ov_map.vo[poly_index]
        lin_v_poly = ov_map.lin_v[poly_index]

        for a in range(ov_map.v):
            va = vinegar[a] % p
            acc += lin_v_poly[a] * va
            for b in range(a, ov_map.v):
                acc += vv_poly[a][b] * va * (vinegar[b] % p)
            for k in range(ov_map.o):
                acc += vo_poly[a][k] * va * (oil[k] % p)

        out.append(acc % p)
    return out


def ov_polar(ov_map: OVMap, x: Sequence[int], y: Sequence[int]) -> List[int]:
    p = ov_map.p
    return vec_sub(ov_eval(ov_map, vec_add(x, y, p)), vec_add(ov_eval(ov_map, x), ov_eval(ov_map, y), p), p)


def uov_linear_system_for_oil(ov_map: OVMap, vinegar: Sequence[int], target: Sequence[int]) -> Tuple[List[List[int]], List[int]]:
    """
    Build the linear system A * oil = b for a fixed vinegar and desired target output.
    """
    if len(vinegar) != ov_map.v:
        raise ValueError("vinegar length mismatch")
    if len(target) != ov_map.m:
        raise ValueError("target length mismatch")

    p = ov_map.p
    constant = ov_eval(ov_map, list(vinegar) + [0] * ov_map.o)
    rhs = vec_sub(target, constant, p)

    matrix: List[List[int]] = [[0 for _ in range(ov_map.o)] for _ in range(ov_map.m)]
    for poly_index in range(ov_map.m):
        for k in range(ov_map.o):
            coeff = 0
            for a in range(ov_map.v):
                coeff += ov_map.vo[poly_index][a][k] * (vinegar[a] % p)
            matrix[poly_index][k] = coeff % p
    return matrix, rhs


@dataclass(frozen=True)
class ToyUOVKeypair:
    p: int
    ov_map: OVMap
    s: List[List[int]]
    s_inv: List[List[int]]
    t: List[List[int]]
    t_inv: List[List[int]]


def random_invertible_matrix(n: int, p: int, rng: random.Random) -> List[List[int]]:
    while True:
        candidate = [[rng.randrange(p) for _ in range(n)] for _ in range(n)]
        inv = mat_inverse(candidate, p)
        if inv is not None:
            return candidate


def uov_keygen(seed: int, p: int, v: int, o: int) -> ToyUOVKeypair:
    """
    Generate a toy UOV keypair.

    For the toy, we set m=o so the classic OV trapdoor gives an (attempted) square
    linear system in the oil variables.
    """
    rng = random.Random(seed)
    ov_map = ov_map_random(p=p, v=v, o=o, m=o, rng=rng)

    s = random_invertible_matrix(ov_map.n, p, rng)
    s_inv = mat_inverse(s, p)
    if s_inv is None:
        raise RuntimeError("unexpected: failed to invert S")

    t = random_invertible_matrix(ov_map.m, p, rng)
    t_inv = mat_inverse(t, p)
    if t_inv is None:
        raise RuntimeError("unexpected: failed to invert T")

    return ToyUOVKeypair(p=p, ov_map=ov_map, s=s, s_inv=s_inv, t=t, t_inv=t_inv)


def uov_public_eval(keypair: ToyUOVKeypair, signature: Sequence[int]) -> List[int]:
    x_prime = mat_vec_mul(keypair.s, signature, keypair.p)
    y_prime = ov_eval(keypair.ov_map, x_prime)
    return mat_vec_mul(keypair.t, y_prime, keypair.p)


def uov_sign(keypair: ToyUOVKeypair, message: bytes, rng_seed: int, max_attempts: int = 256) -> List[int]:
    """
    Toy UOV signing:
    - hash message to target in F_p^m
    - invert secret output transform T
    - sample random vinegar, solve linear system for oil
    - apply secret input transform S^{-1}
    """
    rng = random.Random(rng_seed)
    p = keypair.p

    target = hash_to_field_vec(message, p, keypair.ov_map.m, domain=b"uov")
    target_prime = mat_vec_mul(keypair.t_inv, target, p)

    for _ in range(max_attempts):
        vinegar = [rng.randrange(p) for _ in range(keypair.ov_map.v)]
        matrix, rhs = uov_linear_system_for_oil(keypair.ov_map, vinegar, target_prime)
        oil = solve_linear_system_modp(matrix, rhs, p)
        if oil is None:
            continue
        x_prime = vinegar + oil
        return mat_vec_mul(keypair.s_inv, x_prime, p)

    raise ValueError("failed to find a signature (toy params too small / unlucky RNG)")


def uov_verify(keypair: ToyUOVKeypair, message: bytes, signature: Sequence[int]) -> bool:
    p = keypair.p
    target = hash_to_field_vec(message, p, keypair.ov_map.m, domain=b"uov")
    return uov_public_eval(keypair, signature) == target


def mayo_whipped_eval(ov_map: OVMap, blocks: Sequence[Sequence[int]]) -> List[int]:
    """
    Toy MAYO whipped map:
      P*(x1,...,xk) = sum_i P(x_i) + sum_{i<j} P'(x_i, x_j)
    with E-matrices = identity (for teaching only).
    """
    p = ov_map.p
    k = len(blocks)
    if k == 0:
        return [0] * ov_map.m
    if any(len(block) != ov_map.n for block in blocks):
        raise ValueError("block size mismatch")

    acc = [0] * ov_map.m
    for i in range(k):
        acc = vec_add(acc, ov_eval(ov_map, blocks[i]), p)
    for i in range(k):
        for j in range(i + 1, k):
            acc = vec_add(acc, ov_polar(ov_map, blocks[i], blocks[j]), p)
    return acc


def mayo_build_oil_system(
    ov_map: OVMap, vinegar_blocks: Sequence[Sequence[int]], target: Sequence[int]
) -> Tuple[List[List[int]], List[int], List[int]]:
    """
    Build A * oil_vec = b for the whipped map equation:
      P*(v1+o1, ..., vk+ok) = target

    This uses "probing": because the expression is linear in the oil variables (for OV maps
    that vanish on the oil space), each column can be recovered by flipping one oil basis
    coordinate to 1.
    """
    p = ov_map.p
    k = len(vinegar_blocks)
    if k == 0:
        raise ValueError("need at least one block")
    if len(target) != ov_map.m:
        raise ValueError("target length mismatch")
    if any(len(vb) != ov_map.v for vb in vinegar_blocks):
        raise ValueError("vinegar block length mismatch")

    base_blocks = [list(vb) + [0] * ov_map.o for vb in vinegar_blocks]
    base_value = mayo_whipped_eval(ov_map, base_blocks)
    rhs = vec_sub(target, base_value, p)

    num_vars = k * ov_map.o
    matrix = [[0 for _ in range(num_vars)] for _ in range(ov_map.m)]

    for var_index in range(num_vars):
        blocks = [block[:] for block in base_blocks]
        block_index = var_index // ov_map.o
        oil_index = var_index % ov_map.o
        blocks[block_index][ov_map.v + oil_index] = 1
        value = mayo_whipped_eval(ov_map, blocks)
        col = vec_sub(value, base_value, p)
        for eq in range(ov_map.m):
            matrix[eq][var_index] = col[eq]

    return matrix, rhs, base_value


def mayo_sign(
    ov_map: OVMap, message: bytes, k: int, rng_seed: int, max_attempts: int = 256
) -> List[int]:
    """
    Toy MAYO signing:
    - hash message to target in F_p^m
    - choose k random vinegar blocks
    - solve m linear equations in k*o oil variables using the whipped map
    - output signature as a flat vector of length k*n (block concatenation)
    """
    if k <= 0:
        raise ValueError("k must be positive")
    rng = random.Random(rng_seed)
    p = ov_map.p

    target = hash_to_field_vec(message, p, ov_map.m, domain=b"mayo")
    for _ in range(max_attempts):
        vinegar_blocks = [[rng.randrange(p) for _ in range(ov_map.v)] for _ in range(k)]
        matrix, rhs, _ = mayo_build_oil_system(ov_map, vinegar_blocks, target)
        oil_vec = solve_linear_system_modp(matrix, rhs, p)
        if oil_vec is None:
            continue
        blocks: List[List[int]] = []
        for block_index in range(k):
            oil_block = oil_vec[block_index * ov_map.o : (block_index + 1) * ov_map.o]
            blocks.append(vinegar_blocks[block_index] + oil_block)
        signature_flat: List[int] = []
        for block in blocks:
            signature_flat.extend([x % p for x in block])
        return signature_flat

    raise ValueError("failed to find a signature (toy params too small / unlucky RNG)")


def mayo_verify(ov_map: OVMap, message: bytes, k: int, signature_flat: Sequence[int]) -> bool:
    p = ov_map.p
    target = hash_to_field_vec(message, p, ov_map.m, domain=b"mayo")
    if len(signature_flat) != k * ov_map.n:
        return False
    blocks = [
        list(signature_flat[i * ov_map.n : (i + 1) * ov_map.n]) for i in range(k)
    ]
    return mayo_whipped_eval(ov_map, blocks) == target


def _fmt_vec(vec: Sequence[int]) -> str:
    return "[" + ", ".join(str(x) for x in vec) + "]"


def main() -> None:
    p = 31

    print("=== Step 1: Finite field + linear solver ===")
    matrix = [[1, 2], [3, 4]]
    rhs = [5, 6]
    solution = solve_linear_system_modp(matrix, rhs, p)
    print(f"solve A x = b mod {p}")
    print(f"A = {matrix}")
    print(f"b = {rhs}")
    print(f"x = {solution}")
    if solution is not None:
        check = mat_vec_mul(matrix, solution, p)
        print(f"A x mod {p} = {check}")
    print()

    print("=== Step 2: OV map evaluation + polar form ===")
    rng = random.Random(1234)
    demo_map = ov_map_random(p=p, v=2, o=1, m=2, rng=rng)
    x = [3, 5, 7]
    y = [11, 13, 17]
    px = ov_eval(demo_map, x)
    py = ov_eval(demo_map, y)
    pxy = ov_eval(demo_map, vec_add(x, y, p))
    polar_xy = ov_polar(demo_map, x, y)
    print(f"P(x) = {_fmt_vec(px)} for x={_fmt_vec(x)}")
    print(f"P(y) = {_fmt_vec(py)} for y={_fmt_vec(y)}")
    print(f"P(x+y) = {_fmt_vec(pxy)} for x+y={_fmt_vec(vec_add(x, y, p))}")
    print(f"P'(x,y)=P(x+y)-P(x)-P(y) = {_fmt_vec(polar_xy)}")
    print()

    print("=== Step 3: Toy UOV (o = m) sign/verify ===")
    uov_kp = uov_keygen(seed=2026, p=p, v=4, o=3)
    message = b"attack at dawn"
    signature = uov_sign(uov_kp, message, rng_seed=424242)
    ok = uov_verify(uov_kp, message, signature)
    print(f"message = {message!r}")
    print(f"signature (len={len(signature)}) = {_fmt_vec(signature)}")
    print(f"verify = {ok}")
    print()

    print("=== Step 4: Toy MAYO (o < m) via whipped map ===")
    mayo_map = ov_map_random(p=p, v=4, o=2, m=4, rng=random.Random(9001))
    target_mayo = hash_to_field_vec(message, p, mayo_map.m, domain=b"mayo")
    print(f"target t = {_fmt_vec(target_mayo)}")
    print("Trying to sign with a single block (overdetermined: m equations, o unknowns)...")
    failed = True
    for attempt in range(25):
        vinegar = [attempt % p for _ in range(mayo_map.v)]
        matrix_1, rhs_1 = uov_linear_system_for_oil(mayo_map, vinegar, target_mayo)
        oil_1 = solve_linear_system_modp(matrix_1, rhs_1, p)
        if oil_1 is not None:
            failed = False
            break
    print(f"single-block signing success? {not failed}")
    print("Now sign with k=3 blocks (variables = k*o = 6 > m):")
    sig_flat = mayo_sign(mayo_map, message, k=3, rng_seed=777, max_attempts=1024)
    ok_mayo = mayo_verify(mayo_map, message, k=3, signature_flat=sig_flat)
    print(f"signature (len={len(sig_flat)}) = {_fmt_vec(sig_flat)}")
    print(f"verify = {ok_mayo}")


if __name__ == "__main__":
    main()
