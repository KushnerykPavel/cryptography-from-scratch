"""
Toy Dual-Regev decryption keys from gadget trapdoors (stdlib-only).

Run:
  python3 code/main.py

What this script does:
  1) Builds the MP12-style gadget matrix G and its easy "inversion" G^{-1} (bit decomposition).
  2) Constructs a trapdoored matrix A = [A' | G - A'R] (mod q) with trapdoor T = [R; I].
  3) Uses T to sample a short preimage x such that A x = y (mod q) for an arbitrary y.
  4) Plugs that preimage x into a toy Dual-Regev encryption/decryption flow.

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Sequence, Tuple

Matrix = List[List[int]]


def _is_power_of_two(q: int) -> bool:
    return q > 0 and (q & (q - 1)) == 0


def _log2_int(q: int) -> int:
    if not _is_power_of_two(q):
        raise ValueError("this toy implementation assumes q is a power of 2")
    return q.bit_length() - 1


def mod_q(x: int, q: int) -> int:
    return x % q


def dot(a: Sequence[int], b: Sequence[int]) -> int:
    if len(a) != len(b):
        raise ValueError("vector length mismatch")
    return sum(ai * bi for ai, bi in zip(a, b))


def dot_mod(a: Sequence[int], b: Sequence[int], q: int) -> int:
    return dot(a, b) % q


def mat_dims(A: Matrix) -> Tuple[int, int]:
    if not A:
        return (0, 0)
    return (len(A), len(A[0]))


def mat_mul_mod(A: Matrix, B: Matrix, q: int) -> Matrix:
    n, m = mat_dims(A)
    m2, p = mat_dims(B)
    if m != m2:
        raise ValueError("matrix dimension mismatch")
    out: Matrix = [[0 for _ in range(p)] for _ in range(n)]
    for i in range(n):
        for k in range(m):
            aik = A[i][k]
            if aik == 0:
                continue
            for j in range(p):
                out[i][j] = (out[i][j] + aik * B[k][j]) % q
    return out


def mat_vec_mul_mod(A: Matrix, x: Sequence[int], q: int) -> List[int]:
    n, m = mat_dims(A)
    if len(x) != m:
        raise ValueError("matrix/vector dimension mismatch")
    return [sum(A[i][j] * x[j] for j in range(m)) % q for i in range(n)]


def mat_vec_mul_int(A: Matrix, x: Sequence[int]) -> List[int]:
    n, m = mat_dims(A)
    if len(x) != m:
        raise ValueError("matrix/vector dimension mismatch")
    return [sum(A[i][j] * x[j] for j in range(m)) for i in range(n)]


def mat_hcat(left: Matrix, right: Matrix) -> Matrix:
    n1, _m1 = mat_dims(left)
    n2, _m2 = mat_dims(right)
    if n1 != n2:
        raise ValueError("row mismatch for horizontal concatenation")
    return [left[i] + right[i] for i in range(n1)]


def identity_matrix(n: int) -> Matrix:
    out: Matrix = [[0 for _ in range(n)] for _ in range(n)]
    for i in range(n):
        out[i][i] = 1
    return out


def max_abs(v: Sequence[int]) -> int:
    return max((abs(x) for x in v), default=0)


def gadget_matrix(n: int, q: int) -> Matrix:
    k = _log2_int(q)
    g = [1 << i for i in range(k)]
    out: Matrix = [[0 for _ in range(n * k)] for _ in range(n)]
    for row in range(n):
        for i, gi in enumerate(g):
            out[row][row * k + i] = gi % q
    return out


def bit_decompose_element(x: int, q: int) -> List[int]:
    k = _log2_int(q)
    x = x % q
    return [(x >> i) & 1 for i in range(k)]


def bit_decompose_vec(v: Sequence[int], q: int) -> List[int]:
    bits: List[int] = []
    for x in v:
        bits.extend(bit_decompose_element(x, q))
    return bits


def gadget_compose_vec(bits: Sequence[int], q: int) -> List[int]:
    k = _log2_int(q)
    if len(bits) % k != 0:
        raise ValueError("bit vector length must be a multiple of k")
    n = len(bits) // k
    out: List[int] = []
    for i in range(n):
        chunk = bits[i * k : (i + 1) * k]
        out.append(sum(int(b) * (1 << j) for j, b in enumerate(chunk)) % q)
    return out


@dataclass(frozen=True)
class Trapdoor:
    q: int
    A: Matrix
    A_prime: Matrix
    R: Matrix
    T: Matrix


def trapdoor_generate(A_prime: Matrix, R: Matrix, q: int) -> Trapdoor:
    n, m_prime = mat_dims(A_prime)
    m_r, nk = mat_dims(R)
    if m_r != m_prime:
        raise ValueError("R must have shape (m_prime, n*k)")
    k = _log2_int(q)
    if nk != n * k:
        raise ValueError("R must have width n*k where k=log2(q)")

    G = gadget_matrix(n, q)
    AprimeR = mat_mul_mod(A_prime, R, q)
    right: Matrix = [[(G[i][j] - AprimeR[i][j]) % q for j in range(nk)] for i in range(n)]
    A = mat_hcat(A_prime, right)

    I = identity_matrix(nk)
    T: Matrix = [row[:] for row in R] + I
    return Trapdoor(q=q, A=A, A_prime=A_prime, R=R, T=T)


def trapdoor_preimage(trap: Trapdoor, y: Sequence[int]) -> List[int]:
    n, _m = mat_dims(trap.A)
    if len(y) != n:
        raise ValueError("y must have length n")
    yq = [yi % trap.q for yi in y]
    x_prime = bit_decompose_vec(yq, trap.q)
    return mat_vec_mul_int(trap.T, x_prime)


def small_error_vector(m: int, bound: int, rng: random.Random) -> List[int]:
    return [rng.randint(-bound, bound) for _ in range(m)]


def dual_regev_encrypt(
    A: Matrix,
    y: Sequence[int],
    q: int,
    message_bit: int,
    rng: random.Random,
    error_bound: int,
) -> Tuple[List[int], int]:
    n, m = mat_dims(A)
    if len(y) != n:
        raise ValueError("y must have length n")
    if message_bit not in (0, 1):
        raise ValueError("message_bit must be 0 or 1")

    s = [rng.randrange(q) for _ in range(n)]
    e = small_error_vector(m, error_bound, rng)
    e_prime = rng.randint(-error_bound, error_bound)

    ct1 = []
    for j in range(m):
        val = sum(s[i] * A[i][j] for i in range(n)) + e[j]
        ct1.append(val % q)

    ct2 = (dot(s, y) + e_prime + message_bit * (q // 2)) % q
    return (ct1, ct2)


def decode_bit_from_mod_q(value: int, q: int) -> int:
    value = value % q

    def circ_dist(a: int, b: int) -> int:
        d = (a - b) % q
        return min(d, q - d)

    d0 = circ_dist(value, 0)
    d1 = circ_dist(value, q // 2)
    return 0 if d0 <= d1 else 1


def dual_regev_decrypt(ct1: Sequence[int], ct2: int, sk_x: Sequence[int], q: int) -> Tuple[int, int]:
    if len(ct1) != len(sk_x):
        raise ValueError("ciphertext/key dimension mismatch")
    inner = dot_mod(ct1, sk_x, q)
    raw = (ct2 - inner) % q
    return (decode_bit_from_mod_q(raw, q), raw)


def _format_matrix(A: Matrix, max_rows: int = 6, max_cols: int = 20) -> str:
    n, m = mat_dims(A)
    shown_rows = min(n, max_rows)
    shown_cols = min(m, max_cols)
    lines = []
    for i in range(shown_rows):
        row = A[i][:shown_cols]
        suffix = " ..." if shown_cols < m else ""
        lines.append("[" + " ".join(f"{x:3d}" for x in row) + suffix + "]")
    if shown_rows < n:
        lines.append("...")
    return "\n".join(lines)


def step_1_gadgets(q: int) -> None:
    print("=== Step 1: Gadget matrix (G) and bit decomposition (G^{-1}) ===")
    n = 3
    G = gadget_matrix(n, q)
    print(f"q={q}, k=log2(q)={_log2_int(q)}, G shape={mat_dims(G)}")
    print(_format_matrix(G))
    y = [5, 42, 199]
    bits = bit_decompose_vec(y, q)
    y2 = gadget_compose_vec(bits, q)
    print(f"y = {y}")
    print(f"G^{-1}(y) (first 24 bits) = {bits[:24]}")
    print(f"G * G^(-1)(y) mod q = {y2}")
    print()


def step_2_trapdoor_generation(q: int, rng: random.Random) -> Trapdoor:
    print("=== Step 2: Trapdoor generation A = [A' | G - A'R] ===")
    n = 2
    k = _log2_int(q)
    m_prime = 4
    nk = n * k
    A_prime: Matrix = [[rng.randrange(q) for _ in range(m_prime)] for _ in range(n)]
    R: Matrix = [[rng.choice([-1, 0, 1]) for _ in range(nk)] for _ in range(m_prime)]
    trap = trapdoor_generate(A_prime, R, q)
    print(f"A' shape={mat_dims(trap.A_prime)}, R shape={mat_dims(trap.R)}")
    print(f"A shape={mat_dims(trap.A)}, T shape={mat_dims(trap.T)}")
    print("A (first rows):")
    print(_format_matrix(trap.A, max_rows=4, max_cols=18))
    print()
    return trap


def step_3_preimage_sampling(trap: Trapdoor, rng: random.Random) -> Tuple[List[int], List[int]]:
    print("=== Step 3: Use trapdoor to find short x with A x = y (mod q) ===")
    n, _m = mat_dims(trap.A)
    y = [rng.randrange(trap.q) for _ in range(n)]
    x = trapdoor_preimage(trap, y)
    Ax = mat_vec_mul_mod(trap.A, x, trap.q)
    print(f"y = {y}")
    print(f"x (len={len(x)}) max|x_i|={max_abs(x)}")
    print(f"A x mod q = {Ax}")
    print()
    return (y, x)


def step_4_dual_regev(trap: Trapdoor, y: List[int], sk_x: List[int], rng: random.Random) -> None:
    print("=== Step 4: Toy Dual-Regev using sk = short preimage x (Ax=y) ===")
    msg = 1
    ct1, ct2 = dual_regev_encrypt(trap.A, y, trap.q, msg, rng=rng, error_bound=1)
    dec, raw = dual_regev_decrypt(ct1, ct2, sk_x, trap.q)
    print(f"message bit = {msg}")
    print(f"ct1 (first 12 entries) = {ct1[:12]}")
    print(f"ct2 = {ct2}")
    print(f"decrypt -> {dec} (raw after subtraction: {raw})")
    print()


def main() -> None:
    q = 256
    rng = random.Random(1337)
    step_1_gadgets(q)
    trap = step_2_trapdoor_generation(q, rng)
    y, x = step_3_preimage_sampling(trap, rng)
    step_4_dual_regev(trap, y, x, rng)


if __name__ == "__main__":
    main()
