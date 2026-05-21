"""
Toy Falcon (FN-DSA) demo for tiny parameters.

This script implements the *verification equation* used by Falcon signatures:

    s1 = c - s2*h mod (x^n + 1, q)

and demonstrates how a trapdoor (f, g, F, G) lets a signer find a short (s1, s2)
for a given target point c = HashToPoint(salt || message).

It is intentionally small, slow, and not constant-time.

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import hashlib
import itertools
from typing import List, Sequence, Tuple


TOY_N = 4
TOY_Q = 12289
TOY_BETA2 = 50_000_000


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValueError(msg)


def _l2_norm2(v: Sequence[int]) -> int:
    return sum(int(x) * int(x) for x in v)


def _center_lift_coeff(x: int, q: int) -> int:
    y = x % q
    if y > q // 2:
        y -= q
    return y


def poly_center_lift(a: Sequence[int], q: int, n: int) -> List[int]:
    _require(len(a) == n, "wrong polynomial length")
    return [_center_lift_coeff(x, q) for x in a]


def poly_mod_q(a: Sequence[int], q: int, n: int) -> List[int]:
    if len(a) != n:
        raise ValueError("wrong polynomial length")
    return [int(x) % q for x in a]


def poly_add_mod_q(a: Sequence[int], b: Sequence[int], q: int, n: int) -> List[int]:
    _require(len(a) == n and len(b) == n, "wrong polynomial length")
    return [(int(x) + int(y)) % q for x, y in zip(a, b)]


def poly_sub_mod_q(a: Sequence[int], b: Sequence[int], q: int, n: int) -> List[int]:
    _require(len(a) == n and len(b) == n, "wrong polynomial length")
    return [(int(x) - int(y)) % q for x, y in zip(a, b)]


def poly_mul_mod_phi_int(a: Sequence[int], b: Sequence[int], n: int) -> List[int]:
    _require(len(a) == n and len(b) == n, "wrong polynomial length")
    out = [0] * n
    for i, ai in enumerate(a):
        ai = int(ai)
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            bj = int(bj)
            if bj == 0:
                continue
            k = i + j
            if k < n:
                out[k] += ai * bj
            else:
                out[k - n] -= ai * bj
    return out


def poly_mul_mod_phi_q(a: Sequence[int], b: Sequence[int], q: int, n: int) -> List[int]:
    out = poly_mul_mod_phi_int(a, b, n)
    return [x % q for x in out]


def poly_rotate_x(a: Sequence[int]) -> List[int]:
    n = len(a)
    if n == 0:
        return []
    return [-int(a[-1])] + [int(x) for x in a[:-1]]


def poly_rotate(a: Sequence[int], k: int) -> List[int]:
    n = len(a)
    k %= 2 * n
    out = [int(x) for x in a]
    for _ in range(k % n):
        out = poly_rotate_x(out)
    if k >= n:
        out = [-x for x in out]
    return out


def _poly_strip_mod_q(p: List[int], q: int) -> List[int]:
    while len(p) > 0 and (p[-1] % q) == 0:
        p.pop()
    if not p:
        return [0]
    return [x % q for x in p]


def _poly_add_poly_mod_q(a: List[int], b: List[int], q: int) -> List[int]:
    out = [0] * max(len(a), len(b))
    for i in range(len(out)):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % q
    return _poly_strip_mod_q(out, q)


def _poly_sub_poly_mod_q(a: List[int], b: List[int], q: int) -> List[int]:
    out = [0] * max(len(a), len(b))
    for i in range(len(out)):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % q
    return _poly_strip_mod_q(out, q)


def _poly_mul_poly_mod_q(a: List[int], b: List[int], q: int) -> List[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        ai %= q
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            bj %= q
            if bj == 0:
                continue
            out[i + j] = (out[i + j] + ai * bj) % q
    return _poly_strip_mod_q(out, q)


def _poly_divmod_mod_q(a: List[int], b: List[int], q: int) -> Tuple[List[int], List[int]]:
    a = _poly_strip_mod_q(a[:], q)
    b = _poly_strip_mod_q(b[:], q)
    if b == [0]:
        raise ZeroDivisionError("polynomial division by zero")
    da = len(a) - 1
    db = len(b) - 1
    if da < db:
        return [0], a
    inv_lead = pow(b[-1] % q, -1, q)
    quotient = [0] * (da - db + 1)
    rem = a[:]
    while len(rem) - 1 >= db and rem != [0]:
        dr = len(rem) - 1
        coeff = (rem[-1] * inv_lead) % q
        shift = dr - db
        quotient[shift] = coeff
        sub = [0] * shift + [(coeff * x) % q for x in b]
        rem = _poly_sub_poly_mod_q(rem, sub, q)
    return _poly_strip_mod_q(quotient, q), _poly_strip_mod_q(rem, q)


def _poly_mod_mod_q(a: List[int], modulus: List[int], q: int) -> List[int]:
    _, r = _poly_divmod_mod_q(a, modulus, q)
    return r


def poly_inv_mod_phi_q(f: Sequence[int], q: int, n: int) -> List[int]:
    _require(len(f) == n, "wrong polynomial length")
    phi = [1] + [0] * (n - 1) + [1]

    r0 = _poly_strip_mod_q([int(x) % q for x in f], q)
    r1 = _poly_strip_mod_q(phi[:], q)
    s0, s1 = [1], [0]
    t0, t1 = [0], [1]

    while r1 != [0]:
        quotient, r2 = _poly_divmod_mod_q(r0, r1, q)
        r0, r1 = r1, r2
        s0, s1 = s1, _poly_sub_poly_mod_q(s0, _poly_mul_poly_mod_q(quotient, s1, q), q)
        t0, t1 = t1, _poly_sub_poly_mod_q(t0, _poly_mul_poly_mod_q(quotient, t1, q), q)

    if len(r0) != 1 or r0[0] % q == 0:
        raise ValueError("not invertible modulo (x^n+1, q)")
    inv_g = pow(r0[0], -1, q)
    inv = [(inv_g * x) % q for x in s0]
    inv = _poly_mod_mod_q(inv, phi, q)
    inv = inv + [0] * (n - len(inv))
    return inv[:n]


def hash_to_point(msg: bytes, salt: bytes, n: int, q: int) -> List[int]:
    out: List[int] = []
    counter = 0
    while len(out) < n:
        h = hashlib.sha256(salt + msg + counter.to_bytes(4, "big")).digest()
        for i in range(0, len(h), 2):
            if len(out) >= n:
                break
            val = int.from_bytes(h[i : i + 2], "big") % q
            out.append(val)
        counter += 1
    return out


def _mul_matrix_negacyclic(poly: Sequence[int], n: int) -> List[List[int]]:
    poly = [int(x) for x in poly]
    _require(len(poly) == n, "wrong polynomial length")
    mat = [[0 for _ in range(n)] for _ in range(n)]
    for j in range(n):
        e = [0] * n
        e[j] = 1
        col = poly_mul_mod_phi_int(poly, e, n)
        for i in range(n):
            mat[i][j] = int(col[i])
    return mat


def _mat_vec_mul(mat: Sequence[Sequence[int]], vec: Sequence[int]) -> List[int]:
    _require(len(mat) > 0, "empty matrix")
    _require(len(mat[0]) == len(vec), "dimension mismatch")
    out = [0] * len(mat)
    for i, row in enumerate(mat):
        s = 0
        for a, b in zip(row, vec):
            s += int(a) * int(b)
        out[i] = s
    return out


def _rref_augmented(a: Sequence[Sequence[int]], b: Sequence[int]) -> Tuple[List[List[Fraction]], List[Fraction], List[int]]:
    m = len(a)
    n = len(a[0]) if m > 0 else 0
    mat = [[Fraction(int(x)) for x in row] for row in a]
    rhs = [Fraction(int(x)) for x in b]

    pivots: List[int] = []
    row = 0
    for col in range(n):
        if row >= m:
            break
        pivot_row = None
        for r in range(row, m):
            if mat[r][col] != 0:
                pivot_row = r
                break
        if pivot_row is None:
            continue
        if pivot_row != row:
            mat[row], mat[pivot_row] = mat[pivot_row], mat[row]
            rhs[row], rhs[pivot_row] = rhs[pivot_row], rhs[row]

        pivot_val = mat[row][col]
        inv = Fraction(1, 1) / pivot_val
        mat[row] = [x * inv for x in mat[row]]
        rhs[row] *= inv

        for r in range(m):
            if r == row:
                continue
            factor = mat[r][col]
            if factor == 0:
                continue
            mat[r] = [x - factor * y for x, y in zip(mat[r], mat[row])]
            rhs[r] = rhs[r] - factor * rhs[row]

        pivots.append(col)
        row += 1

    return mat, rhs, pivots


def solve_ntru_equation_small(
    f: Sequence[int], g: Sequence[int], q: int, n: int, *, max_abs: int = 2
) -> Tuple[List[int], List[int]]:
    _require(len(f) == n and len(g) == n, "wrong polynomial length")
    mf = _mul_matrix_negacyclic(f, n)
    mg = _mul_matrix_negacyclic(g, n)
    a = [row_f + [-x for x in row_g] for row_f, row_g in zip(mf, mg)]
    rhs = [0] * n
    rhs[0] = q

    rref, rref_rhs, pivots = _rref_augmented(a, rhs)
    nvars = 2 * n

    for i in range(n):
        if all(rref[i][j] == 0 for j in range(nvars)) and rref_rhs[i] != 0:
            raise ValueError("no solution to NTRU equation")

    free_cols = [j for j in range(nvars) if j not in pivots]
    _require(len(free_cols) > 0, "unexpected full-rank system")

    best: Tuple[int, List[int]] | None = None
    values_range = range(-max_abs, max_abs + 1)
    for values in itertools.product(values_range, repeat=len(free_cols)):
        x: List[Fraction] = [Fraction(0) for _ in range(nvars)]
        for col, val in zip(free_cols, values):
            x[col] = Fraction(val)
        for i, pcol in enumerate(pivots):
            acc = rref_rhs[i]
            for j in free_cols:
                acc -= rref[i][j] * x[j]
            x[pcol] = acc

        if any(xx.denominator != 1 for xx in x):
            continue
        x_int = [int(xx) for xx in x]

        g_coeffs = x_int[:n]
        f_coeffs = x_int[n:]

        lhs = poly_mul_mod_phi_int(f, g_coeffs, n)
        rhs_part = poly_mul_mod_phi_int(g, f_coeffs, n)
        check = [lhs[i] - rhs_part[i] for i in range(n)]
        if check[0] != q or any(check[i] != 0 for i in range(1, n)):
            continue

        score = _l2_norm2(g_coeffs) + _l2_norm2(f_coeffs)
        if best is None or score < best[0]:
            best = (score, x_int)

    if best is None:
        raise ValueError("failed to find (F, G) for NTRU equation")

    x_int = best[1]
    g_poly = x_int[:n]
    f_poly = x_int[n:]
    F = f_poly
    G = g_poly
    return F, G


def ntru_public_key_h(f: Sequence[int], g: Sequence[int], q: int, n: int) -> List[int]:
    inv_f = poly_inv_mod_phi_q(f, q, n)
    return poly_mul_mod_phi_q(g, inv_f, q, n)


def _basis_from_fgFG(f: Sequence[int], g: Sequence[int], F: Sequence[int], G: Sequence[int], n: int) -> List[List[int]]:
    _require(len(f) == n and len(g) == n and len(F) == n and len(G) == n, "wrong polynomial length")
    basis: List[List[int]] = []
    for i in range(n):
        fi = poly_rotate(f, i)
        gi = poly_rotate(g, i)
        basis.append([*fi, *gi])
    for i in range(n):
        Fi = poly_rotate(F, i)
        Gi = poly_rotate(G, i)
        basis.append([*Fi, *Gi])
    return basis


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    return float(sum(x * y for x, y in zip(a, b)))


def gram_schmidt(basis: Sequence[Sequence[int]]) -> Tuple[List[List[float]], List[List[float]], List[float]]:
    n = len(basis)
    dim = len(basis[0]) if n > 0 else 0
    b = [[float(x) for x in row] for row in basis]
    mu = [[0.0 for _ in range(n)] for _ in range(n)]
    b_star = [[0.0 for _ in range(dim)] for _ in range(n)]
    norm2 = [0.0 for _ in range(n)]

    for i in range(n):
        v = b[i][:]
        for j in range(i):
            if norm2[j] == 0.0:
                raise ValueError("dependent basis")
            mu[i][j] = _dot(b[i], b_star[j]) / norm2[j]
            for k in range(dim):
                v[k] -= mu[i][j] * b_star[j][k]
        b_star[i] = v
        norm2[i] = _dot(v, v)

    return b, b_star, norm2


def babai_nearest_plane(basis: Sequence[Sequence[int]], target: Sequence[int]) -> List[int]:
    b, b_star, norm2 = gram_schmidt(basis)
    y = [float(x) for x in target]
    coeffs = [0] * len(basis)

    for i in reversed(range(len(basis))):
        if norm2[i] == 0.0:
            raise ValueError("dependent basis")
        t = _dot(y, b_star[i]) / norm2[i]
        c = int(round(t))
        coeffs[i] = c
        for k in range(len(y)):
            y[k] -= c * b[i][k]

    out = [0] * len(target)
    for c, vec in zip(coeffs, basis):
        if c == 0:
            continue
        for i, x in enumerate(vec):
            out[i] += c * int(x)
    return out


@dataclass(frozen=True)
class ToyFalconSecretKey:
    n: int
    q: int
    f: List[int]
    g: List[int]
    F: List[int]
    G: List[int]


@dataclass(frozen=True)
class ToyFalconPublicKey:
    n: int
    q: int
    h: List[int]


def toy_keypair(n: int = TOY_N, q: int = TOY_Q) -> Tuple[ToyFalconSecretKey, ToyFalconPublicKey]:
    f = [1, 1, 0, -1]
    g = [0, 1, 1, 0]
    _require(len(f) == n and len(g) == n, "toy parameters require n=4")

    F, G = solve_ntru_equation_small(f, g, q, n)
    h = ntru_public_key_h(f, g, q, n)
    return ToyFalconSecretKey(n=n, q=q, f=f, g=g, F=F, G=G), ToyFalconPublicKey(n=n, q=q, h=h)


def toy_sign(msg: bytes, sk: ToyFalconSecretKey, salt: bytes) -> Tuple[bytes, List[int]]:
    _require(len(salt) == 16, "toy signer expects 16-byte salt")
    c = hash_to_point(msg, salt, sk.n, sk.q)
    c_center = poly_center_lift(c, sk.q, sk.n)

    basis = _basis_from_fgFG(sk.f, sk.g, sk.F, sk.G, sk.n)
    target = [0] * sk.n + c_center
    closest = babai_nearest_plane(basis, target)
    s2 = closest[: sk.n]
    return salt, s2


def toy_verify(msg: bytes, sig: Tuple[bytes, Sequence[int]], pk: ToyFalconPublicKey, beta2: int = TOY_BETA2) -> bool:
    salt, s2 = sig
    if len(salt) != 16:
        return False
    if len(s2) != pk.n:
        return False
    c = hash_to_point(msg, salt, pk.n, pk.q)
    s2_modq = [int(x) % pk.q for x in s2]
    s2h = poly_mul_mod_phi_q(s2_modq, pk.h, pk.q, pk.n)
    s1_modq = poly_sub_mod_q(c, s2h, pk.q, pk.n)
    s1 = poly_center_lift(s1_modq, pk.q, pk.n)
    norm2 = _l2_norm2(s1) + _l2_norm2([int(x) for x in s2])
    return norm2 <= beta2


def _fmt_poly(a: Sequence[int]) -> str:
    return "[" + ", ".join(str(int(x)) for x in a) + "]"


def main() -> None:
    print("=== Step 1: Negacyclic polynomial arithmetic ===")
    a = [1, 2, 0, 0]
    b = [0, 1, 0, 1]
    ab = poly_mul_mod_phi_q(a, b, TOY_Q, TOY_N)
    print("n =", TOY_N, "q =", TOY_Q)
    print("a(x) =", _fmt_poly(a))
    print("b(x) =", _fmt_poly(b))
    print("a*b mod (x^n+1,q) =", _fmt_poly(ab))
    print()

    print("=== Step 2: Public key h = g / f (mod q) ===")
    sk, pk = toy_keypair()
    inv_f = poly_inv_mod_phi_q(sk.f, sk.q, sk.n)
    print("f =", _fmt_poly(sk.f))
    print("g =", _fmt_poly(sk.g))
    print("inv(f) mod (phi,q) =", _fmt_poly(inv_f))
    print("h = g * inv(f) mod q =", _fmt_poly(pk.h))
    print()

    print("=== Step 3: Solve the NTRU equation fG - gF = q ===")
    left = poly_mul_mod_phi_int(sk.f, sk.G, sk.n)
    right = poly_mul_mod_phi_int(sk.g, sk.F, sk.n)
    check = [left[i] - right[i] for i in range(sk.n)]
    print("F =", _fmt_poly(sk.F))
    print("G =", _fmt_poly(sk.G))
    print("fG - gF =", _fmt_poly(check))
    print()

    print("=== Step 4: HashToPoint + sign/verify equation ===")
    msg = b"hello, falcon"
    salt = hashlib.sha256(b"toy-falcon-salt" + msg).digest()[:16]
    sig = toy_sign(msg, sk, salt=salt)
    ok = toy_verify(msg, sig, pk, beta2=TOY_BETA2)
    print("message =", msg)
    print("salt(hex) =", sig[0].hex())
    print("signature s2 =", _fmt_poly(sig[1]))
    c = hash_to_point(msg, sig[0], sk.n, sk.q)
    s2_modq = [x % sk.q for x in sig[1]]
    s2h = poly_mul_mod_phi_q(s2_modq, pk.h, sk.q, sk.n)
    s1_modq = poly_sub_mod_q(c, s2h, sk.q, sk.n)
    s1 = poly_center_lift(s1_modq, sk.q, sk.n)
    print("computed s1 =", _fmt_poly(s1))
    print("|| (s1,s2) ||^2 =", _l2_norm2(s1) + _l2_norm2(sig[1]))
    print("verify =", ok)


if __name__ == "__main__":
    main()
