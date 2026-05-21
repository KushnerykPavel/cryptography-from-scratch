"""Toy Classic McEliece from scratch (educational, tiny parameters).

Run:
  python3 code/main.py

This lesson implements a miniature McEliece-style public-key encryption scheme
using the Hamming(7,4) code as the secret decodable code. It demonstrates the
core Classic McEliece idea:

  Public key: a random-looking generator matrix G_pub.
  Secret key: a decoder for some structured code, plus the scramblers that
              turn G_base into G_pub.

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
from random import Random


def _assert_bit(x: int) -> None:
    if x not in (0, 1):
        raise ValueError("bit must be 0 or 1")


def assert_bits(v: list[int], *, length: int | None = None) -> None:
    if length is not None and len(v) != length:
        raise ValueError(f"expected {length} bits, got {len(v)}")
    for b in v:
        _assert_bit(b)


def assert_matrix(m: list[list[int]], *, rows: int | None = None, cols: int | None = None) -> None:
    if rows is not None and len(m) != rows:
        raise ValueError(f"expected {rows} rows, got {len(m)}")
    if len(m) == 0:
        if cols not in (None, 0):
            raise ValueError("empty matrix has 0 columns")
        return
    width = len(m[0])
    if cols is not None and width != cols:
        raise ValueError(f"expected {cols} cols, got {width}")
    for r in m:
        if len(r) != width:
            raise ValueError("ragged matrix")
        assert_bits(r)


def hamming_weight(v: list[int]) -> int:
    assert_bits(v)
    return sum(v)


def gf2_identity(n: int) -> list[list[int]]:
    if n < 0:
        raise ValueError("n must be non-negative")
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def gf2_row_vec_mul_mat(v: list[int], m: list[list[int]]) -> list[int]:
    assert_bits(v)
    assert_matrix(m)
    if len(m) != len(v):
        raise ValueError("dimension mismatch for row_vec_mul_mat")
    if len(m) == 0:
        return []
    out = [0] * len(m[0])
    for i, vi in enumerate(v):
        if vi == 0:
            continue
        row = m[i]
        for j, aij in enumerate(row):
            out[j] ^= aij
    return out


def gf2_mat_vec_mul(m: list[list[int]], v: list[int]) -> list[int]:
    assert_matrix(m)
    assert_bits(v)
    if len(m) == 0:
        return []
    if len(m[0]) != len(v):
        raise ValueError("dimension mismatch for mat_vec_mul")
    out = []
    for row in m:
        acc = 0
        for aij, vj in zip(row, v, strict=True):
            acc ^= (aij & vj)
        out.append(acc)
    return out


def gf2_mat_mul(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    assert_matrix(a)
    assert_matrix(b)
    if len(a) == 0:
        return []
    if len(b) == 0:
        raise ValueError("cannot multiply by empty matrix with unknown column count")
    if len(a[0]) != len(b):
        raise ValueError("dimension mismatch for mat_mul")

    rows = len(a)
    inner = len(b)
    cols = len(b[0])
    out = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        for k in range(inner):
            if a[i][k] == 0:
                continue
            bk = b[k]
            for j in range(cols):
                out[i][j] ^= bk[j]
    return out


def gf2_matrix_inv(a: list[list[int]]) -> list[list[int]]:
    assert_matrix(a)
    n = len(a)
    if n == 0:
        return []
    if len(a[0]) != n:
        raise ValueError("matrix must be square to invert")

    left = [row[:] for row in a]
    right = gf2_identity(n)

    col = 0
    for row in range(n):
        pivot = None
        for r in range(row, n):
            if left[r][col] == 1:
                pivot = r
                break
        while pivot is None:
            col += 1
            if col >= n:
                raise ValueError("matrix is not invertible over GF(2)")
            for r in range(row, n):
                if left[r][col] == 1:
                    pivot = r
                    break

        if pivot != row:
            left[row], left[pivot] = left[pivot], left[row]
            right[row], right[pivot] = right[pivot], right[row]

        for r in range(n):
            if r == row:
                continue
            if left[r][col] == 1:
                for j in range(n):
                    left[r][j] ^= left[row][j]
                    right[r][j] ^= right[row][j]

        col += 1

    if left != gf2_identity(n):
        raise ValueError("matrix inversion failed")
    return right


def invert_permutation(perm: list[int]) -> list[int]:
    n = len(perm)
    inv = [0] * n
    seen = [False] * n
    for i, p in enumerate(perm):
        if not (0 <= p < n):
            raise ValueError("permutation entries must be in range")
        if seen[p]:
            raise ValueError("permutation has duplicates")
        seen[p] = True
        inv[p] = i
    return inv


def apply_permutation(v: list[int], perm: list[int]) -> list[int]:
    assert_bits(v)
    if len(v) != len(perm):
        raise ValueError("dimension mismatch for apply_permutation")
    return [v[p] for p in perm]


def apply_permutation_to_columns(m: list[list[int]], perm: list[int]) -> list[list[int]]:
    assert_matrix(m)
    if len(m) == 0:
        return []
    if len(m[0]) != len(perm):
        raise ValueError("dimension mismatch for apply_permutation_to_columns")
    out = []
    for row in m:
        out.append([row[p] for p in perm])
    return out


HAMMING74_G: list[list[int]] = [
    [1, 1, 1, 0, 0, 0, 0],
    [1, 0, 0, 1, 1, 0, 0],
    [0, 1, 0, 1, 0, 1, 0],
    [1, 1, 0, 1, 0, 0, 1],
]

HAMMING74_H: list[list[int]] = [
    [1, 0, 1, 0, 1, 0, 1],
    [0, 1, 1, 0, 0, 1, 1],
    [0, 0, 0, 1, 1, 1, 1],
]


def hamming74_encode(msg: list[int]) -> list[int]:
    assert_bits(msg, length=4)
    return gf2_row_vec_mul_mat(msg, HAMMING74_G)


def hamming74_syndrome(word: list[int]) -> list[int]:
    assert_bits(word, length=7)
    return gf2_mat_vec_mul(HAMMING74_H, word)


def _syndrome_to_position(syndrome: list[int]) -> int:
    assert_bits(syndrome, length=3)
    return syndrome[0] + 2 * syndrome[1] + 4 * syndrome[2]


def hamming_distance(a: list[int], b: list[int]) -> int:
    assert_bits(a)
    assert_bits(b)
    if len(a) != len(b):
        raise ValueError("dimension mismatch for hamming_distance")
    return sum((x ^ y) for x, y in zip(a, b, strict=True))


def hamming74_decode_nearest(received: list[int], *, t: int = 1) -> list[int]:
    assert_bits(received, length=7)
    if t < 0:
        raise ValueError("t must be non-negative")

    best_msg: list[int] | None = None
    best_dist: int | None = None
    ties = 0
    for m in range(16):
        msg = [(m >> 3) & 1, (m >> 2) & 1, (m >> 1) & 1, m & 1]
        codeword = hamming74_encode(msg)
        dist = hamming_distance(codeword, received)
        if best_dist is None or dist < best_dist:
            best_dist = dist
            best_msg = msg
            ties = 1
        elif dist == best_dist:
            ties += 1

    if best_msg is None or best_dist is None:
        raise ValueError("decode failed")
    if ties != 1:
        raise ValueError("decode is ambiguous")
    if best_dist > t:
        raise ValueError("too many errors to correct")
    return best_msg


@dataclass(frozen=True)
class PublicKey:
    k: int
    n: int
    t: int
    g_pub: list[list[int]]


@dataclass(frozen=True)
class PrivateKey:
    k: int
    n: int
    t: int
    g_base: list[list[int]]
    s: list[list[int]]
    s_inv: list[list[int]]
    perm: list[int]
    perm_inv: list[int]


def _random_invertible_matrix(k: int, rng: Random) -> list[list[int]]:
    if k <= 0:
        raise ValueError("k must be positive")
    for _attempt in range(10_000):
        m = [[rng.randrange(2) for _ in range(k)] for _ in range(k)]
        try:
            gf2_matrix_inv(m)
        except ValueError:
            continue
        return m
    raise ValueError("failed to sample an invertible matrix")


def classic_mceliece_keygen_hamming74(*, rng: Random | None = None) -> tuple[PublicKey, PrivateKey]:
    if rng is None:
        rng = Random()

    g_base = [row[:] for row in HAMMING74_G]
    k = 4
    n = 7
    t = 1

    s = _random_invertible_matrix(k, rng)
    s_inv = gf2_matrix_inv(s)
    perm = list(range(n))
    rng.shuffle(perm)
    perm_inv = invert_permutation(perm)

    g_scrambled = gf2_mat_mul(s, g_base)
    g_pub = apply_permutation_to_columns(g_scrambled, perm)

    pub = PublicKey(k=k, n=n, t=t, g_pub=g_pub)
    priv = PrivateKey(k=k, n=n, t=t, g_base=g_base, s=s, s_inv=s_inv, perm=perm, perm_inv=perm_inv)
    return pub, priv


def classic_mceliece_keygen_hamming74_with_secrets(
    *, s: list[list[int]], perm: list[int]
) -> tuple[PublicKey, PrivateKey]:
    k = 4
    n = 7
    t = 1
    assert_matrix(s, rows=k, cols=k)
    if len(perm) != n:
        raise ValueError("bad permutation length")

    s_inv = gf2_matrix_inv(s)
    perm_inv = invert_permutation(perm)
    g_base = [row[:] for row in HAMMING74_G]
    g_scrambled = gf2_mat_mul(s, g_base)
    g_pub = apply_permutation_to_columns(g_scrambled, perm)

    pub = PublicKey(k=k, n=n, t=t, g_pub=g_pub)
    priv = PrivateKey(k=k, n=n, t=t, g_base=g_base, s=s, s_inv=s_inv, perm=perm, perm_inv=perm_inv)
    return pub, priv


def classic_mceliece_encrypt(pub: PublicKey, msg: list[int], err: list[int]) -> list[int]:
    assert_bits(msg, length=pub.k)
    assert_bits(err, length=pub.n)
    if hamming_weight(err) > pub.t:
        raise ValueError("error weight exceeds decoder capability t")
    codeword = gf2_row_vec_mul_mat(msg, pub.g_pub)
    return [c ^ e for c, e in zip(codeword, err, strict=True)]


def classic_mceliece_decrypt(priv: PrivateKey, ct: list[int]) -> list[int]:
    assert_bits(ct, length=priv.n)
    ct_unperm = apply_permutation(ct, priv.perm_inv)
    u = hamming74_decode_nearest(ct_unperm, t=priv.t)
    msg = gf2_row_vec_mul_mat(u, priv.s_inv)
    assert_bits(msg, length=priv.k)
    return msg


def bits_to_str(v: list[int]) -> str:
    assert_bits(v)
    return "".join(str(b) for b in v)


def _print_matrix(name: str, m: list[list[int]]) -> None:
    print(f"{name} =")
    for row in m:
        print("  " + bits_to_str(row))


def main() -> None:
    print("=== Step 1: GF(2) linear algebra ===")
    a = [
        [1, 0, 1, 1],
        [1, 1, 0, 1],
        [0, 1, 1, 1],
        [1, 0, 0, 1],
    ]
    a_inv = gf2_matrix_inv(a)
    _print_matrix("A", a)
    _print_matrix("A_inv", a_inv)
    _print_matrix("A*A_inv", gf2_mat_mul(a, a_inv))

    print("\n=== Step 2: Hamming(7,4) as the secret decodable code ===")
    msg = [1, 0, 1, 1]
    cw = hamming74_encode(msg)
    print(f"msg      = {bits_to_str(msg)}")
    print(f"codeword = {bits_to_str(cw)}")
    err = [0, 0, 0, 0, 1, 0, 0]
    r = [c ^ e for c, e in zip(cw, err, strict=True)]
    print(f"error    = {bits_to_str(err)} (weight={hamming_weight(err)})")
    print(f"received = {bits_to_str(r)} syndrome={bits_to_str(hamming74_syndrome(r))}")
    decoded = hamming74_decode_nearest(r, t=1)
    print(f"decoded  = {bits_to_str(decoded)}")

    print("\n=== Step 3: Hide the structure (S and permutation) ===")
    s = [
        [1, 0, 0, 1],
        [1, 0, 1, 0],
        [0, 1, 0, 1],
        [1, 0, 1, 1],
    ]
    perm = [2, 4, 6, 0, 1, 3, 5]
    pub, priv = classic_mceliece_keygen_hamming74_with_secrets(s=s, perm=perm)
    _print_matrix("G_base", priv.g_base)
    _print_matrix("S", priv.s)
    print(f"perm     = {perm}")
    _print_matrix("G_pub", pub.g_pub)

    print("\n=== Step 4: Encrypt / decrypt (toy Classic McEliece) ===")
    msg2 = [1, 1, 0, 1]
    err2 = [0, 0, 0, 1, 0, 0, 0]
    ct = classic_mceliece_encrypt(pub, msg2, err2)
    pt = classic_mceliece_decrypt(priv, ct)
    print(f"msg      = {bits_to_str(msg2)}")
    print(f"err      = {bits_to_str(err2)} (weight={hamming_weight(err2)})")
    print(f"ct       = {bits_to_str(ct)}")
    print(f"dec(msg) = {bits_to_str(pt)}")

    bad_err = [1, 0, 0, 1, 0, 0, 0]
    try:
        _ = classic_mceliece_encrypt(pub, msg2, bad_err)
    except ValueError as exc:
        print(f"encrypt with bad err rejected: {exc}")


if __name__ == "__main__":
    main()
