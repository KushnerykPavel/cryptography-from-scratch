"""
Toy McEliece from scratch (binary, GF(2)).

This lesson implements a minimal, fully-stdlib, "McEliece-shaped" public-key
encryption scheme:
- A tiny linear algebra toolkit over GF(2)
- A Hamming(7,4) linear code with 1-bit error correction (the "trapdoor")
- A McEliece-style public key G_pub = S · G · P that hides the code structure
- Encryption: c = m · G_pub ⊕ e
- Decryption: undo P, decode with the trapdoor to recover mS, then undo S

This is an educational implementation. It is not constant-time and not
production-safe.

Run:
  python3 phases/15-pq-code-hash-multivariate/01-mceliece/code/main.py
"""

from __future__ import annotations

import random
from typing import Any


def is_bit(x: int) -> bool:
    return x in (0, 1)


def assert_binary_vector(v: list[int], *, name: str = "vector") -> None:
    if not isinstance(v, list):
        raise TypeError(f"{name} must be a list[int]")
    if any(not isinstance(b, int) for b in v):
        raise TypeError(f"{name} must be a list[int]")
    if any(not is_bit(b) for b in v):
        raise ValueError(f"{name} must contain only 0/1")


def assert_binary_matrix(m: list[list[int]], *, name: str = "matrix") -> None:
    if not isinstance(m, list) or any(not isinstance(row, list) for row in m):
        raise TypeError(f"{name} must be a list[list[int]]")
    if len(m) == 0 or len(m[0]) == 0:
        raise ValueError(f"{name} must be non-empty")
    width = len(m[0])
    for row in m:
        if len(row) != width:
            raise ValueError(f"{name} must be rectangular")
        assert_binary_vector(row, name=name + " row")


def xor_vec(a: list[int], b: list[int]) -> list[int]:
    assert_binary_vector(a, name="a")
    assert_binary_vector(b, name="b")
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    return [x ^ y for x, y in zip(a, b)]


def mul_vec_mat_mod2(v: list[int], m: list[list[int]]) -> list[int]:
    assert_binary_vector(v, name="v")
    assert_binary_matrix(m, name="m")
    rows = len(m)
    cols = len(m[0])
    if len(v) != rows:
        raise ValueError("vector length must match number of matrix rows")

    out: list[int] = []
    for j in range(cols):
        s = 0
        for i in range(rows):
            s ^= (v[i] & m[i][j])
        out.append(s)
    return out


def mul_mat_vec_mod2(m: list[list[int]], v: list[int]) -> list[int]:
    assert_binary_matrix(m, name="m")
    assert_binary_vector(v, name="v")
    rows = len(m)
    cols = len(m[0])
    if len(v) != cols:
        raise ValueError("vector length must match number of matrix columns")

    out: list[int] = []
    for i in range(rows):
        s = 0
        for j in range(cols):
            s ^= (m[i][j] & v[j])
        out.append(s)
    return out


def mul_mat_mat_mod2(a: list[list[int]], b: list[list[int]]) -> list[list[int]]:
    assert_binary_matrix(a, name="a")
    assert_binary_matrix(b, name="b")
    a_rows = len(a)
    a_cols = len(a[0])
    b_rows = len(b)
    b_cols = len(b[0])
    if a_cols != b_rows:
        raise ValueError("a columns must match b rows")

    out: list[list[int]] = []
    for i in range(a_rows):
        row: list[int] = []
        for j in range(b_cols):
            s = 0
            for k in range(a_cols):
                s ^= (a[i][k] & b[k][j])
            row.append(s)
        out.append(row)
    return out


def identity_matrix(n: int) -> list[list[int]]:
    if n <= 0:
        raise ValueError("n must be positive")
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def invert_matrix_mod2(a: list[list[int]]) -> list[list[int]]:
    assert_binary_matrix(a, name="a")
    n = len(a)
    if len(a[0]) != n:
        raise ValueError("a must be square")

    aug = [row[:] + identity_row[:] for row, identity_row in zip(a, identity_matrix(n))]

    for col in range(n):
        pivot = None
        for r in range(col, n):
            if aug[r][col] == 1:
                pivot = r
                break
        if pivot is None:
            raise ValueError("matrix is singular over GF(2)")
        if pivot != col:
            aug[col], aug[pivot] = aug[pivot], aug[col]

        for r in range(n):
            if r != col and aug[r][col] == 1:
                aug[r] = xor_vec(aug[r], aug[col])

    inv = [row[n:] for row in aug]
    assert_binary_matrix(inv, name="inv")
    return inv


def apply_permutation(v: list[int], perm_new_to_old: list[int]) -> list[int]:
    assert_binary_vector(v, name="v")
    if not isinstance(perm_new_to_old, list) or any(not isinstance(i, int) for i in perm_new_to_old):
        raise TypeError("perm must be a list[int]")
    if len(perm_new_to_old) != len(v):
        raise ValueError("perm length must match vector length")
    if sorted(perm_new_to_old) != list(range(len(v))):
        raise ValueError("perm must be a permutation of 0..n-1")
    return [v[i] for i in perm_new_to_old]


def invert_permutation(perm_new_to_old: list[int]) -> list[int]:
    if not isinstance(perm_new_to_old, list) or any(not isinstance(i, int) for i in perm_new_to_old):
        raise TypeError("perm must be a list[int]")
    n = len(perm_new_to_old)
    if sorted(perm_new_to_old) != list(range(n)):
        raise ValueError("perm must be a permutation of 0..n-1")
    inv = [0] * n
    for new_idx, old_idx in enumerate(perm_new_to_old):
        inv[old_idx] = new_idx
    return inv


def permute_columns(m: list[list[int]], perm_new_to_old: list[int]) -> list[list[int]]:
    assert_binary_matrix(m, name="m")
    n = len(m[0])
    if len(perm_new_to_old) != n:
        raise ValueError("perm length must match number of columns")
    if sorted(perm_new_to_old) != list(range(n)):
        raise ValueError("perm must be a permutation of 0..n-1")
    out: list[list[int]] = []
    for row in m:
        out.append([row[i] for i in perm_new_to_old])
    return out


def random_permutation(n: int, rng: random.Random) -> list[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    perm = list(range(n))
    rng.shuffle(perm)
    return perm


def random_invertible_matrix(k: int, rng: random.Random) -> list[list[int]]:
    if k <= 0:
        raise ValueError("k must be positive")
    for _ in range(10_000):
        m = [[rng.getrandbits(1) for _ in range(k)] for _ in range(k)]
        try:
            invert_matrix_mod2(m)
            return m
        except ValueError:
            continue
    raise RuntimeError("failed to sample an invertible matrix")


def hamming74_matrices() -> tuple[list[list[int]], list[list[int]]]:
    g = [
        [1, 0, 0, 0, 1, 1, 0],
        [0, 1, 0, 0, 1, 0, 1],
        [0, 0, 1, 0, 0, 1, 1],
        [0, 0, 0, 1, 1, 1, 1],
    ]
    h = parity_check_matrix_from_systematic_g(g)
    return g, h


def parity_check_matrix_from_systematic_g(g: list[list[int]]) -> list[list[int]]:
    assert_binary_matrix(g, name="g")
    k = len(g)
    n = len(g[0])
    if n <= k:
        raise ValueError("need n > k to have parity symbols")

    for i in range(k):
        for j in range(k):
            expected = 1 if i == j else 0
            if g[i][j] != expected:
                raise ValueError("g is not systematic: expected left block to be identity")

    p = [row[k:] for row in g]
    r = n - k
    p_t = [list(col) for col in zip(*p)]
    i_r = [[1 if i == j else 0 for j in range(r)] for i in range(r)]
    return [p_t[i] + i_r[i] for i in range(r)]


def hamming74_encode(message_4: list[int]) -> list[int]:
    g, _ = hamming74_matrices()
    if len(message_4) != 4:
        raise ValueError("expected 4-bit message for Hamming(7,4)")
    return mul_vec_mat_mod2(message_4, g)


def hamming74_syndrome(received_7: list[int]) -> list[int]:
    _, h = hamming74_matrices()
    if len(received_7) != 7:
        raise ValueError("expected 7-bit received word for Hamming(7,4)")
    return mul_mat_vec_mod2(h, received_7)


def correct_single_bit_error_hamming74(received_7: list[int]) -> tuple[list[int], int | None]:
    if len(received_7) != 7:
        raise ValueError("expected 7-bit received word for Hamming(7,4)")
    s = hamming74_syndrome(received_7)
    if all(bit == 0 for bit in s):
        return received_7[:], None

    _, h = hamming74_matrices()
    columns = [list(col) for col in zip(*h)]
    try:
        idx = columns.index(s)
    except ValueError as e:
        raise ValueError("syndrome does not match any single-bit error pattern") from e

    corrected = received_7[:]
    corrected[idx] ^= 1
    return corrected, idx


def hamming74_decode_1error(received_7: list[int]) -> tuple[list[int], list[int], int | None]:
    assert_binary_vector(received_7, name="received_7")
    if len(received_7) != 7:
        raise ValueError("expected 7-bit received word for Hamming(7,4)")

    corrected, flipped = correct_single_bit_error_hamming74(received_7)
    message_4 = corrected[:4]
    if hamming74_encode(message_4) != corrected:
        raise ValueError("received word is not within 1 bit of a valid Hamming(7,4) codeword")
    return message_4, corrected, flipped


def random_error_vector(n: int, t: int, rng: random.Random) -> list[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    if t < 0 or t > n:
        raise ValueError("t must satisfy 0 <= t <= n")
    positions = rng.sample(range(n), k=t)
    e = [0] * n
    for idx in positions:
        e[idx] = 1
    return e


def mceliece_keygen_toy(rng: random.Random) -> tuple[dict[str, Any], dict[str, Any]]:
    g, _ = hamming74_matrices()
    s = random_invertible_matrix(4, rng)
    s_inv = invert_matrix_mod2(s)
    p = random_permutation(7, rng)
    p_inv = invert_permutation(p)

    g_pub = permute_columns(mul_mat_mat_mod2(s, g), p)
    public_key = {"G_pub": g_pub, "t": 1}
    secret_key = {"G": g, "S_inv": s_inv, "P_inv": p_inv, "t": 1}
    return public_key, secret_key


def mceliece_encrypt_toy(
    public_key: dict[str, Any],
    message_4: list[int],
    *,
    rng: random.Random | None = None,
    error_7: list[int] | None = None,
) -> list[int]:
    assert_binary_vector(message_4, name="message_4")
    if len(message_4) != 4:
        raise ValueError("expected 4-bit message")
    g_pub = public_key["G_pub"]
    t = int(public_key["t"])

    codeword_7 = mul_vec_mat_mod2(message_4, g_pub)
    if error_7 is None:
        if rng is None:
            raise ValueError("rng is required when error_7 is not provided")
        error_7 = random_error_vector(7, t, rng)
    assert_binary_vector(error_7, name="error_7")
    if len(error_7) != 7:
        raise ValueError("expected 7-bit error vector")
    if sum(error_7) > t:
        raise ValueError("error vector weight exceeds t")
    return xor_vec(codeword_7, error_7)


def mceliece_decrypt_toy(secret_key: dict[str, Any], ciphertext_7: list[int]) -> list[int]:
    assert_binary_vector(ciphertext_7, name="ciphertext_7")
    if len(ciphertext_7) != 7:
        raise ValueError("expected 7-bit ciphertext")

    t = int(secret_key["t"])
    if t != 1:
        raise ValueError("this toy decryptor only supports t=1")

    p_inv = secret_key["P_inv"]
    s_inv = secret_key["S_inv"]

    unpermuted_7 = apply_permutation(ciphertext_7, p_inv)
    msg_s, _corrected, _flipped = hamming74_decode_1error(unpermuted_7)
    message = mul_vec_mat_mod2(msg_s, s_inv)
    return message


def format_bits(v: list[int]) -> str:
    return "".join(str(b) for b in v)


def format_matrix(m: list[list[int]]) -> str:
    return "\n".join("[" + " ".join(str(x) for x in row) + "]" for row in m)


def main() -> int:
    rng = random.Random(12345)

    print("\n=== Step 1: GF(2) linear algebra (matrices as bits) ===\n")
    a = random_invertible_matrix(4, rng)
    a_inv = invert_matrix_mod2(a)
    prod = mul_mat_mat_mod2(a, a_inv)
    print("A:")
    print(format_matrix(a))
    print("\nA^{-1}:")
    print(format_matrix(a_inv))
    print("\nA · A^{-1}:")
    print(format_matrix(prod))

    print("\n=== Step 2: Hamming(7,4) encode + 1-bit decode ===\n")
    m = [1, 0, 1, 1]
    c = hamming74_encode(m)
    received = c[:]
    received[5] ^= 1
    print(f"message  m = {format_bits(m)}")
    print(f"codeword c = {format_bits(c)}")
    print(f"received r = {format_bits(received)}  (bit 5 flipped)")
    print(f"syndrome s = {format_bits(hamming74_syndrome(received))}")
    m2, corrected, flipped = hamming74_decode_1error(received)
    print(f"corrected  = {format_bits(corrected)}  (flipped index: {flipped})")
    print(f"decoded m  = {format_bits(m2)}")

    print("\n=== Step 3: McEliece-shaped public key G_pub = S · G · P ===\n")
    pk, sk = mceliece_keygen_toy(rng)
    print("Public key G_pub (4x7):")
    print(format_matrix(pk["G_pub"]))
    print("Note: to an attacker, this should look like a random linear code.")

    print("\n=== Step 4: Encrypt (add an error) and decrypt (correct it) ===\n")
    plaintext = [1, 1, 0, 1]
    ct = mceliece_encrypt_toy(pk, plaintext, rng=rng)
    recovered = mceliece_decrypt_toy(sk, ct)
    print(f"plaintext  = {format_bits(plaintext)}")
    print(f"ciphertext = {format_bits(ct)}")
    print(f"recovered  = {format_bits(recovered)}")

    print("\nTrying to decrypt with too many errors (t=1):")
    codeword_only = mul_vec_mat_mod2(plaintext, pk["G_pub"])
    too_noisy = xor_vec(codeword_only, [1, 1, 0, 0, 0, 0, 0])
    print(f"ciphertext = {format_bits(too_noisy)}  (weight(error)=2)")
    recovered2 = mceliece_decrypt_toy(sk, too_noisy)
    print(f"decrypted  = {format_bits(recovered2)}  (miscorrection is possible when wt(error) > t)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
