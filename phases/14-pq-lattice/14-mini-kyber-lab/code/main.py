"""
Mini Kyber (toy) lab.

Implements a tiny Kyber-like public-key encryption scheme over the negacyclic
ring R_q = Z_q[x] / (x^N + 1) with small demo parameters (N=8, k=2).

Run:
  python3 code/main.py
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import List, Sequence, Tuple

N = 8
Q = 3329
K = 2
ETA = 2


Poly = List[int]
PolyVec = List[Poly]
PolyMat = List[List[Poly]]


def _shake256(data: bytes, outlen: int) -> bytes:
    if outlen < 0:
        raise ValueError("outlen must be >= 0")
    return hashlib.shake_256(data).digest(outlen)


def prg(seed: bytes, domain: bytes, nonce: int, outlen: int) -> bytes:
    if not (0 <= nonce < 2**16):
        raise ValueError("nonce must fit in 16 bits")
    return _shake256(seed + domain + nonce.to_bytes(2, "little"), outlen)


def mod_q(x: int, q: int = Q) -> int:
    return x % q


def poly_reduce(a: Sequence[int], q: int = Q) -> Poly:
    if len(a) != N:
        raise ValueError(f"poly must have length {N}")
    return [x % q for x in a]


def poly_add(a: Sequence[int], b: Sequence[int], q: int = Q) -> Poly:
    if len(a) != N or len(b) != N:
        raise ValueError(f"polys must have length {N}")
    return [(x + y) % q for x, y in zip(a, b)]


def poly_sub(a: Sequence[int], b: Sequence[int], q: int = Q) -> Poly:
    if len(a) != N or len(b) != N:
        raise ValueError(f"polys must have length {N}")
    return [(x - y) % q for x, y in zip(a, b)]


def poly_mul_negacyclic(a: Sequence[int], b: Sequence[int], q: int = Q) -> Poly:
    if len(a) != N or len(b) != N:
        raise ValueError(f"polys must have length {N}")

    tmp = [0] * (2 * N - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            tmp[i + j] += ai * bj

    out = [0] * N
    for k, val in enumerate(tmp):
        if k < N:
            out[k] += val
        else:
            out[k - N] -= val
    return [x % q for x in out]


def vec_add(v: Sequence[Sequence[int]], w: Sequence[Sequence[int]], q: int = Q) -> PolyVec:
    if len(v) != K or len(w) != K:
        raise ValueError(f"vectors must have length {K}")
    return [poly_add(v[i], w[i], q=q) for i in range(K)]


def vec_sub(v: Sequence[Sequence[int]], w: Sequence[Sequence[int]], q: int = Q) -> PolyVec:
    if len(v) != K or len(w) != K:
        raise ValueError(f"vectors must have length {K}")
    return [poly_sub(v[i], w[i], q=q) for i in range(K)]


def mat_vec_mul(a: PolyMat, s: Sequence[Sequence[int]], q: int = Q) -> PolyVec:
    if len(a) != K or any(len(row) != K for row in a):
        raise ValueError(f"matrix must be {K}x{K}")
    if len(s) != K:
        raise ValueError(f"vector must have length {K}")

    out: PolyVec = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = poly_add(acc, poly_mul_negacyclic(a[i][j], s[j], q=q), q=q)
        out.append(acc)
    return out


def mat_t_vec_mul(a: PolyMat, r: Sequence[Sequence[int]], q: int = Q) -> PolyVec:
    if len(a) != K or any(len(row) != K for row in a):
        raise ValueError(f"matrix must be {K}x{K}")
    if len(r) != K:
        raise ValueError(f"vector must have length {K}")

    out: PolyVec = []
    for i in range(K):
        acc = [0] * N
        for j in range(K):
            acc = poly_add(acc, poly_mul_negacyclic(a[j][i], r[j], q=q), q=q)
        out.append(acc)
    return out


def vec_dot(v: Sequence[Sequence[int]], w: Sequence[Sequence[int]], q: int = Q) -> Poly:
    if len(v) != K or len(w) != K:
        raise ValueError(f"vectors must have length {K}")
    acc = [0] * N
    for i in range(K):
        acc = poly_add(acc, poly_mul_negacyclic(v[i], w[i], q=q), q=q)
    return acc


def _bytes_to_bits_le(data: bytes) -> List[int]:
    return [(b >> i) & 1 for b in data for i in range(8)]


def sample_cbd_poly(seed: bytes, nonce: int, eta: int = ETA, n: int = N) -> Poly:
    if eta <= 0:
        raise ValueError("eta must be >= 1")
    if n <= 0:
        raise ValueError("n must be >= 1")
    nbits = 2 * eta * n
    nbytes = (nbits + 7) // 8
    raw = prg(seed, b"|N|", nonce, nbytes)
    bits = _bytes_to_bits_le(raw)[:nbits]

    out: Poly = []
    idx = 0
    for _ in range(n):
        a = sum(bits[idx : idx + eta])
        idx += eta
        b = sum(bits[idx : idx + eta])
        idx += eta
        out.append((a - b) % Q)
    if len(out) != N:
        raise ValueError("internal error: unexpected cbd length")
    return out


def sample_uniform_poly(seed: bytes, nonce: int, n: int = N, q: int = Q) -> Poly:
    raw = prg(seed, b"|A|", nonce, 2 * n)
    out = [int.from_bytes(raw[2 * i : 2 * i + 2], "little") % q for i in range(n)]
    if len(out) != N:
        raise ValueError("internal error: unexpected uniform length")
    return out


def gen_matrix(seed_a: bytes) -> PolyMat:
    a: PolyMat = []
    nonce = 0
    for _ in range(K):
        row: List[Poly] = []
        for _ in range(K):
            row.append(sample_uniform_poly(seed_a, nonce))
            nonce += 1
        a.append(row)
    return a


def gen_noise_vec(seed: bytes, start_nonce: int) -> PolyVec:
    return [sample_cbd_poly(seed, start_nonce + i) for i in range(K)]


def gen_noise_poly(seed: bytes, nonce: int) -> Poly:
    return sample_cbd_poly(seed, nonce)


def msg_to_poly(m: int) -> Poly:
    if not (0 <= m < 2**N):
        raise ValueError(f"message must fit in {N} bits")
    half = (Q + 1) // 2
    return [half if ((m >> i) & 1) else 0 for i in range(N)]


def poly_to_msg(p: Sequence[int]) -> int:
    if len(p) != N:
        raise ValueError(f"poly must have length {N}")
    lo = Q // 4
    hi = (3 * Q) // 4
    out = 0
    for i, c in enumerate(p):
        c = c % Q
        bit = 1 if (lo <= c < hi) else 0
        out |= bit << i
    return out


@dataclass(frozen=True)
class PublicKey:
    seed_a: bytes
    t: PolyVec


@dataclass(frozen=True)
class SecretKey:
    s: PolyVec


@dataclass(frozen=True)
class Ciphertext:
    u: PolyVec
    v: Poly


def keygen(master_seed: bytes) -> Tuple[PublicKey, SecretKey]:
    if len(master_seed) < 16:
        raise ValueError("master_seed must be at least 16 bytes")

    seed_a = _shake256(b"A" + master_seed, 32)
    seed_n = _shake256(b"N" + master_seed, 32)

    a = gen_matrix(seed_a)
    s = gen_noise_vec(seed_n, 0)
    e = gen_noise_vec(seed_n, K)
    t = vec_add(mat_vec_mul(a, s), e)
    return PublicKey(seed_a=seed_a, t=t), SecretKey(s=s)


def encrypt(pk: PublicKey, m: int, coins: bytes) -> Ciphertext:
    if len(coins) < 16:
        raise ValueError("coins must be at least 16 bytes")
    a = gen_matrix(pk.seed_a)

    seed_r = _shake256(b"R" + coins, 32)
    r = gen_noise_vec(seed_r, 0)
    e1 = gen_noise_vec(seed_r, K)
    e2 = gen_noise_poly(seed_r, 2 * K)

    u = vec_add(mat_t_vec_mul(a, r), e1)
    v = poly_add(vec_dot(pk.t, r), poly_add(e2, msg_to_poly(m)))
    return Ciphertext(u=u, v=v)


def decrypt(sk: SecretKey, ct: Ciphertext) -> int:
    m_poly = poly_sub(ct.v, vec_dot(sk.s, ct.u))
    return poly_to_msg(m_poly)


def compress_coeff(x: int, d: int, q: int = Q) -> int:
    if d <= 0 or d > 12:
        raise ValueError("d must be in 1..12 for this demo")
    x = x % q
    t = ((x << d) + (q // 2)) // q
    return t & ((1 << d) - 1)


def decompress_coeff(t: int, d: int, q: int = Q) -> int:
    if d <= 0 or d > 12:
        raise ValueError("d must be in 1..12 for this demo")
    t &= (1 << d) - 1
    return ((t * q) + (1 << (d - 1))) >> d


def compress_poly(p: Sequence[int], d: int, q: int = Q) -> List[int]:
    if len(p) != N:
        raise ValueError(f"poly must have length {N}")
    return [compress_coeff(c, d=d, q=q) for c in p]


def decompress_poly(p: Sequence[int], d: int, q: int = Q) -> Poly:
    if len(p) != N:
        raise ValueError(f"poly must have length {N}")
    return [decompress_coeff(int(t), d=d, q=q) for t in p]


def pack_bits_le(values: Sequence[int], bits: int) -> bytes:
    if bits <= 0 or bits > 16:
        raise ValueError("bits must be in 1..16")
    mask = (1 << bits) - 1
    acc = 0
    acc_bits = 0
    out = bytearray()
    for v in values:
        v &= mask
        acc |= v << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8
    if acc_bits:
        out.append(acc & 0xFF)
    return bytes(out)


def unpack_bits_le(data: bytes, count: int, bits: int) -> List[int]:
    if count < 0:
        raise ValueError("count must be >= 0")
    if bits <= 0 or bits > 16:
        raise ValueError("bits must be in 1..16")
    mask = (1 << bits) - 1
    acc = 0
    acc_bits = 0
    out: List[int] = []
    it = iter(data)
    while len(out) < count:
        while acc_bits < bits:
            try:
                b = next(it)
            except StopIteration as e:
                raise ValueError("not enough bytes to unpack") from e
            acc |= b << acc_bits
            acc_bits += 8
        out.append(acc & mask)
        acc >>= bits
        acc_bits -= bits
    return out


def _step_header(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    _step_header(1, "Negacyclic ring arithmetic (R_q = Z_q[x]/(x^N+1))")
    a = [1, 2, 3, 4, 0, 0, 0, 0]
    b = [0, 1, 0, 1, 0, 0, 0, 0]
    print("a =", a)
    print("b =", b)
    print("a+b mod q =", poly_add(a, b))
    print("a*b mod (x^N+1, q) =", poly_mul_negacyclic(a, b))
    print()

    _step_header(2, "Deterministic sampling: uniform A and small noise")
    seed_a = b"A" * 32
    a_mat = gen_matrix(seed_a)
    noise = sample_cbd_poly(b"N" * 32, nonce=0)
    print("A[0][0] =", a_mat[0][0])
    print("noise (CBD eta=2) =", [((x + Q // 2) % Q) - Q // 2 for x in noise])
    print()

    _step_header(3, "Mini Kyber-style PKE: keygen, encrypt, decrypt")
    pk, sk = keygen(b"this is a deterministic demo seed!!")
    m = 0b1010_1100
    ct = encrypt(pk, m=m, coins=b"coins for encryption (deterministic)")
    m2 = decrypt(sk, ct)
    print("message (bits as int) =", m)
    print("ciphertext.u[0] =", ct.u[0])
    print("ciphertext.v =", ct.v)
    print("decrypted message =", m2)
    print("roundtrip ok =", m == m2)
    print()

    _step_header(4, "Compression + bit-packing (toy serialization)")
    du, dv = 10, 4
    u0_comp = compress_poly(ct.u[0], d=du)
    u0_decomp = decompress_poly(u0_comp, d=du)
    print("compress(u[0]) =", u0_comp)
    print("decompress(compress(u[0])) =", u0_decomp)
    packed = pack_bits_le(u0_comp, bits=du)
    unpacked = unpack_bits_le(packed, count=N, bits=du)
    print("packed bytes (hex) =", packed.hex())
    print("unpacked =", unpacked)


if __name__ == "__main__":
    main()
