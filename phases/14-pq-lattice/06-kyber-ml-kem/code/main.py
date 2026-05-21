"""
Educational Kyber / ML-KEM (FIPS 203) walk-through in pure Python (stdlib only).

Run:
  python3 code/main.py

This script implements a compact, readable subset of ML-KEM-512-style building blocks:
- polynomial ring arithmetic in R_q = Z_q[X]/(X^N + 1)
- Kyber-style bit packing (ByteEncode/ByteDecode) and coefficient compression
- an IND-CPA PKE (K-PKE) and an IND-CCA KEM wrapper (ML-KEM) using an FO transform

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

Q = 3329
N = 256

MLKEM_512_K = 2
MLKEM_512_ETA1 = 3
MLKEM_512_ETA2 = 2
MLKEM_512_DU = 10
MLKEM_512_DV = 4

SEED_BYTES = 32
KEM_SEED_BYTES = 64
MESSAGE_BYTES = 32
SHARED_SECRET_BYTES = 32

MESSAGE_COEFF = (Q + 1) // 2


@dataclass(frozen=True)
class MlKemParams:
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int


MLKEM_512 = MlKemParams(
    k=MLKEM_512_K, eta1=MLKEM_512_ETA1, eta2=MLKEM_512_ETA2, du=MLKEM_512_DU, dv=MLKEM_512_DV
)


def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()


def _shake128(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_128(data).digest(outlen)


def _shake256(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def pack_bits(values: list[int], bits: int) -> bytes:
    if bits <= 0:
        raise ValueError("bits must be positive")
    mask = (1 << bits) - 1
    acc = 0
    acc_bits = 0
    out = bytearray()
    for v in values:
        if v < 0 or v > mask:
            raise ValueError("value out of range for packing")
        acc |= (v & mask) << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8
    if acc_bits:
        out.append(acc & 0xFF)
    return bytes(out)


def unpack_bits(data: bytes, bits: int, count: int) -> list[int]:
    if bits <= 0:
        raise ValueError("bits must be positive")
    if count < 0:
        raise ValueError("count must be non-negative")
    mask = (1 << bits) - 1
    acc = 0
    acc_bits = 0
    pos = 0
    out: list[int] = []
    for _ in range(count):
        while acc_bits < bits:
            if pos >= len(data):
                raise ValueError("not enough bytes to unpack requested count")
            acc |= data[pos] << acc_bits
            acc_bits += 8
            pos += 1
        out.append(acc & mask)
        acc >>= bits
        acc_bits -= bits
    return out


def compress_coeff(x: int, d: int) -> int:
    if not (1 <= d <= 12):
        raise ValueError("d must be in [1, 12]")
    x = x % Q
    return (((x << d) + Q // 2) // Q) & ((1 << d) - 1)


def decompress_coeff(y: int, d: int) -> int:
    if not (1 <= d <= 12):
        raise ValueError("d must be in [1, 12]")
    if y < 0 or y >= (1 << d):
        raise ValueError("compressed coefficient out of range")
    return ((y * Q) + (1 << (d - 1))) >> d


def _centered_mod_q(x: int) -> int:
    x %= Q
    if x > Q // 2:
        x -= Q
    return x


def poly_add(a: list[int], b: list[int]) -> list[int]:
    if len(a) != N or len(b) != N:
        raise ValueError("polynomials must have length N")
    return [(x + y) % Q for x, y in zip(a, b)]


def poly_sub(a: list[int], b: list[int]) -> list[int]:
    if len(a) != N or len(b) != N:
        raise ValueError("polynomials must have length N")
    return [(x - y) % Q for x, y in zip(a, b)]


def poly_mul(a: list[int], b: list[int]) -> list[int]:
    if len(a) != N or len(b) != N:
        raise ValueError("polynomials must have length N")
    acc = [0] * N
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            prod = ai * bj
            idx = i + j
            if idx < N:
                acc[idx] += prod
            else:
                acc[idx - N] -= prod
    return [x % Q for x in acc]


def polyvec_add(a: list[list[int]], b: list[list[int]], params: MlKemParams) -> list[list[int]]:
    if len(a) != params.k or len(b) != params.k:
        raise ValueError("polyvec length mismatch")
    return [poly_add(x, y) for x, y in zip(a, b)]


def polyvec_sub(a: list[list[int]], b: list[list[int]], params: MlKemParams) -> list[list[int]]:
    if len(a) != params.k or len(b) != params.k:
        raise ValueError("polyvec length mismatch")
    return [poly_sub(x, y) for x, y in zip(a, b)]


def mat_vec_mul(A: list[list[list[int]]], v: list[list[int]], params: MlKemParams) -> list[list[int]]:
    if len(A) != params.k or any(len(row) != params.k for row in A):
        raise ValueError("matrix shape mismatch")
    if len(v) != params.k:
        raise ValueError("vector length mismatch")
    out: list[list[int]] = []
    for i in range(params.k):
        acc = [0] * N
        for j in range(params.k):
            prod = poly_mul(A[i][j], v[j])
            acc = poly_add(acc, prod)
        out.append(acc)
    return out


def vec_dot(a: list[list[int]], b: list[list[int]], params: MlKemParams) -> list[int]:
    if len(a) != params.k or len(b) != params.k:
        raise ValueError("vector length mismatch")
    acc = [0] * N
    for x, y in zip(a, b):
        acc = poly_add(acc, poly_mul(x, y))
    return acc


def _prf(seed: bytes, nonce: int, outlen: int) -> bytes:
    if len(seed) != SEED_BYTES:
        raise ValueError("seed must be 32 bytes")
    if not (0 <= nonce <= 255):
        raise ValueError("nonce must be a byte")
    return _shake256(seed + bytes([nonce]), outlen)


def sample_uniform_poly(rho: bytes, i: int, j: int) -> list[int]:
    if len(rho) != SEED_BYTES:
        raise ValueError("rho must be 32 bytes")
    if not (0 <= i <= 255 and 0 <= j <= 255):
        raise ValueError("indices must fit in a byte")
    buf = _shake128(rho + bytes([j, i]), 4096)
    coeffs: list[int] = []
    pos = 0
    while len(coeffs) < N:
        if pos + 3 > len(buf):
            raise RuntimeError("unexpected rejection-sampling shortfall")
        b0 = buf[pos]
        b1 = buf[pos + 1]
        b2 = buf[pos + 2]
        pos += 3
        d1 = b0 | ((b1 & 0x0F) << 8)
        d2 = (b1 >> 4) | (b2 << 4)
        if d1 < Q:
            coeffs.append(d1)
            if len(coeffs) == N:
                break
        if d2 < Q:
            coeffs.append(d2)
    return coeffs


def gen_matrix(rho: bytes, params: MlKemParams, transpose: bool) -> list[list[list[int]]]:
    A: list[list[list[int]]] = []
    for i in range(params.k):
        row: list[list[int]] = []
        for j in range(params.k):
            if transpose:
                row.append(sample_uniform_poly(rho, j, i))
            else:
                row.append(sample_uniform_poly(rho, i, j))
        A.append(row)
    return A


def sample_cbd_poly(seed: bytes, nonce: int, eta: int) -> list[int]:
    if eta <= 0:
        raise ValueError("eta must be positive")
    needed_bits = 2 * eta * N
    needed_bytes = (needed_bits + 7) // 8
    buf = _prf(seed, nonce, needed_bytes)
    bit_pos = 0
    out: list[int] = []
    for _ in range(N):
        a = 0
        b = 0
        for _ in range(eta):
            byte = buf[bit_pos >> 3]
            a += (byte >> (bit_pos & 7)) & 1
            bit_pos += 1
        for _ in range(eta):
            byte = buf[bit_pos >> 3]
            b += (byte >> (bit_pos & 7)) & 1
            bit_pos += 1
        out.append((a - b) % Q)
    return out


def byte_encode(d: int, values: list[int]) -> bytes:
    if not (1 <= d <= 12):
        raise ValueError("d must be in [1, 12]")
    for v in values:
        if v < 0 or v >= (1 << d):
            raise ValueError("value out of range for ByteEncode")
    return pack_bits(values, d)


def byte_decode(d: int, data: bytes, count: int) -> list[int]:
    if not (1 <= d <= 12):
        raise ValueError("d must be in [1, 12]")
    values = unpack_bits(data, d, count)
    for v in values:
        if v < 0 or v >= (1 << d):
            raise ValueError("decoded value out of range")
    return values


def poly_to_bytes(poly: list[int]) -> bytes:
    if len(poly) != N:
        raise ValueError("polynomial must have length N")
    for c in poly:
        if c < 0 or c >= Q:
            raise ValueError("coefficient out of range for encode12")
    return byte_encode(12, poly)


def poly_from_bytes(data: bytes) -> list[int]:
    expected_len = (12 * N + 7) // 8
    if len(data) != expected_len:
        raise ValueError("wrong poly length for decode12")
    vals = byte_decode(12, data, N)
    return [v % Q for v in vals]


def polyvec_to_bytes(vec: list[list[int]], params: MlKemParams) -> bytes:
    if len(vec) != params.k:
        raise ValueError("polyvec length mismatch")
    out = bytearray()
    for poly in vec:
        out += poly_to_bytes(poly)
    return bytes(out)


def polyvec_from_bytes(data: bytes, params: MlKemParams) -> list[list[int]]:
    poly_len = (12 * N + 7) // 8
    expected_len = params.k * poly_len
    if len(data) != expected_len:
        raise ValueError("wrong polyvec length")
    out: list[list[int]] = []
    for i in range(params.k):
        start = i * poly_len
        out.append(poly_from_bytes(data[start : start + poly_len]))
    return out


def poly_compress_to_bytes(poly: list[int], d: int) -> bytes:
    if len(poly) != N:
        raise ValueError("polynomial must have length N")
    vals = [compress_coeff(c, d) for c in poly]
    return byte_encode(d, vals)


def poly_decompress_from_bytes(data: bytes, d: int) -> list[int]:
    expected_len = (d * N + 7) // 8
    if len(data) != expected_len:
        raise ValueError("wrong compressed polynomial length")
    vals = byte_decode(d, data, N)
    return [decompress_coeff(v, d) for v in vals]


def polyvec_compress_to_bytes(vec: list[list[int]], d: int, params: MlKemParams) -> bytes:
    if len(vec) != params.k:
        raise ValueError("polyvec length mismatch")
    out = bytearray()
    for poly in vec:
        out += poly_compress_to_bytes(poly, d)
    return bytes(out)


def polyvec_decompress_from_bytes(data: bytes, d: int, params: MlKemParams) -> list[list[int]]:
    poly_len = (d * N + 7) // 8
    expected_len = params.k * poly_len
    if len(data) != expected_len:
        raise ValueError("wrong compressed polyvec length")
    out: list[list[int]] = []
    for i in range(params.k):
        start = i * poly_len
        out.append(poly_decompress_from_bytes(data[start : start + poly_len], d))
    return out


def msg_to_poly(m: bytes) -> list[int]:
    if len(m) != MESSAGE_BYTES:
        raise ValueError("message must be 32 bytes")
    poly = [0] * N
    for i in range(N):
        bit = (m[i >> 3] >> (i & 7)) & 1
        poly[i] = MESSAGE_COEFF if bit else 0
    return poly


def poly_to_msg(poly: list[int]) -> bytes:
    if len(poly) != N:
        raise ValueError("polynomial must have length N")
    out = bytearray(MESSAGE_BYTES)
    for i in range(N):
        c = poly[i] % Q
        d0 = abs(_centered_mod_q(c))
        d1 = abs(_centered_mod_q(c - MESSAGE_COEFF))
        bit = 1 if d1 < d0 else 0
        out[i >> 3] |= bit << (i & 7)
    return bytes(out)


def kpke_keygen(seed_d: bytes, params: MlKemParams) -> tuple[bytes, bytes]:
    if len(seed_d) != SEED_BYTES:
        raise ValueError("seed_d must be 32 bytes")
    rho_sigma = _sha3_512(seed_d)
    rho = rho_sigma[:SEED_BYTES]
    sigma = rho_sigma[SEED_BYTES:]

    A = gen_matrix(rho, params, transpose=False)
    s = [sample_cbd_poly(sigma, nonce=i, eta=params.eta1) for i in range(params.k)]
    e = [sample_cbd_poly(sigma, nonce=params.k + i, eta=params.eta1) for i in range(params.k)]
    t = polyvec_add(mat_vec_mul(A, s, params), e, params)

    pk = polyvec_to_bytes(t, params) + rho
    sk = polyvec_to_bytes(s, params)
    return pk, sk


def kpke_encrypt(pk: bytes, m: bytes, coins: bytes, params: MlKemParams) -> bytes:
    if len(pk) != (12 * params.k * N) // 8 + SEED_BYTES:
        raise ValueError("bad public key length")
    if len(coins) != SEED_BYTES:
        raise ValueError("coins must be 32 bytes")
    t = polyvec_from_bytes(pk[: (12 * params.k * N) // 8], params)
    rho = pk[(12 * params.k * N) // 8 :]

    A_t = gen_matrix(rho, params, transpose=True)
    r = [sample_cbd_poly(coins, nonce=i, eta=params.eta1) for i in range(params.k)]
    e1 = [sample_cbd_poly(coins, nonce=params.k + i, eta=params.eta2) for i in range(params.k)]
    e2 = sample_cbd_poly(coins, nonce=2 * params.k, eta=params.eta2)

    u = polyvec_add(mat_vec_mul(A_t, r, params), e1, params)
    v = poly_add(vec_dot(t, r, params), poly_add(e2, msg_to_poly(m)))

    c1 = polyvec_compress_to_bytes(u, params.du, params)
    c2 = poly_compress_to_bytes(v, params.dv)
    return c1 + c2


def kpke_decrypt(sk: bytes, ct: bytes, params: MlKemParams) -> bytes:
    sk_len = (12 * params.k * N) // 8
    if len(sk) != sk_len:
        raise ValueError("bad secret key length")
    c1_len = (params.du * params.k * N) // 8
    c2_len = (params.dv * N) // 8
    if len(ct) != c1_len + c2_len:
        raise ValueError("bad ciphertext length")

    s = polyvec_from_bytes(sk, params)
    u = polyvec_decompress_from_bytes(ct[:c1_len], params.du, params)
    v = poly_decompress_from_bytes(ct[c1_len:], params.dv)

    w = poly_sub(v, vec_dot(s, u, params))
    return poly_to_msg(w)


def ml_kem_keygen(seed: bytes | None, params: MlKemParams) -> tuple[bytes, bytes]:
    if seed is None:
        seed = os.urandom(KEM_SEED_BYTES)
    if len(seed) != KEM_SEED_BYTES:
        raise ValueError("seed must be 64 bytes")
    d = seed[:SEED_BYTES]
    z = seed[SEED_BYTES:]
    ek, dk_pke = kpke_keygen(d, params)
    dk = dk_pke + ek + _sha3_256(ek) + z
    return ek, dk


def ml_kem_encaps(ek: bytes, seed: bytes | None, params: MlKemParams) -> tuple[bytes, bytes]:
    if len(ek) != (12 * params.k * N) // 8 + SEED_BYTES:
        raise ValueError("bad encapsulation key length")
    if seed is None:
        seed = os.urandom(SEED_BYTES)
    if len(seed) != SEED_BYTES:
        raise ValueError("encapsulation seed must be 32 bytes")

    m = _sha3_256(seed)
    k_r = _sha3_512(m + _sha3_256(ek))
    k_bar = k_r[:SEED_BYTES]
    coins = k_r[SEED_BYTES:]
    ct = kpke_encrypt(ek, m, coins, params)
    ss = _shake256(k_bar + _sha3_256(ct), SHARED_SECRET_BYTES)
    return ct, ss


def ml_kem_decaps(dk: bytes, ct: bytes, params: MlKemParams) -> bytes:
    dk_pke_len = (12 * params.k * N) // 8
    ek_len = (12 * params.k * N) // 8 + SEED_BYTES
    expected_dk_len = dk_pke_len + ek_len + 32 + 32
    if len(dk) != expected_dk_len:
        raise ValueError("bad decapsulation key length")

    dk_pke = dk[:dk_pke_len]
    ek = dk[dk_pke_len : dk_pke_len + ek_len]
    z = dk[-SEED_BYTES:]

    m = kpke_decrypt(dk_pke, ct, params)
    k_r = _sha3_512(m + _sha3_256(ek))
    k_bar = k_r[:SEED_BYTES]
    coins = k_r[SEED_BYTES:]

    ct_check = kpke_encrypt(ek, m, coins, params)
    if ct_check == ct:
        key = k_bar
    else:
        key = z
    return _shake256(key + _sha3_256(ct), SHARED_SECRET_BYTES)


def _hex(b: bytes, n: int = 16) -> str:
    if len(b) <= n:
        return b.hex()
    return b[:n].hex() + "…"


def main() -> None:
    params = MLKEM_512

    print(f"Using params: k={params.k} n={N} q={Q} eta1={params.eta1} eta2={params.eta2} du={params.du} dv={params.dv}")

    print("\n=== Step 1: Pack bits + Compress coefficients ===")
    xs = [0, 1, 2, 3]
    packed = pack_bits(xs, 2)
    unpacked = unpack_bits(packed, 2, len(xs))
    print("pack_bits([0,1,2,3], 2) =", packed.hex())
    print("unpack_bits(..., 2, 4)  =", unpacked)
    sample = 1234
    c = compress_coeff(sample, params.dv)
    d = decompress_coeff(c, params.dv)
    print(f"compress/decompress: x={sample} -> {c} -> {d}")

    print("\n=== Step 2: Sample A uniformly + Sample CBD noise ===")
    rho = bytes.fromhex("00" * 32)
    A00 = sample_uniform_poly(rho, 0, 0)
    print("A[0][0] first 8 coeffs:", A00[:8])
    sigma = bytes.fromhex("11" * 32)
    e0 = sample_cbd_poly(sigma, nonce=0, eta=params.eta1)
    print("CBD eta1 noise first 8 centered coeffs:", [_centered_mod_q(x) for x in e0[:8]])

    print("\n=== Step 3: K-PKE (KeyGen / Encrypt / Decrypt) ===")
    seed_d = bytes.fromhex("22" * 32)
    pk, sk = kpke_keygen(seed_d, params)
    msg = bytes.fromhex("33" * 32)
    coins = bytes.fromhex("44" * 32)
    ct = kpke_encrypt(pk, msg, coins, params)
    msg2 = kpke_decrypt(sk, ct, params)
    print("pk bytes:", len(pk), "ct bytes:", len(ct), "sk bytes:", len(sk))
    print("msg :", _hex(msg, 32))
    print("msg':", _hex(msg2, 32))
    print("decrypt ok:", msg2 == msg)

    print("\n=== Step 4: ML-KEM (KeyGen / Encaps / Decaps) ===")
    kem_seed = bytes.fromhex("55" * 64)
    ek, dk = ml_kem_keygen(kem_seed, params)
    ct2, ss1 = ml_kem_encaps(ek, seed=bytes.fromhex("66" * 32), params=params)
    ss2 = ml_kem_decaps(dk, ct2, params)
    print("ek bytes:", len(ek), "dk bytes:", len(dk), "ct bytes:", len(ct2))
    print("ss(encaps):", ss1.hex())
    print("ss(decaps):", ss2.hex())
    print("shared secret match:", ss1 == ss2)

    ct_bad = ct2[:-1] + bytes([ct2[-1] ^ 1])
    ss_bad = ml_kem_decaps(dk, ct_bad, params)
    print("tampered ct changes ss:", ss_bad != ss2)

if __name__ == "__main__":
    main()
