"""
FrodoKEM (toy) — LWE without rings.

This file implements a small, educational FrodoKEM-like KEM built from LWE
matrices. It is intentionally tiny (n=8) so you can read the whole thing.

Run:
  python3 code/main.py

WARNING: Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
from typing import Iterable, List, Sequence, Tuple


Matrix = List[List[int]]


@dataclass(frozen=True)
class FrodoParams:
    n: int
    nbar: int
    q: int
    B: int
    eta: int

    def mu_bytes(self) -> int:
        bits = self.B * self.nbar * self.nbar
        if bits % 8 != 0:
            raise ValueError("B * nbar^2 must be a multiple of 8")
        return bits // 8

    def validate(self) -> None:
        if self.q <= 2**self.B:
            raise ValueError("need 2^B <= q")
        if self.q & (self.q - 1) != 0:
            raise ValueError("this toy expects q as a power of two")
        if self.n % 8 != 0 or self.nbar % 8 != 0:
            raise ValueError("this toy expects n, nbar ≡ 0 (mod 8)")
        if self.eta <= 0:
            raise ValueError("eta must be positive")
        _ = self.mu_bytes()


DEFAULT_PARAMS = FrodoParams(n=8, nbar=8, q=1 << 15, B=2, eta=2)


@dataclass(frozen=True)
class FrodoPublicKey:
    seed_a: bytes
    b: Matrix  # n x nbar


@dataclass(frozen=True)
class FrodoSecretKey:
    pk: FrodoPublicKey
    s: Matrix  # n x nbar
    fail_seed: bytes


@dataclass(frozen=True)
class FrodoCiphertext:
    bprime: Matrix  # nbar x n
    c: Matrix  # nbar x nbar


def shake256(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def expand_seed(seed: bytes, label: bytes, outlen: int) -> bytes:
    return shake256(b"FRODO-TOY|" + label + b"|" + seed, outlen)


def _chunk_bits_le(buf: bytes) -> Iterable[int]:
    for byte in buf:
        for i in range(8):
            yield (byte >> i) & 1


def sample_cbd(seed: bytes, count: int, eta: int) -> List[int]:
    """
    Sample 'count' integers from a centered binomial distribution CBD_eta:
      e = sum_{i=1..eta}(a_i - b_i), with a_i,b_i ∈ {0,1} uniform.
    """

    needed_bits = count * 2 * eta
    needed_bytes = (needed_bits + 7) // 8
    stream = expand_seed(seed, b"CBD", needed_bytes)
    bits = _chunk_bits_le(stream)

    out: List[int] = []
    for _ in range(count):
        a = 0
        b = 0
        for _ in range(eta):
            a += next(bits)
        for _ in range(eta):
            b += next(bits)
        out.append(a - b)
    return out


def zeros(rows: int, cols: int) -> Matrix:
    return [[0 for _ in range(cols)] for _ in range(rows)]


def mat_add_mod_q(a: Matrix, b: Matrix, q: int) -> Matrix:
    rows = len(a)
    cols = len(a[0])
    out = zeros(rows, cols)
    for i in range(rows):
        for j in range(cols):
            out[i][j] = (a[i][j] + b[i][j]) % q
    return out


def mat_sub_mod_q(a: Matrix, b: Matrix, q: int) -> Matrix:
    rows = len(a)
    cols = len(a[0])
    out = zeros(rows, cols)
    for i in range(rows):
        for j in range(cols):
            out[i][j] = (a[i][j] - b[i][j]) % q
    return out


def mat_mul_mod_q(a: Matrix, b: Matrix, q: int) -> Matrix:
    rows = len(a)
    mid = len(a[0])
    cols = len(b[0])
    out = zeros(rows, cols)
    for i in range(rows):
        for k in range(mid):
            aik = a[i][k]
            for j in range(cols):
                out[i][j] = (out[i][j] + aik * b[k][j]) % q
    return out


def gen_matrix_a(seed_a: bytes, n: int, q: int) -> Matrix:
    """
    Deterministically expand seed_a into an n×n uniform matrix mod q.

    Real FrodoKEM uses careful generation; for this toy we exploit q=2^D and
    take 16-bit words mod q.
    """

    out = zeros(n, n)
    buf = expand_seed(seed_a, b"A", 2 * n * n)
    idx = 0
    for i in range(n):
        for j in range(n):
            word = buf[idx] | (buf[idx + 1] << 8)
            idx += 2
            out[i][j] = word % q
    return out


def sample_error_matrix(seed: bytes, rows: int, cols: int, eta: int) -> Matrix:
    samples = sample_cbd(seed, rows * cols, eta)
    out = zeros(rows, cols)
    idx = 0
    for i in range(rows):
        for j in range(cols):
            out[i][j] = samples[idx]
            idx += 1
    return out


def encode(mu: bytes, params: FrodoParams) -> Matrix:
    """
    Encode mu (B*nbar^2 bits) into an nbar×nbar matrix over Z_q.

    FrodoKEM's ec(k) is: ec(k) = k * q / 2^B.
    """

    params.validate()
    if len(mu) != params.mu_bytes():
        raise ValueError(f"mu must be exactly {params.mu_bytes()} bytes")

    step = params.q // (1 << params.B)
    out = zeros(params.nbar, params.nbar)

    bits = []
    for byte in mu:
        for i in range(8):
            bits.append((byte >> i) & 1)

    symbols: List[int] = []
    for i in range(0, len(bits), params.B):
        sym = 0
        for j in range(params.B):
            sym |= bits[i + j] << j
        symbols.append(sym)

    idx = 0
    for i in range(params.nbar):
        for j in range(params.nbar):
            out[i][j] = symbols[idx] * step
            idx += 1
    return out


def decode(m: Matrix, params: FrodoParams) -> bytes:
    """
    Decode an nbar×nbar matrix over Z_q back into mu.

    FrodoKEM's dc(c) is: dc(c) = round(c * 2^B / q) mod 2^B.
    """

    params.validate()
    if len(m) != params.nbar or len(m[0]) != params.nbar:
        raise ValueError("matrix must be nbar×nbar")

    mask = (1 << params.B) - 1
    bits: List[int] = []
    for i in range(params.nbar):
        for j in range(params.nbar):
            c = m[i][j] % params.q
            k = ((c * (1 << params.B) + (params.q // 2)) // params.q) & mask
            for t in range(params.B):
                bits.append((k >> t) & 1)

    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte |= bits[i + j] << j
        out.append(byte)
    return bytes(out)


def frodo_pke_keygen(seed: bytes, params: FrodoParams = DEFAULT_PARAMS) -> Tuple[FrodoPublicKey, FrodoSecretKey]:
    params.validate()

    seed_a = expand_seed(seed, b"seedA", 16)
    seed_se = expand_seed(seed, b"seedSE", 16)
    fail_seed = expand_seed(seed, b"fail", 16)

    a = gen_matrix_a(seed_a, params.n, params.q)
    s = sample_error_matrix(seed_se + b"|S", params.n, params.nbar, params.eta)
    e = sample_error_matrix(seed_se + b"|E", params.n, params.nbar, params.eta)

    b = mat_add_mod_q(mat_mul_mod_q(a, s, params.q), e, params.q)
    pk = FrodoPublicKey(seed_a=seed_a, b=b)
    sk = FrodoSecretKey(pk=pk, s=s, fail_seed=fail_seed)
    return pk, sk


def frodo_pke_encrypt(
    pk: FrodoPublicKey, mu: bytes, seed: bytes, params: FrodoParams = DEFAULT_PARAMS
) -> FrodoCiphertext:
    params.validate()

    a = gen_matrix_a(pk.seed_a, params.n, params.q)

    sprime = sample_error_matrix(seed + b"|S'", params.nbar, params.n, params.eta)
    eprime = sample_error_matrix(seed + b"|E'", params.nbar, params.n, params.eta)
    edprime = sample_error_matrix(seed + b"|E''", params.nbar, params.nbar, params.eta)

    bprime = mat_add_mod_q(mat_mul_mod_q(sprime, a, params.q), eprime, params.q)
    v = mat_add_mod_q(mat_mul_mod_q(sprime, pk.b, params.q), edprime, params.q)
    c = mat_add_mod_q(v, encode(mu, params), params.q)
    return FrodoCiphertext(bprime=bprime, c=c)


def frodo_pke_decrypt(ct: FrodoCiphertext, sk: FrodoSecretKey, params: FrodoParams = DEFAULT_PARAMS) -> bytes:
    params.validate()

    w = mat_sub_mod_q(ct.c, mat_mul_mod_q(ct.bprime, sk.s, params.q), params.q)
    return decode(w, params)


def kem_kdf(mu: bytes, ct: FrodoCiphertext) -> bytes:
    packed = serialize_ciphertext(ct)
    return shake256(b"KDF|" + mu + b"|" + packed, 32)


def serialize_matrix(m: Matrix) -> bytes:
    out = bytearray()
    for row in m:
        for x in row:
            out += int(x).to_bytes(2, "little", signed=False)
    return bytes(out)


def serialize_ciphertext(ct: FrodoCiphertext) -> bytes:
    return serialize_matrix(ct.bprime) + serialize_matrix(ct.c)


def frodo_encaps(pk: FrodoPublicKey, seed: bytes, params: FrodoParams = DEFAULT_PARAMS) -> Tuple[FrodoCiphertext, bytes]:
    params.validate()

    mu = expand_seed(seed, b"mu", params.mu_bytes())
    coins = expand_seed(mu + pk.seed_a, b"coins", 16)

    ct = frodo_pke_encrypt(pk, mu, coins, params)
    ss = kem_kdf(mu, ct)
    return ct, ss


def frodo_decaps(ct: FrodoCiphertext, sk: FrodoSecretKey, params: FrodoParams = DEFAULT_PARAMS) -> bytes:
    params.validate()

    mu_hat = frodo_pke_decrypt(ct, sk, params)
    coins_hat = expand_seed(mu_hat + sk.pk.seed_a, b"coins", 16)
    ct_hat = frodo_pke_encrypt(sk.pk, mu_hat, coins_hat, params)

    ok = hmac.compare_digest(serialize_ciphertext(ct_hat), serialize_ciphertext(ct))
    if ok:
        mu_final = mu_hat
    else:
        mu_final = expand_seed(sk.fail_seed + serialize_ciphertext(ct), b"failmu", params.mu_bytes())
    return kem_kdf(mu_final, ct)


def _format_small(m: Matrix, rows: int = 2, cols: int = 8) -> str:
    out = []
    for i in range(min(rows, len(m))):
        out.append("[" + ", ".join(f"{m[i][j]:5d}" for j in range(min(cols, len(m[i])))) + "]")
    return "\n".join(out)


def main() -> None:
    params = DEFAULT_PARAMS
    params.validate()

    seed = bytes.fromhex("00112233445566778899aabbccddeeff")

    print("=== Step 1: Deterministic matrix A (uniform mod q) ===")
    seed_a = expand_seed(seed, b"seedA", 16)
    a = gen_matrix_a(seed_a, params.n, params.q)
    print(f"q={params.q}, n={params.n}")
    print("A[0:2, 0:8] =")
    print(_format_small(a))

    print("\n=== Step 2: LWE public key (B = A*S + E mod q) ===")
    pk, sk = frodo_pke_keygen(seed, params)
    residual = mat_sub_mod_q(pk.b, mat_mul_mod_q(a, sk.s, params.q), params.q)
    centered = [[x if x < params.q // 2 else x - params.q for x in row] for row in residual]
    print("B[0:2, 0:8] =")
    print(_format_small(pk.b))
    print("E (recovered, centered) [0:2, 0:8] =")
    print(_format_small(centered))

    print("\n=== Step 3: CPA encryption with Encode/Decode ===")
    mu = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    coins = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    ct = frodo_pke_encrypt(pk, mu, coins, params)
    mu2 = frodo_pke_decrypt(ct, sk, params)
    print(f"mu      = {mu.hex()}")
    print(f"mu_hat  = {mu2.hex()}")
    print(f"decrypt ok? {mu2 == mu}")
    print("C[0:2, 0:8] =")
    print(_format_small(ct.c))

    print("\n=== Step 4: KEM (encaps/decaps + re-encrypt check) ===")
    ct_kem, ss1 = frodo_encaps(pk, seed=b"toy-encaps-seed", params=params)
    ss2 = frodo_decaps(ct_kem, sk, params)
    print(f"ss_encaps = {ss1.hex()}")
    print(f"ss_decaps = {ss2.hex()}")
    print(f"match? {ss1 == ss2}")

    tampered = FrodoCiphertext(
        bprime=[row[:] for row in ct_kem.bprime],
        c=[row[:] for row in ct_kem.c],
    )
    tampered.c[0][0] = (tampered.c[0][0] + 1) % params.q
    ss3 = frodo_decaps(tampered, sk, params)
    print(f"ss_decaps(tampered) = {ss3.hex()}")
    print(f"tamper changed key? {ss3 != ss2}")


if __name__ == "__main__":
    main()
