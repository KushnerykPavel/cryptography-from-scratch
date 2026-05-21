"""
Regev Encryption (toy, educational) built from LWE samples using stdlib-only math.

What this file does:
- Implements a tiny Regev-style public-key encryption scheme for bits.
- Shows how you can use "encrypt many bits" to build a KEM-DEM (hybrid encryption) toy.
- Demonstrates why parameters/noise matter and why production schemes use audited libraries.

How to run:
  python3 code/main.py

Important:
- Educational implementation. Not constant-time. Not production-safe.
- Uses small toy parameters and a deterministic SHA-256 counter-mode RNG for reproducibility.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from itertools import product
from typing import Iterable, Sequence


Vec = tuple[int, ...]
Matrix = list[list[int]]
CiphertextBit = tuple[Vec, int]


class Sha256CtrRng:
    def __init__(self, seed: bytes):
        if not isinstance(seed, (bytes, bytearray)):
            raise TypeError("seed must be bytes")
        if len(seed) == 0:
            raise ValueError("seed must be non-empty")
        self._seed = bytes(seed)
        self._ctr = 0
        self._buf = b""
        self._pos = 0

    def _refill(self) -> None:
        h = hashlib.sha256()
        h.update(self._seed)
        h.update(self._ctr.to_bytes(8, "big"))
        self._ctr += 1
        self._buf = h.digest()
        self._pos = 0

    def random_bytes(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        out = bytearray()
        while len(out) < n:
            if self._pos >= len(self._buf):
                self._refill()
            take = min(n - len(out), len(self._buf) - self._pos)
            out += self._buf[self._pos : self._pos + take]
            self._pos += take
        return bytes(out)

    def _randbits(self, k: int) -> int:
        if k < 0:
            raise ValueError("k must be non-negative")
        nbytes = (k + 7) // 8
        x = int.from_bytes(self.random_bytes(nbytes), "big")
        if k % 8:
            x &= (1 << k) - 1
        return x

    def randbelow(self, n: int) -> int:
        if n <= 0:
            raise ValueError("n must be positive")
        k = n.bit_length()
        while True:
            x = self._randbits(k)
            if x < n:
                return x


def _require_positive_int(name: str, x: int) -> None:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")
    if x <= 0:
        raise ValueError(f"{name} must be positive")


def _require_vec_dim(v: Vec, n: int, *, name: str) -> None:
    if len(v) != n:
        raise ValueError(f"{name} dimension mismatch")


def _require_matrix_dim(A: Matrix, m: int, n: int, *, name: str) -> None:
    if len(A) != m:
        raise ValueError(f"{name} row dimension mismatch")
    for row in A:
        if len(row) != n:
            raise ValueError(f"{name} column dimension mismatch")


def mod_q(x: int, q: int) -> int:
    _require_positive_int("q", q)
    return x % q


def center_lift(x: int, q: int) -> int:
    _require_positive_int("q", q)
    y = x % q
    half = q // 2
    if y > half:
        y -= q
    return y


def vec_add_mod(a: Vec, b: Vec, q: int) -> Vec:
    _require_vec_dim(a, len(b), name="a")
    return tuple((x + y) % q for x, y in zip(a, b))


def vec_sub_mod(a: Vec, b: Vec, q: int) -> Vec:
    _require_vec_dim(a, len(b), name="a")
    return tuple((x - y) % q for x, y in zip(a, b))


def dot_mod(a: Vec, b: Vec, q: int) -> int:
    _require_vec_dim(a, len(b), name="a")
    acc = 0
    for x, y in zip(a, b):
        acc += x * y
    return acc % q


def mat_vec_mul_mod(A: Matrix, x: Vec, q: int) -> Vec:
    _require_positive_int("q", q)
    m = len(A)
    if m == 0:
        raise ValueError("A must be non-empty")
    n = len(A[0])
    _require_matrix_dim(A, m, n, name="A")
    _require_vec_dim(x, n, name="x")
    out = []
    for i in range(m):
        out.append(dot_mod(tuple(A[i]), x, q))
    return tuple(out)


def mat_t_vec_mul_mod(A: Matrix, r: Vec, q: int) -> Vec:
    _require_positive_int("q", q)
    m = len(A)
    if m == 0:
        raise ValueError("A must be non-empty")
    n = len(A[0])
    _require_matrix_dim(A, m, n, name="A")
    _require_vec_dim(r, m, name="r")
    out = []
    for j in range(n):
        acc = 0
        for i in range(m):
            acc += A[i][j] * r[i]
        out.append(acc % q)
    return tuple(out)


def sample_uniform_vector(rng: Sha256CtrRng, n: int, q: int) -> Vec:
    _require_positive_int("n", n)
    _require_positive_int("q", q)
    return tuple(rng.randbelow(q) for _ in range(n))


def sample_uniform_matrix(rng: Sha256CtrRng, m: int, n: int, q: int) -> Matrix:
    _require_positive_int("m", m)
    _require_positive_int("n", n)
    _require_positive_int("q", q)
    return [[rng.randbelow(q) for _ in range(n)] for __ in range(m)]


def sample_ternary_vector(rng: Sha256CtrRng, n: int) -> Vec:
    _require_positive_int("n", n)
    return tuple(rng.randbelow(3) - 1 for _ in range(n))


def sample_binary_vector(rng: Sha256CtrRng, n: int) -> Vec:
    _require_positive_int("n", n)
    return tuple(rng.randbelow(2) for _ in range(n))


@dataclass(frozen=True)
class RegevParams:
    n: int
    m: int
    q: int
    error_bound: int = 1

    def validate(self) -> None:
        _require_positive_int("n", self.n)
        _require_positive_int("m", self.m)
        _require_positive_int("q", self.q)
        if self.q <= 2:
            raise ValueError("q must be >= 3")
        if self.error_bound < 0:
            raise ValueError("error_bound must be non-negative")


@dataclass(frozen=True)
class RegevPublicKey:
    A: Matrix
    b: Vec


@dataclass(frozen=True)
class RegevSecretKey:
    s: Vec


def regev_keygen(rng: Sha256CtrRng, params: RegevParams) -> tuple[RegevPublicKey, RegevSecretKey]:
    params.validate()
    A = sample_uniform_matrix(rng, params.m, params.n, params.q)
    s = sample_ternary_vector(rng, params.n)
    e = sample_ternary_vector(rng, params.m)
    As = mat_vec_mul_mod(A, s, params.q)
    b = vec_add_mod(As, e, params.q)
    return RegevPublicKey(A=A, b=b), RegevSecretKey(s=s)


def _circular_distance(a: int, b: int, q: int) -> int:
    d = (a - b) % q
    return min(d, (-d) % q)


def regev_encrypt_bit(
    rng: Sha256CtrRng,
    params: RegevParams,
    pk: RegevPublicKey,
    mu: int,
) -> CiphertextBit:
    params.validate()
    if mu not in (0, 1):
        raise ValueError("mu must be 0 or 1")
    _require_matrix_dim(pk.A, params.m, params.n, name="pk.A")
    _require_vec_dim(pk.b, params.m, name="pk.b")

    r = sample_binary_vector(rng, params.m)
    e1 = sample_ternary_vector(rng, params.n)
    e2 = rng.randbelow(3) - 1

    u0 = mat_t_vec_mul_mod(pk.A, r, params.q)
    u = vec_add_mod(u0, e1, params.q)
    v0 = dot_mod(r, pk.b, params.q)
    v = (v0 + e2 + mu * (params.q // 2)) % params.q
    return u, v


def regev_decrypt_bit(params: RegevParams, sk: RegevSecretKey, ct: CiphertextBit) -> int:
    params.validate()
    u, v = ct
    _require_vec_dim(u, params.n, name="u")
    _require_vec_dim(sk.s, params.n, name="sk.s")
    x = (v - dot_mod(u, sk.s, params.q)) % params.q
    d0 = _circular_distance(x, 0, params.q)
    d1 = _circular_distance(x, params.q // 2, params.q)
    return 0 if d0 < d1 else 1


def bits_from_bytes(data: bytes) -> list[int]:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes-like")
    out = []
    for b in data:
        for i in range(7, -1, -1):
            out.append((b >> i) & 1)
    return out


def bytes_from_bits(bits: Sequence[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        acc = 0
        for j in range(8):
            bit = bits[i + j]
            if bit not in (0, 1):
                raise ValueError("bits must be 0/1")
            acc = (acc << 1) | bit
        out.append(acc)
    return bytes(out)


class Sha256XorStream:
    def __init__(self, key: bytes, *, domain: bytes = b"regev-demo-stream-v1"):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes-like")
        if len(key) == 0:
            raise ValueError("key must be non-empty")
        self._key = bytes(key)
        self._domain = bytes(domain)

    def keystream(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        out = bytearray()
        ctr = 0
        while len(out) < n:
            h = hashlib.sha256()
            h.update(self._domain)
            h.update(self._key)
            h.update(ctr.to_bytes(8, "big"))
            out += h.digest()
            ctr += 1
        return bytes(out[:n])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("xor requires equal-length inputs")
    return bytes(x ^ y for x, y in zip(a, b))


def regev_encrypt_bits(
    rng: Sha256CtrRng,
    params: RegevParams,
    pk: RegevPublicKey,
    bits: Sequence[int],
) -> list[CiphertextBit]:
    out = []
    for bit in bits:
        if bit not in (0, 1):
            raise ValueError("bits must be 0/1")
        out.append(regev_encrypt_bit(rng, params, pk, bit))
    return out


def regev_decrypt_bits(params: RegevParams, sk: RegevSecretKey, cts: Sequence[CiphertextBit]) -> list[int]:
    return [regev_decrypt_bit(params, sk, ct) for ct in cts]


def hybrid_encrypt(
    rng: Sha256CtrRng,
    params: RegevParams,
    pk: RegevPublicKey,
    plaintext: bytes,
    *,
    key_len: int = 4,
) -> dict:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes-like")
    _require_positive_int("key_len", key_len)
    kem_key = rng.random_bytes(key_len)
    kem_bits = bits_from_bytes(kem_key)
    kem_ct = regev_encrypt_bits(rng, params, pk, kem_bits)

    stream = Sha256XorStream(kem_key)
    mask = stream.keystream(len(plaintext))
    ciphertext = xor_bytes(bytes(plaintext), mask)

    return {
        "kem_ct": kem_ct,
        "ciphertext": ciphertext,
        "key_len": key_len,
    }


def hybrid_decrypt(params: RegevParams, sk: RegevSecretKey, payload: dict) -> bytes:
    kem_ct = payload["kem_ct"]
    ciphertext = payload["ciphertext"]
    key_len = payload["key_len"]

    kem_bits = regev_decrypt_bits(params, sk, kem_ct)
    kem_key = bytes_from_bits(kem_bits[: key_len * 8])

    stream = Sha256XorStream(kem_key)
    mask = stream.keystream(len(ciphertext))
    return xor_bytes(ciphertext, mask)


def recover_ternary_secret_bruteforce(*, params: RegevParams, A: Matrix, b: Vec) -> Vec | None:
    params.validate()
    _require_matrix_dim(A, params.m, params.n, name="A")
    _require_vec_dim(b, params.m, name="b")

    for s in product((-1, 0, 1), repeat=params.n):
        As = mat_vec_mul_mod(A, tuple(s), params.q)
        e = vec_sub_mod(b, As, params.q)
        ok = True
        for ei in e:
            if abs(center_lift(ei, params.q)) > params.error_bound:
                ok = False
                break
        if ok:
            return tuple(s)
    return None


def _step_header(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    params = RegevParams(n=4, m=8, q=97, error_bound=1)
    rng = Sha256CtrRng(b"14-pq-lattice/04-regev-encryption")

    _step_header(1, "Modular linear algebra + center lift")
    demo_x = 96
    print(f"center_lift({demo_x}, q={params.q}) = {center_lift(demo_x, params.q)}")

    _step_header(2, "Deterministic RNG + sampling helpers")
    print(f"rng.random_bytes(8) = {rng.random_bytes(8).hex()}")
    print(f"sample_binary_vector(rng, 8) = {list(sample_binary_vector(rng, 8))}")

    _step_header(3, "Key generation (LWE public key)")
    pk, sk = regev_keygen(rng, params)
    print(f"params: n={params.n} m={params.m} q={params.q} error_bound={params.error_bound}")
    print(f"sk (ternary): {list(sk.s)}")
    print(f"pk.b (first 4): {list(pk.b)[:4]}")

    _step_header(4, "Encrypt/decrypt one bit (Regev)")
    ct0 = regev_encrypt_bit(rng, params, pk, 0)
    ct1 = regev_encrypt_bit(rng, params, pk, 1)
    d0 = regev_decrypt_bit(params, sk, ct0)
    d1 = regev_decrypt_bit(params, sk, ct1)
    print(f"decrypt(E(0)) = {d0}")
    print(f"decrypt(E(1)) = {d1}")

    _step_header(5, "Hybrid encryption (KEM-DEM toy)")
    msg = b"hello from Regev (toy)"
    payload = hybrid_encrypt(rng, params, pk, msg, key_len=4)
    pt = hybrid_decrypt(params, sk, payload)
    print(f"plaintext:  {msg!r}")
    print(f"ciphertext: {payload['ciphertext'].hex()}")
    print(f"roundtrip ok: {pt == msg}")
    print(f"KEM ciphertext bits: {len(payload['kem_ct'])}")

    rec = recover_ternary_secret_bruteforce(params=params, A=pk.A, b=pk.b)
    print(f"bruteforce recovered sk: {list(rec) if rec is not None else None}")

    noisy_params = RegevParams(n=4, m=8, q=13, error_bound=1)
    noisy_rng = Sha256CtrRng(b"noisy-demo")
    noisy_pk, noisy_sk = regev_keygen(noisy_rng, noisy_params)
    flips = 0
    trials = 50
    for _ in range(trials):
        mu = noisy_rng.randbelow(2)
        ct = regev_encrypt_bit(noisy_rng, noisy_params, noisy_pk, mu)
        mu_hat = regev_decrypt_bit(noisy_params, noisy_sk, ct)
        flips += int(mu_hat != mu)
    print(f"with smaller q: bit errors in {trials} trials = {flips}")


if __name__ == "__main__":
    main()
