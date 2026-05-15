from __future__ import annotations

import hashlib
from dataclasses import dataclass
from itertools import product

Vec = tuple[int, ...]
Matrix = list[list[int]]


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
class LWEParams:
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
class LWEPublicKey:
    A: Matrix
    b: Vec


@dataclass(frozen=True)
class LWESecretKey:
    s: Vec


def lwe_keygen(rng: Sha256CtrRng, params: LWEParams) -> tuple[LWEPublicKey, LWESecretKey]:
    params.validate()
    A = sample_uniform_matrix(rng, params.m, params.n, params.q)
    s = sample_ternary_vector(rng, params.n)
    e = sample_ternary_vector(rng, params.m)
    As = mat_vec_mul_mod(A, s, params.q)
    b = vec_add_mod(As, e, params.q)
    return LWEPublicKey(A=A, b=b), LWESecretKey(s=s)


def lwe_encrypt_bit(
    rng: Sha256CtrRng,
    params: LWEParams,
    pk: LWEPublicKey,
    mu: int,
) -> tuple[Vec, int]:
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


def _circular_distance(a: int, b: int, q: int) -> int:
    d = (a - b) % q
    return min(d, (-d) % q)


def lwe_decrypt_bit(params: LWEParams, sk: LWESecretKey, ct: tuple[Vec, int]) -> int:
    params.validate()
    u, v = ct
    _require_vec_dim(u, params.n, name="u")
    _require_vec_dim(sk.s, params.n, name="sk.s")
    x = (v - dot_mod(u, sk.s, params.q)) % params.q
    d0 = _circular_distance(x, 0, params.q)
    d1 = _circular_distance(x, params.q // 2, params.q)
    return 0 if d0 < d1 else 1


def recover_ternary_secret_bruteforce(
    *,
    params: LWEParams,
    A: Matrix,
    b: Vec,
) -> Vec | None:
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


def main() -> None:
    params = LWEParams(n=4, m=8, q=97, error_bound=1)
    rng = Sha256CtrRng(b"04-lattices/09-lwe")

    pk, sk = lwe_keygen(rng, params)
    ct0 = lwe_encrypt_bit(rng, params, pk, 0)
    ct1 = lwe_encrypt_bit(rng, params, pk, 1)
    d0 = lwe_decrypt_bit(params, sk, ct0)
    d1 = lwe_decrypt_bit(params, sk, ct1)

    rec = recover_ternary_secret_bruteforce(params=params, A=pk.A, b=pk.b)

    print("LWE demo (educational, not constant-time, not production-safe)")
    print(f"params: n={params.n} m={params.m} q={params.q} error_bound={params.error_bound}")
    print(f"sk (ternary): {list(sk.s)}")
    print(f"encrypt/decrypt 0 -> {d0}, 1 -> {d1}")
    print(f"bruteforce recovered sk: {list(rec) if rec is not None else None}")


if __name__ == "__main__":
    main()
