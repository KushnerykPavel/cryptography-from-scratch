from __future__ import annotations

import hashlib
from dataclasses import dataclass
from itertools import product

Poly = tuple[int, ...]
PolyVec = tuple[Poly, ...]


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


def _require_power_of_two(name: str, n: int) -> None:
    _require_positive_int(name, n)
    if n < 2:
        raise ValueError(f"{name} must be >= 2")
    if n & (n - 1):
        raise ValueError(f"{name} must be a power of two")


def _require_poly_dim(p: Poly, n: int, *, name: str) -> None:
    if len(p) != n:
        raise ValueError(f"{name} dimension mismatch")


def _require_polyvec_dim(v: PolyVec, k: int, n: int, *, name: str) -> None:
    if len(v) != k:
        raise ValueError(f"{name} dimension mismatch")
    for i, p in enumerate(v):
        _require_poly_dim(p, n, name=f"{name}[{i}]")


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


def poly_add_mod(a: Poly, b: Poly, q: int) -> Poly:
    _require_positive_int("q", q)
    _require_poly_dim(a, len(b), name="a")
    return tuple((x + y) % q for x, y in zip(a, b))


def poly_sub_mod(a: Poly, b: Poly, q: int) -> Poly:
    _require_positive_int("q", q)
    _require_poly_dim(a, len(b), name="a")
    return tuple((x - y) % q for x, y in zip(a, b))


def poly_mul_mod_xn_plus_1(a: Poly, b: Poly, q: int) -> Poly:
    _require_positive_int("q", q)
    n = len(a)
    _require_poly_dim(b, n, name="b")
    _require_power_of_two("n", n)

    tmp = [0] * (2 * n - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            tmp[i + j] += ai * bj

    out = [0] * n
    for k, ck in enumerate(tmp):
        if k < n:
            out[k] += ck
        else:
            out[k - n] -= ck
    return tuple(x % q for x in out)


def poly_inner_product_mod(a: PolyVec, b: PolyVec, q: int) -> Poly:
    _require_positive_int("q", q)
    k = len(a)
    if k == 0:
        raise ValueError("poly vector must be non-empty")
    n = len(a[0])
    _require_polyvec_dim(a, k, n, name="a")
    _require_polyvec_dim(b, k, n, name="b")
    acc = (0,) * n
    for ai, bi in zip(a, b):
        acc = poly_add_mod(acc, poly_mul_mod_xn_plus_1(ai, bi, q), q)
    return acc


def sample_uniform_poly(rng: Sha256CtrRng, n: int, q: int) -> Poly:
    _require_power_of_two("n", n)
    _require_positive_int("q", q)
    return tuple(rng.randbelow(q) for _ in range(n))


def sample_ternary_poly(rng: Sha256CtrRng, n: int) -> Poly:
    _require_power_of_two("n", n)
    return tuple(rng.randbelow(3) - 1 for _ in range(n))


def sample_binary_poly(rng: Sha256CtrRng, n: int) -> Poly:
    _require_power_of_two("n", n)
    return tuple(rng.randbelow(2) for _ in range(n))


def sample_uniform_polyvec(rng: Sha256CtrRng, k: int, n: int, q: int) -> PolyVec:
    _require_positive_int("k", k)
    return tuple(sample_uniform_poly(rng, n, q) for _ in range(k))


def sample_ternary_polyvec(rng: Sha256CtrRng, k: int, n: int) -> PolyVec:
    _require_positive_int("k", k)
    return tuple(sample_ternary_poly(rng, n) for _ in range(k))


def _circular_distance(a: int, b: int, q: int) -> int:
    d = (a - b) % q
    return min(d, (-d) % q)


def _encode_bit_poly(mu: int, n: int, q: int) -> Poly:
    if mu not in (0, 1):
        raise ValueError("mu must be 0 or 1")
    return tuple((mu * (q // 2)) % q for _ in range(n))


def _decode_bit_from_poly(p: Poly, q: int) -> int:
    _require_positive_int("q", q)
    if len(p) == 0:
        raise ValueError("p must be non-empty")
    half = q // 2
    votes_for_one = 0
    for x in p:
        d0 = _circular_distance(x, 0, q)
        d1 = _circular_distance(x, half, q)
        votes_for_one += 1 if d1 < d0 else 0
    return 1 if votes_for_one * 2 > len(p) else 0


@dataclass(frozen=True)
class RLWEParams:
    n: int
    q: int
    error_bound: int = 1

    def validate(self) -> None:
        _require_power_of_two("n", self.n)
        _require_positive_int("q", self.q)
        if self.q <= 2:
            raise ValueError("q must be >= 3")
        if self.error_bound < 0:
            raise ValueError("error_bound must be non-negative")


@dataclass(frozen=True)
class RLWEPublicKey:
    a: Poly
    b: Poly


@dataclass(frozen=True)
class RLWESecretKey:
    s: Poly


def rlwe_keygen(rng: Sha256CtrRng, params: RLWEParams) -> tuple[RLWEPublicKey, RLWESecretKey]:
    params.validate()
    a = sample_uniform_poly(rng, params.n, params.q)
    s = sample_ternary_poly(rng, params.n)
    e = sample_ternary_poly(rng, params.n)
    b = poly_add_mod(poly_mul_mod_xn_plus_1(a, s, params.q), tuple(x % params.q for x in e), params.q)
    return RLWEPublicKey(a=a, b=b), RLWESecretKey(s=s)


def rlwe_encrypt_bit(
    rng: Sha256CtrRng,
    params: RLWEParams,
    pk: RLWEPublicKey,
    mu: int,
) -> tuple[Poly, Poly]:
    params.validate()
    _require_poly_dim(pk.a, params.n, name="pk.a")
    _require_poly_dim(pk.b, params.n, name="pk.b")

    r = sample_binary_poly(rng, params.n)
    e1 = sample_ternary_poly(rng, params.n)
    e2 = sample_ternary_poly(rng, params.n)

    u0 = poly_mul_mod_xn_plus_1(pk.a, r, params.q)
    u = poly_add_mod(u0, tuple(x % params.q for x in e1), params.q)
    v0 = poly_mul_mod_xn_plus_1(pk.b, r, params.q)
    v = poly_add_mod(poly_add_mod(v0, tuple(x % params.q for x in e2), params.q), _encode_bit_poly(mu, params.n, params.q), params.q)
    return u, v


def rlwe_decrypt_bit(params: RLWEParams, sk: RLWESecretKey, ct: tuple[Poly, Poly]) -> int:
    params.validate()
    u, v = ct
    _require_poly_dim(u, params.n, name="u")
    _require_poly_dim(v, params.n, name="v")
    _require_poly_dim(sk.s, params.n, name="sk.s")
    x = poly_sub_mod(v, poly_mul_mod_xn_plus_1(u, sk.s, params.q), params.q)
    return _decode_bit_from_poly(x, params.q)


def recover_ternary_rlwe_secret_bruteforce(
    *,
    params: RLWEParams,
    a: Poly,
    b: Poly,
) -> Poly | None:
    params.validate()
    _require_poly_dim(a, params.n, name="a")
    _require_poly_dim(b, params.n, name="b")

    for s in product((-1, 0, 1), repeat=params.n):
        As = poly_mul_mod_xn_plus_1(a, tuple(s), params.q)
        e = poly_sub_mod(b, As, params.q)
        ok = True
        for ei in e:
            if abs(center_lift(ei, params.q)) > params.error_bound:
                ok = False
                break
        if ok:
            return tuple(s)
    return None


@dataclass(frozen=True)
class MLWEParams:
    k: int
    n: int
    q: int
    error_bound: int = 1

    def validate(self) -> None:
        _require_positive_int("k", self.k)
        _require_power_of_two("n", self.n)
        _require_positive_int("q", self.q)
        if self.q <= 2:
            raise ValueError("q must be >= 3")
        if self.error_bound < 0:
            raise ValueError("error_bound must be non-negative")


@dataclass(frozen=True)
class MLWEPublicKey:
    a: PolyVec
    b: Poly


@dataclass(frozen=True)
class MLWESecretKey:
    s: PolyVec


def mlwe_keygen(rng: Sha256CtrRng, params: MLWEParams) -> tuple[MLWEPublicKey, MLWESecretKey]:
    params.validate()
    a = sample_uniform_polyvec(rng, params.k, params.n, params.q)
    s = sample_ternary_polyvec(rng, params.k, params.n)
    e = sample_ternary_poly(rng, params.n)
    a_s = poly_inner_product_mod(a, s, params.q)
    b = poly_add_mod(a_s, tuple(x % params.q for x in e), params.q)
    return MLWEPublicKey(a=a, b=b), MLWESecretKey(s=s)


def mlwe_encrypt_bit(
    rng: Sha256CtrRng,
    params: MLWEParams,
    pk: MLWEPublicKey,
    mu: int,
) -> tuple[PolyVec, Poly]:
    params.validate()
    _require_polyvec_dim(pk.a, params.k, params.n, name="pk.a")
    _require_poly_dim(pk.b, params.n, name="pk.b")

    r = sample_binary_poly(rng, params.n)
    e1 = sample_ternary_polyvec(rng, params.k, params.n)
    e2 = sample_ternary_poly(rng, params.n)

    u = []
    for ai, e1i in zip(pk.a, e1):
        u0 = poly_mul_mod_xn_plus_1(ai, r, params.q)
        u.append(poly_add_mod(u0, tuple(x % params.q for x in e1i), params.q))

    v0 = poly_mul_mod_xn_plus_1(pk.b, r, params.q)
    v = poly_add_mod(poly_add_mod(v0, tuple(x % params.q for x in e2), params.q), _encode_bit_poly(mu, params.n, params.q), params.q)
    return tuple(u), v


def mlwe_decrypt_bit(params: MLWEParams, sk: MLWESecretKey, ct: tuple[PolyVec, Poly]) -> int:
    params.validate()
    u, v = ct
    _require_polyvec_dim(u, params.k, params.n, name="u")
    _require_poly_dim(v, params.n, name="v")
    _require_polyvec_dim(sk.s, params.k, params.n, name="sk.s")

    u_s = poly_inner_product_mod(u, sk.s, params.q)
    x = poly_sub_mod(v, u_s, params.q)
    return _decode_bit_from_poly(x, params.q)


def recover_ternary_mlwe_secret_bruteforce(
    *,
    params: MLWEParams,
    a: PolyVec,
    b: Poly,
) -> PolyVec | None:
    params.validate()
    _require_polyvec_dim(a, params.k, params.n, name="a")
    _require_poly_dim(b, params.n, name="b")

    for flat in product((-1, 0, 1), repeat=params.k * params.n):
        s = []
        for i in range(params.k):
            s.append(tuple(flat[i * params.n : (i + 1) * params.n]))
        s_t = tuple(s)
        a_s = poly_inner_product_mod(a, s_t, params.q)
        e = poly_sub_mod(b, a_s, params.q)
        ok = True
        for ei in e:
            if abs(center_lift(ei, params.q)) > params.error_bound:
                ok = False
                break
        if ok:
            return s_t
    return None


def main() -> None:
    print("RLWE/MLWE demo (educational, not constant-time, not production-safe)")

    rlwe_params = RLWEParams(n=8, q=97, error_bound=1)
    rng = Sha256CtrRng(b"04-lattices/10-rlwe-mlwe/rlwe")
    rlwe_pk, rlwe_sk = rlwe_keygen(rng, rlwe_params)
    rlwe_ct0 = rlwe_encrypt_bit(rng, rlwe_params, rlwe_pk, 0)
    rlwe_ct1 = rlwe_encrypt_bit(rng, rlwe_params, rlwe_pk, 1)
    rlwe_d0 = rlwe_decrypt_bit(rlwe_params, rlwe_sk, rlwe_ct0)
    rlwe_d1 = rlwe_decrypt_bit(rlwe_params, rlwe_sk, rlwe_ct1)
    rlwe_rec = recover_ternary_rlwe_secret_bruteforce(params=rlwe_params, a=rlwe_pk.a, b=rlwe_pk.b)

    print(f"RLWE params: n={rlwe_params.n} q={rlwe_params.q} error_bound={rlwe_params.error_bound}")
    print(f"RLWE decrypt 0 -> {rlwe_d0}, 1 -> {rlwe_d1}")
    print(f"RLWE bruteforce recovered sk: {list(rlwe_rec) if rlwe_rec is not None else None}")

    mlwe_params = MLWEParams(k=2, n=4, q=97, error_bound=1)
    rng2 = Sha256CtrRng(b"04-lattices/10-rlwe-mlwe/mlwe")
    mlwe_pk, mlwe_sk = mlwe_keygen(rng2, mlwe_params)
    mlwe_ct0 = mlwe_encrypt_bit(rng2, mlwe_params, mlwe_pk, 0)
    mlwe_ct1 = mlwe_encrypt_bit(rng2, mlwe_params, mlwe_pk, 1)
    mlwe_d0 = mlwe_decrypt_bit(mlwe_params, mlwe_sk, mlwe_ct0)
    mlwe_d1 = mlwe_decrypt_bit(mlwe_params, mlwe_sk, mlwe_ct1)
    mlwe_rec = recover_ternary_mlwe_secret_bruteforce(params=mlwe_params, a=mlwe_pk.a, b=mlwe_pk.b)

    print()
    print(f"MLWE params: k={mlwe_params.k} n={mlwe_params.n} q={mlwe_params.q} error_bound={mlwe_params.error_bound}")
    print(f"MLWE decrypt 0 -> {mlwe_d0}, 1 -> {mlwe_d1}")
    print(
        f"MLWE bruteforce recovered sk: {[[*p] for p in mlwe_rec] if mlwe_rec is not None else None}"
    )


if __name__ == "__main__":
    main()
