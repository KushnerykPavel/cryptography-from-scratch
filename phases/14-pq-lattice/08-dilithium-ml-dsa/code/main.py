"""
Toy, educational implementation inspired by ML-DSA (FIPS 204 / Dilithium).

This script demonstrates:
- Ring arithmetic in R_q = Z_q[x]/(x^n + 1) for small toy n
- Decomposition into high/low bits and the MakeHint/UseHint mechanism
- A tiny (insecure) ML-DSA-shaped signature flow: keygen, sign, verify

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable, Sequence


TOY_N = 16
TOY_Q = 8_380_417
TOY_K = 2
TOY_L = 2

TOY_ETA = 2
TOY_GAMMA1 = 1 << 12
TOY_BETA = 64

TOY_ALPHA = 512
TOY_TAU = 4
TOY_OMEGA = 20

TOY_D = 3


def shake256(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_256(data).digest(outlen)


def _i2le(x: int, nbytes: int) -> bytes:
    return int(x).to_bytes(nbytes, "little", signed=False)


def _centered_mod_q(x: int, q: int) -> int:
    x %= q
    if x > q // 2:
        x -= q
    return x


def poly_normalize(p: Sequence[int], q: int) -> list[int]:
    if len(p) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [int(c) % q for c in p]


def poly_add(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    if len(a) != len(b) or len(a) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [(int(x) + int(y)) % q for x, y in zip(a, b)]


def poly_sub(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    if len(a) != len(b) or len(a) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [(int(x) - int(y)) % q for x, y in zip(a, b)]


def poly_scale(a: Sequence[int], s: int, q: int) -> list[int]:
    if len(a) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [(int(s) * int(x)) % q for x in a]


def poly_mul_negacyclic(a: Sequence[int], b: Sequence[int], q: int) -> list[int]:
    if len(a) != len(b) or len(a) != TOY_N:
        raise ValueError("wrong polynomial length")
    out = [0] * TOY_N
    for i, ai in enumerate(a):
        ai = int(ai) % q
        for j, bj in enumerate(b):
            bj = int(bj) % q
            k = i + j
            prod = (ai * bj) % q
            if k < TOY_N:
                out[k] = (out[k] + prod) % q
            else:
                out[k - TOY_N] = (out[k - TOY_N] - prod) % q
    return out


def vec_add(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]], q: int) -> list[list[int]]:
    if len(a) != len(b):
        raise ValueError("wrong vector length")
    return [poly_add(x, y, q) for x, y in zip(a, b)]


def vec_sub(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]], q: int) -> list[list[int]]:
    if len(a) != len(b):
        raise ValueError("wrong vector length")
    return [poly_sub(x, y, q) for x, y in zip(a, b)]


def vec_scale(a: Sequence[Sequence[int]], s: int, q: int) -> list[list[int]]:
    return [poly_scale(x, s, q) for x in a]


def vec_mul_poly(v: Sequence[Sequence[int]], c: Sequence[int], q: int) -> list[list[int]]:
    return [poly_mul_negacyclic(c, x, q) for x in v]


def mat_vec_mul(a_mat: Sequence[Sequence[Sequence[int]]], v: Sequence[Sequence[int]], q: int) -> list[list[int]]:
    if len(a_mat) == 0 or len(a_mat[0]) != len(v):
        raise ValueError("dimension mismatch")
    out: list[list[int]] = []
    for row in a_mat:
        acc = [0] * TOY_N
        for aij, vj in zip(row, v):
            acc = poly_add(acc, poly_mul_negacyclic(aij, vj, q), q)
        out.append(acc)
    return out


def vec_norm_inf_centered(v: Sequence[Sequence[int]], q: int) -> int:
    m = 0
    for p in v:
        for c in p:
            m = max(m, abs(_centered_mod_q(int(c), q)))
    return m


def decompose_coeff(r: int, q: int, alpha: int) -> tuple[int, int]:
    if alpha <= 0 or (q - 1) % alpha != 0:
        raise ValueError("alpha must divide q-1")
    r = int(r) % q
    r1 = (r + alpha // 2) // alpha
    r0 = r - r1 * alpha
    if r0 > alpha // 2:
        r0 -= alpha
        r1 += 1
    if r0 < -alpha // 2:
        r0 += alpha
        r1 -= 1
    r1 %= (q - 1) // alpha
    return int(r1), int(r0)


def high_bits(p: Sequence[int], q: int, alpha: int) -> list[int]:
    if len(p) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [decompose_coeff(c, q, alpha)[0] for c in p]


def low_bits(p: Sequence[int], q: int, alpha: int) -> list[int]:
    if len(p) != TOY_N:
        raise ValueError("wrong polynomial length")
    return [decompose_coeff(c, q, alpha)[1] for c in p]


def make_hint(z: Sequence[int], r: Sequence[int], q: int, alpha: int) -> list[int]:
    if len(z) != len(r) or len(r) != TOY_N:
        raise ValueError("wrong polynomial length")
    out = []
    for zi, ri in zip(z, r):
        r1 = decompose_coeff(ri, q, alpha)[0]
        v1 = decompose_coeff(ri + zi, q, alpha)[0]
        out.append(1 if r1 != v1 else 0)
    return out


def use_hint(h: Sequence[int], r: Sequence[int], q: int, alpha: int) -> list[int]:
    if len(h) != len(r) or len(r) != TOY_N:
        raise ValueError("wrong polynomial length")
    out = []
    m = (q - 1) // alpha
    for hi, ri in zip(h, r):
        r1, r0 = decompose_coeff(ri, q, alpha)
        if int(hi) == 0:
            out.append(r1)
            continue
        if r0 > 0:
            out.append((r1 + 1) % m)
        else:
            out.append((r1 - 1) % m)
    return out


def _encode_vec_mod_q(v: Sequence[Sequence[int]], q: int) -> bytes:
    out = bytearray()
    for p in v:
        for c in p:
            out += _i2le(int(c) % q, 4)
    return bytes(out)


def _encode_vec_u32(v: Sequence[Sequence[int]]) -> bytes:
    out = bytearray()
    for p in v:
        for c in p:
            out += _i2le(int(c) & 0xFFFFFFFF, 4)
    return bytes(out)


def _encode_vec_small(v: Sequence[Sequence[int]]) -> bytes:
    out = bytearray()
    for p in v:
        for c in p:
            out += _i2le(int(c) & 0xFFFF, 2)
    return bytes(out)


def _sample_small_poly(seed: bytes, domain: bytes, eta: int, q: int) -> list[int]:
    buf = shake256(seed + domain, TOY_N)
    out = []
    for b in buf:
        out.append((b % (2 * eta + 1)) - eta)
    return [c % q for c in out]


def _sample_mask_poly(seed: bytes, domain: bytes, gamma1: int, q: int) -> list[int]:
    buf = shake256(seed + domain, TOY_N * 3)
    out: list[int] = []
    i = 0
    while len(out) < TOY_N:
        x = int.from_bytes(buf[i : i + 3], "little")
        i += 3
        out.append((x % (2 * gamma1 + 1)) - gamma1)
    return [c % q for c in out]


def expand_a(rho: bytes, q: int) -> list[list[list[int]]]:
    if len(rho) != 32:
        raise ValueError("rho must be 32 bytes")
    mat: list[list[list[int]]] = []
    for i in range(TOY_K):
        row: list[list[int]] = []
        for j in range(TOY_L):
            stream = shake256(rho + bytes([i, j]), TOY_N * 4)
            poly = []
            for t in range(TOY_N):
                coeff = int.from_bytes(stream[t * 4 : (t + 1) * 4], "little") % q
                poly.append(coeff)
            row.append(poly)
        mat.append(row)
    return mat


def sample_in_ball(seed32: bytes, q: int, tau: int) -> list[int]:
    if len(seed32) != 32:
        raise ValueError("seed must be 32 bytes")
    if tau < 0 or tau > TOY_N:
        raise ValueError("bad tau")
    out = [0] * TOY_N
    used: set[int] = set()
    stream = shake256(seed32, 128)
    idx = 0
    while len(used) < tau:
        if idx + 2 > len(stream):
            stream += shake256(seed32 + bytes([idx & 0xFF]), 64)
        pos = stream[idx] % TOY_N
        sgn = 1 if (stream[idx + 1] & 1) == 0 else -1
        idx += 2
        if pos in used:
            continue
        used.add(pos)
        out[pos] = sgn % q
    return out


def hint_weight(h: Sequence[Sequence[int]]) -> int:
    return sum(int(x) for p in h for x in p)


@dataclass(frozen=True)
class PublicKey:
    rho: bytes
    t1: list[list[int]]

    def encode(self) -> bytes:
        return self.rho + _encode_vec_u32(self.t1)


@dataclass(frozen=True)
class SecretKey:
    rho: bytes
    key_seed: bytes
    s1: list[list[int]]
    s2: list[list[int]]
    t0: list[list[int]]
    pk: PublicKey


@dataclass(frozen=True)
class Signature:
    c_seed: bytes
    z: list[list[int]]
    h: list[list[int]]


def power2round_coeff(r: int, q: int, d: int) -> tuple[int, int]:
    if d <= 0 or d >= 31:
        raise ValueError("bad d")
    r = int(r) % q
    two_d = 1 << d
    r0 = r % two_d
    if r0 > two_d // 2:
        r0 -= two_d
    r1 = (r - r0) // two_d
    return int(r1), int(r0)


def power2round_vec(v: Sequence[Sequence[int]], q: int, d: int) -> tuple[list[list[int]], list[list[int]]]:
    high: list[list[int]] = []
    low: list[list[int]] = []
    for p in v:
        if len(p) != TOY_N:
            raise ValueError("wrong polynomial length")
        p_high = []
        p_low = []
        for c in p:
            r1, r0 = power2round_coeff(c, q, d)
            p_high.append(r1)
            p_low.append(r0)
        high.append(p_high)
        low.append(p_low)
    return high, low


def split_vec_high_low(v: Sequence[Sequence[int]], q: int, alpha: int) -> tuple[list[list[int]], list[list[int]]]:
    high: list[list[int]] = []
    low: list[list[int]] = []
    for p in v:
        high.append(high_bits(p, q, alpha))
        low.append(low_bits(p, q, alpha))
    return high, low


def toy_mldsa_keygen(seed: bytes) -> tuple[PublicKey, SecretKey]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    rho = shake256(seed + b"rho", 32)
    key_seed = shake256(seed + b"key", 32)
    mat_a = expand_a(rho, TOY_Q)

    s1 = [_sample_small_poly(seed, b"s1" + bytes([i]), TOY_ETA, TOY_Q) for i in range(TOY_L)]
    s2 = [_sample_small_poly(seed, b"s2" + bytes([i]), TOY_ETA, TOY_Q) for i in range(TOY_K)]

    t = vec_add(mat_vec_mul(mat_a, s1, TOY_Q), s2, TOY_Q)
    t1, t0 = power2round_vec(t, TOY_Q, TOY_D)

    pk = PublicKey(rho=rho, t1=t1)
    sk = SecretKey(rho=rho, key_seed=key_seed, s1=s1, s2=s2, t0=t0, pk=pk)
    return pk, sk


def _challenge_from(mu: bytes, w1: Sequence[Sequence[int]]) -> bytes:
    return shake256(mu + _encode_vec_small(w1), 32)


def toy_mldsa_sign_det(sk: SecretKey, msg: bytes, max_tries: int = 64) -> Signature:
    mat_a = expand_a(sk.rho, TOY_Q)
    mu = shake256(sk.pk.encode() + msg, 64)

    for kappa in range(max_tries):
        y_seed = shake256(sk.key_seed + mu + _i2le(kappa, 2), 32)
        y = [_sample_mask_poly(y_seed, b"y" + bytes([i]), TOY_GAMMA1, TOY_Q) for i in range(TOY_L)]
        w = mat_vec_mul(mat_a, y, TOY_Q)
        w1 = [high_bits(p, TOY_Q, TOY_ALPHA) for p in w]

        c_seed = _challenge_from(mu, w1)
        c = sample_in_ball(c_seed, TOY_Q, TOY_TAU)

        cs2 = vec_mul_poly(sk.s2, c, TOY_Q)
        w_minus_cs2 = vec_sub(w, cs2, TOY_Q)
        if [high_bits(p, TOY_Q, TOY_ALPHA) for p in w_minus_cs2] != w1:
            continue

        cs1 = vec_mul_poly(sk.s1, c, TOY_Q)
        z = vec_add(y, cs1, TOY_Q)
        if vec_norm_inf_centered(z, TOY_Q) >= TOY_GAMMA1 - TOY_BETA:
            continue

        az = mat_vec_mul(mat_a, z, TOY_Q)
        ct1_2d = vec_scale(vec_mul_poly(sk.pk.t1, c, TOY_Q), 1 << TOY_D, TOY_Q)
        r = vec_sub(az, ct1_2d, TOY_Q)

        neg_ct0 = vec_scale(vec_mul_poly(sk.t0, c, TOY_Q), -1, TOY_Q)
        h = [make_hint(zp, rp, TOY_Q, TOY_ALPHA) for zp, rp in zip(neg_ct0, r)]
        if hint_weight(h) > TOY_OMEGA:
            continue

        return Signature(c_seed=c_seed, z=z, h=h)

    raise RuntimeError("signing failed (too many rejections)")


def toy_mldsa_verify(pk: PublicKey, msg: bytes, sig: Signature) -> bool:
    if len(sig.c_seed) != 32:
        return False
    if len(pk.t1) != TOY_K or len(sig.z) != TOY_L or len(sig.h) != TOY_K:
        return False
    for p in pk.t1:
        if len(p) != TOY_N:
            return False
    for p in sig.z:
        if len(p) != TOY_N:
            return False
    for p in sig.h:
        if len(p) != TOY_N or any(int(x) not in (0, 1) for x in p):
            return False
    if vec_norm_inf_centered(sig.z, TOY_Q) >= TOY_GAMMA1 - TOY_BETA:
        return False
    if hint_weight(sig.h) > TOY_OMEGA:
        return False

    mat_a = expand_a(pk.rho, TOY_Q)
    mu = shake256(pk.encode() + msg, 64)
    c = sample_in_ball(sig.c_seed, TOY_Q, TOY_TAU)

    az = mat_vec_mul(mat_a, sig.z, TOY_Q)
    ct1_2d = vec_scale(vec_mul_poly(pk.t1, c, TOY_Q), 1 << TOY_D, TOY_Q)
    r = vec_sub(az, ct1_2d, TOY_Q)

    w1 = [use_hint(hp, rp, TOY_Q, TOY_ALPHA) for hp, rp in zip(sig.h, r)]
    c_seed_check = _challenge_from(mu, w1)
    return c_seed_check == sig.c_seed


def _fmt_poly(p: Sequence[int], q: int) -> str:
    centered = [_centered_mod_q(int(c), q) for c in p]
    return "[" + ", ".join(f"{x:+d}" for x in centered) + "]"


def _fmt_vec(v: Sequence[Sequence[int]], q: int) -> str:
    return "[" + ", ".join(_fmt_poly(p, q) for p in v) + "]"


def main():
    print("=== Step 1: Ring arithmetic (R_q) ===")
    a = [1, 2, 3] + [0] * (TOY_N - 3)
    b = [4, 0, 1] + [0] * (TOY_N - 3)
    ab = poly_mul_negacyclic(a, b, TOY_Q)
    print("a =", _fmt_poly(a, TOY_Q))
    print("b =", _fmt_poly(b, TOY_Q))
    print("a*b mod (x^n+1) =", _fmt_poly(ab, TOY_Q))

    print("\n=== Step 2: HighBits / LowBits + hints ===")
    r = [0] * TOY_N
    r[0] = 12345
    r[1] = TOY_Q - 10
    z = [0] * TOY_N
    z[0] = -200
    z[1] = 200
    r = [x % TOY_Q for x in r]
    z = [x % TOY_Q for x in z]
    h = make_hint(z, r, TOY_Q, TOY_ALPHA)
    hb_rz = high_bits(poly_add(r, z, TOY_Q), TOY_Q, TOY_ALPHA)
    hb_from_hint = use_hint(h, r, TOY_Q, TOY_ALPHA)
    print("r =", _fmt_poly(r, TOY_Q))
    print("z =", _fmt_poly(z, TOY_Q))
    print("HighBits(r+z) =", hb_rz)
    print("UseHint(MakeHint(z,r), r) =", hb_from_hint)

    print("\n=== Step 3: Toy ML-DSA key generation ===")
    seed = bytes.fromhex("00" * 32)
    pk, sk = toy_mldsa_keygen(seed)
    print("rho =", pk.rho.hex()[:16] + "...")
    print("t1 =", pk.t1)

    print("\n=== Step 4: Toy ML-DSA sign + verify ===")
    msg = b"hello, lattice signatures"
    sig = toy_mldsa_sign_det(sk, msg)
    ok = toy_mldsa_verify(pk, msg, sig)
    print("message =", msg)
    print("signature.c_seed =", sig.c_seed.hex()[:16] + "...")
    print("signature.z =", _fmt_vec(sig.z, TOY_Q))
    print("signature.h weight =", hint_weight(sig.h))
    print("verify =", ok)

    tampered = toy_mldsa_verify(pk, msg + b"!", sig)
    print("verify(tampered message) =", tampered)


if __name__ == "__main__":
    main()
