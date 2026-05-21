"""
BIKE & HQC — toy code-based (QC) constructions.

This file demonstrates the core math shared by BIKE and HQC:

- Represent binary polynomials in R = GF(2)[x]/(x^r - 1) as Python integers.
- Compute QC syndromes like s = e0*h0 + e1*h1 (BIKE/QC-MDPC style) and u = r1 + h*r2 (HQC style).
- Run a tiny, educational bit-flipping decoder (QC-MDPC syndrome decoding).
- Run a tiny, educational HQC-like PKE skeleton using a repetition code as the "decodable code".

Run:
  python3 code/main.py

Educational implementation. Not constant-time. Not production-safe.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass


def mask_r(r: int) -> int:
    if r <= 0:
        raise ValueError("r must be positive")
    return (1 << r) - 1


def popcount(x: int) -> int:
    return int(x).bit_count()


def rotl(x: int, r: int, k: int) -> int:
    k %= r
    m = mask_r(r)
    x &= m
    if k == 0:
        return x
    return ((x << k) | (x >> (r - k))) & m


def poly_from_positions(r: int, positions: list[int]) -> int:
    m = mask_r(r)
    acc = 0
    for p in positions:
        if not (0 <= p < r):
            raise ValueError("position out of range")
        acc ^= 1 << p
    return acc & m


def poly_positions(x: int, r: int) -> list[int]:
    x &= mask_r(r)
    out: list[int] = []
    while x:
        lsb = x & -x
        out.append(lsb.bit_length() - 1)
        x ^= lsb
    return out


def poly_str(x: int, r: int) -> str:
    bits = [(x >> i) & 1 for i in range(r)]
    return "".join(str(b) for b in reversed(bits))


def poly_mul_mod_xr1(a: int, b: int, r: int) -> int:
    """
    Multiply in R = GF(2)[x]/(x^r - 1) using cyclic convolution.

    Representation: bit i of an int is the coefficient of x^i.
    """
    a &= mask_r(r)
    b &= mask_r(r)
    out = 0
    aa = a
    while aa:
        lsb = aa & -aa
        i = lsb.bit_length() - 1
        out ^= rotl(b, r, i)
        aa ^= lsb
    return out & mask_r(r)


def syndrome_bike_like(h0: int, h1: int, e0: int, e1: int, r: int) -> int:
    return poly_mul_mod_xr1(e0, h0, r) ^ poly_mul_mod_xr1(e1, h1, r)


def columns_from_parity_polys(h0: int, h1: int, r: int) -> list[int]:
    """
    Expand H = [H0 | H1] columns in polynomial/circulant form.

    With our conventions, if bit i of e0 is 1, the syndrome toggles by rotl(h0, i).
    Likewise for e1 with h1.
    """
    cols: list[int] = []
    for i in range(r):
        cols.append(rotl(h0, r, i))
    for i in range(r):
        cols.append(rotl(h1, r, i))
    return cols


@dataclass(frozen=True)
class BitFlipResult:
    e0: int
    e1: int
    success: bool
    iters: int
    final_syndrome: int


def bitflip_decode_qcmdpc(
    h0: int,
    h1: int,
    syndrome: int,
    r: int,
    *,
    max_iters: int = 20,
    threshold_start: int | None = None,
    threshold_min: int = 1,
) -> BitFlipResult:
    """
    Educational bit-flipping decoder for QC-MDPC syndrome decoding (toy scale).

    This is intentionally tiny and readable, not constant-time, and not tuned for
    real BIKE parameters.
    """
    cols = columns_from_parity_polys(h0, h1, r)
    s = syndrome & mask_r(r)
    e0 = 0
    e1 = 0

    row_weight = popcount(h0 & mask_r(r)) + popcount(h1 & mask_r(r))
    if threshold_start is None:
        threshold_start = (row_weight + 1) // 2

    threshold = threshold_start
    for it in range(1, max_iters + 1):
        if s == 0:
            return BitFlipResult(e0=e0, e1=e1, success=True, iters=it - 1, final_syndrome=0)

        flips: list[int] = []
        for j, col in enumerate(cols):
            if popcount(s & col) >= threshold:
                flips.append(j)

        if not flips:
            if threshold > threshold_min:
                threshold -= 1
                continue
            return BitFlipResult(e0=e0, e1=e1, success=False, iters=it - 1, final_syndrome=s)

        for j in flips:
            s ^= cols[j]
            if j < r:
                e0 ^= 1 << j
            else:
                e1 ^= 1 << (j - r)

        s &= mask_r(r)

    return BitFlipResult(e0=e0, e1=e1, success=(s == 0), iters=max_iters, final_syndrome=s)


def sample_fixed_weight(r: int, weight: int, rng: random.Random) -> int:
    if not (0 <= weight <= r):
        raise ValueError("weight out of range")
    positions = rng.sample(range(r), k=weight)
    return poly_from_positions(r, positions)


def split_weight_across_two_blocks(r: int, total_weight: int, rng: random.Random) -> tuple[int, int]:
    if not (0 <= total_weight <= 2 * r):
        raise ValueError("total_weight out of range")
    w0 = rng.randrange(0, total_weight + 1)
    w1 = total_weight - w0
    e0 = sample_fixed_weight(r, w0, rng)
    e1 = sample_fixed_weight(r, w1, rng)
    return e0, e1


def kdf_sha256(label: str, *parts: bytes, out_len: int = 32) -> bytes:
    h = hashlib.sha256()
    h.update(label.encode("utf-8"))
    h.update(b"\x00")
    for p in parts:
        h.update(p)
        h.update(b"\x00")
    digest = h.digest()
    if out_len <= len(digest):
        return digest[:out_len]
    out = bytearray()
    ctr = 0
    while len(out) < out_len:
        out.extend(hashlib.sha256(digest + ctr.to_bytes(4, "big")).digest())
        ctr += 1
    return bytes(out[:out_len])


@dataclass(frozen=True)
class ToyBikeKeypair:
    r: int
    h0: int
    h1: int


@dataclass(frozen=True)
class ToyBikeCiphertext:
    r: int
    syndrome: int


def toy_bike_keygen(*, r: int, w_each: int, rng: random.Random) -> ToyBikeKeypair:
    h0 = sample_fixed_weight(r, w_each, rng)
    h1 = sample_fixed_weight(r, w_each, rng)
    return ToyBikeKeypair(r=r, h0=h0, h1=h1)


def toy_bike_encaps(pk: ToyBikeKeypair, *, t: int, rng: random.Random) -> tuple[ToyBikeCiphertext, bytes]:
    e0, e1 = split_weight_across_two_blocks(pk.r, t, rng)
    s = syndrome_bike_like(pk.h0, pk.h1, e0, e1, pk.r)
    ct = ToyBikeCiphertext(r=pk.r, syndrome=s)
    ss = kdf_sha256(
        "toy-bike-ss",
        pk.r.to_bytes(2, "big"),
        e0.to_bytes((pk.r + 7) // 8, "little"),
        e1.to_bytes((pk.r + 7) // 8, "little"),
        s.to_bytes((pk.r + 7) // 8, "little"),
    )
    return ct, ss


def toy_bike_decaps(sk: ToyBikeKeypair, ct: ToyBikeCiphertext, *, max_iters: int = 20) -> tuple[bytes, BitFlipResult]:
    if ct.r != sk.r:
        raise ValueError("ciphertext r mismatch")
    res = bitflip_decode_qcmdpc(sk.h0, sk.h1, ct.syndrome, sk.r, max_iters=max_iters)
    ss = kdf_sha256(
        "toy-bike-ss",
        sk.r.to_bytes(2, "big"),
        res.e0.to_bytes((sk.r + 7) // 8, "little"),
        res.e1.to_bytes((sk.r + 7) // 8, "little"),
        ct.syndrome.to_bytes((sk.r + 7) // 8, "little"),
    )
    return ss, res


def rep3_encode(msg_bits: int, k: int) -> int:
    out = 0
    for i in range(k):
        b = (msg_bits >> i) & 1
        if b:
            out |= 1 << (3 * i + 0)
            out |= 1 << (3 * i + 1)
            out |= 1 << (3 * i + 2)
    return out


def rep3_decode(codeword: int, k: int) -> int:
    out = 0
    for i in range(k):
        triplet = (codeword >> (3 * i)) & 0b111
        if popcount(triplet) >= 2:
            out |= 1 << i
    return out


@dataclass(frozen=True)
class ToyHqcKeypair:
    n: int
    h: int
    s: int
    x: int
    y: int
    k: int


@dataclass(frozen=True)
class ToyHqcCiphertext:
    n: int
    u: int
    v: int


def toy_hqc_keygen(*, n: int, w_h: int, w_x: int, w_y: int, k: int, rng: random.Random) -> ToyHqcKeypair:
    h = sample_fixed_weight(n, w_h, rng)
    x = sample_fixed_weight(n, w_x, rng)
    y = sample_fixed_weight(n, w_y, rng)
    s = x ^ poly_mul_mod_xr1(h, y, n)
    return ToyHqcKeypair(n=n, h=h, s=s, x=x, y=y, k=k)


def toy_hqc_encrypt(pk: ToyHqcKeypair, msg_bits: int, *, w_r: int, w_e: int, rng: random.Random) -> ToyHqcCiphertext:
    if msg_bits < 0 or msg_bits >= (1 << pk.k):
        raise ValueError("msg_bits out of range")

    r1 = sample_fixed_weight(pk.n, w_r, rng)
    r2 = sample_fixed_weight(pk.n, w_r, rng)
    e = sample_fixed_weight(pk.n, w_e, rng)

    u = r1 ^ poly_mul_mod_xr1(pk.h, r2, pk.n)

    mG = rep3_encode(msg_bits, pk.k)
    if 3 * pk.k != pk.n:
        raise ValueError("toy HQC uses n=3k for rep3 code")

    v = mG ^ poly_mul_mod_xr1(pk.s, r2, pk.n) ^ e
    return ToyHqcCiphertext(n=pk.n, u=u, v=v)


def toy_hqc_encrypt_fixed(pk: ToyHqcKeypair, msg_bits: int, *, r1: int, r2: int, e: int) -> ToyHqcCiphertext:
    if msg_bits < 0 or msg_bits >= (1 << pk.k):
        raise ValueError("msg_bits out of range")
    if 3 * pk.k != pk.n:
        raise ValueError("toy HQC uses n=3k for rep3 code")

    r1 &= mask_r(pk.n)
    r2 &= mask_r(pk.n)
    e &= mask_r(pk.n)

    u = r1 ^ poly_mul_mod_xr1(pk.h, r2, pk.n)
    mG = rep3_encode(msg_bits, pk.k)
    v = mG ^ poly_mul_mod_xr1(pk.s, r2, pk.n) ^ e
    return ToyHqcCiphertext(n=pk.n, u=u, v=v)


def toy_hqc_decrypt(sk: ToyHqcKeypair, ct: ToyHqcCiphertext) -> int:
    if ct.n != sk.n:
        raise ValueError("ciphertext n mismatch")
    v_prime = ct.v ^ poly_mul_mod_xr1(ct.u, sk.y, sk.n)
    return rep3_decode(v_prime, sk.k)


def main():
    rng = random.Random(0)

    print("=== Step 1: Bit-Polynomials in GF(2)[x]/(x^r - 1) ===")
    r = 7
    f = poly_from_positions(r, [0, 2, 5])
    print(f"r={r}")
    print(f"f positions = {poly_positions(f, r)}")
    print(f"f bits      = {poly_str(f, r)}")
    print(f"wt(f)       = {popcount(f)}")
    print(f"rotl(f,2)   = {poly_str(rotl(f, r, 2), r)}")

    print()
    print("=== Step 2: Cyclic Multiplication and QC Syndromes ===")
    a = poly_from_positions(r, [0, 1])
    b = poly_from_positions(r, [2])
    ab = poly_mul_mod_xr1(a, b, r)
    print(f"a = {poly_str(a, r)}   (positions {poly_positions(a, r)})")
    print(f"b = {poly_str(b, r)}   (positions {poly_positions(b, r)})")
    print(f"a*b mod (x^r-1) = {poly_str(ab, r)}   (positions {poly_positions(ab, r)})")

    h0 = poly_from_positions(r, [0, 2])
    h1 = poly_from_positions(r, [1, 2])
    e0 = poly_from_positions(r, [3])
    e1 = 0
    s = syndrome_bike_like(h0, h1, e0, e1, r)
    print(f"h0 = {poly_positions(h0, r)}, h1 = {poly_positions(h1, r)}")
    print(f"e0 = {poly_positions(e0, r)}, e1 = {poly_positions(e1, r)}")
    print(f"syndrome s = e0*h0 + e1*h1 = {poly_str(s, r)}   (positions {poly_positions(s, r)})")

    print()
    print("=== Step 3: A Toy QC-MDPC Bit-Flipping Decoder ===")
    print(f"target syndrome s = {poly_str(s, r)}")
    dec = bitflip_decode_qcmdpc(h0, h1, s, r, max_iters=10)
    print(f"decoded e0 positions = {poly_positions(dec.e0, r)}")
    print(f"decoded e1 positions = {poly_positions(dec.e1, r)}")
    print(f"success={dec.success}, iters={dec.iters}, final_syndrome={poly_str(dec.final_syndrome, r)}")

    print()
    print("=== Step 4: Tiny BIKE-like KEM + HQC-like PKE Skeleton ===")
    bike_r = 11
    bike_key = toy_bike_keygen(r=bike_r, w_each=3, rng=rng)
    ct, ss1 = toy_bike_encaps(bike_key, t=1, rng=rng)
    ss2, bike_dec = toy_bike_decaps(bike_key, ct, max_iters=30)
    print(
        f"toy BIKE: r={bike_r}, wt(h0)={popcount(bike_key.h0)}, wt(h1)={popcount(bike_key.h1)}, ct.syndrome_wt={popcount(ct.syndrome)}"
    )
    print(f"toy BIKE: decaps success={bike_dec.success}, shared_secret_match={ss1==ss2}")

    hqc_n = 21
    hqc_k = 7
    hqc = ToyHqcKeypair(
        n=hqc_n,
        h=poly_from_positions(hqc_n, [0]),  # h = 1, so h*r2 = r2
        x=poly_from_positions(hqc_n, [0]),  # x = 1
        y=0,  # y = 0 (toy simplification)
        s=poly_from_positions(hqc_n, [0]),  # s = x + h*y = 1
        k=hqc_k,
    )
    msg = 0b1011010
    hqc_ct = toy_hqc_encrypt_fixed(
        hqc,
        msg,
        r1=poly_from_positions(hqc_n, []),
        r2=poly_from_positions(hqc_n, [3]),
        e=poly_from_positions(hqc_n, [6]),
    )
    msg2 = toy_hqc_decrypt(hqc, hqc_ct)
    print(f"toy HQC: n={hqc_n}, k={hqc_k}, msg={msg:07b}, dec={msg2:07b}, ok={msg==msg2}")


if __name__ == "__main__":
    main()
