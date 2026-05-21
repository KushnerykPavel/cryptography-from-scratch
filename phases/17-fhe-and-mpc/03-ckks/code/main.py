"""
Toy CKKS walk-through (approximate arithmetic).

This lesson does NOT implement real CKKS encryption. Instead, it implements a
minimal "ciphertext = scaled message + noise" simulator that makes the CKKS
engineering ideas concrete:

- encoding reals by scaling + rounding
- noise as "approximation error"
- addition keeping the same scale
- multiplication squaring the scale
- rescaling to bring the scale back down (spending a level)

Run:
    python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import random
from typing import Iterable, List, Sequence


Slots = List[int]


@dataclass(frozen=True)
class Plaintext:
    slots: Slots
    scale: int


@dataclass(frozen=True)
class Ciphertext:
    slots: Slots
    noise: Slots
    scale: int
    level: int


def _require_int(name: str, x: object) -> int:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")
    return x


def _require_positive_int(name: str, x: object) -> int:
    x = _require_int(name, x)
    if x <= 0:
        raise ValueError(f"{name} must be > 0")
    return x


def _require_nonnegative_int(name: str, x: object) -> int:
    x = _require_int(name, x)
    if x < 0:
        raise ValueError(f"{name} must be >= 0")
    return x


def _require_finite_real(name: str, x: object) -> float:
    if not isinstance(x, (int, float)):
        raise TypeError(f"{name} must be a real number")
    xf = float(x)
    if not math.isfinite(xf):
        raise ValueError(f"{name} must be finite")
    return xf


def round_nearest_int(x: float) -> int:
    x = _require_finite_real("x", x)
    if x >= 0:
        return int(math.floor(x + 0.5))
    return -int(math.floor(-x + 0.5))


def round_div_int(num: int, den: int) -> int:
    num = _require_int("num", num)
    den = _require_positive_int("den", den)
    if num >= 0:
        return (num + den // 2) // den
    return -((-num + den // 2) // den)


def _require_same_len(a: Sequence[object], b: Sequence[object], *, name: str) -> None:
    if len(a) != len(b):
        raise ValueError(f"{name}: length mismatch")


def ckks_encode(values: Sequence[float], *, scale: int) -> Plaintext:
    scale = _require_positive_int("scale", scale)
    slots: Slots = [round_nearest_int(_require_finite_real("value", v) * scale) for v in values]
    return Plaintext(slots=slots, scale=scale)


def ckks_decode(pt: Plaintext) -> List[float]:
    if not isinstance(pt, Plaintext):
        raise TypeError("pt must be Plaintext")
    scale = _require_positive_int("pt.scale", pt.scale)
    return [s / scale for s in pt.slots]


def ckks_encrypt(pt: Plaintext, *, noise_bound: int, seed: int, level: int = 0) -> Ciphertext:
    if not isinstance(pt, Plaintext):
        raise TypeError("pt must be Plaintext")
    noise_bound = _require_nonnegative_int("noise_bound", noise_bound)
    seed = _require_int("seed", seed)
    level = _require_nonnegative_int("level", level)

    rng = random.Random(seed)
    noise = [rng.randint(-noise_bound, noise_bound) for _ in pt.slots]
    slots = [m + e for m, e in zip(pt.slots, noise)]
    return Ciphertext(slots=slots, noise=noise, scale=pt.scale, level=level)


def ckks_decrypt(ct: Ciphertext) -> Plaintext:
    if not isinstance(ct, Ciphertext):
        raise TypeError("ct must be Ciphertext")
    return Plaintext(slots=ct.slots[:], scale=ct.scale)


def ckks_add(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    if not isinstance(a, Ciphertext) or not isinstance(b, Ciphertext):
        raise TypeError("a and b must be Ciphertext")
    if a.scale != b.scale:
        raise ValueError("ckks_add: scale mismatch")
    if a.level != b.level:
        raise ValueError("ckks_add: level mismatch")
    _require_same_len(a.slots, b.slots, name="ckks_add")
    slots = [x + y for x, y in zip(a.slots, b.slots)]
    noise = [x + y for x, y in zip(a.noise, b.noise)]
    return Ciphertext(slots=slots, noise=noise, scale=a.scale, level=a.level)


def ckks_mul(a: Ciphertext, b: Ciphertext) -> Ciphertext:
    if not isinstance(a, Ciphertext) or not isinstance(b, Ciphertext):
        raise TypeError("a and b must be Ciphertext")
    if a.scale != b.scale:
        raise ValueError("ckks_mul: scale mismatch")
    if a.level != b.level:
        raise ValueError("ckks_mul: level mismatch")
    _require_same_len(a.slots, b.slots, name="ckks_mul")

    msg_a = [x - e for x, e in zip(a.slots, a.noise)]
    msg_b = [y - e for y, e in zip(b.slots, b.noise)]
    msg_prod = [x * y for x, y in zip(msg_a, msg_b)]

    slots = [x * y for x, y in zip(a.slots, b.slots)]
    noise = [c - m for c, m in zip(slots, msg_prod)]
    return Ciphertext(slots=slots, noise=noise, scale=a.scale * b.scale, level=a.level)


def ckks_rescale(ct: Ciphertext, *, factor: int) -> Ciphertext:
    if not isinstance(ct, Ciphertext):
        raise TypeError("ct must be Ciphertext")
    factor = _require_positive_int("factor", factor)
    if ct.scale % factor != 0:
        raise ValueError("ckks_rescale: factor must divide ct.scale exactly in this toy model")

    slots = [round_div_int(x, factor) for x in ct.slots]
    noise = [round_div_int(e, factor) for e in ct.noise]
    return Ciphertext(slots=slots, noise=noise, scale=ct.scale // factor, level=ct.level + 1)


def max_abs(xs: Iterable[int]) -> int:
    m = 0
    for x in xs:
        ax = abs(_require_int("x", x))
        if ax > m:
            m = ax
    return m


def approx_linf_error(decoded: Sequence[float], expected: Sequence[float]) -> float:
    _require_same_len(decoded, expected, name="approx_linf_error")
    errs = [abs(_require_finite_real("decoded", a) - _require_finite_real("expected", b)) for a, b in zip(decoded, expected)]
    return max(errs) if errs else 0.0


def _fmt_floats(xs: Sequence[float], *, digits: int = 6) -> str:
    return "[" + ", ".join(f"{x:.{digits}f}" for x in xs) + "]"


def main():
    values = [1.25, -0.5, 2.0]
    scale = 2**10

    print("=== Step 1: Encode & decode (scale + rounding) ===")
    pt = ckks_encode(values, scale=scale)
    dec = ckks_decode(pt)
    print("values:", _fmt_floats(values))
    print("encoded slots:", pt.slots, "scale:", pt.scale)
    print("decoded:", _fmt_floats(dec))
    print("max |quantization error|:", approx_linf_error(dec, values))
    print()

    print("=== Step 2: Encrypt & decrypt (noise = approximation error) ===")
    ct = ckks_encrypt(pt, noise_bound=3, seed=123, level=0)
    dec_ct = ckks_decode(ckks_decrypt(ct))
    print("noise slots:", ct.noise, "max|noise|:", max_abs(ct.noise))
    print("decrypted decoded:", _fmt_floats(dec_ct))
    print("max |error| vs plaintext:", approx_linf_error(dec_ct, values))
    print()

    print("=== Step 3: Add in ciphertext space (same scale) ===")
    ct_sum = ckks_add(ct, ct)
    dec_sum = ckks_decode(ckks_decrypt(ct_sum))
    expect_sum = [2 * x for x in values]
    print("expected:", _fmt_floats(expect_sum))
    print("got:", _fmt_floats(dec_sum))
    print("max |error|:", approx_linf_error(dec_sum, expect_sum))
    print("max|noise| grew from", max_abs(ct.noise), "to", max_abs(ct_sum.noise))
    print()

    print("=== Step 4: Multiply + rescale (scale grows, then shrink it) ===")
    ct_prod = ckks_mul(ct, ct)
    print("raw scale after mul:", ct_prod.scale)
    ct_rs = ckks_rescale(ct_prod, factor=scale)
    dec_prod = ckks_decode(ckks_decrypt(ct_rs))
    expect_prod = [x * x for x in values]
    print("expected:", _fmt_floats(expect_prod))
    print("got:", _fmt_floats(dec_prod))
    print("max |error|:", approx_linf_error(dec_prod, expect_prod))
    print("level after rescale:", ct_rs.level)


if __name__ == "__main__":
    main()
