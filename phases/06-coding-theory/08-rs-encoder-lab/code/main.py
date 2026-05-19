"""
Reed–Solomon encoder lab (GF(256), primitive polynomial 0x11D).

This lesson focuses on the *encoder* side:
- GF(256) arithmetic using log/exp tables
- Polynomial operations over GF(256)
- Generator polynomial construction from consecutive roots
- Systematic RS encoding via polynomial long division
- Shortening RS(255,243) to the GSM/EDGE RS8(85,73) outer code

Run:
  python3 phases/06-coding-theory/08-rs-encoder-lab/code/main.py
"""

from __future__ import annotations


PRIM_POLY = 0x11D
GENERATOR = 2
FIELD_CHARAC = 255

GSM_EDGE_RS255W243_N = 255
GSM_EDGE_RS255W243_K = 243
GSM_EDGE_RS255W243_NSYM = GSM_EDGE_RS255W243_N - GSM_EDGE_RS255W243_K  # 12
GSM_EDGE_RS255W243_FIRST_ROOT = 122
GSM_EDGE_SHORTENING = 170
GSM_EDGE_RS85W73_N = GSM_EDGE_RS255W243_N - GSM_EDGE_SHORTENING  # 85
GSM_EDGE_RS85W73_K = GSM_EDGE_RS255W243_K - GSM_EDGE_SHORTENING  # 73

GSM_EDGE_RS255W243_GENERATOR_POLY_12: list[int] = [
    1,
    18,
    157,
    162,
    134,
    157,
    253,
    157,
    134,
    162,
    157,
    18,
    1,
]

GF_EXP: list[int] = [0] * (FIELD_CHARAC * 2)
GF_LOG: list[int] = [0] * 256


def assert_byte(x: int, *, name: str = "x") -> None:
    if not isinstance(x, int):
        raise TypeError(f"{name} must be int")
    if x < 0 or x > 255:
        raise ValueError(f"{name} must be in [0, 255]")


def assert_bytes(v: list[int], *, name: str = "v") -> None:
    if not isinstance(v, list):
        raise TypeError(f"{name} must be a list[int]")
    for i, b in enumerate(v):
        assert_byte(b, name=f"{name}[{i}]")


def gf_add(x: int, y: int) -> int:
    assert_byte(x, name="x")
    assert_byte(y, name="y")
    return x ^ y


def gf_mul_no_lut(x: int, y: int, *, prim: int = PRIM_POLY) -> int:
    assert_byte(x, name="x")
    assert_byte(y, name="y")
    r = 0
    while y:
        if y & 1:
            r ^= x
        y >>= 1
        x <<= 1
        if x & 0x100:
            x ^= prim
        x &= 0x1FF
    return r & 0xFF


def init_tables(*, prim: int = PRIM_POLY, generator: int = GENERATOR) -> None:
    assert_byte(generator, name="generator")
    x = 1
    for i in range(FIELD_CHARAC):
        GF_EXP[i] = x
        GF_LOG[x] = i
        x = gf_mul_no_lut(x, generator, prim=prim)
    for i in range(FIELD_CHARAC, FIELD_CHARAC * 2):
        GF_EXP[i] = GF_EXP[i - FIELD_CHARAC]


init_tables()


def gf_mul(x: int, y: int) -> int:
    assert_byte(x, name="x")
    assert_byte(y, name="y")
    if x == 0 or y == 0:
        return 0
    return GF_EXP[GF_LOG[x] + GF_LOG[y]]


def gf_div(x: int, y: int) -> int:
    assert_byte(x, name="x")
    assert_byte(y, name="y")
    if y == 0:
        raise ZeroDivisionError("division by zero in GF(256)")
    if x == 0:
        return 0
    return GF_EXP[(GF_LOG[x] + FIELD_CHARAC - GF_LOG[y]) % FIELD_CHARAC]


def gf_pow(x: int, power: int) -> int:
    assert_byte(x, name="x")
    if not isinstance(power, int):
        raise TypeError("power must be int")
    if power < 0:
        return gf_pow(gf_inv(x), -power)
    if x == 0:
        return 0 if power > 0 else 1
    return GF_EXP[(GF_LOG[x] * power) % FIELD_CHARAC]


def gf_inv(x: int) -> int:
    assert_byte(x, name="x")
    if x == 0:
        raise ZeroDivisionError("0 has no inverse in GF(256)")
    return GF_EXP[FIELD_CHARAC - GF_LOG[x]]


def poly_trim(p: list[int]) -> list[int]:
    assert_bytes(p, name="p")
    i = 0
    while i < len(p) - 1 and p[i] == 0:
        i += 1
    return p[i:]


def poly_add(p: list[int], q: list[int]) -> list[int]:
    assert_bytes(p, name="p")
    assert_bytes(q, name="q")
    r = [0] * max(len(p), len(q))
    r[len(r) - len(p) :] = p[:]
    for i in range(len(q)):
        r[i + len(r) - len(q)] ^= q[i]
    return poly_trim(r)


def poly_mul(p: list[int], q: list[int]) -> list[int]:
    assert_bytes(p, name="p")
    assert_bytes(q, name="q")
    r = [0] * (len(p) + len(q) - 1)
    for j, qj in enumerate(q):
        if qj == 0:
            continue
        for i, pi in enumerate(p):
            if pi == 0:
                continue
            r[i + j] ^= gf_mul(pi, qj)
    return poly_trim(r)


def poly_div(dividend: list[int], divisor: list[int]) -> tuple[list[int], list[int]]:
    assert_bytes(dividend, name="dividend")
    assert_bytes(divisor, name="divisor")
    if len(divisor) == 0 or all(c == 0 for c in divisor):
        raise ZeroDivisionError("polynomial division by zero")

    msg_out = dividend[:]
    for i in range(len(dividend) - (len(divisor) - 1)):
        coef = msg_out[i]
        if coef != 0:
            for j in range(1, len(divisor)):
                if divisor[j] != 0:
                    msg_out[i + j] ^= gf_mul(divisor[j], coef)
    sep = -(len(divisor) - 1)
    quotient = msg_out[:sep] if sep != 0 else []
    remainder = msg_out[sep:] if sep != 0 else msg_out[:]
    return poly_trim(quotient), poly_trim(remainder)


def poly_eval(p: list[int], x: int) -> int:
    assert_bytes(p, name="p")
    assert_byte(x, name="x")
    y = p[0]
    for c in p[1:]:
        y = gf_mul(y, x) ^ c
    return y


def rs_generator_poly(nsym: int, *, first_root: int = 0) -> list[int]:
    if not isinstance(nsym, int):
        raise TypeError("nsym must be int")
    if nsym <= 0:
        raise ValueError("nsym must be >= 1")
    if not isinstance(first_root, int):
        raise TypeError("first_root must be int")
    if first_root < 0:
        raise ValueError("first_root must be >= 0")

    g = [1]
    for i in range(nsym):
        g = poly_mul(g, [1, gf_pow(GENERATOR, first_root + i)])
    return g


def rs_encode_msg(msg: list[int], nsym: int, *, first_root: int = 0) -> list[int]:
    assert_bytes(msg, name="msg")
    if not isinstance(nsym, int):
        raise TypeError("nsym must be int")
    if nsym <= 0:
        raise ValueError("nsym must be >= 1")
    if len(msg) + nsym > FIELD_CHARAC:
        raise ValueError("message too long for GF(256) RS codeword")
    gen = rs_generator_poly(nsym, first_root=first_root)
    _, remainder = poly_div(msg + [0] * nsym, gen)
    remainder = ([0] * (nsym - len(remainder))) + remainder
    return msg + remainder


def rs_calc_syndromes(codeword: list[int], nsym: int, *, first_root: int = 0) -> list[int]:
    assert_bytes(codeword, name="codeword")
    if not isinstance(nsym, int):
        raise TypeError("nsym must be int")
    if nsym <= 0:
        raise ValueError("nsym must be >= 1")
    return [0] + [poly_eval(codeword, gf_pow(GENERATOR, first_root + i)) for i in range(nsym)]


def gsm_edge_rs85w73_encode(data73: list[int]) -> list[int]:
    assert_bytes(data73, name="data73")
    if len(data73) != GSM_EDGE_RS85W73_K:
        raise ValueError(f"data73 must have length {GSM_EDGE_RS85W73_K}")
    msg243 = [0] * GSM_EDGE_SHORTENING + data73
    code255 = rs_encode_msg(msg243, GSM_EDGE_RS255W243_NSYM, first_root=GSM_EDGE_RS255W243_FIRST_ROOT)
    code85 = code255[GSM_EDGE_SHORTENING:]
    if len(code85) != GSM_EDGE_RS85W73_N:
        raise AssertionError("internal error: shortened length mismatch")
    return code85


def gsm_edge_rs85w73_syndromes(code85: list[int]) -> list[int]:
    assert_bytes(code85, name="code85")
    if len(code85) != GSM_EDGE_RS85W73_N:
        raise ValueError(f"code85 must have length {GSM_EDGE_RS85W73_N}")
    expanded = [0] * GSM_EDGE_SHORTENING + code85
    return rs_calc_syndromes(expanded, GSM_EDGE_RS255W243_NSYM, first_root=GSM_EDGE_RS255W243_FIRST_ROOT)


def format_bytes(v: list[int], *, max_len: int = 48) -> str:
    if len(v) <= max_len:
        return "[" + ", ".join(f"{b:02x}" for b in v) + "]"
    head = v[: max_len // 2]
    tail = v[-(max_len // 2) :]
    return "[" + ", ".join(f"{b:02x}" for b in head) + ", …, " + ", ".join(f"{b:02x}" for b in tail) + "]"


def main() -> int:
    print("\n=== Step 1: GF(256) basics (3GPP/ETSI field) ===\n")
    checks = [
        (224, 18),
        (32, 157),
        (209, 162),
        (99, 134),
        (80, 253),
        (255, 1),
    ]
    for exp, expected in checks:
        got = gf_pow(GENERATOR, exp)
        ok = "OK" if got == expected else "MISMATCH"
        print(f"α^{exp:<3} = {got:3} (0x{got:02x})  expected {expected:3} (0x{expected:02x})  [{ok}]")

    print("\n=== Step 2: Polynomials over GF(256) ===\n")
    p = [1, 2, 3]
    q = [5, 0, 7]
    print(f"p(x) = {p}")
    print(f"q(x) = {q}")
    print(f"p(x) + q(x) = {poly_add(p, q)}")
    print(f"p(x) * q(x) = {poly_mul(p, q)}")
    quotient, remainder = poly_div(poly_mul(p, q), p)
    print(f"(p*q) / p => quotient={quotient}, remainder={remainder}")

    print("\n=== Step 3: Generator polynomial (RS(255,243), nsym=12) ===\n")
    g = rs_generator_poly(GSM_EDGE_RS255W243_NSYM, first_root=GSM_EDGE_RS255W243_FIRST_ROOT)
    print(f"g(x) degree = {len(g) - 1}")
    print(f"g(x) (computed) = {format_bytes(g)}")
    print(f"g(x) (spec)     = {format_bytes(GSM_EDGE_RS255W243_GENERATOR_POLY_12)}")
    print(f"matches spec?   = {g == GSM_EDGE_RS255W243_GENERATOR_POLY_12}")

    print("\n=== Step 4: Encode + shorten to RS8(85,73) (GSM/EDGE) ===\n")
    data73 = [(17 * i + 23) % 256 for i in range(GSM_EDGE_RS85W73_K)]
    code85 = gsm_edge_rs85w73_encode(data73)
    print(f"data73  = {format_bytes(data73)}")
    print(f"code85  = data73 || parity12 = {format_bytes(code85)}")
    synd = gsm_edge_rs85w73_syndromes(code85)
    print(f"syndromes(expanded(code85)) = {format_bytes(synd)}  (all-zero means valid)")

    print("\n=== Step 5: Error detection via syndromes ===\n")
    corrupted = code85[:]
    corrupted[3] ^= 0x99
    corrupted[-1] ^= 0x01
    synd_bad = gsm_edge_rs85w73_syndromes(corrupted)
    print(f"corrupted = {format_bytes(corrupted)}  (2 symbol errors injected)")
    print(f"syndromes = {format_bytes(synd_bad)}  (non-zero means 'not a codeword')")
    print(f"valid?    = {max(synd_bad) == 0}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
