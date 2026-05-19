"""
Reed-Solomon codes from scratch (GF(256), primitive polynomial 0x11D).

This script implements a minimal Reed-Solomon encoder/decoder over GF(2^8):
- GF(256) arithmetic with log/exp tables
- Polynomial operations in GF(256)
- Systematic RS encoding (append parity)
- Syndrome computation
- Decoding: Berlekamp–Massey + Chien search + Forney algorithm

Run:
  python3 phases/06-coding-theory/04-reed-solomon/code/main.py
"""

from __future__ import annotations


PRIM_POLY = 0x11D
GENERATOR = 2
FIELD_CHARAC = 255

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


def poly_scale(p: list[int], x: int) -> list[int]:
    assert_bytes(p, name="p")
    assert_byte(x, name="x")
    return [gf_mul(c, x) for c in p]


def poly_add(p: list[int], q: list[int]) -> list[int]:
    assert_bytes(p, name="p")
    assert_bytes(q, name="q")
    r = [0] * max(len(p), len(q))
    r[len(r) - len(p) :] = p[:]
    for i in range(len(q)):
        r[i + len(r) - len(q)] ^= q[i]
    return r


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


def poly_trim(p: list[int]) -> list[int]:
    i = 0
    while i < len(p) - 1 and p[i] == 0:
        i += 1
    return p[i:]


def rs_generator_poly(nsym: int) -> list[int]:
    if not isinstance(nsym, int):
        raise TypeError("nsym must be int")
    if nsym <= 0:
        raise ValueError("nsym must be >= 1")
    g = [1]
    for i in range(nsym):
        g = poly_mul(g, [1, gf_pow(GENERATOR, i)])
    return g


def rs_encode_msg(msg: list[int], nsym: int) -> list[int]:
    assert_bytes(msg, name="msg")
    if len(msg) + nsym > FIELD_CHARAC:
        raise ValueError("message too long for GF(256) RS codeword")
    gen = rs_generator_poly(nsym)
    _, remainder = poly_div(msg + [0] * nsym, gen)
    remainder = ([0] * (nsym - len(remainder))) + remainder
    return msg + remainder


def rs_calc_syndromes(codeword: list[int], nsym: int) -> list[int]:
    assert_bytes(codeword, name="codeword")
    if not isinstance(nsym, int):
        raise TypeError("nsym must be int")
    if nsym <= 0:
        raise ValueError("nsym must be >= 1")
    return [0] + [poly_eval(codeword, gf_pow(GENERATOR, i)) for i in range(nsym)]


def rs_find_error_locator(synd: list[int], nsym: int) -> list[int]:
    assert_bytes(synd, name="synd")
    if not isinstance(nsym, int):
        raise TypeError("nsym must be int")
    if len(synd) != nsym:
        raise ValueError("synd must have length nsym (no leading 0)")

    err_loc = [1]
    old_loc = [1]
    for i in range(nsym):
        delta = synd[i]
        for j in range(1, len(err_loc)):
            delta ^= gf_mul(err_loc[-(j + 1)], synd[i - j])
        old_loc = old_loc + [0]
        if delta != 0:
            if len(old_loc) > len(err_loc):
                new_loc = poly_scale(old_loc, delta)
                old_loc = poly_scale(err_loc, gf_inv(delta))
                err_loc = new_loc
            err_loc = poly_trim(poly_add(err_loc, poly_scale(old_loc, delta)))

    err_loc = poly_trim(err_loc)
    errs = len(err_loc) - 1
    if errs * 2 > nsym:
        raise ValueError("too many errors to correct")
    return err_loc


def rs_find_errors(err_loc: list[int], nmess: int) -> list[int]:
    assert_bytes(err_loc, name="err_loc")
    if not isinstance(nmess, int):
        raise TypeError("nmess must be int")
    if nmess <= 0:
        raise ValueError("nmess must be positive")

    errs = len(err_loc) - 1
    err_pos: list[int] = []
    for i in range(nmess):
        if poly_eval(err_loc, gf_pow(GENERATOR, i)) == 0:
            err_pos.append(nmess - 1 - i)
    if len(err_pos) != errs:
        raise ValueError("Chien search found wrong number of roots")
    return err_pos


def rs_find_errata_locator(coef_pos: list[int]) -> list[int]:
    if not isinstance(coef_pos, list) or any(not isinstance(i, int) for i in coef_pos):
        raise TypeError("coef_pos must be list[int]")
    e_loc = [1]
    for i in coef_pos:
        if i < 0:
            raise ValueError("coef_pos entries must be non-negative")
        e_loc = poly_mul(e_loc, poly_add([1], [gf_pow(GENERATOR, i), 0]))
    return e_loc


def rs_find_error_evaluator(synd: list[int], err_loc: list[int], nsym: int) -> list[int]:
    assert_bytes(synd, name="synd")
    assert_bytes(err_loc, name="err_loc")
    if not isinstance(nsym, int):
        raise TypeError("nsym must be int")
    product = poly_mul(synd, err_loc)
    return product[-(nsym + 1) :]


def rs_correct_errata(codeword: list[int], synd: list[int], err_pos: list[int]) -> list[int]:
    assert_bytes(codeword, name="codeword")
    assert_bytes(synd, name="synd")
    if not isinstance(err_pos, list) or any(not isinstance(i, int) for i in err_pos):
        raise TypeError("err_pos must be list[int]")
    if len(synd) < 2:
        raise ValueError("synd must include leading 0 and at least one syndrome")

    msg = codeword[:]
    coef_pos = [len(msg) - 1 - p for p in err_pos]
    err_loc = rs_find_errata_locator(coef_pos)
    err_eval = list(reversed(rs_find_error_evaluator(list(reversed(synd)), err_loc, len(err_loc) - 1)))

    X: list[int] = []
    for p in coef_pos:
        l = FIELD_CHARAC - p
        X.append(gf_pow(GENERATOR, -l))

    E = [0] * len(msg)
    for i, Xi in enumerate(X):
        Xi_inv = gf_inv(Xi)
        err_loc_prime = 1
        for j, Xj in enumerate(X):
            if j != i:
                err_loc_prime = gf_mul(err_loc_prime, gf_add(1, gf_mul(Xi_inv, Xj)))
        if err_loc_prime == 0:
            raise ValueError("Forney denominator is 0")

        y = poly_eval(list(reversed(err_eval)), Xi_inv)
        y = gf_mul(Xi, y)
        magnitude = gf_div(y, err_loc_prime)
        E[err_pos[i]] = magnitude

    if len(E) != len(msg):
        raise AssertionError("internal error: magnitude vector length mismatch")
    return [a ^ b for a, b in zip(msg, E)]


def rs_decode(codeword: list[int], nsym: int) -> tuple[list[int], list[int], list[int]]:
    assert_bytes(codeword, name="codeword")
    if not isinstance(nsym, int):
        raise TypeError("nsym must be int")
    if nsym <= 0:
        raise ValueError("nsym must be >= 1")
    if len(codeword) > FIELD_CHARAC:
        raise ValueError("codeword too long for GF(256) RS codeword")

    synd = rs_calc_syndromes(codeword, nsym)
    if max(synd) == 0:
        return codeword[:-nsym], codeword[:], []

    err_loc = rs_find_error_locator(synd[1:], nsym)
    err_pos = rs_find_errors(list(reversed(err_loc)), len(codeword))
    corrected = rs_correct_errata(codeword, synd, err_pos)

    synd2 = rs_calc_syndromes(corrected, nsym)
    if max(synd2) != 0:
        raise ValueError("could not correct message")
    return corrected[:-nsym], corrected, err_pos


def format_bytes(v: list[int], *, max_len: int = 48) -> str:
    if len(v) <= max_len:
        return "[" + ", ".join(f"{b:02x}" for b in v) + "]"
    head = v[: max_len // 2]
    tail = v[-(max_len // 2) :]
    return "[" + ", ".join(f"{b:02x}" for b in head) + ", …, " + ", ".join(f"{b:02x}" for b in tail) + "]"


def main() -> int:
    print("\n=== Step 1: GF(256) arithmetic ===\n")
    a, b = 0x53, 0xCA
    print(f"a = 0x{a:02x}, b = 0x{b:02x}")
    print(f"a + b = 0x{gf_add(a, b):02x}  (XOR)")
    print(f"a * b = 0x{gf_mul(a, b):02x}")
    print(f"a / b = 0x{gf_div(a, b):02x}")

    print("\n=== Step 2: Polynomials over GF(256) ===\n")
    p = [1, 2, 3]
    q = [5, 0, 7]
    x = 0x02
    print(f"p(x) = {p}")
    print(f"q(x) = {q}")
    print(f"p(x) + q(x) = {poly_add(p, q)}")
    print(f"p(x) * q(x) = {poly_mul(p, q)}")
    print(f"p(0x{x:02x}) = 0x{poly_eval(p, x):02x}")

    print("\n=== Step 3: RS generator polynomial and encoding ===\n")
    nsym = 8
    gen = rs_generator_poly(nsym)
    print(f"nsym = {nsym}, generator polynomial degree = {len(gen) - 1}")
    print(f"g(x) = {format_bytes(gen)}")
    msg = list(b"reed-solomon")
    codeword = rs_encode_msg(msg, nsym)
    print(f"msg      = {format_bytes(msg)}")
    print(f"codeword = msg || parity = {format_bytes(codeword)}")

    print("\n=== Step 4: Syndromes and decoding (correct up to nsym//2 symbol errors) ===\n")
    synd0 = rs_calc_syndromes(codeword, nsym)
    print(f"syndromes(codeword) = {format_bytes(synd0)}  (all-zero means valid)")

    received = codeword[:]
    for idx, val in [(1, 0xFF), (4, 0x11), (7, 0x42), (len(received) - 2, 0x99)]:
        received[idx] ^= val
    print(f"received = {format_bytes(received)}  (4 symbol errors injected)")

    decoded_msg, corrected, err_pos = rs_decode(received, nsym)
    print(f"err_pos  = {err_pos}")
    print(f"decoded  = {decoded_msg!r}")
    print(f"correct? = {decoded_msg == msg}")

    print("\n=== Step 5: Failure mode (too many errors) ===\n")
    received2 = codeword[:]
    for idx, val in [(0, 1), (2, 2), (3, 3), (5, 4), (6, 5)]:
        received2[idx] ^= val
    print(f"received2 = {format_bytes(received2)}  (5 symbol errors injected)")
    try:
        rs_decode(received2, nsym)
        print("unexpected: decoded with too many errors")
    except ValueError as e:
        print(f"decode failed as expected: {e}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
