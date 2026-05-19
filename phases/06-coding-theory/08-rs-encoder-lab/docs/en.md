# RS Encoder Lab — Parity as a Remainder (GSM/EDGE RS8(85,73))

> A codeword is “valid” if dividing by `g(x)` leaves remainder zero.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 6 Lesson 4 (Reed-Solomon), basic polynomials
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** how RS parity is a polynomial remainder
- **Compute** generator polynomials from consecutive roots (with the right root offset)
- **Implement** a systematic RS encoder over GF(256)
- **Distinguish** “full-length” RS(255,243) from shortened RS8(85,73)
- **Apply** syndromes as a validity check (detect corruption)

## The Problem

Reed–Solomon encoding looks deceptively simple: “append parity bytes.” But in real systems, RS encoders fail in a more dangerous way than “crash”: they produce *plausible-looking parity* that is silently **incompatible** with everyone else.

The reason is that an RS code is not just “(n,k) with 12 parity bytes”. It is also defined by *conventions*: which primitive polynomial defines GF(256), which field element is used as `α`, which consecutive roots define `g(x)`, and (for shortened codes) where the “missing” symbols are assumed to be zero. One off-by-one root index (or a wrong shortening direction) gives you a codeword that no decoder can correct.

This lab builds a spec-aligned encoder for the GSM/EDGE outer code: shortened RS8(85,73) derived from RS8(255,243) over GF(256), with the generator polynomial roots starting at `α^122`.

## The Concept

### Encoder in one equation

Let `D(x)` be your message polynomial (coefficients are bytes in GF(256)). For `nsym` parity symbols, systematic RS encoding is:

\[
R(x) = \mathrm{remainder}\left[\frac{x^{nsym}D(x)}{g(x)}\right],\quad
U(x) = x^{nsym}D(x) + R(x)
\]

The key property is: `U(x)` is divisible by `g(x)`. That’s what makes the syndromes at the generator roots all zero.

### Why the “first consecutive root” matters

Many tutorials use:

\[
g(x) = \prod_{i=0}^{nsym-1}(x-\alpha^i)
\]

GSM/EDGE uses a shifted root set:

\[
g(x) = \prod_{i=0}^{11}(x-\alpha^{i+122})
\]

Same field, same `nsym`, different code.

### Shortening

Shortening RS(255,243) to RS(85,73) means:

- Pretend your message is 243 symbols by **prepending 170 zeros**
- Encode as RS(255,243) (systematic)
- Drop those 170 leading zeros from the codeword, leaving 85 symbols

## Build It

### Step 1: GF(256) arithmetic (primitive polynomial 0x11D)

```python
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
```

This defines GF(256) as GF(2)[x] reduced modulo the primitive polynomial `0x11D` (i.e., `x^8 + x^4 + x^3 + x^2 + 1`). Addition is XOR; multiplication uses log/exp tables built from `GENERATOR = 2` as the primitive element `α`.

### Step 2: Polynomial arithmetic + long division

```python
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
```

This is the “CRC-style” engine of RS encoding: multiply by `x^nsym` (append zeros), divide by `g(x)`, keep the remainder as parity.

### Step 3: Generator polynomial + systematic encoding (with root offset)

```python
GSM_EDGE_RS255W243_N = 255
GSM_EDGE_RS255W243_K = 243
GSM_EDGE_RS255W243_NSYM = GSM_EDGE_RS255W243_N - GSM_EDGE_RS255W243_K  # 12
GSM_EDGE_RS255W243_FIRST_ROOT = 122

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
```

The GSM/EDGE generator polynomial is self-reciprocal because it uses the shifted roots `α^(122..133)`, matching the spec polynomial exactly.

### Step 4: Shorten RS(255,243) to RS8(85,73) and validate

```python
GSM_EDGE_SHORTENING = 170
GSM_EDGE_RS85W73_N = GSM_EDGE_RS255W243_N - GSM_EDGE_SHORTENING  # 85
GSM_EDGE_RS85W73_K = GSM_EDGE_RS255W243_K - GSM_EDGE_SHORTENING  # 73


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
```

Shortening is “prepend zeros, encode, then drop them”. To validate a shortened codeword, expand it back with those leading zeros and check that the syndromes are all zero.

Run it:

`python3 code/main.py`

## Use It

Production systems usually don’t implement RS arithmetic ad hoc.

- **GSM/EDGE implementations:** follow 3GPP TS 45.003 / ETSI TS 145 003 exactly (field polynomial + first root + shortening).
- **General RS libraries:** use well-tested RS codecs for storage/transport (often matrix-based for speed).
- **Hardware IP cores:** FPGA/DSP blocks typically expose parameters like primitive polynomial and “first consecutive root”.

## Pitfalls

- Using GF(256) with the wrong primitive polynomial (`0x11D` vs `0x11B` vs others).
- Using the right `nsym` but the wrong **first consecutive root** (GSM/EDGE uses `122`, not `0`).
- Mixing symbol order conventions (is index 0 the highest-degree coefficient or the first transmitted byte?).
- Shortening the wrong way (prepend vs append zeros) so the “systematic” part doesn’t match the spec.
- Failing open: accepting a codeword even when syndromes are non-zero.

## Ship It

This lesson ships an encoder review checklist you can reuse in PRs and audits:

- Open `outputs/rs-encoder-spec-alignment-checklist.md`
- Use it to review any RS encoder implementation for interop hazards (field parameters, root offset, shortening, validity checks).

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the spec generator polynomial matches when `first_root = 122`, and that corrupted codewords produce non-zero syndromes.
2. Medium. Modify `GSM_EDGE_RS255W243_FIRST_ROOT` to `0` and re-run. What changes in the parity bytes and syndrome checks? Restore it to `122`.
3. Hard. Integrate a real RS library (or hardware IP) and confirm you can reproduce the exact GSM/EDGE `g(x)` coefficients and syndromes using the same `(prim_poly, generator, first_root)`.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| GF(256) | “field of bytes” | 256 symbols with XOR add and polynomial-mod multiply |
| Primitive polynomial | “the reducer” | the irreducible polynomial that defines multiplication (here `0x11D`) |
| Primitive element `α` | “generator” | an element whose powers cover all non-zero field elements (here `2`) |
| First consecutive root | “B parameter” | exponent offset that picks which roots define `g(x)` (here `122`) |
| Generator polynomial `g(x)` | “the RS polynomial” | the degree-`nsym` polynomial whose roots define valid codewords |
| Shortening | “make it smaller” | prepend zero symbols, encode full length, then drop those symbols |
| Syndrome | “error indicator” | evaluations of the received polynomial at the generator roots |

## Further Reading

- 3GPP, *TS 45.003: GSM/EDGE Channel coding* — defines the RS8(85,73) outer code parameters.
- ETSI, *TS 145 003* — contains the explicit generator polynomial and `first_root = 122` construction for RS8(255,243).
- RFC 5510, *Reed-Solomon Forward Error Correction (FEC) Schemes* — a practical view of RS parameters and interop choices.
