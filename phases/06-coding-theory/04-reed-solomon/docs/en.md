# Reed-Solomon Codes (RS) — Burst Errors into Algebra

> Add parity as a polynomial constraint, then *solve for the errors*.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 6 Lesson 1 (Linear Codes), Phase 6 Lesson 2 (Hamming Distance), basic polynomial arithmetic  
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why Reed-Solomon works on **symbols** (bytes), not bits
- **Compute** syndromes by evaluating a codeword polynomial at roots of the generator polynomial
- **Implement** a systematic RS encoder over GF(256) using a generator polynomial
- **Distinguish** encoding (“polynomial division”) from decoding (BM + Chien + Forney)
- **Apply** a decoder that corrects up to `nsym//2` **symbol errors** and fails safely when it can’t

## The Problem

You’re moving data through a channel that does **bursts**: scratched discs, smeared QR codes, noisy radio packets, flaky NAND pages, or a UDP stream with clumps of corruption. A single burst can wreck dozens of consecutive bits.

Binary codes like Hamming are great for single-bit flips, but bursts quickly overwhelm them: the corruption is not “one bit somewhere”, it’s “a chunk is wrong”. If you treat this as a bit-level problem, your redundancy budget explodes.

Reed-Solomon solves this by switching the unit of corruption: instead of “a bit is wrong”, the model is “a **symbol** is wrong” (typically one byte). Then you can correct multiple *byte* errors even if each bad byte has many bad bits — exactly what burst noise looks like after interleaving or chunking.

## The Concept

### RS in one sentence

A Reed-Solomon codeword is a polynomial over a finite field that is forced to have **known zeros** at specific field points; those zeros become “parity constraints” that let you recover from symbol errors.

### Why GF(256)?

If you want “1 symbol = 1 byte”, you want a field with 256 elements: **GF(2^8)**.

- Addition/subtraction in GF(2^8) is XOR (same as GF(2), just on bytes).
- Multiplication/division are not integer multiply/divide. They are “multiply polynomials mod an irreducible polynomial”, typically `0x11D` for RS over bytes.

### Encoding (systematic)

Let `nsym = n-k` be the number of parity symbols you add. The RS encoder:

1. Builds a **generator polynomial**  
   \[
   g(x) = \prod_{i=0}^{nsym-1} (x - \alpha^i)
   \]
2. Treats the message as a polynomial `m(x)` and computes a codeword `c(x)` so that `c(x)` is divisible by `g(x)`.

In code, this becomes “append `nsym` zeros, divide by `g(x)`, append the remainder as parity”.

### Decoding (syndrome → locator → positions → magnitudes)

Decoding is a pipeline:

1. Compute **syndromes** by evaluating the received polynomial at the roots of `g(x)`. If all are zero: no errors.
2. Use **Berlekamp–Massey** to recover the **error locator polynomial**.
3. Use **Chien search** to find its roots ⇒ error positions.
4. Use **Forney’s algorithm** to compute error magnitudes and correct the bytes.
5. Recompute syndromes to confirm the fix; otherwise, fail (too many errors / ambiguous).

## Build It

### Step 1: GF(256) arithmetic (log/exp tables)

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

This is the “engine room”: GF(256) multiplication/division using log/exp tables (plus a slow no-table multiply to build those tables). The *only* thing that makes GF(256) “GF” is the modular reduction by `PRIM_POLY`.

### Step 2: Polynomials over GF(256)

```python
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
```

RS encoding/decoding is mostly polynomial plumbing. The key thing to notice is that polynomial addition is just XOR (coefficient-wise), while multiply/divide use GF(256) multiply/divide.

### Step 3: Generator polynomial and systematic encoding

```python
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
```

Systematic encoding means the codeword literally begins with the message bytes. The parity is computed so the *whole* codeword polynomial is divisible by `g(x)`.

### Step 4: Syndromes + error locations (BM + Chien)

```python
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
```

The first exit hatch is syndromes: if they’re all zero, the codeword is valid. If not, BM reconstructs an error locator polynomial whose roots correspond to error locations, then Chien search finds those roots by brute-force evaluation.

### Step 5: Error magnitudes and full decode (Forney)

```python
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
```

This step is the “danger zone” from a production perspective: decoders can miscorrect when there are too many errors. The safety rule is simple: **recompute syndromes after correction** and fail if any remain non-zero.

Run it:

```bash
python3 code/main.py
```

## Use It

In real systems, you don’t ship a from-scratch RS decoder. You pick a library and match parameters (field size, primitive polynomial, generator, `nsym`, interleaving, erasures, etc.).

| Use case | Typical choice | Notes |
|---|---|---|
| Python prototypes | `reedsolo` | Widely used reference implementation |
| Erasure coding (storage / distributed) | RS-erasure libraries (e.g., ISA-L, Jerasure, Rust crates) | Usually focus on erasures (known missing blocks) |
| QR / barcodes / media formats | Spec-defined RS parameters | The “library” is the spec + a known-good implementation |
| Hardware ECC | Controller firmware / silicon | Conventions and polynomials are fixed by the design |

## Pitfalls

- Confusing **symbol errors** with bit errors: RS corrects corrupted bytes; it does not “see” bit positions.
- Mixing conventions: codeword coefficient order, where parity sits, and which roots define syndromes must all match.
- Using the wrong primitive polynomial (`0x11D` vs something else) or generator element: you still get *a* field, but not the one your peer implementation expects.
- Forgetting the bound: with `nsym` parity bytes you correct at most `t = nsym//2` unknown symbol errors.
- Not failing safely: if you decode beyond capacity, you can get a plausible-looking output that is wrong — always re-check syndromes.

## Ship It

This lesson ships a reusable RS integration / code review prompt:

- Open `outputs/prompt-reed-solomon-ecc-review.md`
- Paste it into an assistant or a PR review
- Use it to verify field parameters, generator roots vs syndrome calculation, and “fail-safe” decoding behavior

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that 4 symbol errors are corrected (for `nsym=8`) and that 5 symbol errors fail.
2. Medium: Change the injected error positions/values in `main.py`. Verify you can correct any set of 4 symbol errors, and see how the reported `err_pos` changes.
3. Hard: Integrate RS into a “chunked file” toy: split a file into fixed-size byte chunks, append RS parity, corrupt random bytes, and recover — then replace your decoder with a production library and compare results byte-for-byte.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Symbol | “a byte” | One element of GF(256) (often stored as an 8-bit byte) |
| GF(256) | “finite field for bytes” | 256-element field with XOR addition and polynomial-reduced multiplication |
| Generator polynomial `g(x)` | “the parity polynomial” | Polynomial whose roots define the RS parity constraints |
| Syndrome | “error fingerprint” | Evaluations of the received polynomial at the roots of `g(x)` |
| Error locator polynomial | “finds where bytes are wrong” | Polynomial whose roots correspond to error positions |
| Chien search | “root finding” | Brute-force evaluation to find roots / positions efficiently enough in practice |
| Forney algorithm | “error values” | Computes the magnitudes to apply once positions are known |

## Further Reading

- Reed & Solomon, *Polynomial Codes Over Certain Finite Fields* (1960) — the original RS paper
- Blahut, *Algebraic Codes for Data Transmission* (2003) — practical decoding algorithms (BM / Forney)
- MacWilliams & Sloane, *The Theory of Error-Correcting Codes* (1977) — classic reference text
- Wikiversity, “Reed–Solomon codes for coders” (online) — hands-on derivations and implementation notes
