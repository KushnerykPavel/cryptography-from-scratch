# Big Integers in Every Language

> Big integers are easy until you serialize them. Then every bug becomes a protocol bug.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 00, Lesson 02 (Bytes/Hex/Base64)
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

Cryptography is built on integers that are far larger than what “native” machine integers can hold: 256-bit scalars, 2048-bit RSA moduli, 12,381-bit curve field elements, 4096-bit groups, and beyond.

In Python, that part feels deceptively easy because `int` is unbounded. The pain starts the moment you need to interoperate:

- network protocols encode integers as bytes (big-endian, fixed-length)
- test vectors are written in hex strings, not Python integers
- different languages disagree on defaults (signed vs unsigned, endianness, minimal vs fixed-length)

If you get serialization wrong, your implementation can “work locally” and still fail every RFC/NIST vector — or worse, accept malformed encodings in a way that becomes a vulnerability.

## The Concept

There are three separate questions that people often mix up:

1. **Representation in memory:** how a big integer is stored internally (usually “limbs”).
2. **Representation on the wire:** how the same integer is encoded as bytes (endianness + length).
3. **Canonicalization:** whether multiple byte strings are allowed to represent the same integer.

### Endianness: same bits, different bytes

Consider the integer:

```
x = 0x12_34_56
```

It can be encoded as bytes in two common ways:

```
big-endian (most significant byte first):    12 34 56
little-endian (least significant byte first): 56 34 12
```

Crypto protocols almost always use **big-endian** for integers on the wire.

### Fixed-length vs minimal-length bytes

The integer `9` can be encoded as:

```
minimal:  09
fixed(2): 00 09
fixed(4): 00 00 00 09
```

All three decode to the same integer. That’s convenient — and also a source of bugs when a protocol expects a **fixed length**.

RFC 8017 (PKCS #1) makes this explicit via two named conversions:

- **OS2IP**: Octet String to Integer Primitive (bytes → integer)
- **I2OSP**: Integer to Octet String Primitive (integer → fixed-length bytes)

### Limbs: how big integers are stored

Most big-integer libraries store values as a list of fixed-size “limbs”, e.g. 32-bit chunks:

```
x = limb[0] + limb[1]*2^32 + limb[2]*2^(64) + ...
```

This is why “carry” exists: addition is performed limb-by-limb.

## Build It

### Step 1: OS2IP (bytes → integer)

Implement the RFC-style decoding: treat the input as a big-endian base-256 number.

```python
def os2ip(x: bytes) -> int:
    n = 0
    for b in x:
        n = (n << 8) | b
    return n
```

### Step 2: I2OSP (integer → fixed-length bytes)

I2OSP is the inverse of OS2IP, but with a critical constraint: the caller chooses the output length, and values that don’t fit must fail.

```python
def i2osp(x: int, x_len: int) -> bytes:
    ...
```

In this repo we implement it via `uint_to_bytes_be(x, length)` and raise `ValueError("integer too large")` if the value does not fit.

### Step 3: Limb arithmetic (how BigInt libraries work)

To see what languages without unbounded integers are doing, represent a nonnegative integer as a little-endian list of 32-bit limbs and implement addition with carry.

```python
def split_uint_le_limbs(x: int, *, limb_bits: int = 32) -> list[int]:
    ...

def add_le_limbs(a: list[int], b: list[int], *, limb_bits: int = 32) -> list[int]:
    ...
```

## Use It

In production code, you normally use your language’s hardened primitives:

- Python: `int.from_bytes(data, "big", signed=False)` and `x.to_bytes(length, "big", signed=False)`
- GMP-backed big integers (optional): `gmpy2.mpz` for performance in some number-theory-heavy workloads

Two footguns to watch:

1. `signed` defaults differ across languages and libraries. In this course, treat most crypto integers as **unsigned** unless a spec explicitly says otherwise.
2. Fixed-length encodings are protocol requirements, not formatting preferences. Use I2OSP-style checks when a spec gives a length.

## Attack It

The most common “big integer bug” is **accepting multiple encodings** of the same integer when a protocol expects a unique one.

Example: these are different byte strings:

```
01
00 01
00 00 01
```

But OS2IP maps all of them to the same integer `1`.

If you verify signatures, parse keys, or hash transcript elements and you do not enforce a fixed length (or other canonical rule), you can introduce:

- **malleability** (multiple encodings for the same value)
- **parser differentials** across implementations (“works in Python, fails in Rust”)
- **length-leakage bugs** (when secret-dependent integer sizes are observable)

The defense is boring and effective: when a spec says “exactly `k` bytes”, implement I2OSP with a length check and reject any non-canonical encoding.

## Ship It

Use `outputs/prompt-bigint-encoding.md` as a checklist for integer encoding decisions (endianness, fixed/minimal length, signedness, and canonicalization).

## Exercises

1. Easy: Write a helper `uint_to_bytes_be(x)` that returns the minimal-length big-endian encoding and round-trip it with OS2IP.
2. Medium: Add support for 16-bit limbs and verify `combine_uint_le_limbs(split_uint_le_limbs(x, limb_bits=16)) == x` for random values.
3. Hard: Implement subtraction on limb lists (with borrow), and add test vectors for edge cases like underflow.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Big integer | “A bigger int” | An integer type that grows to as many bits as needed (often stored as limbs). |
| Limb | “A chunk” | A fixed-size word (e.g. 32 bits) used as the internal base for big integers. |
| Endianness | “Byte order” | The ordering of bytes when serializing a multi-byte number. |
| Canonical encoding | “The correct format” | A rule that makes the encoding unique (prevents alternate forms like leading zeros). |
| I2OSP / OS2IP | “Integer ↔ bytes” | RFC-defined conversions used widely in RSA and related specs. |

## Test Vectors

Source: RFC 8017 (PKCS #1 v2.2), Section 4 (I2OSP/OS2IP). Code must pass `tests/vectors.json`.

## Further Reading

- [RFC 8017: PKCS #1 v2.2](https://www.rfc-editor.org/rfc/rfc8017) — defines I2OSP/OS2IP and RSA encoding rules.
- [Python `int.to_bytes` / `int.from_bytes`](https://docs.python.org/3/library/stdtypes.html#int.to_bytes) — the standard, audited way to do these conversions in Python.
