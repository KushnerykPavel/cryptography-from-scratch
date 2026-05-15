# Finite Fields GF(2^n) — Binary Polynomial Math

> Bits become field elements when you stop carrying and start reducing polynomials.

**Type:** Build
**Languages:** Python
**Prerequisites:** 02-abstract-algebra/05-rings-ideals-quotients, 02-abstract-algebra/06-fields-and-extensions, 02-abstract-algebra/07-finite-fields-gf-p
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

Prime fields use integer residues. AES, BCH codes, binary elliptic curves, GHASH-style polynomial arithmetic, and many compact hardware circuits use a different shape: `GF(2^n)`.

In a binary field, an element is not an integer in the ordinary arithmetic sense. It is a polynomial whose coefficients are bits. The byte `0x57` is not "fifty seven" while the field operation is running. It is:

```text
0x57 = 0101 0111 = x^6 + x^4 + x^2 + x + 1
```

If you accidentally use integer addition, carries appear. Carries do not exist in `F_2[x]`. If you multiply bytes and reduce with `% 256`, you get a ring with the wrong algebra. AES MixColumns, AES inversion, Reed-Solomon style coding, and binary extension arithmetic all depend on the same habit: add with XOR, multiply without carries, then reduce by a fixed irreducible polynomial.

## The Concept

`GF(2^n)` is an extension field over `F_2`. Build it as a quotient:

```text
GF(2^n) = F_2[x] / (m(x))
```

where `m(x)` is an irreducible polynomial of degree `n`.

Each element is a polynomial with degree `< n`. Each coefficient is either `0` or `1`, so an element fits naturally in an integer bit pattern:

```text
bit position:  7 6 5 4 3 2 1 0
coefficient:   0 1 0 1 0 1 1 1
polynomial:      x^6 + x^4 + x^2 + x + 1
integer:       0x57
```

### Addition is XOR

In `F_2`, `1 + 1 = 0`. Adding two binary polynomials cancels terms that appear twice:

```text
  x^3 + x + 1       1011
+ x^3 + x^2 + 1   ^ 1101
----------------   ----
        x^2 + x      0110
```

The same operation is subtraction, because `-1 = 1` in characteristic 2.

### Multiplication is carryless

Polynomial multiplication still distributes terms, but coefficients are reduced modulo 2:

```text
(x^3 + x + 1)(x^2 + x)

= x^5 + x^4 + x^3 + x^2 + x^2 + x
= x^5 + x^4 + x^3 + x
```

The two `x^2` terms cancel.

As bit operations, multiplication is shift and XOR:

```text
if the low bit of b is set, XOR a into the result
shift a left
shift b right
repeat
```

No carries ever move between bit positions.

### Reduction chooses the field

Multiplication can produce degree `>= n`. To return to the field, divide by `m(x)` and keep the remainder.

AES uses:

```text
m(x) = x^8 + x^4 + x^3 + x + 1
     = 1_0001_1011
     = 0x11b
```

Every AES byte operation in the field happens modulo that polynomial.

```text
0x57 * 0x83 = 0xc1 in GF(2^8) with modulus 0x11b
```

Change the modulus and you have a different representation of a different field. Use a reducible modulus and you do not have a field at all.

### Why irreducible matters

The quotient `F_2[x] / (m(x))` is a field only when `m(x)` is irreducible. If `m(x)` factors, then nonzero elements can multiply to zero.

Example:

```text
x^3 + x^2 + x + 1 = (x + 1)(x^2 + 1)
```

Modulo that polynomial:

```text
(x + 1)(x^2 + 1) = 0
```

Both factors are nonzero. Division is broken.

## Build It

This lesson builds binary-polynomial helpers, a `GF2N` value type, and AES-friendly operations.

### Step 1: Encode polynomials as integers

The degree is the highest set bit:

```python
def poly_degree(poly: int) -> int:
    require_nonnegative(poly)
    return poly.bit_length() - 1
```

The AES modulus `0x11b` decodes as:

```python
poly_to_terms(0x11b)
# "x^8 + x^4 + x^3 + x + 1"
```

### Step 2: Add and multiply over F_2[x]

Addition is XOR:

```python
def poly_add(a: int, b: int) -> int:
    return a ^ b
```

Carryless multiplication scans the bits of `b`:

```python
def poly_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return result
```

This is polynomial multiplication before field reduction.

### Step 3: Divide polynomials

Binary polynomial long division cancels the leading term of the remainder until its degree is smaller than the divisor:

```python
def poly_divmod(dividend: int, divisor: int) -> tuple[int, int]:
    if divisor == 0:
        raise ValueError("division by zero polynomial")

    quotient = 0
    remainder = dividend
    divisor_degree = poly_degree(divisor)

    while remainder and poly_degree(remainder) >= divisor_degree:
        shift = poly_degree(remainder) - divisor_degree
        quotient ^= 1 << shift
        remainder ^= divisor << shift

    return quotient, remainder
```

`poly_mod(poly, modulus)` keeps only the remainder.

### Step 4: Multiply inside GF(2^n)

Field multiplication is carryless multiplication followed by reduction:

```python
def gf2n_mul(a: int, b: int, modulus: int) -> int:
    require_modulus(modulus)
    return poly_mod(poly_mul(a, b), modulus)
```

For AES:

```python
gf2n_mul(0x57, 0x83, 0x11b)
# 0xc1
```

Addition only needs XOR and masking to degree `< n`:

```python
def gf2n_add(a: int, b: int, modulus: int) -> int:
    mask = (1 << poly_degree(modulus)) - 1
    return (a ^ b) & mask
```

### Step 5: Invert with polynomial Euclid

To divide, find `x` such that:

```text
a(x) * x(x) + m(x) * y(x) = 1
```

Reducing modulo `m(x)` leaves:

```text
a(x) * x(x) = 1
```

So `x(x)` is the inverse of `a(x)` in the field.

```python
def gf2n_inverse(a: int, modulus: int) -> int:
    a = poly_mod(a, modulus)
    if a == 0:
        raise ValueError("zero has no multiplicative inverse")

    gcd, x, _ = poly_extended_gcd(a, modulus)
    if gcd != 1:
        raise ValueError("element is not invertible with this modulus")
    return poly_mod(x, modulus)
```

If the modulus is reducible, some nonzero values will fail here. That failure is useful: it exposes a bad field parameter.

### Step 6: Carry the modulus with the value

Like `Fp` in the previous lesson, `GF2N` prevents accidental cross-field arithmetic:

```python
@dataclass(frozen=True)
class GF2N:
    value: int
    modulus: int

    def __post_init__(self) -> None:
        require_modulus(self.modulus)
        object.__setattr__(self, "value", poly_mod(self.value, self.modulus))
```

Now field expressions read like algebra:

```python
a = GF2N(0x57, 0x11b)
b = GF2N(0x83, 0x11b)

a + b        # GF2N(0xd4, modulus=0x11b)
a * b        # GF2N(0xc1, modulus=0x11b)
a.inverse()  # GF2N(0xbf, modulus=0x11b)
```

### Step 7: Connect to AES

AES `xtime` multiplies one byte by `x`, represented as `0x02`:

```python
def aes_xtime(byte: int) -> int:
    return gf2n_mul(byte, 0x02, 0x11b)
```

AES MixColumns is a matrix-vector multiplication over the same field:

```text
[02 03 01 01]   [db]   [8e]
[01 02 03 01] * [13] = [4d]
[01 01 02 03]   [53]   [a1]
[03 01 01 02]   [45]   [bc]
```

The code implements one column with `aes_mix_single_column`.

## Use It

For real work, use a library that names the field and owns the side-channel details.

The `galois` package exposes field array classes:

```python
import galois

GF = galois.GF(2**8, irreducible_poly="x^8 + x^4 + x^3 + x + 1")
a = GF(0x57)
b = GF(0x83)
int(a * b)
# 0xc1
```

For AES itself, do not assemble your own block cipher from this lesson. Use PyCryptodome, OpenSSL, RustCrypto, libsodium, or another audited implementation. This lesson explains why the constants work, not how to ship a cipher.

## Attack It

The easy bug is using a reducible modulus and still calling the result a field.

Take:

```text
m(x) = x^3 + x^2 + x + 1
     = 0b1111
     = (x + 1)(x^2 + 1)
```

Then:

```text
(x + 1)(x^2 + 1) = 0 mod m(x)
```

In code:

```python
gf2n_mul(0b0011, 0b0101, 0b1111)
# 0
```

Both inputs are nonzero. Any protocol that expects every nonzero denominator to have an inverse can now fail. If a secret-dependent branch handles that failure differently, the bug can become a side channel.

The second bug is table timing. AES implementations often use lookup tables for speed. Secret-dependent table access can leak through cache behavior. That is why production AES uses constant-time software techniques or hardware instructions such as AES-NI where available.

## Ship It

This lesson ships `outputs/skill-binary-field-review.md`: a checklist for reviewing `GF(2^n)` arithmetic, AES field constants, irreducible-polynomial assumptions, and common representation bugs.

## Exercises

1. Compute `0x57 + 0x83` and `0x57 * 0x83` by hand using binary polynomials.
2. Add `gf2n_trace(a, modulus)` where the trace is `a + a^2 + a^(2^2) + ... + a^(2^(n-1))`.
3. Find a nonzero zero divisor for another reducible degree-4 polynomial over `F_2`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| `GF(2^n)` | A field of `n`-bit integers | A degree-`n` extension of `F_2` |
| Binary polynomial | A bit string | A polynomial whose coefficients are bits |
| Carryless multiplication | Weird integer multiply | Polynomial multiplication over `F_2` |
| Irreducible polynomial | A modulus | A polynomial that creates a field quotient |
| AES modulus | `0x11b` | `x^8 + x^4 + x^3 + x + 1` |
| `xtime` | Left shift with a trick | Multiplication by `x` in the AES field |

## Test Vectors

Source: project-internal binary-polynomial examples plus AES `GF(2^8)` examples from NIST FIPS 197, Sections 4.2.1 and 5.1.3. The AES field uses `x^8 + x^4 + x^3 + x + 1`, encoded as `0x11b`. The current NIST FIPS 197 update was published May 9, 2023, with no technical changes to the AES algorithm.

Run:

```bash
python3 phases/02-abstract-algebra/08-finite-fields-gf-2n/tests/test_vectors.py
```

## Further Reading

- [NIST FIPS 197, Advanced Encryption Standard](https://doi.org/10.6028/NIST.FIPS.197-upd1) - the AES standard and the source for the AES field and MixColumns examples.
- [NIST update note for FIPS 197](https://www.nist.gov/news-events/news/2023/05/nist-updates-fips-197-advanced-encryption-standard-aes) - confirms the 2023 update made no technical changes to AES.
- [Handbook of Applied Cryptography, Chapter 2](https://cacr.uwaterloo.ca/hac/about/chap2.pdf) - finite-field background for applied cryptography.
- [galois documentation](https://galois.readthedocs.io/en/stable/) - practical Python finite-field arrays and polynomial tools.
