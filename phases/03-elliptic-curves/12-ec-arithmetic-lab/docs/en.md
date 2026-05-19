# Curve Lab — Build an EC Arithmetic Library

> ECC is not “one formula” — it’s a pile of edge cases, encodings, and invariants you must make explicit.

**Type:** Build
**Languages:** Python
**Prerequisites:** 03-elliptic-curves/02-weierstrass-and-point-addition, 03-elliptic-curves/03-scalar-multiplication, 03-elliptic-curves/04-montgomery-ladder, plus Phase 1 modular arithmetic basics
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Package short-Weierstrass curve arithmetic behind a coherent, testable API surface.
- Make failures explicit: invalid curves, invalid points, non-invertible denominators, and missing square roots.
- Implement multiple scalar multiplication strategies and cross-check them against each other.
- Use Jacobian coordinates to avoid inversions inside the main scalar-multiplication loop.
- Implement SEC1 point encodings (compressed/uncompressed) and safe decoding (on-curve validation).

## The Problem

In earlier lessons you implemented point addition, scalar multiplication, and a constant-pattern ladder. Each piece worked in isolation, but real cryptographic code is rarely “one function”. It is a small ecosystem:

- points arrive in byte encodings and must be parsed safely,
- curves must be validated (at least “not singular”),
- every function must handle the identity, inverses, and doubling edge cases consistently,
- scalars can be negative, zero, or huge,
- performance matters enough that you can’t do a field inversion for every addition.

If you don’t package these correctly, you don’t get a clean “math layer” to build ECDH, ECDSA, hash-to-curve, or protocol lessons on top of. You get a pile of copy-pasted formulas with inconsistent behavior.

This lab is the packaging step: one file, one style, one set of invariants, and one set of vectors.

## The Concept

### What a “tiny EC arithmetic library” needs

At minimum, for a prime-field short Weierstrass curve:

1) Curve validation:

```text
E: y^2 = x^3 + a·x + b  (mod p)
non-singular ⇔ 4a^3 + 27b^2 ≠ 0 (mod p)
```

2) Point validation:

- `𝒪` (the identity) is allowed.
- every affine point must satisfy the curve equation modulo `p`.

3) Group law (addition/doubling) with edge cases:

- identity, inverses, vertical lines, `y = 0` doubling.

4) Scalar multiplication that is:

- correct for `k=0`, `k<0`,
- testable across multiple strategies (double-and-add, NAF/wNAF, ladder),
- optionally structured to *aim* at constant-pattern behavior (ladder), while being honest about Python not being constant-time.

5) Byte encodings:

- uncompressed `0x04 || x || y`
- compressed `0x02/0x03 || x` where the prefix encodes `y` parity

Decoding compressed points requires a modular square root. That is where many “ECC is easy” implementations go wrong.

## Build It

The implementation lives in `code/main.py`.

### Step 1: Define types, errors, and modular helpers

This lab uses typed exceptions (e.g., `InvalidPointError`, `NoSquareRootError`) so tests can assert failure modes without string matching.

### Step 2: Curve and point validation

Implement:

- `validate_curve(curve)`
- `is_on_curve(curve, point)` and `require_on_curve(...)`

Point validation is not optional: you should never do arithmetic on untrusted points without it.

### Step 3: Affine group law (short Weierstrass)

Implement `point_add_affine(curve, P, Q)` and `point_neg(curve, P)`, using `None` for `𝒪`.

### Step 4: Scalar multiplication variants

Implement and cross-check:

- `scalar_mul_affine` (double-and-add baseline)
- `scalar_mul_naf_affine` and `scalar_mul_wnaf_affine`
- `scalar_mul_montgomery_ladder_affine` (constant-pattern structure per bit)

The goal is not “the fastest Python”. The goal is: multiple independent paths to the same output, so mistakes get caught.

### Step 5: Jacobian coordinates (avoid inversions in the loop)

Affine addition needs one modular inverse. In Jacobian coordinates, you pay inversions only when converting back to affine:

- `jacobian_double`, `jacobian_add`
- `scalar_mul_jacobian`

### Step 6: SEC1 encoding/decoding + modular square roots

Implement:

- `mod_sqrt(a, p)` (Tonelli–Shanks with a fast path when `p ≡ 3 (mod 4)`)
- `lift_x(curve, x, y_parity)` (decompress a point)
- `serialize_compressed`, `serialize_uncompressed`, `parse_point_sec1`

Decoding must validate that the resulting point is on-curve, and must reject invalid encodings cleanly.

Run it:

```
python3 code/main.py
```

## Use It

Do not implement EC arithmetic from scratch for production.

Use audited libraries:

- `cryptography` for X25519, ECDH, and ECDSA APIs.
- If you want a math-only cross-check in Python, `ecdsa` is a convenient reference for standard Weierstrass curves:

```python
from ecdsa.curves import SECP256k1

G = SECP256k1.generator
P = 37 * G
print(P.x(), P.y())
```

Treat cross-checks as a learning tool, not a security argument.

## Attack It

Two textbook failures show up over and over:

1) Invalid point acceptance

If you parse a point encoding and never check “is it on the curve?”, an attacker can send nonsense points that:

- crash your code (division by zero / no square root),
- or worse, push you into small subgroups / invalid curves in protocols that do scalar multiplication with secret scalars.

This lab makes “on-curve validation” part of the decoding and part of the arithmetic API.

2) Side-channel leakage from scalar multiplication

Double-and-add (and table-based wNAF) have secret-dependent control flow. The ladder is structured to do the same high-level work per scalar bit, but Python still isn’t constant-time. The correct lesson is reviewer mindset: recognize constant-time intent, and know when the environment invalidates it.

## Ship It

This lesson ships a review prompt for EC arithmetic implementations:

- `outputs/prompt-ec-arithmetic-library-review.md`

## Exercises

1. Easy: Add a `roundtrip_sec1(curve, P)` helper that asserts `parse_point_sec1(serialize_compressed(P)) == P` and same for uncompressed.
2. Medium: Add vectors for a second scalar multiplication strategy cross-check on secp256k1 (e.g., `k=123`, `k=2^255+1`) and verify all strategies match.
3. Hard (security mindset): Explain why “on-curve check” is not always enough (cofactor / subgroup membership) and when you must also check `n·P = 𝒪` or clear the cofactor.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| discriminant | “a curve validity check” | the expression `4a^3 + 27b^2 (mod p)`; zero means the curve is singular (bad) |
| point at infinity (`𝒪`) | “a special case” | the identity element of the elliptic-curve group |
| SEC1 encoding | “compressed pubkeys” | standard byte encodings for affine points, including parity-based compression |
| Tonelli–Shanks | “mod sqrt algorithm” | a method to compute `sqrt(a) (mod p)` when it exists (odd prime p) |
| Jacobian coordinates | “projective coords” | a representation that avoids inversions during point add/double by carrying a `z` coordinate |

## Test Vectors

Vectors are in `tests/vectors.json` and include:

- a toy curve over `p=97`,
- SEC1 encode/decode checks,
- secp256k1 and P-256 generator encodings,
- cross-checks that affine and Jacobian scalar multiplication agree.

## Further Reading

- SEC 1: Elliptic Curve Cryptography (Version 2.0) — point addition formulas and SEC1 encodings.
- Hankerson–Menezes–Vanstone: *Guide to Elliptic Curve Cryptography* — coordinate systems and scalar multiplication.
- RFC 7748 (X25519/X448) — ladder-style scalar multiplication design (for Montgomery curves).
