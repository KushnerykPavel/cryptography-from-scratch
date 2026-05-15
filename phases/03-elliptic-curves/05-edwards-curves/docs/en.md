# Edwards & Twisted Edwards Curves

> Edwards curves make elliptic-curve addition “complete”: fewer special cases, faster formulas, and cleaner constant-time structure.

**Type:** Build
**Languages:** Python
**Prerequisites:** 03-elliptic-curves/02-weierstrass-and-point-addition, 03-elliptic-curves/03-scalar-multiplication
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## The Problem

You’ll keep seeing “Curve25519”, “Ed25519”, “Ristretto”, “Decaf”, and “twisted Edwards” in real systems:

- Ed25519 signatures use a **twisted Edwards** curve for fast group operations.
- Many constant-time ECC designs rely on **complete/unified** formulas (avoid “if P == Q then…”).
- Protocol security reviews often come down to subgroup / cofactor details: “Did you validate the point? Did you clear the cofactor?”

If you only know short Weierstrass formulas, Edwards curves can look like a different planet. This lesson gives you a working mental model and a from-scratch implementation for **Edwards25519 (the Edwards form behind Ed25519)**:

- decode/encode points (compressed form),
- add/double points (extended coordinates),
- do scalar multiplication,
- demonstrate the classic cofactor pitfall (small-subgroup confinement).

## The Concept

### Edwards vs twisted Edwards

An (untwisted) Edwards curve over a prime field `F_p` is often written:

```text
x^2 + y^2 = 1 + d x^2 y^2
```

A **twisted Edwards** curve generalizes this with a parameter `a`:

```text
a x^2 + y^2 = 1 + d x^2 y^2
```

For Ed25519/Edwards25519, `a = -1` (mod `p`) and `p = 2^255 - 19`.

### Group law: the key facts

For twisted Edwards curves (with suitable parameters), points form an abelian group under addition:

- Identity: `𝟘 = (0, 1)`
- Negation: `-(x, y) = (-x, y)`

That’s already a big quality-of-life improvement over Weierstrass form (where the identity is a “point at infinity”).

### Affine addition (what you’d write first)

Given `P = (x1, y1)` and `Q = (x2, y2)`, the twisted Edwards affine formulas are:

```text
x3 = (x1 y2 + y1 x2) / (1 + d x1 x2 y1 y2)
y3 = (y1 y2 - a x1 x2) / (1 - d x1 x2 y1 y2)
```

This is great for understanding, but it has a practical problem: each “division” is a modular inverse, which is expensive.

### Extended coordinates (what real code uses)

Real implementations avoid inversions by switching to projective-style coordinates. For Ed25519, a very common choice is **extended Edwards coordinates**:

```text
x = X/Z
y = Y/Z
T = XY/Z
```

Then point addition and doubling become sequences of field multiplications and additions (no inversions), and for Ed25519 the formulas used in practice are described in RFC 8032.

### Cofactor and subgroup checks

Edwards25519 has a **cofactor** of 8:

```text
|E(F_p)| = 8 · l
```

where `l` is a large prime (the “main subgroup” order).

Consequences:

- Not every on-curve point is in the prime-order subgroup.
- If you accept untrusted points (ECDH-style), you must either:
  - validate subgroup membership, or
  - clear the cofactor, or
  - use a construction like Ristretto that removes the cofactor hazard by design.

## Build It

We’ll implement Edwards25519 (the curve used by Ed25519) with:

- point encoding/decoding (compressed form),
- extended-coordinate add/double,
- scalar multiplication (double-and-add),
- subgroup check (`l·P == 𝟘`) and cofactor clearing (`8·P`).

### Step 1: Curve constants + point representation

Edwards25519 uses:

- `p = 2^255 - 19`
- `a = -1 (mod p)`
- `d = -121665 / 121666 (mod p)`
- subgroup order `l = 2^252 + 27742317777372353535851937790883648493`

In this lesson:

- affine points are `Point(x, y)`
- extended points are `ExtPoint(X, Y, Z, T)`
- identity is the *actual* point `(0, 1)` (no special `None` case)

```python
from main import ED25519_B_ENC, ed25519_decode

B = ed25519_decode(ED25519_B_ENC)
print(B)
```

### Step 2: Decode and encode points (compressed form)

Ed25519 encodes a point as:

- 255-bit little-endian `y`
- plus 1 sign bit for `x` (the low bit of `x`)

Decoding means:

1) parse `y` and `sign`
2) recover `x` using the curve equation (a square root mod `p`)
3) choose the root matching the sign bit

```python
from main import ed25519_decode, ed25519_encode, ed25519_identity

enc0 = ed25519_encode(ed25519_identity())
print(enc0.hex())
print(ed25519_decode(enc0))
```

### Step 3: Add and double points (extended coordinates)

Affine formulas are good for understanding but slow (inversions). The extended-coordinate formulas let us add and double using only field ops.

```python
from main import ED25519_B_ENC, ed25519_decode, ed25519_from_ext, ed25519_scalar_mul, ed25519_to_ext

B = ed25519_decode(ED25519_B_ENC)
B2 = ed25519_from_ext(ed25519_scalar_mul(2, ed25519_to_ext(B)))
print(B2)
```

### Step 4: Subgroup membership and cofactor clearing

When you accept points from an attacker (ECDH-style), “on-curve” is not enough: you must deal with the cofactor.

This lesson implements:

- `ed25519_is_in_prime_subgroup(P)` via `l·P == 𝟘`
- `ed25519_clear_cofactor(P)` via `8·P`

```python
from main import ed25519_clear_cofactor, ed25519_decode, ed25519_is_in_prime_subgroup

torsion = ed25519_decode(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"))
print(ed25519_is_in_prime_subgroup(torsion))
print(ed25519_clear_cofactor(torsion))
```

## Use It

Use audited libraries for real signatures and key exchange.

Ed25519 signatures in `cryptography`:

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

sk = ed25519.Ed25519PrivateKey.generate()
pk = sk.public_key()

msg = b"hello"
sig = sk.sign(msg)
pk.verify(sig, msg)
```

If you need a prime-order group abstraction on top of Edwards25519 for protocols, prefer constructions designed for that (e.g., Ristretto255), instead of rolling your own cofactor handling.

## Attack It

### Small-subgroup confinement (cofactor pitfall)

Suppose you (incorrectly) try to do “ECDH” on Edwards25519 by:

```text
shared = secret · peer_point
```

and you accept `peer_point` from the network without subgroup checks.

An attacker can send a **torsion point** `T` of small order (e.g., order 8). Then:

```text
shared = secret · T
```

can take only **8 possible values**, because `T` generates a tiny subgroup. This leaks `secret mod 8` immediately, and in real protocols repeated queries can leak more structure.

Mitigations:

- Reject points not in the prime-order subgroup (`l·P == 𝟘`).
- Or clear the cofactor before using a point (`P' = 8·P`).
- Or use a protocol/encoding that eliminates the cofactor hazard by design (e.g., X25519’s clamping rules for DH on the Montgomery form, or Ristretto for Edwards25519).

## Ship It

This lesson ships an Edwards25519 review checklist prompt:

- `outputs/prompt-ec-edwards-curves-checklist.md`

## Exercises

1. Easy: Verify that `ed25519_add_affine(B, B)` matches `2·B` (by encoding equality).
2. Medium: Find (by searching `y` values) an on-curve point `P` that is *not* in the prime-order subgroup, and show `ed25519_is_in_prime_subgroup(P) == False`.
3. Hard (security mindset): Implement a tiny “oracle” that returns `secret·P` for attacker-chosen `P`, and show how a torsion point recovers `secret mod 8`. Then show how cofactor clearing collapses the attack.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Twisted Edwards curve | “Like Edwards but with a” | Curve `a x^2 + y^2 = 1 + d x^2 y^2` over `F_p` |
| Extended coordinates | “Faster Edwards math” | A coordinate system that avoids inversions by tracking `(X, Y, Z, T)` |
| Cofactor | “A small multiplier” | The small factor (here 8) in the curve group order `|E| = 8·l` |
| Torsion / small subgroup | “Bad points” | Points whose order divides the cofactor (2/4/8 here) |
| Subgroup check | “Validate point” | Ensure `l·P = 𝟘` before using attacker-controlled points |

## Test Vectors

Source: RFC 8032 (Ed25519 encoding and formulas) and RFC 7748 (curve constants context). Code must pass `tests/vectors.json`.

## Further Reading

- RFC 8032 — EdDSA: Ed25519 and Ed448 (encoding + formulas)
- RFC 7748 — X25519 and X448 (Curve25519 context + cofactor handling choices)
- Bernstein et al. (2008): *Twisted Edwards Curves Revisited* (design + formulas)
- The Explicit Formula Database (hyperelliptic.org/EFD) — reference formulas for Edwards curves
