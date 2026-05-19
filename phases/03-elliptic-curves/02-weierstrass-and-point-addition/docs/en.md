# Weierstrass Form & Point Addition

> Point addition is “just algebra” — until you miss one edge case and your protocol falls apart.

**Type:** Build
**Languages:** Python
**Prerequisites:** 01-number-theory/03-modular-inverse-and-fast-exp, 02-abstract-algebra/01-groups, 03-elliptic-curves/01-why-elliptic-curves
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain the four edge cases (identity, inverse, vertical line, doubling with `y = 0`) that every correct short-Weierstrass point-addition implementation must handle
- Compute the slope `λ` using the chord formula for distinct points and the tangent formula for doubling, both modulo `p`
- Implement curve validation using the discriminant condition `4a³ + 27b² ≠ 0 (mod p)` to detect singular curves
- Distinguish valid on-curve points from attacker-supplied points of small order and explain the resulting small-subgroup information leak
- Verify point-addition results by checking that the output satisfies the curve equation mod `p`

## The Problem

ECC codebases look deceptively simple: a point is two integers, and “adding points” is a few modular multiplications and one modular inverse.

The trap is that **the formula only works if you handle the geometry’s special cases**: identity, inverses, vertical lines, and doubling. Miss one case and you don’t just get wrong math — you can get:

- crashed signature verification (division by zero),
- interoperability bugs (“works for most points but fails sometimes”),
- security bugs when you accept untrusted points (invalid-curve / small-subgroup issues).

This lesson turns the chord-and-tangent picture into an exact finite-field implementation you can test and reason about.

## The Concept

### Short Weierstrass form (prime fields)

We’ll use a short Weierstrass curve over a prime field `F_p`:

```text
E: y^2 ≡ x^3 + a·x + b  (mod p)
```

To avoid extra complications, assume:

- `p > 3` (so `2` and `3` are invertible),
- the curve is **non-singular**, meaning it has no cusps/self-intersections.

For short Weierstrass curves, non-singular is equivalent to:

```text
4a^3 + 27b^2 ≠ 0 (mod p)
```

### The group law in one paragraph

Over the reals, the group law is: draw the line through `P` and `Q`, find the third intersection `R'`, then reflect across the x-axis to get `R = P + Q`. The identity element is the “point at infinity” `𝒪`, and inverses are `(x, y) -> (x, -y)`.

Over `F_p` you can’t draw the curve, but the **same algebraic formulas** define a valid group operation.

### Where the formulas come from

Let `P = (x1, y1)` and `Q = (x2, y2)` be points on the curve, and consider the line:

```text
y = λx + ν
```

Plugging into the curve equation gives a cubic in `x`. The three roots are the `x`-coordinates of the intersection points: `x1`, `x2`, and `x3` (for the third intersection).

For short Weierstrass curves, the resulting addition formulas are:

1) Slope `λ`:

- If `P != Q`:

```text
λ = (y2 - y1) / (x2 - x1) (mod p)
```

- If `P == Q` (doubling; use the tangent line):

```text
λ = (3x1^2 + a) / (2y1) (mod p)
```

2) New point:

```text
x3 = λ^2 - x1 - x2 (mod p)
y3 = λ(x1 - x3) - y1 (mod p)
```

### The four edge cases you must handle

1) **Identity**: `P + 𝒪 = P`.
2) **Inverse**: `P + (-P) = 𝒪`.
3) **Vertical line**: if `x1 == x2` and `y1 == -y2`, the denominator is `0` and the result is `𝒪`.
4) **Doubling with y = 0**: the tangent is vertical, so `2P = 𝒪`.

These are not “rare corner cases”. They happen all the time in real protocols.

## Build It

We’ll implement:

- curve validation (non-singular short Weierstrass),
- point membership checks,
- point addition (including all edge cases),
- scalar multiplication (only to exercise the group law; not constant-time),
- tiny “small subgroup” demo to motivate point validation.

### Step 1: Represent the curve and points

Use `None` to represent the identity element `𝒪`.

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int


@dataclass(frozen=True)
class Point:
    x: int
    y: int


ECPoint = Point | None
```

### Step 2: Validate the curve (non-singular)

```python
def curve_is_singular(curve: Curve) -> bool:
    p = curve.p
    return (4 * pow(curve.a, 3, p) + 27 * pow(curve.b, 2, p)) % p == 0


def validate_curve(curve: Curve) -> None:
    if curve.p <= 3:
        raise ValueError("p must be > 3 for short Weierstrass form")
    if curve_is_singular(curve):
        raise ValueError("curve is singular")
```

### Step 3: Modular inverse (division in F_p)

Point addition needs division. Over `F_p`, division is multiplication by an inverse, so we implement `mod_inv`.

```python
def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse does not exist")

    t, new_t = 0, 1
    r, new_r = p, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r

    if r != 1:
        raise ValueError("inverse does not exist")
    return t % p
```

### Step 4: Membership check and negation

```python
def is_on_curve(curve: Curve, point: ECPoint) -> bool:
    validate_curve(curve)
    if point is None:
        return True
    x, y = point.x % curve.p, point.y % curve.p
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0


def require_on_curve(curve: Curve, point: ECPoint) -> None:
    if not is_on_curve(curve, point):
        raise ValueError("point is not on curve")


def point_neg(curve: Curve, point: ECPoint) -> ECPoint:
    validate_curve(curve)
    if point is None:
        return None
    require_on_curve(curve, point)
    return Point(point.x % curve.p, (-point.y) % curve.p)
```

### Step 5: Point addition (with all edge cases)

This is the heart of the lesson.

```python
def point_add(curve: Curve, p: ECPoint, q: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    require_on_curve(curve, q)

    if p is None:
        return q
    if q is None:
        return p

    if p.x % curve.p == q.x % curve.p and (p.y + q.y) % curve.p == 0:
        return None

    if p != q:
        lam = (q.y - p.y) * mod_inv(q.x - p.x, curve.p)
    else:
        if p.y % curve.p == 0:
            return None
        lam = (3 * p.x * p.x + curve.a) * mod_inv(2 * p.y, curve.p)

    lam %= curve.p
    x3 = (lam * lam - p.x - q.x) % curve.p
    y3 = (lam * (p.x - x3) - p.y) % curve.p
    result = Point(x3, y3)
    require_on_curve(curve, result)
    return result
```

### Step 6: Scalar multiplication (only to exercise the group law)

This is *not* a production-safe scalar mul. It’s a correctness scaffold so you can test `point_add` in a few ways.

```python
def scalar_mul(curve: Curve, k: int, p: ECPoint) -> ECPoint:
    validate_curve(curve)
    require_on_curve(curve, p)
    if p is None or k == 0:
        return None
    if k < 0:
        return scalar_mul(curve, -k, point_neg(curve, p))

    acc: ECPoint = None
    addend: ECPoint = p

    while k > 0:
        if k & 1:
            acc = point_add(curve, acc, addend)
        addend = point_add(curve, addend, addend)
        k >>= 1

    return acc
```

Run it:

```
python3 code/main.py
```

## Use It

Real libraries don’t usually expose “point add” as a public API, but they do implement it internally and they do expose curve points you can add.

With the `ecdsa` Python package, you can sanity-check a known curve like secp256k1:

```python
from ecdsa.curves import SECP256k1

G = SECP256k1.generator
twoG = G + G

print(G.x(), G.y())
print(twoG.x(), twoG.y())
```

Your from-scratch `point_add` should match the same doubling result when you plug in secp256k1’s `(p, a, b)` and `G`.

## Attack It

Point addition is “pure math”, but **how you use it** can create security vulnerabilities.

Here’s the core pattern behind invalid-curve / small-subgroup attacks in ECDH-style protocols:

1) Victim has secret scalar `k`.
2) Attacker sends a malicious point `Q` of **small order**.
3) Victim computes `S = k·Q` and returns something derived from `S` (often `x(S)`).
4) Since `Q` has order `r`, there are only `r` possible outputs, so the attacker learns `k mod r`.

Toy demo curve:

```text
E: y^2 = x^3 + 1 (mod 97)
|E(F_97)| = 84, so small-order points exist.
```

Example: `Q = (60, 46)` has order `7`. That means `k·Q` can only be one of 7 points (including `𝒪`), so observing the result leaks `k mod 7`.

The lesson-level fix is simple: **validate points** and (in real curves) also enforce subgroup membership / cofactor clearing where relevant.

## Ship It

This lesson ships a short checklist-style prompt you can reuse whenever you implement or review elliptic-curve point arithmetic:

- `outputs/prompt-ec-point-addition-checklist.md`

## Exercises

1. Implement `point_double(curve, p)` as a thin wrapper and verify it matches `point_add(curve, p, p)` for 10 random points on a small curve.
2. For the toy curve `y^2 = x^3 + 1 (mod 97)`, find a point of order `14`. Verify that `k·Q` leaks `k mod 14` if you treat the output as a secret.
3. Modify `point_add` to accept points in Jacobian coordinates and implement a Jacobian-to-affine conversion. Compare the number of modular inversions needed.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Short Weierstrass form | “The normal curve equation” | A simplified curve model `y^2 = x^3 + ax + b` valid over fields with characteristic not 2 or 3. |
| Point at infinity `𝒪` | “A fake point” | The identity element that makes the curve points into a group. |
| Discriminant | “Some parameter check” | A condition that rules out singular curves; for short Weierstrass curves, `4a^3 + 27b^2 != 0 (mod p)`. |
| Doubling | “Same as add, just P=P” | The tangent-line case with slope `(3x^2 + a)/(2y)`; special-case when `y = 0`. |
| Small subgroup | “Just a math detail” | A small-order set of points that can leak information about secret scalars if an implementation multiplies untrusted points without subgroup checks. |

## Test Vectors

Vectors live in `tests/vectors.json` and are exercised by `tests/test_vectors.py`.

Source notes:

- Group law formulas: SEC 1: Elliptic Curve Cryptography (Version 2.0), Section 2.3.
- secp256k1 test points are cross-checked against the `ecdsa` Python library.

## Further Reading

- SEC 1: Elliptic Curve Cryptography (Version 2.0) — concise reference for group law formulas.
- Hankerson, Menezes, Vanstone, *Guide to Elliptic Curve Cryptography* — the “why” behind edge cases and validation.
