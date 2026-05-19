# Why Elliptic Curves — Group Law in Pictures

> An elliptic curve is a finite group disguised as points.

**Type:** Learn
**Languages:** Python
**Prerequisites:** 02-abstract-algebra/01-groups, 02-abstract-algebra/02-cyclic-groups, 01-number-theory/03-modular-inverse-and-fast-exp
**Time:** ~45 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain how the chord-and-tangent geometric construction defines point addition on an elliptic curve over the reals
- Identify the identity element, inverse, and group axioms satisfied by the set of points on a Weierstrass curve
- Compute point addition and scalar multiplication on a small finite-field toy curve (`y² = x³ + 7 mod 211`)
- Distinguish why ECC achieves ~128-bit security with 256-bit keys while RSA requires ~3072-bit keys for equivalent strength
- Apply a brute-force discrete-log search to recover a scalar on the toy curve and explain why the same attack is infeasible on real 256-bit curves

## The Problem

Elliptic curves show up everywhere: TLS certificates (ECDSA), modern key exchange (ECDH / X25519), blockchains (secp256k1), and even inside zero-knowledge systems (curve groups for commitments, pairings, and polynomial commitments).

But when you first see ECC code, it often feels like magic: a “public key” is a point `(x, y)` and a “private key” is an integer `k`, and the whole system hinges on the operation:

```text
P = k · G
```

If you don’t have a mental model for “adding points” and why the set of points forms a group, you can’t answer basic engineering questions:

- What is the identity element? What is the inverse?
- What does “multiply a point by an integer” actually do?
- Why do we need to validate points received from the network?
- Why do 256-bit curves feel “RSA-3072-ish” in security strength?

This lesson makes the group law intuitive first, then gives you a small finite-field playground where you can *see* the group structure in action.

## The Concept

An elliptic curve in (short) Weierstrass form looks like:

```text
y^2 = x^3 + a·x + b
```

Over the real numbers, you can draw it and define an “addition” operation geometrically.

### The chord-and-tangent picture (over the reals)

Take two points `P` and `Q` on the curve. Draw the line through them. That line intersects the curve at a third point `R'`. Reflect `R'` across the x-axis to get `R`.

Then define:

```text
P + Q = R
```

ASCII sketch (not to scale):

```text
           Q •
             \        • R (result)
              \      /
               \    /
                \  /
                 • R'   (third intersection)
                /
               /
           P •
```

Key takeaways you want to keep in your head:

- **Inverse is a flip.** If `P = (x, y)`, then `-P = (x, -y)` (reflect across the x-axis).
- **Identity is “the point at infinity.”** It’s the do-nothing element `𝒪`. A vertical line hits the curve at `P` and `-P`, so `P + (-P) = 𝒪`.
- **Doubling uses a tangent.** For `P + P`, use the tangent line at `P` instead of a chord.

Associativity is not obvious from the picture, but the full theory proves that this operation makes the curve points into an abelian group.

### What cryptography actually uses (finite fields)

ECC does *not* run over the real numbers. It runs over a finite field `F_p` (or sometimes `F_{2^m}`):

```text
y^2 ≡ x^3 + a·x + b  (mod p)
```

You can’t “draw” `F_p` points the same way, but the *same algebraic formulas* derived from the chord-and-tangent picture define the group operation. That’s why the picture is useful even though crypto runs in a finite field.

### Why elliptic curves are attractive

1. **Compact keys and signatures.** Rough rule of thumb for ~128-bit classical security:

| Symmetric | RSA modulus | ECC curve |
|----------:|------------:|----------:|
| 128-bit | ~3072-bit | ~256-bit |

2. **Fast operations at high security.** EC groups give you a large prime-order subgroup with efficient arithmetic.
3. **Hard reverse direction.** Given `G` and `P = k·G`, recovering `k` is the *elliptic-curve discrete log problem* (ECDLP). On real curves used in practice, the best known attacks are far from feasible.

## Build It

This is a Learn lesson, so you’ll implement a small playground:

- a toy curve `E: y^2 = x^3 + 7 (mod 211)`
- point addition `P + Q`
- scalar multiplication `k·P` (repeat-add)
- a brute-force discrete log (to see what “hard” means at tiny sizes)

### Step 1: Represent the curve and field inverse

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


def is_on_curve(curve: Curve, p: ECPoint) -> bool:
    if p is None:
        return True
    x, y = p.x, p.y
    return (y * y - (x * x * x + curve.a * x + curve.b)) % curve.p == 0
```

### Step 2: Negation and addition

```python
def point_neg(curve: Curve, p: ECPoint) -> ECPoint:
    if p is None:
        return None
    return Point(p.x, (-p.y) % curve.p)


def point_add(curve: Curve, p: ECPoint, q: ECPoint) -> ECPoint:
    if p is None:
        return q
    if q is None:
        return p

    if p.x == q.x and (p.y + q.y) % curve.p == 0:
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
    return Point(x3, y3)
```

### Step 3: Scalar multiplication (repeat-add)

```python
def scalar_mul(curve: Curve, k: int, p: ECPoint) -> ECPoint:
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

### Step 4: A “toy attack” (brute-force discrete log)

```python
def discrete_log_bruteforce(
    curve: Curve, base: Point, target: ECPoint, limit: int
) -> int | None:
    if target is None:
        return 0
    current: ECPoint = None
    for k in range(1, limit + 1):
        current = point_add(curve, current, base)
        if current == target:
            return k
    return None
```

For the lesson curve `E: y^2 = x^3 + 7 (mod 211)`, you can sanity-check everything with a known base point:

```python
curve = Curve(p=211, a=0, b=7)
g = Point(3, 33)
assert is_on_curve(curve, g)

p = scalar_mul(curve, 123, g)
assert discrete_log_bruteforce(curve, g, p, limit=199) == 123
assert point_add(curve, g, point_neg(curve, g)) is None
```

Run it:

```
python3 code/main.py
```

## Use It

In real life you almost never implement elliptic-curve arithmetic yourself. You use audited libraries and standardized curves.

Two Python examples:

### `cryptography` (high-level)

```python
from cryptography.hazmat.primitives.asymmetric import ec

priv = ec.generate_private_key(ec.SECP256R1())
pub = priv.public_key()
```

### `ecdsa` (educational)

```python
import ecdsa

sk = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
vk = sk.verifying_key
```

Your takeaway: *keep the mental model and the invariants; ship real code with real libraries.*

## Attack It

ECC is secure because ECDLP is hard at real sizes. But in small toy groups, it’s trivial:

```text
Given G and P = k·G, try k = 1, 2, 3, ... until you hit P.
```

In the playground curve (`p = 211`), the group order is `199`, so brute force takes at most 199 steps. On a real 256-bit curve, it’s astronomically larger.

## Ship It

This lesson ships a reusable prompt you can use to sanity-check your intuition while reading real ECC code:

- `outputs/prompt-ec-group-law-mental-model.md`

## Exercises

1. Easy: On the toy curve, compute `-G` and verify `G + (-G) = 𝒪`.
2. Medium: Pick any `k` and verify `(199 - k)·G = -(k·G)` for the toy curve (order `199`).
3. Hard: Implement a “discrete log” brute force with a step limit, and show it recovers `k` for random `k` in `[1, 198]`.

## Key Terms

| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Elliptic curve | “A curve” | A set of solutions to an equation, plus one special point, with a group operation |
| Point at infinity (`𝒪`) | “A weird extra point” | The identity element for point addition |
| Point addition | “Add two points” | A group operation defined by algebraic formulas (in crypto: over `F_p`) |
| Scalar multiplication (`k·P`) | “Multiply a point by k” | Repeated addition: `P + P + ... + P` (k times) |
| ECDLP | “Discrete log on a curve” | Given `G` and `P = k·G`, find `k` |
| Point validation | “Check inputs” | Ensure a received point is on the curve (and in the right subgroup) before using it |

## Test Vectors

This is a Learn lesson, so vectors are “project-internal” for a toy curve. They pin down the group operation so you can trust the playground:

- `tests/vectors.json`
- `tests/test_vectors.py`

## Further Reading

- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf) — the standard reference for the group law and point formats
- [Guide to Elliptic Curve Cryptography](https://link.springer.com/book/10.1007/b97644) — practical ECC engineering context
