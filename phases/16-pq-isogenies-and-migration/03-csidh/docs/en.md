# CSIDH from Scratch (Toy Version)

> CSIDH is “just” a commutative walk over elliptic-curve isogenies — once you can build and evaluate small isogenies, the rest is protocol design and engineering discipline.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 16 · 01 (Isogenies basics), Phase 02 · Elliptic curves over finite fields (group law, scalar multiplication)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what CSIDH is trying to achieve (commutative group action for key exchange) and what makes it different from ECDH.
- **Compute** elliptic-curve group operations over a prime field `F_p` in short Weierstrass form.
- **Implement** odd-prime-degree isogenies via Vélu’s formulas for a cyclic kernel.
- **Distinguish** “isogeny math that works on tiny parameters” from “production-grade, constant-time CSIDH evaluation”.
- **Apply** the “transport the subgroup through the isogeny map” idea to build an order-independent two-prime quotient walk.

## The Problem

Isogeny-based cryptography is a maze of abstractions: graphs of curves, hidden paths, kernels, and “actions” that are not group operations in the usual sense. Without a concrete implementation of *one* isogeny step, everything sounds like magic — and you can’t meaningfully review designs, evaluate risks, or plan migrations.

This lesson makes CSIDH tangible by building the core plumbing from scratch: prime-field arithmetic, elliptic-curve arithmetic, finding torsion points, and constructing/evaluating small-degree isogenies. Once you can do that on toy parameters, you can reason about what must be hardened for real deployments (constant-time, validation, large parameters, and protocol safety).

## The Concept

**CSIDH in one line.** CSIDH (Commutative Supersingular Isogeny Diffie–Hellman) replaces “exponentiation in a group” (ECDH) with a **commutative action** of an ideal class group on a set of **supersingular elliptic curves over `F_p`**. The public key is (essentially) a curve identifier; the shared secret is the curve you get after applying both parties’ secret actions.

**What you’ll implement here (toy).**

- Work over a tiny prime field `F_p` where `p ≡ 3 (mod 4)`.
- Use the supersingular curve `E: y^2 = x^3 + x` which (for such `p`) has `#E(F_p) = p + 1`.
- Choose small primes `ℓ` dividing `#E(F_p)` so the curve has `ℓ`-torsion points.
- Use **Vélu’s formulas** to compute an `ℓ`-isogeny `φ: E → E' = E/⟨P⟩` given a generator `P` of a cyclic kernel.

**What you will *not* implement (and why).**

Real CSIDH uses **Montgomery curves** and carefully chosen kernels tied to Frobenius eigenspaces to make the action correspond to a class-group element (and to support negative exponents). It also needs constant-time evaluation and large parameters. That is far beyond “stdlib-only, in one file” — but the math building blocks below are the part you must understand to trust any CSIDH implementation.

## Build It

### Step 1: Finite-field building blocks (invert + sqrt)

All elliptic-curve arithmetic happens in `F_p`. We need modular inversion for division, and modular square root to find points.

```python
class ModSqrtError(ValueError):
    pass


def inv_mod(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("division by zero mod p")
    return pow(a, p - 2, p)


def legendre_symbol(a: int, p: int) -> int:
    a %= p
    if a == 0:
        return 0
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls


def sqrt_mod(a: int, p: int) -> int:
    """
    Return y such that y^2 ≡ a (mod p), for odd prime p.

    Deterministic: returns the smaller root min(y, p-y).
    Raises ModSqrtError if no square root exists.
    """
    a %= p
    if a == 0:
        return 0
    if p == 2:
        return a
    if legendre_symbol(a, p) != 1:
        raise ModSqrtError("not a quadratic residue")

    if p % 4 == 3:
        y = pow(a, (p + 1) // 4, p)
        return min(y, (-y) % p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1

    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    while t != 1:
        i = 1
        t2i = (t * t) % p
        while i < m and t2i != 1:
            t2i = (t2i * t2i) % p
            i += 1
        if i == m:
            raise ModSqrtError("tonelli-shanks failed")
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p

    return min(r, (-r) % p)
```

This is enough to (a) divide safely and (b) find points on a curve by scanning `x` and checking whether `x^3 + ax + b` is a quadratic residue.

### Step 2: Elliptic-curve points + group law

We represent a curve as `y^2 = x^3 + ax + b (mod p)`, and implement affine addition + double-and-add scalar multiplication.

```python
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int

    def normalize(self) -> "Curve":
        return Curve(self.p, self.a % self.p, self.b % self.p)


@dataclass(frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]

    @staticmethod
    def inf() -> "Point":
        return Point(None, None)

    def is_inf(self) -> bool:
        return self.x is None and self.y is None


def point_neg(curve: Curve, pt: Point) -> Point:
    if pt.is_inf():
        return pt
    assert pt.x is not None and pt.y is not None
    return Point(pt.x % curve.p, (-pt.y) % curve.p)


def point_add(curve: Curve, p1: Point, p2: Point) -> Point:
    if p1.is_inf():
        return p2
    if p2.is_inf():
        return p1

    p = curve.p
    assert p1.x is not None and p1.y is not None
    assert p2.x is not None and p2.y is not None

    x1, y1 = p1.x % p, p1.y % p
    x2, y2 = p2.x % p, p2.y % p

    if x1 == x2 and (y1 + y2) % p == 0:
        return Point.inf()

    if x1 == x2 and y1 == y2:
        num = (3 * x1 * x1 + curve.a) % p
        den = (2 * y1) % p
    else:
        num = (y2 - y1) % p
        den = (x2 - x1) % p

    lam = (num * inv_mod(den, p)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return Point(x3, y3)


def scalar_mul(curve: Curve, k: int, pt: Point) -> Point:
    if k == 0 or pt.is_inf():
        return Point.inf()
    if k < 0:
        return scalar_mul(curve, -k, point_neg(curve, pt))

    acc = Point.inf()
    base = pt
    while k:
        if k & 1:
            acc = point_add(curve, acc, base)
        base = point_add(curve, base, base)
        k >>= 1
    return acc
```

This is slow and not constant-time — perfect for learning, unacceptable for production.

### Step 3: Find torsion points on a supersingular curve

We’ll use the toy curve `E: y^2 = x^3 + x` over `F_p` with `p = 419 ≡ 3 (mod 4)`. For this curve, `#E(F_p) = p + 1 = 420 = 2^2·3·5·7`, so it contains points of orders `3` and `5`.

```python
from typing import Iterable


def count_points(curve: Curve) -> int:
    p = curve.p
    total = 1  # point at infinity
    for x in range(p):
        rhs = (x * x * x + curve.a * x + curve.b) % p
        ls = legendre_symbol(rhs, p)
        if ls == 0:
            total += 1
        elif ls == 1:
            total += 2
    return total


def iter_points(curve: Curve) -> Iterable[Point]:
    p = curve.p
    for x in range(p):
        rhs = (x * x * x + curve.a * x + curve.b) % p
        if rhs == 0:
            yield Point(x, 0)
            continue
        if legendre_symbol(rhs, p) == 1:
            y = sqrt_mod(rhs, p)
            yield Point(x, y)
            if y != 0:
                yield Point(x, (-y) % p)


def find_point_of_order(curve: Curve, ell: int, group_order: int) -> Point:
    if group_order % ell != 0:
        raise ValueError("ell does not divide group order")
    cofactor = group_order // ell
    for r in iter_points(curve):
        p = scalar_mul(curve, cofactor, r)
        if not p.is_inf() and scalar_mul(curve, ell, p).is_inf():
            return p
    raise ValueError("no point of the requested order found")
```

The idea: multiply a random point by the cofactor to land in the `ℓ`-torsion, then check the order.

### Step 4: Build and evaluate an odd-degree isogeny (Vélu)

Given a generator `P` of an odd prime-order subgroup `⟨P⟩`, Vélu’s formulas let us compute:

- the codomain curve `E' = E/⟨P⟩`, and
- the map `φ: E → E'` evaluated at points not in the kernel.

```python
def subgroup_points(curve: Curve, gen: Point, ell: int) -> list[Point]:
    pts: list[Point] = []
    acc = Point.inf()
    for k in range(1, ell):
        acc = point_add(curve, acc, gen) if not acc.is_inf() else gen
        pts.append(acc)
    return pts


def velu_isogeny_odd_prime(curve: Curve, gen: Point, ell: int) -> tuple[Curve, list[Point]]:
    """
    Vélu for odd prime-degree cyclic kernel <gen>, on y^2 = x^3 + a x + b (char != 2,3).

    Returns (codomain_curve, kernel_points_nonzero).
    """
    if ell <= 2:
        raise ValueError("this helper is for odd prime ell")
    if scalar_mul(curve, ell, gen).is_inf() is False:
        raise ValueError("gen is not of order ell")

    p = curve.p
    ker = subgroup_points(curve, gen, ell)

    t = 0
    w = 0
    for q in ker:
        assert q.x is not None and q.y is not None
        xq = q.x % p
        yq = q.y % p
        t_q = (3 * xq * xq + curve.a) % p
        u_q = (2 * yq * yq) % p
        w_q = (u_q + t_q * xq) % p
        t = (t + t_q) % p
        w = (w + w_q) % p

    a2 = (curve.a - 5 * t) % p
    b2 = (curve.b - 7 * w) % p
    return Curve(p, a2, b2), ker


def velu_map_point(curve: Curve, kernel_nonzero: list[Point], pt: Point) -> Point:
    """
    Evaluate φ(x,y) = (r(x), r'(x) * y) where
      r(x) = x + Σ_{Q != O} ( t_Q/(x-x_Q) + u_Q/(x-x_Q)^2 )
      t_Q = 3 x_Q^2 + a
      u_Q = 2 y_Q^2

    Raises ValueError if pt is in the kernel (division by zero).
    """
    if pt.is_inf():
        return pt

    p = curve.p
    assert pt.x is not None and pt.y is not None
    x = pt.x % p
    y = pt.y % p

    rx = x
    rpx = 1
    for q in kernel_nonzero:
        assert q.x is not None and q.y is not None
        xq = q.x % p
        yq = q.y % p
        denom = (x - xq) % p
        if denom == 0:
            raise ValueError("point is in the kernel (or shares x with it)")
        inv1 = inv_mod(denom, p)
        inv2 = (inv1 * inv1) % p
        inv3 = (inv2 * inv1) % p

        t_q = (3 * xq * xq + curve.a) % p
        u_q = (2 * yq * yq) % p

        rx = (rx + t_q * inv1 + u_q * inv2) % p
        rpx = (rpx - t_q * inv2 - 2 * u_q * inv3) % p

    return Point(rx, (rpx * y) % p)
```

This is the “one isogeny step” that everything else builds on.

### Step 5: A toy commutative pattern (two coprime kernels)

If you quotient by two **coprime-order** subgroups, the end result is order-independent *as long as you transport the remaining subgroup through the isogeny map*.

```python
def j_invariant(curve: Curve) -> int:
    """
    j(E) = 1728 * 4a^3 / (4a^3 + 27b^2)  (short Weierstrass, char != 2,3)
    """
    p = curve.p
    a = curve.a % p
    b = curve.b % p
    num = (1728 * 4 * pow(a, 3, p)) % p
    den = (4 * pow(a, 3, p) + 27 * pow(b, 2, p)) % p
    return (num * inv_mod(den, p)) % p


def velu_demo_two_prime_commute(base: Curve, p3: Point, p5: Point) -> dict[str, int]:
    """
    Demonstrate order-independence when quotients are taken by two coprime-order subgroups,
    as long as we transport the "other" subgroup through the isogeny map.
    """
    e3, ker3 = velu_isogeny_odd_prime(base, p3, 3)
    p5_on_e3 = velu_map_point(base, ker3, p5)
    e35, _ = velu_isogeny_odd_prime(e3, p5_on_e3, 5)

    e5, ker5 = velu_isogeny_odd_prime(base, p5, 5)
    p3_on_e5 = velu_map_point(base, ker5, p3)
    e53, _ = velu_isogeny_odd_prime(e5, p3_on_e5, 3)

    return {"j_e35": j_invariant(e35), "j_e53": j_invariant(e53)}
```

This is only a toy pattern, but it builds the intuition for why CSIDH can be commutative: you’re not just composing arbitrary walks; you’re applying an algebraic action with structure that survives reordering.

Run it:

`python3 code/main.py`

## Use It

Production implementations do **not** look like this lesson code:

- CSIDH implementations use Montgomery curves and specialized formulas (e.g., optimized Vélu variants) for large primes.
- Production code is constant-time and includes key validation, blinding/dummy work, and hardening against side channels.

If you want a reality check, compare:

| What you wrote | What production code adds |
|---|---|
| Affine points, inversion-heavy | Projective x-only arithmetic, careful ladders |
| `O(ℓ)` kernel enumeration | Faster isogeny evaluation (square-root Vélu and friends) |
| No constant-time discipline | Constant-time end-to-end, including failure paths |
| Tiny demo parameters | Large parameters + careful parameter generation |

## Pitfalls

1. **Secret-dependent control flow.** Early exits, branching on secret bits, or data-dependent table lookups leak through timing/cache.
2. **Invalid public keys.** Accepting malformed curve parameters or points can force exceptional cases (or worse: key recovery).
3. **Non-deterministic validation.** “Try until it works” loops leak information unless made constant-time.
4. **Confusing “same j-invariant” with “same curve over F_p”.** Over finite fields, equal `j` implies isomorphic over an algebraic closure, but protocol rules usually require a specific model/normal form.
5. **Over-trusting toy correctness.** Passing tiny tests means your algebra is plausible, not that your implementation is safe.

## Ship It

Save and reuse `outputs/csidh-review-and-migration-checklist.md` as:

- a PR review checklist when someone proposes isogeny-based KEX,
- a design doc template for answering the “hard questions” (validation, constant-time, negotiation, migration),
- a migration plan skeleton for PQ rollout.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe that `#E(F_p) = p + 1` for the toy curve and that the two quotient orders produce the same `j`.
2. **Medium.** Change `p` from `419` to another small prime `p ≡ 3 (mod 4)` (try a few) and see when `#E(F_p) = p + 1` still holds for `y^2 = x^3 + x`.
3. **Hard.** Add a third prime `ℓ = 7` (it also divides `420`) and extend the “order-independent” demo to compare three different quotient orders — but only by transporting the remaining torsion points through each isogeny map.

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Isogeny | “A map between curves” | A non-constant group homomorphism between elliptic curves with finite kernel. |
| Kernel | “Points that go to infinity” | The subgroup of points mapped to the identity (point at infinity) by the isogeny. |
| Supersingular | “Special curve” | Over `F_p`, a curve with special endomorphism structure; for some families it implies `#E(F_p) = p + 1`. |
| Vélu’s formulas | “Compute isogenies explicitly” | Explicit formulas to compute the quotient curve `E/G` and the isogeny map from `E` to `E/G` from the subgroup `G`. |
| Class-group action | “Walk that commutes” | An algebraic action where different secret elements commute; CSIDH uses this to mimic Diffie–Hellman without a traditional group operation. |

## Further Reading

- Castryck, Lange, Martindale, Panny, Renes — *CSIDH: An Efficient Post-Quantum Commutative Group Action* (2018) — the original CSIDH paper.
- Vélu — *Isogénies entre courbes elliptiques* (1971) — the original source of Vélu’s formulas.
- De Feo — *Mathematics of Isogeny Based Cryptography* (2017) — gentle survey with cryptographic perspective.
