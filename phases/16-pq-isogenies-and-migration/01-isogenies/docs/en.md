# Isogenies — Maps Between Elliptic Curves

> An isogeny is a “many-to-one” curve map whose kernel is a finite subgroup.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/03-elliptic-curves/02-weierstrass-and-point-addition`, `phases/03-elliptic-curves/03-scalar-multiplication`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** what an isogeny is (as a group homomorphism with finite kernel)
- **Compute** small elliptic-curve groups over `F_p` by brute force (toy sizes)
- **Implement** Vélu’s formulas for short Weierstrass curves over prime fields
- **Distinguish** isogeny vs isomorphism vs “just a coordinate change”
- **Apply** this to migration thinking: why SIDH/SIKE-style isogenies are not “drop-in PQ TLS”

## The Problem

Isogenies show up in two places that matter in practice:

1) **Modern theory / tooling**: elliptic curves are not isolated objects. They live inside *isogeny classes* — families of curves connected by structure-preserving maps. If you can’t recognize an isogeny, you can’t reason about “same group size but different curve”, and you can’t read the cryptography literature around supersingular curves.

2) **Post-quantum history & migration**: for a while, “supersingular isogeny graphs” were a serious PQC direction (SIDH/SIKE). Then in 2022, SIDH/SIKE fell to efficient key-recovery attacks. Teams still encounter the code and papers — and need a clear “what is an isogeny, what went wrong, and what do we migrate to?” mental model.

This lesson builds a tiny, runnable isogeny by hand. Not because you will implement SIDH in production (you must not), but because *you should be able to audit and reason about isogeny-based designs and migration decisions*.

## The Concept

### What an isogeny “is”

An **isogeny** is a structure-preserving map between elliptic curves:

- It’s a map `φ: E -> E'` that behaves like a **group homomorphism** on curve points:
  - `φ(P + Q) = φ(P) + φ(Q)`
- It has a **finite kernel**:
  - `ker(φ) = {P in E : φ(P) = O}` is a finite subgroup of `E`.

You can think of it as a quotient:

```
E  --φ-->  E'   where   E' ~ E / ker(φ)
```

### Why kernels matter (degree = kernel size)

For the toy case in this lesson:

- We work over a prime field `F_p` and a short Weierstrass curve:
  - `E: y^2 = x^3 + ax + b (mod p)`
- We pick a small cyclic subgroup `G = <K>` as the kernel.
- The isogeny degree is the kernel size: `deg(φ) = |G|`.

### Vélu’s formulas (the practical lever)

Vélu’s formulas say: **given the curve and the kernel points, you can explicitly compute**

- the **codomain curve** `E' = E/G`, and
- the **map** `φ(P)` for any point `P` not in the kernel,

using only finite-field arithmetic.

For short Weierstrass curves over `F_p`, one common presentation is:

- Split the kernel subgroup `G` into:
  - `{O}` (the point at infinity),
  - `G2` (points of order 2; these have `y = 0`),
  - `R` and `-R` (pairs `Q` and `-Q` for all other kernel points).
- Let `S = R ∪ G2` (one representative from each `±` pair, plus all 2-torsion points).

Then for each `Q = (x_Q, y_Q) in S` define:

- `u_Q = 4 y_Q^2`
- `v_Q = (3 x_Q^2 + a)` if `Q` has order 2, else `v_Q = 2(3 x_Q^2 + a)`

Compute:

- `v = Σ_{Q in S} v_Q`
- `w = Σ_{Q in S} (u_Q + x_Q v_Q)`

The codomain curve is:

```
E': y^2 = x^3 + (a - 5v) x + (b - 7w)
```

And the map `φ(x, y) = (X, Y)` is:

```
X = x + Σ_{Q in S} ( v_Q/(x - x_Q) + u_Q/(x - x_Q)^2 )
Y = y - Σ_{Q in S} ( u_Q*(2y)/(x - x_Q)^3
                    + v_Q*(y - y_Q)/(x - x_Q)^2
                    + 2y_Q*(3x_Q^2 + a)/(x - x_Q)^2 )
```

This looks scary, but in code it’s mostly “compute `dx = x - x_Q`, invert it, and accumulate”.

## Build It

### Step 1: Elliptic curve group law (toy)

We’ll implement a tiny elliptic-curve group over a prime field `F_p`, using a short Weierstrass equation and affine formulas. This is not fast and not constant-time — it’s a learning scaffold.

```python
from __future__ import annotations

from dataclasses import dataclass


Point = tuple[int, int] | None  # None == point at infinity


def inv_mod(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 mod p does not exist")
    t0, t1 = 0, 1
    r0, r1 = p, a
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        t0, t1 = t1, t0 - q * t1
    if r0 != 1:
        raise ZeroDivisionError("a is not invertible mod p")
    return t0 % p


def div_mod(n: int, d: int, p: int) -> int:
    return (n % p) * inv_mod(d, p) % p


@dataclass(frozen=True)
class ShortWeierstrassCurve:
    p: int
    a: int
    b: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "a", self.a % self.p)
        object.__setattr__(self, "b", self.b % self.p)
        if self.p <= 3:
            raise ValueError("p must be an odd prime > 3 for short Weierstrass demo")
        if self.discriminant() == 0:
            raise ValueError("singular curve (discriminant == 0)")

    def discriminant(self) -> int:
        p = self.p
        return (-16 * (4 * pow(self.a, 3, p) + 27 * pow(self.b, 2, p))) % p

    def is_on_curve(self, pt: Point) -> bool:
        if pt is None:
            return True
        x, y = pt
        p = self.p
        return (y * y - (x * x * x + self.a * x + self.b)) % p == 0

    def neg(self, pt: Point) -> Point:
        if pt is None:
            return None
        x, y = pt
        return (x % self.p, (-y) % self.p)

    def add(self, p1: Point, p2: Point) -> Point:
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2
        p = self.p

        x1 %= p
        y1 %= p
        x2 %= p
        y2 %= p

        if x1 == x2 and (y1 + y2) % p == 0:
            return None

        if x1 == x2 and y1 == y2:
            if y1 % p == 0:
                return None
            m = div_mod(3 * x1 * x1 + self.a, 2 * y1, p)
        else:
            m = div_mod(y2 - y1, x2 - x1, p)

        x3 = (m * m - x1 - x2) % p
        y3 = (m * (x1 - x3) - y1) % p
        return (x3, y3)

    def mul(self, k: int, pt: Point) -> Point:
        if k < 0:
            return self.mul(-k, self.neg(pt))
        acc: Point = None
        addend = pt
        while k:
            if k & 1:
                acc = self.add(acc, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return acc
```

This gives us everything we need to do “inputs → outputs” for point addition and scalar multiplication on a tiny curve.

### Step 2: Find a small kernel subgroup

For a toy isogeny we need an explicit kernel subgroup. We’ll brute-force all points on the curve, find a point of a target small order (here: 3), and expand its cyclic subgroup.

```python
    def enumerate_points(self) -> list[Point]:
        p = self.p
        pts: list[Point] = [None]
        for x in range(p):
            rhs = (x * x * x + self.a * x + self.b) % p
            for y in range(p):
                if (y * y) % p == rhs:
                    pts.append((x, y))
        return pts

    def subgroup_points(self, generator: Point) -> list[Point]:
        if generator is None:
            return [None]
        if not self.is_on_curve(generator):
            raise ValueError("generator is not on curve")
        pts = [None]
        cur = generator
        seen: set[Point] = {None}
        while cur not in seen:
            pts.append(cur)
            seen.add(cur)
            cur = self.add(cur, generator)
        if cur is not None:
            raise RuntimeError("subgroup generation did not return to infinity")
        return pts

    def order(self, pt: Point) -> int:
        if pt is None:
            return 1
        cur = None
        for k in range(1, self.p + 2 + 2 * int(self.p**0.5) + 10):
            cur = self.add(cur, pt)
            if cur is None:
                return k
        raise RuntimeError("failed to find point order (p too large for demo?)")


def find_point_with_order(curve: ShortWeierstrassCurve, target_order: int) -> Point:
    for pt in curve.enumerate_points():
        if pt is None:
            continue
        if curve.order(pt) == target_order:
            return pt
    raise ValueError(f"no point of order {target_order} found on this curve")
```

In real cryptography, we never brute-force points like this — we pick curves with known structure. Here, brute force keeps the demo dependency-free.

### Step 3: Build an isogeny using Vélu's formulas

Vélu’s formulas want a set `S` that contains:

- every 2-torsion kernel point (where `y = 0`), and
- exactly one representative from each `±` pair for the rest.

```python
def velu_kernel_representatives(curve: ShortWeierstrassCurve, kernel: list[Point]) -> list[Point]:
    p = curve.p
    reps: dict[tuple[int, int], Point] = {}
    for q in kernel:
        if q is None:
            continue
        xq, yq = q
        xq %= p
        yq %= p
        if yq == 0:
            reps[(xq, 0)] = (xq, 0)
            continue
        yneg = (-yq) % p
        yrep = yq if yq < yneg else yneg
        reps[(xq, yrep)] = (xq, yrep)
    return [reps[k] for k in sorted(reps)]
```

Then we implement the codomain coefficient update and the rational map `φ`. We also special-case kernel points so we never divide by zero: `φ(Q) = O` for all `Q` in the kernel.

```python
def velu_isogeny_short_weierstrass(
    curve: ShortWeierstrassCurve, kernel_generator: Point
) -> tuple[ShortWeierstrassCurve, callable[[Point], Point], list[Point]]:
    kernel = curve.subgroup_points(kernel_generator)
    if len(kernel) <= 2:
        raise ValueError("kernel must have size >= 3 (non-trivial separable isogeny)")

    s_points = velu_kernel_representatives(curve, kernel)

    p = curve.p
    a = curve.a
    b = curve.b

    v_sum = 0
    w_sum = 0
    per_q: list[tuple[Point, int, int, int]] = []
    for q in s_points:
        if q is None:
            continue
        xq, yq = q
        xq %= p
        yq %= p
        u_q = (4 * yq * yq) % p
        base = (3 * xq * xq + a) % p
        v_q = base if yq == 0 else (2 * base) % p
        v_sum = (v_sum + v_q) % p
        w_sum = (w_sum + u_q + xq * v_q) % p
        per_q.append((q, u_q, v_q, base))

    a2 = (a - 5 * v_sum) % p
    b2 = (b - 7 * w_sum) % p
    codomain = ShortWeierstrassCurve(p=p, a=a2, b=b2)

    kernel_set = set(kernel)

    def isogeny_map(pt: Point) -> Point:
        if pt is None:
            return None
        if pt in kernel_set:
            return None
        x, y = pt
        x %= p
        y %= p
        if not curve.is_on_curve((x, y)):
            raise ValueError("point is not on the domain curve")
        x_img = x
        y_img = y
        for q, u_q, v_q, base in per_q:
            xq, yq = q  # type: ignore[misc]
            dx = (x - xq) % p
            if dx == 0:
                raise ZeroDivisionError("isogeny undefined for this point (dx == 0)")
            inv_dx = inv_mod(dx, p)
            inv_dx2 = (inv_dx * inv_dx) % p
            inv_dx3 = (inv_dx2 * inv_dx) % p

            x_img = (x_img + v_q * inv_dx + u_q * inv_dx2) % p

            term1 = (u_q * (2 * y % p) * inv_dx3) % p
            term2 = (v_q * ((y - yq) % p) * inv_dx2) % p
            term3 = ((2 * yq % p) * base * inv_dx2) % p
            y_img = (y_img - term1 - term2 - term3) % p

        return (x_img, y_img)

    return codomain, isogeny_map, kernel
```

### Step 4: Migration demo: map a 'public key' point to the new curve

Now we wire the pieces into a runnable script that prints concrete inputs → outputs for every step.

```python
def step_header(n: int, name: str) -> None:
    print(f"=== Step {n}: {name} ===")


def main() -> None:
    curve = ShortWeierstrassCurve(p=101, a=2, b=3)

    step_header(1, "Elliptic curve group law (toy)")
    p = curve.p
    g = (1, 39)
    if not curve.is_on_curve(g):
        raise RuntimeError("expected base point is not on curve")
    print(f"Curve: y^2 = x^3 + {curve.a}x + {curve.b}  (mod {p})")
    print(f"G = {g}")
    print(f"2G = {curve.mul(2, g)}")
    print(f"7G = {curve.mul(7, g)}")

    step_header(2, "Find a small kernel subgroup")
    kgen = find_point_with_order(curve, target_order=3)
    kernel = curve.subgroup_points(kgen)
    print(f"Kernel generator (order 3): K = {kgen}")
    print(f"Kernel points: {kernel}")

    step_header(3, "Build an isogeny using Vélu's formulas")
    codomain, phi, kernel_pts = velu_isogeny_short_weierstrass(curve, kgen)
    print(f"Codomain curve: y^2 = x^3 + {codomain.a}x + {codomain.b}  (mod {codomain.p})")
    print(f"|E(F_p)| = {len(curve.enumerate_points())}")
    print(f"|E'(F_p)| = {len(codomain.enumerate_points())}")

    step_header(4, "Migration demo: map a 'public key' point to the new curve")
    pub = curve.mul(7, g)
    pub2 = phi(pub)
    print(f"Public key point P = 7G = {pub}")
    print(f"Mapped point φ(P) = {pub2}")
    if pub2 is not None and not codomain.is_on_curve(pub2):
        raise RuntimeError("mapped point is not on codomain curve")
    print("Done.")
```

Run it:

`python3 code/main.py`

## Use It

Real-world tooling does not brute-force points or use Python big loops:

- **SageMath**: has an `EllipticCurve(...).isogeny(...)` API (kernel point / kernel polynomial / degree-specific routines).
- **Research implementations**: SIDH/SIKE-era implementations compute long chains of small-degree isogenies on Montgomery curves.
- **Migration reality**: SIDH/SIKE is broken; use standardized PQ KEMs for key establishment.

| Goal | Use in production | Why |
|------|-------------------|-----|
| Compute an isogeny for math work | SageMath / Magma | Correctness + optimized algorithms |
| PQ key establishment | ML-KEM (Kyber) implementations | Standardized + widely deployed |
| Learn / verify formulas | Toy code like this | Small-field, audit-friendly, dependency-free |

## Pitfalls

- **Confusing isogeny with “same curve in different coordinates”**: an isomorphism is reversible; an isogeny typically is not (it collapses the kernel).
- **Forgetting the kernel special-case**: if you try to evaluate `φ(Q)` for a kernel point with the raw formula, you’ll hit division-by-zero.
- **Using a kernel set that isn’t closed under negation**: Vélu’s setup relies on pairing `Q` and `-Q` (except 2-torsion). Get this wrong and you’ll compute garbage.
- **Not checking the discriminant**: singular “curves” break the group law and silently invalidate algebra.
- **Treating this as production crypto**: affine formulas + inversions + branching are not constant-time; never use this code for secrets.

## Ship It

Save this lesson’s reusable artifact:

- `outputs/isogeny-migration-checklist.md`

Use it as a paste-ready checklist/prompt when reviewing a codebase or design doc for SIDH/SIKE exposure and migration work.

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe that `|E(F_p)|` and `|E'(F_p)|` match in the demo.
2. **Medium:** Change the kernel order in `find_point_with_order(curve, target_order=3)` to `5` (if a point of order 5 exists on this curve), and recompute the codomain. Confirm the kernel points map to `None`.
3. **Hard:** Add a test that checks the homomorphism property `φ(P + Q) = φ(P) + φ(Q)` for (say) 20 random non-kernel points (for this toy curve, “random” can just mean “take the first 20 points from enumeration”).

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Isogeny | “A map between curves” | A morphism that is also a group homomorphism with finite kernel |
| Kernel | “Points that map to infinity” | A finite subgroup `ker(φ) ⊂ E` that gets collapsed by the map |
| Degree | “Size of the map” | For separable isogenies in this setting: `deg(φ) = |ker(φ)|` |
| Isomorphism | “Same curve” | A bijective curve map; reversible; “coordinate change” lives here |
| Vélu’s formulas | “Explicit isogeny formulas” | A concrete recipe to compute `E/G` and `φ` from kernel points |

## Further Reading

- Wouter Castryck, Thomas Decru, *An efficient key recovery attack on SIDH* (2022) — the break that ended SIDH/SIKE as a PQ KEM candidate.
- “SIKE and SIDH are insecure and should not be used” (SIKE team statement) — an explicit deprecation note for migration planning.
- Lawrence Washington, *Elliptic Curves: Number Theory and Cryptography* (2008) — a standard reference for Vélu’s formulas and elliptic curve arithmetic.
