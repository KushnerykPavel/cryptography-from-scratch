# PLONKish Arithmetization
> Turn “N row constraints” into “one polynomial identity”.

**Type:** Build
**Languages:** Python
**Prerequisites:** [PLONK from Scratch](../07-plonk-implement/docs/en.md), [Lookup Arguments](../08-lookup-arguments/docs/en.md)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** what “arithmetization” means in PLONKish systems (rows → polynomials).
- **Compute** an evaluation domain `H = {ω^i}` and its vanishing polynomial `Z_H(X)`.
- **Implement** Lagrange interpolation to turn column values into polynomials.
- **Distinguish** “row check” vs “random-point check” and why degree bounds matter.
- **Apply** the PLONK generic gate equation using selector columns.

## The Problem
You’ve built a circuit and you can check it row-by-row:
for each row `i`, you compute a constraint expression and verify it equals zero.
That’s fine for a unit test, but it’s useless for a succinct proof: the verifier can’t afford to check a million rows, and the prover can’t send a million field elements as “evidence”.

PLONKish proof systems solve this by moving the whole constraint table into the algebra of polynomials.
Instead of “I checked row 0, row 1, row 2, …”, the prover commits to a handful of polynomials (witness columns + selector columns), and the verifier checks *one* polynomial identity at *one* randomly-chosen point.

If you don’t understand this translation, the rest of PLONK/Halo2/Plonky2 looks like magic:
quotient polynomials, vanishing polynomials, “openings at ζ”, and the constant obsession with “degree”.
This lesson makes the translation concrete.

## The Concept
PLONK’s “generic gate” is one equation that can represent many gate types by changing *selectors*.
For each row `i` you have witness wires `a[i], b[i], c[i]` and selectors:

`ql[i], qr[i], qm[i], qo[i], qc[i]`

The row constraint is:

`ql[i]*a[i] + qr[i]*b[i] + qm[i]*(a[i]*b[i]) + qo[i]*c[i] + qc[i] = 0`

Examples:

- Addition gate `a + b = c`: set `ql=1, qr=1, qm=0, qo=-1, qc=0`
- Multiplication gate `a*b = c`: set `ql=0, qr=0, qm=1, qo=-1, qc=0`
- Affine gate `2a + 5 = c`: set `ql=2, qr=0, qm=0, qo=-1, qc=5`

Now comes the arithmetization step:

1. Pick an evaluation domain `H = {1, ω, ω^2, ..., ω^{n-1}}` where `ω` is an `n`-th root of unity in your field.
2. Treat each column as values *on that domain* and interpolate a polynomial:
   - `A(ω^i) = a[i]`, `B(ω^i) = b[i]`, `C(ω^i) = c[i]`
   - `QL(ω^i) = ql[i]`, ..., `QC(ω^i) = qc[i]`
3. Build one “composition polynomial”:

`F(X) = QL(X)*A(X) + QR(X)*B(X) + QM(X)*(A(X)*B(X)) + QO(X)*C(X) + QC(X)`

If every row constraint holds, then `F(ω^i) = 0` for every `ω^i ∈ H`.
That means every point in `H` is a root of `F`, so `F` is divisible by the *vanishing polynomial* of `H`:

`Z_H(X) = ∏_{x∈H} (X - x)`

For a roots-of-unity domain, this simplifies to:

`Z_H(X) = X^n - 1`

So “the whole table is valid” becomes:

`F(X) = Z_H(X) * Q(X)` for some quotient polynomial `Q(X)`.

Real PLONKish systems use a polynomial commitment to commit to these polynomials, then open them at a random challenge point `ζ` and check the identity at `ζ`. Soundness comes from:

- `ζ` is unpredictable to the prover (Fiat–Shamir)
- the polynomials are *degree-bounded* (so “equal at one random point” implies “equal everywhere” except with negligible probability)

## Build It

### Step 1: Finite field + polynomials
We’ll work in a prime field `F_p` and represent polynomials by coefficient lists:
`[c0, c1, c2]` means `c0 + c1*X + c2*X^2` (all arithmetic mod `p`).

```python
from __future__ import annotations

from typing import Dict, Iterable, List, Sequence, Tuple


MODULUS = 18446744069414584321  # Goldilocks prime: 2^64 - 2^32 + 1
PRIMITIVE_ROOT = 7


def inv_mod(a: int, p: int = MODULUS) -> int:
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    return pow(a, p - 2, p)


def poly_trim(poly: Sequence[int], p: int = MODULUS) -> List[int]:
    out = [c % p for c in poly]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def poly_add(a: Sequence[int], b: Sequence[int], p: int = MODULUS) -> List[int]:
    m = max(len(a), len(b))
    out = [0] * m
    for i in range(m):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return poly_trim(out, p)


def poly_sub(a: Sequence[int], b: Sequence[int], p: int = MODULUS) -> List[int]:
    m = max(len(a), len(b))
    out = [0] * m
    for i in range(m):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % p
    return poly_trim(out, p)


def poly_scale(a: Sequence[int], k: int, p: int = MODULUS) -> List[int]:
    return poly_trim([(c % p) * (k % p) % p for c in a], p)


def poly_mul(a: Sequence[int], b: Sequence[int], p: int = MODULUS) -> List[int]:
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        ai %= p
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * (bj % p)) % p
    return poly_trim(out, p)


def poly_eval(poly: Sequence[int], x: int, p: int = MODULUS) -> int:
    x %= p
    acc = 0
    for c in reversed(poly):
        acc = (acc * x + (c % p)) % p
    return acc
```

### Step 2: Roots of unity domain
Pick a domain size `n` and compute an `n`-th root of unity `ω` so we can index rows by `ω^i`.

```python
def nth_root_of_unity(n: int, p: int = MODULUS, g: int = PRIMITIVE_ROOT) -> int:
    if n <= 0:
        raise ValueError("n must be positive")
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1 to get an n-th root of unity")
    return pow(g % p, (p - 1) // n, p)


def domain_points(n: int, omega: int, p: int = MODULUS) -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    omega %= p
    out = []
    cur = 1
    for _ in range(n):
        out.append(cur)
        cur = cur * omega % p
    return out
```

### Step 3: Column interpolation (Lagrange)
Turn a column of `n` values (one per row) into one polynomial that agrees with the column on the domain.

```python
def lagrange_interpolate(xs: Sequence[int], ys: Sequence[int], p: int = MODULUS) -> List[int]:
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have the same length")
    if not xs:
        raise ValueError("need at least one point to interpolate")

    xs_n = [x % p for x in xs]
    ys_n = [y % p for y in ys]
    if len(set(xs_n)) != len(xs_n):
        raise ValueError("xs must be distinct")

    poly = [0]
    n = len(xs_n)
    for i in range(n):
        xi = xs_n[i]
        num = [1]
        den = 1
        for j in range(n):
            if j == i:
                continue
            xj = xs_n[j]
            num = poly_mul(num, [(-xj) % p, 1], p)
            den = den * (xi - xj) % p
        scale = ys_n[i] * inv_mod(den, p) % p
        poly = poly_add(poly, poly_scale(num, scale, p), p)
    return poly_trim(poly, p)
```

### Step 4: The PLONK generic gate as one polynomial
Define the row residual, build a toy table of rows, interpolate every column, then form the composition polynomial `F(X)`.

```python
def vanishing_polynomial(n: int, p: int = MODULUS) -> List[int]:
    if n <= 0:
        raise ValueError("n must be positive")
    return [(p - 1)] + [0] * (n - 1) + [1]


def plonk_gate_row_residual(
    *,
    ql: int,
    qr: int,
    qm: int,
    qo: int,
    qc: int,
    a: int,
    b: int,
    c: int,
    p: int = MODULUS,
) -> int:
    return (ql * a + qr * b + qm * a * b + qo * c + qc) % p


def example_rows(p: int = MODULUS) -> List[Dict[str, int]]:
    m1 = p - 1
    rows = [
        dict(ql=1, qr=1, qm=0, qo=m1, qc=0, a=3, b=4, c=7),
        dict(ql=0, qr=0, qm=1, qo=m1, qc=0, a=5, b=6, c=30),
        dict(ql=2, qr=0, qm=0, qo=m1, qc=5, a=9, b=0, c=23),
        dict(ql=1, qr=1, qm=0, qo=m1, qc=7, a=11, b=12, c=30),
        dict(ql=0, qr=0, qm=1, qo=m1, qc=9, a=2, b=10, c=29),
        dict(ql=3, qr=0, qm=0, qo=m1, qc=p - 5, a=4, b=0, c=7),
        dict(ql=0, qr=0, qm=1, qo=m1, qc=m1, a=3, b=9, c=26),
        dict(ql=1, qr=0, qm=0, qo=m1, qc=0, a=42, b=0, c=42),
    ]
    for r in rows:
        if plonk_gate_row_residual(**r, p=p) != 0:
            raise AssertionError("internal example rows do not satisfy the gate equation")
    return rows


def columns_from_rows(rows: Sequence[Dict[str, int]], names: Sequence[str]) -> Dict[str, List[int]]:
    out: Dict[str, List[int]] = {}
    for name in names:
        out[name] = [int(r[name]) for r in rows]
    return out


def interpolate_columns(domain: Sequence[int], columns: Dict[str, Sequence[int]], p: int = MODULUS) -> Dict[str, List[int]]:
    return {name: lagrange_interpolate(domain, values, p) for name, values in columns.items()}


def plonk_gate_composition_polynomial(polys: Dict[str, Sequence[int]], p: int = MODULUS) -> List[int]:
    a = polys["a"]
    b = polys["b"]
    c = polys["c"]
    ql = polys["ql"]
    qr = polys["qr"]
    qm = polys["qm"]
    qo = polys["qo"]
    qc = polys["qc"]

    ab = poly_mul(a, b, p)
    term = poly_add(poly_mul(ql, a, p), poly_mul(qr, b, p), p)
    term = poly_add(term, poly_mul(qm, ab, p), p)
    term = poly_add(term, poly_mul(qo, c, p), p)
    term = poly_add(term, qc, p)
    return poly_trim(term, p)
```

### Step 5: Divisibility and the “single-point check” intuition
If `F(ω^i)=0` for all points in the domain, then `Z_H(X)` divides `F(X)` exactly.
Also: checking *one* point is only meaningful when the verifier controls that point (Fiat–Shamir) and the polynomials are degree-bounded.

```python
def poly_divmod(numer: Sequence[int], denom: Sequence[int], p: int = MODULUS) -> Tuple[List[int], List[int]]:
    numer_t = poly_trim(numer, p)
    denom_t = poly_trim(denom, p)
    if len(denom_t) == 1 and denom_t[0] == 0:
        raise ZeroDivisionError("polynomial division by zero")
    if len(numer_t) < len(denom_t):
        return [0], numer_t

    q = [0] * (len(numer_t) - len(denom_t) + 1)
    rem = numer_t[:]
    inv_lead = inv_mod(denom_t[-1], p)

    while len(rem) >= len(denom_t) and not (len(rem) == 1 and rem[0] == 0):
        d = len(rem) - len(denom_t)
        coeff = rem[-1] * inv_lead % p
        q[d] = coeff
        for i in range(len(denom_t)):
            rem[i + d] = (rem[i + d] - coeff * denom_t[i]) % p
        rem = poly_trim(rem, p)

    return poly_trim(q, p), rem
```

Run it:

`python3 code/main.py`

## Use It
This lesson is “stdlib only”, but here’s where the same ideas live in production systems:

- **Halo2**: “gates” become algebraic constraints over advice/fixed columns; the prover constructs a set of “expressions” and the system composes them into one quotient polynomial opened at challenges.
- **Plonky2 / Plonky3**: PLONKish arithmetization with custom gates + lookups; composition polynomials + degree bookkeeping are explicit in the gate definitions.
- **arkworks (Rust)**: constraint systems and polynomial commitment backends implement the same “rows → polynomials → open at ζ” pipeline.

What changes across systems is *which* constraints you include (permutation/copy constraints, lookups, custom gates) and *which* polynomial commitment you use (KZG, IPA, FRI).

## Pitfalls
- **Choosing a field with no suitable domain**: if `n` doesn’t divide `p-1`, you don’t get an `n`-th root of unity, so your FFT-friendly domain doesn’t exist.
- **Forgetting degree bounds**: “equal at one random point” is only a sound check when polynomials are degree-bounded (otherwise a prover can cheat by changing high-degree terms).
- **Mixing up coefficient vs evaluation form**: the protocol commits to polynomials, but the prover computes them from an evaluation table; you must be consistent about which form you’re in.
- **Silent duplicate points in interpolation**: if `xs` aren’t distinct, Lagrange denominators hit zero and interpolation breaks.
- **Domain mismatch bugs**: if witnesses are interpolated on one domain and selectors on another, identities “almost work” and debugging is miserable.

## Ship It
Save the reusable checklist at:

`outputs/plonkish-arithmetization-review-checklist.md`

Use it when reviewing (or writing) PLONKish “arithmetization glue” code: gate equations, domains, composition polynomials, quotients, degree checks, and openings. It’s designed to be pasted into a PR review or an audit doc.

## Exercises
1. Easy. Run `python3 code/main.py`. Observe that `F(ω^i)` is zero for every row and the remainder of `F / (X^n - 1)` is `[0]`.
2. Medium. Modify `example_rows()` to add a new gate row (e.g. `c = a*b + 11`) by setting selector values; rerun and confirm the divisibility check still holds.
3. Hard. Add a degree-bound assertion: compute degrees of `A,B,C,QL,...` and show why `deg(F)` grows, then reason about why protocols split the quotient polynomial (e.g. into `t1,t2,t3`) to fit a commitment degree bound.

## Key Terms
| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Arithmetization | “turn the circuit into polynomials” | A specific encoding: rows/columns → low-degree polynomials + identities checked at random points. |
| Selector | “gate type switch” | A fixed column that activates terms like `a`, `b`, `a*b`, `c`, constants per row. |
| Evaluation domain `H` | “FFT domain” | A set of points (often roots of unity) where you sample/interpolate polynomials. |
| Vanishing polynomial `Z_H` | “zero on the domain” | The polynomial that has exactly the points in `H` as roots (for roots of unity: `X^n - 1`). |
| Composition polynomial `F` | “constraint polynomial” | A single polynomial built from witnesses/selectors whose zeros encode all row constraints. |

## Further Reading
- Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru, *PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge* (2019) — the generic gate + quotient/vanishing pattern.
- Electric Coin Company, *Halo2 Book* (ongoing) — practical PLONKish constraints and arithmetization in an engineering-oriented presentation.
- Polygon zkEVM docs, *Plonk in PIL* (ongoing) — selector polynomials and the PLONK gate equation in a “constraint language” setting.
