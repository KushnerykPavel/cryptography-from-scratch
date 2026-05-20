# QAP — Quadratic Arithmetic Programs

> Turn “check every constraint” into “check one polynomial division”.

**Type:** Build
**Languages:** Python
**Prerequisites:** `phases/12-zk-proof-systems/01-arithmetic-circuits/`, `phases/12-zk-proof-systems/02-r1cs/`
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** how a QAP re-encodes an R1CS as polynomials
- **Compute** the target polynomial `t(x)=∏(x-x_i)` for a constraint domain
- **Implement** Lagrange interpolation in a finite field to build per-wire polynomials
- **Distinguish** per-wire polynomials `A_i,B_i,C_i` from the aggregated polynomials `A,B,C`
- **Apply** the divisibility check `t(x) | (A(x)B(x)-C(x))` to accept/reject a witness

## The Problem

R1CS gives you a clean way to describe a computation as `m` constraints, but verification still *sounds* like “check all `m` constraints”. For SNARK-sized circuits, `m` can be millions — you can’t afford to do `m` checks on-chain or inside a tiny verifier.

QAPs are the bridge: they turn “many local checks” (one per constraint) into a **single global algebraic statement** about polynomials. This is the statement that pairing-based SNARKs (Pinocchio / Groth16) end up proving “in the exponent”.

Without QAPs, the next lessons (Pinocchio, Groth16) look like magic: random τ’s, polynomial commitments, quotient polynomials `h(x)`, and a single verification equation. QAPs are where that structure becomes inevitable.

## The Concept

Start with an R1CS with:
- `m` constraints (rows)
- `n` wires (columns), including the constant wire `a_0 = 1`
- matrices `A,B,C ∈ F^{m×n}`

Each constraint says:

`⟨A_i, a⟩ · ⟨B_i, a⟩ = ⟨C_i, a⟩`  for `i=1..m`

Pick `m` distinct evaluation points (the “constraint domain”) `x_1,…,x_m ∈ F`.

For each wire `j` (column), build polynomials `A_j(x), B_j(x), C_j(x)` of degree `< m` such that for every constraint row `i`:

- `A_j(x_i) = A[i][j]`
- `B_j(x_i) = B[i][j]`
- `C_j(x_i) = C[i][j]`

That’s just Lagrange interpolation: “fit the unique degree `< m` polynomial through these `m` points”.

Now define the **target polynomial**:

`t(x) = ∏_{i=1..m} (x - x_i)`

and the **aggregated polynomials** for a witness `a = (a_0,…,a_{n-1})`:

- `A(x) = Σ_j a_j·A_j(x)`
- `B(x) = Σ_j a_j·B_j(x)`
- `C(x) = Σ_j a_j·C_j(x)`

Then the key equivalence is:

If the witness satisfies every R1CS constraint, then for every `x_i` we have:

`A(x_i)B(x_i) - C(x_i) = 0`

So the polynomial `P(x) = A(x)B(x)-C(x)` has roots at every `x_i`, which is the same as:

`t(x) | P(x)`

That divisibility statement is what a SNARK proves succinctly.

## Build It

### Step 1: Field + polynomial arithmetic
We’ll work in a tiny prime field `F_p` and represent polynomials as coefficient lists `[a0, a1, a2, ...]` meaning `a0 + a1·x + a2·x^2 + ...`.

```python
from __future__ import annotations

import sys
from typing import Iterable, List, Sequence, Tuple


Poly = List[int]  # coefficients low->high (a0 + a1*x + a2*x^2 + ...)


def modp(x: int, p: int) -> int:
    return x % p


def field_inv(a: int, p: int) -> int:
    a = a % p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 is undefined")
    return pow(a, p - 2, p)


def poly_trim(poly: Poly) -> Poly:
    while len(poly) > 1 and poly[-1] == 0:
        poly.pop()
    return poly


def poly_add(a: Poly, b: Poly, p: int) -> Poly:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = modp((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0), p)
    return poly_trim(out)


def poly_sub(a: Poly, b: Poly, p: int) -> Poly:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = modp((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0), p)
    return poly_trim(out)


def poly_scale(a: Poly, k: int, p: int) -> Poly:
    k = k % p
    return poly_trim([modp(k * c, p) for c in a])


def poly_mul(a: Poly, b: Poly, p: int) -> Poly:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] = modp(out[i + j] + ai * bj, p)
    return poly_trim(out)


def poly_eval(poly: Poly, x: int, p: int) -> int:
    x = x % p
    acc = 0
    for coeff in reversed(poly):
        acc = modp(acc * x + coeff, p)
    return acc


def poly_divmod(numer: Poly, denom: Poly, p: int) -> Tuple[Poly, Poly]:
    denom = poly_trim(denom[:])
    if denom == [0]:
        raise ZeroDivisionError("polynomial division by 0")

    numer = poly_trim(numer[:])
    if numer == [0]:
        return [0], [0]

    q = [0] * max(0, len(numer) - len(denom) + 1)
    r = numer[:]

    while len(r) >= len(denom) and r != [0]:
        r = poly_trim(r)
        if len(r) < len(denom) or r == [0]:
            break

        deg = len(r) - len(denom)
        lead_factor = modp(r[-1] * field_inv(denom[-1], p), p)
        q[deg] = lead_factor

        sub = [0] * deg + poly_scale(denom, lead_factor, p)
        r = poly_sub(r, sub, p)

    return poly_trim(q if q else [0]), poly_trim(r)
```

This is the minimal algebra we need to say “divides with remainder 0” inside a finite field.

### Step 2: Lagrange interpolation + the target polynomial
Given `m` points `(x_i, y_i)`, Lagrange interpolation returns the unique polynomial of degree `< m` that hits them all.

```python
def lagrange_interpolate(xs: Sequence[int], ys: Sequence[int], p: int) -> Poly:
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have the same length")
    if len(xs) == 0:
        raise ValueError("need at least one point")

    n = len(xs)
    poly = [0]
    xs_mod = [x % p for x in xs]

    if len(set(xs_mod)) != len(xs_mod):
        raise ValueError("xs must be distinct mod p")

    for i in range(n):
        xi = xs_mod[i]
        yi = ys[i] % p

        num = [1]
        den = 1
        for j in range(n):
            if j == i:
                continue
            xj = xs_mod[j]
            num = poly_mul(num, [modp(-xj, p), 1], p)
            den = modp(den * (xi - xj), p)

        scale = modp(yi * field_inv(den, p), p)
        poly = poly_add(poly, poly_scale(num, scale, p), p)

    return poly_trim(poly)


def target_polynomial(xs: Sequence[int], p: int) -> Poly:
    t = [1]
    for x in xs:
        t = poly_mul(t, [modp(-x, p), 1], p)
    return poly_trim(t)
```

In QAP language, `target_polynomial(xs)` is the “vanishing polynomial” over the constraint domain.

### Step 3: Convert R1CS matrices into per-wire QAP polynomials
For each wire `j`, we interpolate the column values across constraint points.

```python
def r1cs_to_qap(
    A: Sequence[Sequence[int]],
    B: Sequence[Sequence[int]],
    C: Sequence[Sequence[int]],
    xs: Sequence[int],
    p: int,
) -> Tuple[List[Poly], List[Poly], List[Poly], Poly]:
    m = len(A)
    if m == 0:
        raise ValueError("R1CS must have at least one constraint")
    if len(B) != m or len(C) != m:
        raise ValueError("A, B, C must have the same number of constraints")
    if len(xs) != m:
        raise ValueError("xs must contain exactly one evaluation point per constraint")

    n = len(A[0])
    if n == 0:
        raise ValueError("R1CS must have at least one wire (including the constant wire)")

    for row in A:
        if len(row) != n:
            raise ValueError("A rows must have a consistent width")
    for row in B:
        if len(row) != n:
            raise ValueError("B rows must have a consistent width")
    for row in C:
        if len(row) != n:
            raise ValueError("C rows must have a consistent width")

    A_polys: List[Poly] = []
    B_polys: List[Poly] = []
    C_polys: List[Poly] = []

    for col in range(n):
        A_polys.append(lagrange_interpolate(xs, [A[row][col] for row in range(m)], p))
        B_polys.append(lagrange_interpolate(xs, [B[row][col] for row in range(m)], p))
        C_polys.append(lagrange_interpolate(xs, [C[row][col] for row in range(m)], p))

    return A_polys, B_polys, C_polys, target_polynomial(xs, p)
```

This is the “one-time arithmetization” step: once you have these polynomials, you can reuse them for many witnesses.

### Step 4: Build `A(x), B(x), C(x)` from the witness and check divisibility
Given a witness vector `a`, we form the aggregated polynomials and check that `P(x)=A(x)B(x)-C(x)` is a multiple of `t(x)`.

```python
def lincomb_polys(polys: Sequence[Poly], witness: Sequence[int], p: int) -> Poly:
    if len(polys) != len(witness):
        raise ValueError("polys and witness must have the same length")
    out = [0]
    for poly, coef in zip(polys, witness):
        out = poly_add(out, poly_scale(poly, coef, p), p)
    return poly_trim(out)


def qap_p_poly(A_polys: Sequence[Poly], B_polys: Sequence[Poly], C_polys: Sequence[Poly], witness: Sequence[int], p: int) -> Poly:
    ax = lincomb_polys(A_polys, witness, p)
    bx = lincomb_polys(B_polys, witness, p)
    cx = lincomb_polys(C_polys, witness, p)
    return poly_trim(poly_sub(poly_mul(ax, bx, p), cx, p))
```

In a real SNARK, the prover won’t send these polynomials explicitly — they’ll prove the divisibility statement at a secret evaluation point τ using cryptography. But algebraically, this is the whole story.

Run it:

```bash
python3 code/main.py
```

## Use It

Where this shows up in production:
- **Groth16 / Pinocchio-style SNARKs**: use **QAP arithmetization** and then prove `A(τ)B(τ)-C(τ)=h(τ)t(τ)` using pairings and a CRS.
- **Circom / snarkjs**: compile circuits to **R1CS**, then (under the hood) to QAP-style checks for Groth16.
- **arkworks / bellman / libsnark**: expose APIs around constraints (R1CS-ish), but the prover/verifier internals use polynomial identities derived from QAP.

## Pitfalls

1. **Forgetting the constant wire** `a_0 = 1`. Most arithmetizations assume it exists; dropping it silently changes the language.
2. **Non-distinct constraint points** `x_i`. Lagrange interpolation breaks (division by zero), and the “roots ⇔ divisible” intuition stops matching your code.
3. **Mixing representations**: per-wire polynomials `A_j(x)` vs aggregated `A(x)` is the #1 source of “my divisibility check is nonsense”.
4. **Assuming divisibility alone gives soundness.** In a real SNARK, you must also cryptographically enforce that the prover used the *correct* per-wire polynomials and a *single consistent witness* (otherwise they can “fake” `A,B,C` to make the division work).
5. **Polynomial division bugs** (leading coefficients, trimming zeros). A single off-by-one in degrees makes “remainder 0” meaningless.

## Ship It

This lesson ships a reusable QAP review prompt/checklist in `outputs/prompt-qap-review-checklist.md`.

Use it when:
- reviewing a PR that implements “R1CS → QAP” conversion,
- auditing a Groth16/Pinocchio codebase’s arithmetization layer,
- debugging “divisibility check fails” issues in toy implementations.

## Exercises

1. **Easy:** Run `python3 code/main.py`. Observe that the valid witness gives remainder `[0]`, and the tampered witness does not.
2. **Medium:** Change the constraint domain from `{1,2}` to `{3,4}`. Update `xs` in `main()` and confirm the check still works (the polynomials change, the logic does not).
3. **Hard:** Replace the example computation with a 3-constraint circuit (e.g. `z = (x + 1)(y + 2)`). Build its R1CS, convert to QAP, and verify divisibility for both a correct and incorrect witness.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| R1CS | “constraints for a circuit” | A system of equations `⟨A_i,a⟩·⟨B_i,a⟩=⟨C_i,a⟩` over a field |
| QAP | “R1CS but polynomials” | Per-wire polynomials whose evaluations reproduce R1CS coefficients at constraint points |
| Constraint domain | “the roots” | The chosen points `x_1,…,x_m` where we enforce constraints |
| Target / vanishing polynomial | “Z(x)” / “t(x)” | `t(x)=∏(x-x_i)`, zero on the whole domain |
| Quotient polynomial | “h(x)” | `h(x) = (A·B - C) / t`, exists iff remainder is 0 |

## Further Reading

- Gennaro, Gentry, Parno, Raykova, *Quadratic Span Programs and Succinct NIZKs without PCPs* (2012) — original QAP/QSP formulation underlying early SNARKs.
- Parno, Howell, Gentry, Raykova, *Pinocchio: Nearly Practical Verifiable Computation* (2013) — QAP-based VC and the “evaluate at secret τ” trick.
- Groth, *On the Size of Pairing-based Non-interactive Arguments* (2016) — Groth16, the dominant QAP-based SNARK in practice.
