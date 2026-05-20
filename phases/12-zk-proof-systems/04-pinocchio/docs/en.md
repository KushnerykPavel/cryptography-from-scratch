# Pinocchio Protocol (Toy Model)

> Turn “check every constraint” into “check one polynomial identity”.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 12 — `01-arithmetic-circuits`, `02-r1cs`, `03-qap`
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** how Pinocchio reduces circuit correctness to a single polynomial identity check.
- **Compute** a vanishing polynomial `Z(x)` and quotient `H(x)` for a QAP instance.
- **Implement** an R1CS→QAP reduction via Lagrange interpolation over a finite field.
- **Distinguish** algebraic soundness (random point checks) from cryptographic consistency (KoE/KoC-style checks).
- **Apply** this model to reason about why later SNARKs (e.g., Groth16) can be constant-size.

## The Problem

You want to outsource a big computation (or prove you ran it) but you don’t want verifiers to re-run it. Examples: “this program ran correctly on this input”, “this transaction is valid”, or “this ML model evaluated correctly”. If verification takes as long as the computation, there’s no win.

Pinocchio is one of the first “nearly practical” zkSNARK-style protocols. The key idea is not the elliptic curve pairing details—it’s the *algebraic reduction*: take thousands of constraints and compress them into *one* polynomial identity that can be checked at *one* point (plus extra checks to prevent cheating).

If you can’t see that reduction end-to-end, later systems can feel like a pile of magic constants (`τ, α, β, δ, …`). This lesson gives you the mental model: where the polynomials come from, what gets divided by what, and what a verifier is trying to catch.

## The Concept

Pinocchio’s proof system sits on top of a chain of reductions:

1. **Arithmetic circuit → R1CS.** Each gate becomes one constraint:

   ```
   (A_i · w) * (B_i · w) = (C_i · w)
   ```

   `w` is the witness vector (values of all wires, including a constant `1` wire).

2. **R1CS → QAP.** Turn each *column* of the R1CS matrices into a polynomial by interpolation. For each variable index `j`, build polynomials `A_j(x), B_j(x), C_j(x)` such that:

   ```
   A_j(k) = A[k][j]   for k = 1..m
   ```

   and similarly for `B_j, C_j`, where `m` is the number of constraints.

   Given a concrete witness `w = (w_0, …, w_{n-1})`, define:

   ```
   A(x) = Σ_j w_j * A_j(x)
   B(x) = Σ_j w_j * B_j(x)
   C(x) = Σ_j w_j * C_j(x)
   ```

3. **One divisibility check.** Let:

   ```
   P(x) = A(x) * B(x) - C(x)
   Z(x) = ∏_{k=1..m} (x - k)
   ```

   `Z(x)` is the “vanishing polynomial” for the constraint domain `{1,2,…,m}`.

   If the witness satisfies every constraint, then for every `k ∈ {1..m}` we have `P(k)=0`, so `P(x)` has roots at all those points. Over a field, that implies `P(x)` is divisible by `Z(x)`, i.e. there exists `H(x)` such that:

   ```
   P(x) = H(x) * Z(x)
   ```

4. **Why a single point is enough (algebraically).** If `P(x) - H(x)Z(x)` is a non-zero polynomial of degree `d`, it can only have ≤ `d` roots. So if a verifier checks the identity at a uniformly random `s` in a large field, a cheating prover passes with probability ≈ `d/|F|`.

5. **Why single-point checks are *not* enough (cryptographically).** A malicious prover could fabricate values `A(s), B(s), C(s), H(s)` that satisfy the identity at one point without corresponding to any real witness. Pinocchio uses additional “consistency” checks (often explained via Knowledge-of-Exponent / Knowledge-of-Coefficient style assumptions) so the prover can’t just pick numbers that “work”.

In this lesson, we implement the full algebraic pipeline and then demonstrate the forgery problem explicitly.

## Build It

### Step 1: Field polynomials
```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Sequence, Tuple


def mod_inv(a: int, p: int) -> int:
    a %= p
    if a == 0:
        raise ValueError("inverse of 0 does not exist")
    return pow(a, p - 2, p)


def _poly_trim(poly: Sequence[int], p: int) -> List[int]:
    out = [c % p for c in poly]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    if not out:
        return [0]
    return out


def poly_add(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return _poly_trim(out, p)


def poly_sub(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % p
    return _poly_trim(out, p)


def poly_scale(a: Sequence[int], k: int, p: int) -> List[int]:
    k %= p
    return _poly_trim([(k * c) % p for c in a], p)


def poly_mul(a: Sequence[int], b: Sequence[int], p: int) -> List[int]:
    if (len(a) == 1 and a[0] % p == 0) or (len(b) == 1 and b[0] % p == 0):
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        ai %= p
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * (bj % p)) % p
    return _poly_trim(out, p)


def poly_eval(poly: Sequence[int], x: int, p: int) -> int:
    x %= p
    acc = 0
    for c in reversed(poly):
        acc = (acc * x + (c % p)) % p
    return acc


def poly_divmod(numer: Sequence[int], denom: Sequence[int], p: int) -> Tuple[List[int], List[int]]:
    n = _poly_trim(numer, p)
    d = _poly_trim(denom, p)
    if len(d) == 1 and d[0] == 0:
        raise ValueError("division by zero polynomial")

    if len(n) < len(d):
        return [0], list(n)

    num = list(n)
    den_lead_inv = mod_inv(d[-1], p)
    q = [0] * (len(num) - len(d) + 1)
    while len(num) >= len(d) and not (len(num) == 1 and num[0] == 0):
        deg_diff = len(num) - len(d)
        lead = (num[-1] * den_lead_inv) % p
        q[deg_diff] = lead

        for i in range(len(d)):
            num[deg_diff + i] = (num[deg_diff + i] - lead * d[i]) % p
        num = _poly_trim(num, p)

    return _poly_trim(q, p), _poly_trim(num, p)


def poly_from_roots(roots: Iterable[int], p: int) -> List[int]:
    out = [1]
    for r in roots:
        out = poly_mul(out, [(-r) % p, 1], p)
    return _poly_trim(out, p)


def vanishing_poly(num_constraints: int, p: int) -> List[int]:
    return poly_from_roots(range(1, num_constraints + 1), p)


def lagrange_interpolate(points: Sequence[Tuple[int, int]], p: int) -> List[int]:
    if not points:
        raise ValueError("need at least one point")
    xs = [x % p for x, _ in points]
    if len(set(xs)) != len(xs):
        raise ValueError("x coordinates must be distinct")

    out = [0]
    for i, (xi, yi) in enumerate(points):
        xi %= p
        yi %= p
        num = [1]
        denom = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            xj %= p
            num = poly_mul(num, [(-xj) % p, 1], p)
            denom = (denom * (xi - xj)) % p
        out = poly_add(out, poly_scale(num, yi * mod_inv(denom, p), p), p)
    return _poly_trim(out, p)
```
This step gives you the only “math engine” you need: polynomial add/mul/eval, division with remainder, the vanishing polynomial `Z(x)`, and Lagrange interpolation (so you can turn “values at constraints” into “a polynomial”).

### Step 2: R1CS for a toy circuit
```python
def _poly_vec_lincomb(polys: Sequence[Sequence[int]], scalars: Sequence[int], p: int) -> List[int]:
    if len(polys) != len(scalars):
        raise ValueError("mismatched lengths")
    out = [0]
    for poly, k in zip(polys, scalars):
        out = poly_add(out, poly_scale(poly, k, p), p)
    return _poly_trim(out, p)


@dataclass(frozen=True)
class R1CS:
    p: int
    A: List[List[int]]
    B: List[List[int]]
    C: List[List[int]]

    def num_constraints(self) -> int:
        return len(self.A)

    def num_variables(self) -> int:
        if not self.A:
            return 0
        return len(self.A[0])


def r1cs_is_satisfied(r1cs: R1CS, witness: Sequence[int]) -> bool:
    p = r1cs.p
    m = r1cs.num_constraints()
    n = r1cs.num_variables()
    if len(witness) != n:
        raise ValueError("witness length mismatch")
    if witness[0] % p != 1:
        raise ValueError("witness[0] must be 1 (constant wire)")

    for i in range(m):
        left = sum((r1cs.A[i][j] % p) * (witness[j] % p) for j in range(n)) % p
        right = sum((r1cs.B[i][j] % p) * (witness[j] % p) for j in range(n)) % p
        out = sum((r1cs.C[i][j] % p) * (witness[j] % p) for j in range(n)) % p
        if (left * right) % p != out:
            return False
    return True


def example_r1cs_x3_plus_x_plus_5_eq_35(p: int) -> Tuple[R1CS, List[int]]:
    names = ["1", "x", "out", "x2", "x3", "x3_plus_x"]
    idx = {name: i for i, name in enumerate(names)}

    def lc(**kwargs: int) -> List[int]:
        row = [0] * len(names)
        for k, v in kwargs.items():
            row[idx[k]] = v % p
        return row

    A = [
        lc(x=1),
        lc(x2=1),
        lc(x3=1, x=1),
        lc(x3_plus_x=1, **{"1": 5}),
        lc(out=1),
    ]
    B = [
        lc(x=1),
        lc(x=1),
        lc(**{"1": 1}),
        lc(**{"1": 1}),
        lc(**{"1": 1}),
    ]
    C = [
        lc(x2=1),
        lc(x3=1),
        lc(x3_plus_x=1),
        lc(out=1),
        lc(**{"1": 35}),
    ]

    r1cs = R1CS(p=p, A=A, B=B, C=C)
    x = 3 % p
    x2 = (x * x) % p
    x3 = (x2 * x) % p
    x3_plus_x = (x3 + x) % p
    out = (x3_plus_x + 5) % p
    witness = [1, x, out, x2, x3, x3_plus_x]
    return r1cs, witness
```
This step fixes a concrete computation: prove you know `x` such that `x^3 + x + 5 = 35`. We encode it as R1CS constraints and check whether a witness vector satisfies all constraints.

### Step 3: R1CS → QAP (divisibility)
```python
@dataclass(frozen=True)
class QAP:
    p: int
    A_polys: List[List[int]]
    B_polys: List[List[int]]
    C_polys: List[List[int]]
    Z: List[int]

    def num_constraints(self) -> int:
        return len(self.Z) - 1

    def num_variables(self) -> int:
        return len(self.A_polys)


def r1cs_to_qap(r1cs: R1CS) -> QAP:
    p = r1cs.p
    m = r1cs.num_constraints()
    n = r1cs.num_variables()
    xs = list(range(1, m + 1))

    def col_to_poly(col_values: Sequence[int]) -> List[int]:
        points = list(zip(xs, col_values))
        return lagrange_interpolate(points, p)

    A_polys: List[List[int]] = []
    B_polys: List[List[int]] = []
    C_polys: List[List[int]] = []
    for j in range(n):
        A_polys.append(col_to_poly([r1cs.A[i][j] % p for i in range(m)]))
        B_polys.append(col_to_poly([r1cs.B[i][j] % p for i in range(m)]))
        C_polys.append(col_to_poly([r1cs.C[i][j] % p for i in range(m)]))

    return QAP(
        p=p,
        A_polys=A_polys,
        B_polys=B_polys,
        C_polys=C_polys,
        Z=vanishing_poly(m, p),
    )


def qap_abc(qap: QAP, witness: Sequence[int]) -> Tuple[List[int], List[int], List[int]]:
    if len(witness) != qap.num_variables():
        raise ValueError("witness length mismatch")
    p = qap.p
    A = _poly_vec_lincomb(qap.A_polys, witness, p)
    B = _poly_vec_lincomb(qap.B_polys, witness, p)
    C = _poly_vec_lincomb(qap.C_polys, witness, p)
    return A, B, C


def qap_h_and_remainder(qap: QAP, witness: Sequence[int]) -> Tuple[List[int], List[int]]:
    p = qap.p
    A, B, C = qap_abc(qap, witness)
    P = poly_sub(poly_mul(A, B, p), C, p)
    H, R = poly_divmod(P, qap.Z, p)
    return H, R


def qap_is_satisfied(qap: QAP, witness: Sequence[int]) -> bool:
    _, R = qap_h_and_remainder(qap, witness)
    return len(R) == 1 and R[0] % qap.p == 0
```
This step is the compression: we convert the entire R1CS into *polynomials* and then check one global condition—`P(x)` must be divisible by the vanishing polynomial `Z(x)`. If the remainder is non-zero, the witness fails some constraint.

### Step 4: Pinocchio-style single-point check
```python
@dataclass(frozen=True)
class ToyProof:
    p: int
    s: int
    A_s: int
    B_s: int
    C_s: int
    H_s: int
    Z_s: int


def pinocchio_toy_prove(qap: QAP, witness: Sequence[int], s: int) -> ToyProof:
    p = qap.p
    A, B, C = qap_abc(qap, witness)
    H, R = qap_h_and_remainder(qap, witness)
    if not (len(R) == 1 and R[0] % p == 0):
        raise ValueError("witness does not satisfy QAP; H(x) would have a remainder")

    return ToyProof(
        p=p,
        s=s % p,
        A_s=poly_eval(A, s, p),
        B_s=poly_eval(B, s, p),
        C_s=poly_eval(C, s, p),
        H_s=poly_eval(H, s, p),
        Z_s=poly_eval(qap.Z, s, p),
    )


def pinocchio_toy_verify(proof: ToyProof) -> bool:
    p = proof.p
    lhs = (proof.A_s * proof.B_s - proof.C_s) % p
    rhs = (proof.H_s * proof.Z_s) % p
    return lhs == rhs
```
This step models the “succinct check”: instead of checking `P(k)=0` for all `k=1..m`, you evaluate the identity at a single point `s`. Then we show the problem: if you don’t enforce that `A(s),B(s),C(s),H(s)` came from the *same* witness, you can forge values that pass the check.

Run it:
`python3 code/main.py`

## Use It

This toy script is *not* a SNARK. Real systems implement the same algebra but add commitments and pairings so the verifier can check consistency without knowing the witness.

Common production equivalents:

- **Groth16 (Pinocchio-style QAP SNARK):** most common deployed constant-size SNARK (e.g., early Zcash era).
- **libsnark / bellman / arkworks:** libraries that implement R1CS/QAP reductions and pairing-based SNARKs.
- **Circom + snarkjs:** builds R1CS from circuits and generates Groth16/Plonk proofs (different backend, similar arithmetization foundations).

## Pitfalls

1. **“Single-point check means the witness is correct.”** Not by itself. You must also bind the prover to *the* polynomials derived from the circuit and *the same* witness coefficients (Pinocchio’s extra checks).
2. **Mixing rings.** These constructions are over a finite field. If you accidentally do integer arithmetic, division and interpolation are not what the protocol assumes.
3. **Forgetting the constant wire.** The `1` entry in the witness is what lets you encode constants (`+5`, `=35`) inside linear combinations.
4. **Silent degree blowups.** Naive polynomial operations are `O(n^2)` and quickly become the bottleneck; real systems use FFTs/NTTs and structured domains.
5. **Assuming “zero remainder” implies zero-knowledge.** Divisibility is about correctness; zero-knowledge requires randomized encodings/blinding.

## Ship It

This lesson ships a reusable review checklist you can paste into a PR review when someone says “we implemented a Pinocchio/Groth16-style SNARK”.

- Artifact: `outputs/skill-pinocchio-review.md`
- Use it when reviewing: circuit→R1CS compilation, R1CS→QAP reduction, divisibility checks, and “consistency binding” mechanisms.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that a wrong witness fails divisibility, and a forged “evaluation-only proof” can still pass the single-point check.
2. Medium: Change the equation (e.g. prove `x^2 + 2x + 1 = 16`) and rewrite the R1CS in `example_r1cs_x3_plus_x_plus_5_eq_35`. Confirm the QAP remainder is still zero for the right witness.
3. Hard: Read a Groth16 verifier equation and map each term back to this lesson’s objects (`A(s),B(s),C(s),H(s),Z(s)`), and identify where the “consistency binding” happens.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| R1CS | “a constraint system” | A list of equations `(A_i·w)*(B_i·w) = (C_i·w)` over a field. |
| QAP | “R1CS but polynomials” | Interpolated polynomials `A_j,B_j,C_j` that reproduce constraints when evaluated at `x=1..m`. |
| Witness | “the secret inputs” | The full assignment to all wires, including intermediate values and the constant `1` wire. |
| Vanishing polynomial `Z(x)` | “the zerofier” | The minimal polynomial that is zero on the constraint domain points. |
| Divisibility check | “prove constraints hold” | Show `A(x)B(x)-C(x)` is a multiple of `Z(x)` (remainder is 0). |
| KoE/KoC consistency | “bind to same coefficients” | Extra checks preventing the prover from fabricating evaluations that satisfy one equation at one point. |

## Further Reading

- Parno, Gentry, Howell, Raykova — *Pinocchio: Nearly Practical Verifiable Computation* (2013) — the original protocol and its verifiable computation framing.
- Buterin — *Quadratic Arithmetic Programs: From Zero to Hero* (2016) — an intuition-heavy walkthrough of R1CS→QAP.
- Electric Coin Company — *Explaining SNARKs Part VI: The Pinocchio Protocol* (2016) — a readable narrative emphasizing consistency checks.
