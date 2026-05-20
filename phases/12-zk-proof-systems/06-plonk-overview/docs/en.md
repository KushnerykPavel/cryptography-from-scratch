# PLONK — Universal SNARKs (Overview)
> Turn a circuit into a handful of polynomials, then prove polynomial identities about them.

**Type:** Learn
**Languages:** Python
**Prerequisites:** `phases/12-zk-proof-systems/01-arithmetic-circuits`, `phases/12-zk-proof-systems/02-r1cs`, `phases/12-zk-proof-systems/03-qap`, `phases/11-zero-knowledge-foundations/04-fiat-shamir`, `phases/11-zero-knowledge-foundations/11-universal-vs-trusted-setup`
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain what makes PLONK “universal” (and what the bound is)
- Compute a PLONK gate constraint value from selector + wire columns
- Implement a toy permutation (copy-constraint) grand product check over a small field
- Distinguish gates (per-row equations) from wiring (copy constraints) from commitments (hiding/binding)
- Apply a review checklist to spot PLONK-ish soundness bugs (transcript binding, boundary conditions, degree checks)

## The Problem

You can build a zero-knowledge proof system from R1CS/QAP, but the classic “proof system flavors” come with painful engineering trade-offs. Circuit-specific systems can be very fast and succinct, but they often require you to regenerate keys every time the circuit changes. That’s brutal in real products where circuits evolve with features, bug fixes, and security patches.

PLONK is one of the ideas that made “programmable SNARKs” practical: keep a fixed *shape* (a small number of columns and a fixed arity per row), and express many different circuits by filling in *selector columns* and *wiring constraints*. That gives you a path to **universal setup** and a more reusable proving/verification stack.

If you’re reviewing or integrating ZK systems in 2026, you’ll constantly run into “PLONK-ish” designs (halo2-style custom gates, permutations, lookups, Fiat–Shamir transcripts, polynomial commitments). Without a clear mental model, it’s easy to ship something that verifies but is not sound.

## The Concept

PLONK is easiest to remember as “a few columns + three checks”:

1) **Gates:** per-row algebraic constraints chosen by selectors  
2) **Wiring:** copy constraints that connect cells across rows/columns  
3) **Commitments:** cryptography that lets you prove polynomial identities without revealing the polynomials

### 1) Gates: selectors + 3-wire rows
PLONK’s basic arity is three witness columns per row: `a`, `b`, `c`.

Each row has selector values (often thought of as selector polynomials evaluated on the domain):

| Column | Meaning |
|--------|---------|
| `qL`   | coefficient for `a` |
| `qR`   | coefficient for `b` |
| `qM`   | coefficient for `a·b` |
| `qO`   | coefficient for `c` (“output” wire) |
| `qC`   | constant term |

The standard PLONK gate equation is:

```
qL·a + qR·b + qM·a·b + qO·c + qC = 0
```

With different selector values per row, you can encode different operations (mul, add, constants, etc.) while keeping the “one gate shape” fixed.

### 2) Wiring: copy constraints via a permutation σ
The witness table has *cells*, not variables. If the same logical variable appears multiple times (e.g., `x` used in several rows), you need copy constraints to enforce equality between those cells.

PLONK encodes wiring as a **permutation** `σ` of wire positions. A permutation argument then checks, probabilistically, that the witness values are consistent with that permutation (so copy constraints hold).

### 3) Arithmetization: columns become low-degree polynomials
Pick an evaluation domain of size `n` (commonly roots of unity). Each column is interpreted as evaluations of a degree-`< n` polynomial over that domain:

- `A(X)` interpolates the `a` column
- `B(X)` interpolates the `b` column
- `C(X)` interpolates the `c` column
- selector columns become `qL(X), qR(X), ...`

Then “all gate constraints hold on all rows” becomes “a certain polynomial is zero on the domain”, i.e., a **polynomial identity**.

In this lesson we’ll implement a toy version of (1)–(2) and the interpolation step of (3). We will *not* implement polynomial commitments (that’s the cryptographic layer that turns these checks into a short proof).

## Build It

### Step 1: Evaluation domain + polynomial interpolation
This step builds the field arithmetic and the “columns → polynomials” bridge. We’ll use a tiny prime field and a small roots-of-unity domain, then interpolate a column into a polynomial via Lagrange interpolation.

```python
from dataclasses import dataclass


def egcd(a, b):
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inv_mod(a, p):
    if p <= 1:
        raise ValueError("modulus must be > 1")
    a %= p
    if a == 0:
        raise ValueError("not invertible modulo p")
    g, x, _ = egcd(a, p)
    if g != 1:
        raise ValueError("not invertible modulo p")
    return x % p


def _mod(x, p):
    return x % p


def poly_trim(coeffs):
    out = list(coeffs)
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out


def poly_add(a, b, p):
    n = max(len(a), len(b))
    out = [0] * n
    for i in range(n):
        out[i] = ((a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)) % p
    return poly_trim(out)


def poly_scale(a, k, p):
    return poly_trim([(k * c) % p for c in a])


def poly_mul(a, b, p):
    if not a or not b:
        return [0]
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] = (out[i + j] + ai * bj) % p
    return poly_trim(out)


def poly_eval(coeffs, x, p):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % p
    return acc


def lagrange_interpolate(xs, ys, p):
    if len(xs) != len(ys):
        raise ValueError("xs and ys must have the same length")
    if len(xs) == 0:
        raise ValueError("need at least one point")
    if len(set(xs)) != len(xs):
        raise ValueError("xs must be distinct")

    total = [0]
    for i, xi in enumerate(xs):
        numer = [1]
        denom = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            numer = poly_mul(numer, [(-xj) % p, 1], p)
            denom = (denom * (xi - xj)) % p
        scale = (ys[i] * inv_mod(denom, p)) % p
        total = poly_add(total, poly_scale(numer, scale, p), p)
    return poly_trim(total)


def find_primitive_root_of_unity(p, n):
    if n <= 1:
        raise ValueError("n must be > 1")
    if (p - 1) % n != 0:
        raise ValueError("n must divide p-1")

    for w in range(2, p):
        if pow(w, n, p) != 1:
            continue
        if pow(w, n // 2, p) == 1:
            continue
        return w
    raise ValueError("no primitive n-th root found")


def evaluation_domain(p, n, omega):
    if n <= 0:
        raise ValueError("n must be positive")
    xs = [1]
    for _ in range(1, n):
        xs.append((xs[-1] * omega) % p)
    return xs
```

This is the core “arithmetization” move: a length-`n` column of field elements becomes a unique degree-`< n` polynomial. PLONK then checks polynomial identities instead of row-by-row constraints.

### Step 2: PLONK gate constraints via selectors
Now we encode the standard PLONK 3-wire gate equation with selector columns. Think of the selectors as “the circuit program”: they decide what equation applies on each row.

```python
@dataclass(frozen=True)
class PlonkColumns:
    qL: list[int]
    qR: list[int]
    qM: list[int]
    qO: list[int]
    qC: list[int]


@dataclass(frozen=True)
class PlonkWitness:
    a: list[int]
    b: list[int]
    c: list[int]


def gate_constraint_values(cols, w, p):
    n = len(w.a)
    if not (len(w.b) == len(w.c) == len(cols.qL) == len(cols.qR) == len(cols.qM) == len(cols.qO) == len(cols.qC) == n):
        raise ValueError("all columns must have the same length")
    out = []
    for i in range(n):
        val = (
            cols.qL[i] * w.a[i]
            + cols.qR[i] * w.b[i]
            + cols.qM[i] * w.a[i] * w.b[i]
            + cols.qO[i] * w.c[i]
            + cols.qC[i]
        ) % p
        out.append(val)
    return out
```

If every row is correct, `gate_constraint_values(...)` returns a list of zeros. In a real PLONK proof, you don’t reveal those values; you prove that the corresponding *polynomial* is zero on the domain.

### Step 3: Copy constraints via permutation grand product
This is the “wiring” layer. We define a permutation over wire *cells* (positions) and use a grand product recurrence (with random β, γ) to probabilistically enforce all copy constraints.

```python
def slot_id_labels(xs, p, k1=2, k2=3):
    ids_a = [(1 * x) % p for x in xs]
    ids_b = [(k1 * x) % p for x in xs]
    ids_c = [(k2 * x) % p for x in xs]
    return ids_a, ids_b, ids_c


def permutation_sigma_columns(n, xs, p, copy_cycles, k1=2, k2=3):
    ids_a, ids_b, ids_c = slot_id_labels(xs, p, k1=k1, k2=k2)
    ids = ids_a + ids_b + ids_c

    perm = list(range(3 * n))
    for cycle in copy_cycles:
        if len(cycle) < 2:
            raise ValueError("each copy cycle must have at least 2 slots")
        for slot in cycle:
            if not (0 <= slot < 3 * n):
                raise ValueError("slot index out of range")
        for idx, slot in enumerate(cycle):
            perm[slot] = cycle[(idx + 1) % len(cycle)]

    sigma_labels = [ids[perm[i]] for i in range(3 * n)]
    sigma_a = sigma_labels[0:n]
    sigma_b = sigma_labels[n : 2 * n]
    sigma_c = sigma_labels[2 * n : 3 * n]
    return sigma_a, sigma_b, sigma_c


def compute_grand_product_z(cols, w, sigma_a, sigma_b, sigma_c, xs, p, beta, gamma, k1=2, k2=3):
    n = len(xs)
    if not (len(w.a) == len(w.b) == len(w.c) == len(sigma_a) == len(sigma_b) == len(sigma_c) == n):
        raise ValueError("all columns must have the same length n")

    ids_a, ids_b, ids_c = slot_id_labels(xs, p, k1=k1, k2=k2)
    z = [1]
    for i in range(n):
        num = (
            (w.a[i] + beta * ids_a[i] + gamma)
            * (w.b[i] + beta * ids_b[i] + gamma)
            * (w.c[i] + beta * ids_c[i] + gamma)
        ) % p
        den = (
            (w.a[i] + beta * sigma_a[i] + gamma)
            * (w.b[i] + beta * sigma_b[i] + gamma)
            * (w.c[i] + beta * sigma_c[i] + gamma)
        ) % p
        z.append((z[-1] * num * inv_mod(den, p)) % p)
    return z
```

The important intuition: with random β and γ, the products “mix” the witness values with their positions. If you violate a copy constraint, you almost certainly can’t make the final product land back on the required boundary value.

### Step 4: Arithmetization summary: columns become polynomials
Finally, we create a tiny 2-gate circuit (plus padding), compute gate constraints and a permutation check, and interpolate a few columns into polynomials so you can see the “everything is a polynomial” picture.

```python
def toy_plonk_instance(p=97, n=4):
    omega = find_primitive_root_of_unity(p, n)
    xs = evaluation_domain(p, n, omega)

    x = 3
    z = (x * x) % p
    y = (z + x + 5) % p

    w = PlonkWitness(
        a=[x, z, 0, 0],
        b=[x, x, 0, 0],
        c=[z, y, 0, 0],
    )

    cols = PlonkColumns(
        qL=[0, 1, 0, 0],
        qR=[0, 1, 0, 0],
        qM=[1, 0, 0, 0],
        qO=[(-1) % p, (-1) % p, 0, 0],
        qC=[0, 5, 0, 0],
    )

    copy_cycles = [
        [0, n + 0, n + 1],  # x: a0, b0, b1
        [2 * n + 0, 1],  # z: c0, a1
    ]

    sigma_a, sigma_b, sigma_c = permutation_sigma_columns(n, xs, p, copy_cycles)
    return {
        "p": p,
        "n": n,
        "omega": omega,
        "xs": xs,
        "cols": cols,
        "witness": w,
        "sigma_a": sigma_a,
        "sigma_b": sigma_b,
        "sigma_c": sigma_c,
        "public": {"y": y},
    }


def _step(n, name):
    print(f"=== Step {n}: {name} ===")


def main():
    inst = toy_plonk_instance()
    p = inst["p"]
    n = inst["n"]
    omega = inst["omega"]
    xs = inst["xs"]
    cols = inst["cols"]
    w = inst["witness"]
    sigma_a = inst["sigma_a"]
    sigma_b = inst["sigma_b"]
    sigma_c = inst["sigma_c"]

    _step(1, "Evaluation domain + polynomial interpolation")
    print(f"field prime p = {p}")
    print(f"domain size n = {n}")
    print(f"primitive n-th root of unity omega = {omega}")
    print(f"domain points x_i = omega^i mod p = {xs}")
    a_poly = lagrange_interpolate(xs, w.a, p)
    print(f"A(X) interpolated from a-column evals = {a_poly}  (coeffs low→high)")
    print(f"A(omega^1) = {poly_eval(a_poly, xs[1], p)}")

    _step(2, "PLONK gate constraints via selectors")
    gate_vals = gate_constraint_values(cols, w, p)
    print("gate constraint values per row (want all 0):", gate_vals)

    _step(3, "Copy constraints via permutation grand product")
    print("sigma_a:", sigma_a)
    print("sigma_b:", sigma_b)
    print("sigma_c:", sigma_c)
    beta, gamma = 7, 9
    z = compute_grand_product_z(cols, w, sigma_a, sigma_b, sigma_c, xs, p, beta=beta, gamma=gamma)
    print(f"beta={beta}, gamma={gamma}")
    print("grand product Z evaluations (including Z(1)=1):", z)
    print("final Z after n steps (want 1):", z[-1])

    _step(4, "Arithmetization summary: columns become polynomials")
    ql_poly = lagrange_interpolate(xs, cols.qL, p)
    qr_poly = lagrange_interpolate(xs, cols.qR, p)
    qm_poly = lagrange_interpolate(xs, cols.qM, p)
    qo_poly = lagrange_interpolate(xs, cols.qO, p)
    qc_poly = lagrange_interpolate(xs, cols.qC, p)
    b_poly = lagrange_interpolate(xs, w.b, p)
    c_poly = lagrange_interpolate(xs, w.c, p)
    g_evals = gate_constraint_values(cols, w, p)
    g_poly = lagrange_interpolate(xs, g_evals, p)

    print("qL(X) =", ql_poly)
    print("qR(X) =", qr_poly)
    print("qM(X) =", qm_poly)
    print("qO(X) =", qo_poly)
    print("qC(X) =", qc_poly)
    print("B(X)  =", b_poly)
    print("C(X)  =", c_poly)
    print("Gate polynomial G(X) evals on domain =", g_evals)
    print("Gate polynomial G(X) =", g_poly)

    print()
    print("Public output y =", inst["public"]["y"])
```

This is the core mental model you want: the “circuit” is selectors + permutation; the “witness” is column values; and “verifying” becomes checking polynomial identities over an evaluation domain (plus a commitment layer that makes it succinct and zero-knowledge).

Run it:
`python3 code/main.py`

## Use It

Real-world “PLONK-ish” systems usually combine:
- A PLONK-style gate + permutation core (often extended with lookups)
- Fiat–Shamir transcripts to make it non-interactive
- A polynomial commitment scheme to make openings succinct

Where you’ll see it:
- **halo2** (Zcash) — PLONK-ish with custom gates + lookups
- **gnark** — supports PLONK-ish provers/constraints (ecosystem-dependent)
- **snarkjs / circom** — PLONK variants in tooling stacks
- **arkworks** — building blocks for polynomial commitments and SNARK components

Use the toy code here only for understanding. Production systems rely on audited libraries and careful transcript/degree/boundary handling.

## Pitfalls

1) **Missing transcript binding (public inputs / circuit ID).** If Fiat–Shamir challenges don’t commit to the statement and circuit, proofs can become malleable or verify for the wrong claim.
2) **Permutation boundary-condition mistakes.** Forgetting `Z(1)=1`, forgetting the end condition, or permuting the wrong set of positions can silently drop copy constraints.
3) **Degree / domain mismatches.** A “polynomial identity” argument is only meaningful with enforced degree bounds and a correct domain. Many real bugs are “it verified, but the prover used higher degree”.
4) **Padding rows that aren’t constrained.** Unconstrained rows can become a hiding place to satisfy algebraic checks while violating intended wiring.
5) **Selector bugs that change the circuit.** If selectors are not committed/bound correctly, the prover can prove a different circuit than the verifier thinks they’re verifying.

## Ship It

Reusable artifact: `outputs/zk-plonk-review-checklist.md`

What to do with it:
1) Paste it into a design doc / PR template for ZK components.
2) Use the copy/paste prompts to force precise answers about gates, wiring, transcripts, and setup.
3) Keep it next to your “SNARK integration” code and run through it before shipping any proof verification change.

## Exercises

1. Easy. Run `python3 code/main.py`. Observe that the gate constraints are all zeros and that the grand product ends with `Z_final = 1`.
2. Medium. Modify the toy circuit to compute `y = x^3 + x + 5` using an extra row. Update selectors, witness, and copy cycles so both gate constraints and permutation constraints pass.
3. Hard. Add a “negative test” mode in `code/main.py` that flips a single wire value and prints which check fails (gate vs permutation), mirroring what a real verifier would reject.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Evaluation domain | “roots of unity” | A fixed set of points where you represent columns as low-degree polynomials |
| Selector | “gate coefficients” | Per-row coefficients that choose the gate equation |
| Copy constraint | “wiring” | Equality constraints that tie multiple cells to the same logical variable |
| Permutation σ | “sigma polynomials” | A mapping of wire positions used to enforce copy constraints |
| Grand product | “Z polynomial” | A recurrence/product identity that checks the permutation condition probabilistically |
| Polynomial commitment | “commit to A(X)” | Cryptography that binds to a polynomial and proves evaluations succinctly |
| Universal setup | “reuse the SRS” | One setup usable for many circuits up to a size/degree bound |

## Further Reading

- Gabizon, Williamson, Ciobotaru, *PLONK: Permutations over Lagrange-bases for Oecumenical Noninteractive arguments of Knowledge* (2019) — the original PLONK construction and permutation argument
- Zcash Foundation, *halo2 Book* (ongoing) — practical “PLONK-ish” proving system engineering (custom gates, lookups, transcripts)
- Bowe, Gabizon, Green, *A Multi-Party Protocol for Constructing the Public Parameters of the Pinocchio zk-SNARK* (2017) — background on universal setup ceremonies (Powers of Tau)
