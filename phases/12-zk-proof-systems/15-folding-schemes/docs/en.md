# Folding Schemes — Nova, SuperNova, HyperNova

> Fold two R1CS instances into one — no recursive SNARK needed.

**Type:** Build
**Languages:** Python
**Prerequisites:** `12-zk-proof-systems/02-r1cs` (R1CS structure), `12-zk-proof-systems/05-groth16` (SNARK recursion cost intuition), finite fields
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- **Explain** why standard SNARK recursion is expensive and what the folding approach replaces.
- **Define** a relaxed R1CS instance (u scalar, error vector E) and show how it generalises ordinary R1CS.
- **Compute** the cross term T for two relaxed R1CS instances and verify its formula algebraically.
- **Implement** the Nova folding step: combine two instances into one relaxed R1CS instance in O(n) field operations.
- **Chain** multiple folding steps and confirm the accumulated relaxed instance remains satisfiable.

## The Problem

Imagine you want to prove that you ran a program for a million steps, where each step is an R1CS constraint. The naive approach generates one giant R1CS covering all million steps and hands it to a SNARK. That works, but two things hurt:

1. **Memory**: the full million-row witness must fit in RAM during proving.
2. **Recursion overhead**: one popular alternative is *verifier recursion* — each step proves it verified the previous step's SNARK proof. But SNARK verifiers contain expensive operations (pairing checks, hash-to-curve) that translate into thousands of extra R1CS constraints per recursion level.

Folding schemes sidestep the second problem entirely. Instead of verifying a proof inside a proof, you *fold* two R1CS instances into a single *relaxed* R1CS instance using only linear operations — vector additions and scalar multiplications. The fold costs O(n) field multiplications where n is the witness size, with no elliptic-curve pairings, no hash-to-curve, and no polynomial commitments in the inner loop. You accumulate all the steps into one relaxed instance and only call a SNARK once, at the very end, to confirm the accumulated instance is satisfying.

This is the insight behind **Nova** (Kothapalli, Setty, Tzialla 2022). SuperNova extends it to non-uniform computation (different circuits per step), and HyperNova generalises the relaxation to customisable constraint systems (CCS), covering PLONK-style gates and lookup arguments.

## The Concept

### Relaxed R1CS

Standard R1CS asks: does a witness `z` satisfy `(Az) ∘ (Bz) = Cz`?

Relaxed R1CS adds two degrees of freedom:

```
(Az) ∘ (Bz) = u · Cz + E
```

- `u` is a scalar (commitment to "how many times" the constraint was applied).
- `E` is an *error vector* that absorbs cross terms from previous folds.

A **fresh** instance has `u = 1` and `E = [0, …, 0]`, which is exactly ordinary R1CS. After folding, `u` grows and `E` becomes non-zero — but the instance still encodes real computation.

### The Cross Term

When you add two witnesses linearly — `z_fold = z1 + r·z2` — the quadratic constraint breaks because:

```
A(z1 + r·z2) ∘ B(z1 + r·z2) = Az1·Bz1 + r·(Az1·Bz2 + Az2·Bz1) + r²·Az2·Bz2
```

The middle term `r·T` is the **cross term**, where:

```
T = (Az1 ∘ Bz2) + (Az2 ∘ Bz1) − u1·Cz2 − u2·Cz1
```

For the squaring gate `a·a = b` with `z = [a, b]`:

```
T = [a1·a2 + a2·a1 − a2² − a1²] = [2·a1·a2 − a1² − a2²] = [−(a1 − a2)²]
```

### Folding Equations

Given two relaxed R1CS instances `(z1, u1, E1)` and `(z2, u2, E2)` and a random challenge `r`:

```
z_fold = z1 + r · z2
u_fold = u1 + r · u2
E_fold = E1 + r · T + r² · E2
```

You can verify algebraically (substituting into the relaxed R1CS check) that if both inputs satisfy their respective relaxed constraints then `(z_fold, u_fold, E_fold)` satisfies the relaxed constraint for the folded instance. The proof is a single line of algebra expanding the quadratic and collecting terms.

### Why It Is Cheap

Each fold is *linear* in the witness size `n`:
- `z_fold`: `n` multiplications and `n` additions.
- `u_fold`: 1 multiplication and 1 addition.
- `E_fold`: `3n` multiplications and `3n` additions (two vscale + two vadd).

No polynomial interpolation, no FFT, no pairing. The O(n) cost per step is why Nova-style IVC can scale to large programs.

## Build It

### Step 1: field and vector helpers

```python
def finv(a: int, p: int) -> int:
    """Modular inverse via Fermat's little theorem (p must be prime)."""
    a %= p
    if a == 0:
        raise ZeroDivisionError("inverse of 0 does not exist")
    return pow(a, p - 2, p)


def vadd(a, b, p):
    return [(x + y) % p for x, y in zip(a, b)]

def vsub(a, b, p):
    return [(x - y) % p for x, y in zip(a, b)]

def vscale(a, k, p):
    return [(k * x) % p for x in a]

def hadamard(a, b, p):
    return [(x * y) % p for x, y in zip(a, b)]

def matvec(M, v, p):
    return [
        sum(M[i][j] * v[j] for j in range(len(v))) % p
        for i in range(len(M))
    ]
```

All operations stay in `F_p`. We use `p = 101` throughout so every intermediate value is a small integer you can check with pencil.

### Step 2: squaring R1CS and witness

```python
def make_squaring_r1cs():
    A = [[1, 0]]
    B = [[1, 0]]
    C = [[0, 1]]
    return A, B, C

def r1cs_witness(a: int, p: int) -> list:
    return [a % p, (a * a) % p]
```

The constraint `(Az) ∘ (Bz) = Cz` becomes `[a] ∘ [a] = [b]`, i.e. `a² = b`. One row, two columns, one multiplication gate — the smallest non-trivial R1CS.

### Step 3: relaxed R1CS checker

```python
def check_relaxed_r1cs(A, B, C, z, u, E, p) -> bool:
    Az = matvec(A, z, p)
    Bz = matvec(B, z, p)
    Cz = matvec(C, z, p)
    lhs = hadamard(Az, Bz, p)
    rhs = vadd(vscale(Cz, u, p), E, p)
    return lhs == rhs
```

When `u = 1` and `E = [0]` this is exactly the standard R1CS check. Pass `u != 1` or `E != [0]` to verify a folded (relaxed) instance.

### Step 4: cross term and fold

```python
def compute_cross_term(A, B, C, z1, u1, z2, u2, p) -> list:
    Az1 = matvec(A, z1, p)
    Bz1 = matvec(B, z1, p)
    Cz1 = matvec(C, z1, p)
    Az2 = matvec(A, z2, p)
    Bz2 = matvec(B, z2, p)
    Cz2 = matvec(C, z2, p)
    t1 = hadamard(Az1, Bz2, p)
    t2 = hadamard(Az2, Bz1, p)
    t3 = vscale(Cz2, u1, p)
    t4 = vscale(Cz1, u2, p)
    return vsub(vadd(t1, t2, p), vadd(t3, t4, p), p)


def nova_fold(A, B, C, z1, u1, E1, z2, u2, E2, r, p):
    T = compute_cross_term(A, B, C, z1, u1, z2, u2, p)
    z_fold = vadd(z1, vscale(z2, r, p), p)
    u_fold = (u1 + r * u2) % p
    r2 = (r * r) % p
    E_fold = vadd(vadd(E1, vscale(T, r, p), p),
                  vscale(E2, r2, p), p)
    return z_fold, u_fold, E_fold, T
```

`compute_cross_term` is purely linear: six `matvec` calls (each O(n)) and four `hadamard`/`vscale` calls. `nova_fold` is one call to `compute_cross_term` plus four more O(n) operations.

### Step 5: chain four folds and verify

```python
a_vals = [3, 5, 11, 17]
r_chain = 17

instances = [(r1cs_witness(a, p), 1, [0]) for a in a_vals]

z_cur, u_cur, E_cur = instances[0]
for i in range(1, len(a_vals)):
    z_next, u_next, E_next = instances[i]
    z_cur, u_cur, E_cur, _ = nova_fold(
        A, B, C,
        z_cur, u_cur, E_cur,
        z_next, u_next, E_next,
        r_chain, p,
    )
    ok_i = check_relaxed_r1cs(A, B, C, z_cur, u_cur, E_cur, p)
    print(f"After fold {i}: z={z_cur}  u={u_cur}  E={E_cur}  valid={ok_i}")
```

After every fold `check_relaxed_r1cs` must return `True`. The final `(z_cur, u_cur, E_cur)` encodes all four squaring computations in a single relaxed instance.

Run it:

```
python3 code/main.py
```

## Use It

In real systems you rarely implement folding from scratch — you use it as part of an IVC stack.

- **Nova (Microsoft Research, 2022):** the original Nova paper introduces committed relaxed R1CS where `T` (and sometimes `E`) are Pedersen-committed, so the verifier checks a group element rather than a raw vector. This makes the fold succinct and hides the witness.
- **SuperNova:** extends Nova to non-uniform IVC: each step can use a different circuit (different `A, B, C`). A "program counter" selects which circuit to fold against. Useful for VMs where each opcode has a different constraint structure.
- **HyperNova:** replaces R1CS with CCS (Customisable Constraint Systems), which subsumes PLONK gates and lookup arguments. The cross term generalises to a multi-linear expression over Spartan-style sumchecks.
- **Sonobe (privacy-scaling-explorations):** a Rust library that implements Nova, SuperNova, and HyperNova folding schemes with Arkworks backends. It provides a high-level `FoldingScheme` trait so you can swap Nova for HyperNova without rewriting your circuit.

## Pitfalls

- **Using a fresh `u=1` when folding a folded instance.** After the first fold, `u_fold != 1` and `E_fold != 0`. Forgetting to pass the updated `u` and `E` to the next fold corrupts the error term and the final check fails.
- **Not committing T before deriving r.** In the real Nova protocol, the prover commits to `T` (as a Pedersen commitment) and the verifier derives `r` by hashing that commitment. If `r` is chosen before `T` is fixed, the prover can adaptively choose `T` to forge a fold.
- **Reusing the same r across folds.** Each fold requires a freshly random challenge. Reusing `r` creates linear dependencies between folded instances that can allow a prover to satisfy the check with an invalid witness.
- **Forgetting the r² term on E2.** The correct error update is `E_fold = E1 + r·T + r²·E2`. Dropping the `r²·E2` term is correct only when both inputs are fresh (`E1 = E2 = 0`), but becomes a soundness hole when chaining folds.
- **Field size too small.** Using `p = 101` is fine for learning, but in practice `r` must be drawn from a field large enough that the probability of `r` landing on a "bad" value is negligible (typically a 254-bit prime). With `p = 101`, an adversary can try all 101 values of `r` and find one that makes a false fold pass.

## Ship It

This lesson ships a reusable review checklist:

- `outputs/nova-folding-review-checklist.md`

Use it when reviewing a Nova-style folding implementation to verify: relaxed R1CS structure, cross term computation, error term accumulation, commitment of T before challenge derivation, and final SNARK on the accumulated instance.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Confirm every step prints `True` for the validity checks. Then change `a1 = 3` to `a1 = 0` and observe that the cross term becomes `T = [0]` — explain why.
2. **Medium.** Add a second constraint to the R1CS: `a + b = c` (a linear gate). Extend the witness to `z = [a, b, c]`, update `A, B, C` to have two rows, and rerun all five steps. Verify that `compute_cross_term` now returns a length-2 vector and `check_relaxed_r1cs` still passes after folding.
3. **Hard.** Implement a committed fold: replace the raw cross term vector `T` with a Pedersen commitment `com_T = r_blind·G + sum(T[i]·H[i])` using small toy group arithmetic (e.g. `secp256k1` or a toy elliptic curve). Derive the folding challenge `r` by hashing `com_T`, making the fold non-interactive via Fiat–Shamir. Verify that changing any entry of `T` causes the challenge to change and the folded check to fail.

## Key Terms

| Term | What people say | What it actually means |
|------|-----------------|------------------------|
| Relaxed R1CS | "The generalised constraint system used in Nova" | An R1CS variant `(Az)∘(Bz) = u·Cz + E` with a scalar `u` and error vector `E`; fresh instances have `u=1, E=0`. |
| Cross term | "The T vector in the fold" | The bilinear term `T = (Az1∘Bz2)+(Az2∘Bz1)−u1·Cz2−u2·Cz1` that arises from expanding `(z1+r·z2)` in the quadratic constraint. |
| Folding | "Combining two instances into one" | A linear map `(z1,u1,E1),(z2,u2,E2) → (z_fold,u_fold,E_fold)` that preserves relaxed R1CS satisfiability, costing only O(n) field operations. |
| Committed relaxed R1CS | "The version used in the real Nova protocol" | Relaxed R1CS where `E` and `T` are Pedersen-committed, so the verifier checks group elements rather than raw vectors, keeping the proof succinct. |
| IVC | "Incrementally Verifiable Computation" | A proof system where each step i produces a proof that steps 1..i were executed correctly, composable without re-proving prior steps from scratch. |

## Further Reading

- Kothapalli, Setty, Tzialla, *Nova: Recursive Zero-Knowledge Arguments from Folding Schemes* (2022, CRYPTO) — the original Nova paper introducing relaxed R1CS and the folding verifier.
- Kothapalli, Setty, *SuperNova: Proving universal machine executions without universal circuits* (2022) — extends Nova to non-uniform computation with per-step circuits.
- Kothapalli, Setty, *HyperNova: Recursive Arguments for Customizable Constraint Systems* (2023) — generalises folding to CCS, covering PLONK and lookup-based circuits.
- Setty, *Spartan: Efficient and general-purpose zkSNARKs without trusted setup* (2020) — the sumcheck-based SNARK that HyperNova uses for the final proof.
