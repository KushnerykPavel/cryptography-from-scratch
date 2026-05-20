# R1CS — Rank-1 Constraint Systems

> Turn a circuit into equations: `A(w) · B(w) = C(w)` over a field.

**Type:** Build
**Languages:** Python
**Prerequisites:** `12-zk-proof-systems/01-arithmetic-circuits` (basic “wires + gates”), basic finite-field arithmetic
**Time:** ~60 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** what an R1CS constraint means (`A(w)·B(w)=C(w)`).
- **Compute** linear combinations on a witness vector.
- **Implement** an R1CS satisfiability checker for a prime field.
- **Distinguish** “constraint system satisfied” from “zero-knowledge proof verified”.
- **Apply** the pattern to encode simple circuits with intermediate wires.

## The Problem
Every modern zkSNARK/zkSTARK pipeline has a “front-end” that turns your program into algebra. If you can’t read that algebra, you can’t debug it. You end up staring at failures like “constraint 17342 unsatisfied” with no idea what wire is wrong, what the prover forgot to compute, or why verification fails.

R1CS is one of the most common intermediate representations: it’s the bridge between “code” (circuits) and “proof systems” (Groth16, PLONK-ish systems, etc.). If you understand how an R1CS instance is built and what it means for a witness to satisfy it, you can reason about correctness, soundness footguns, and what proof systems are *actually* proving.

## The Concept
An R1CS instance is:
- a prime field `F_p` (all arithmetic is modulo `p`)
- a witness vector `w = [1, w1, w2, ...]` where `w[0] == 1` is a special “constant wire”
- a list of constraints; each constraint is three **linear combinations** `(A, B, C)`

Each linear combination is “a weighted sum of witness wires”:

`A(w) = Σ_i (a_i · w[i])   (mod p)`

An R1CS constraint says:

`A(w) · B(w) = C(w)   (mod p)`

That’s the whole model: “multiply two linear expressions and compare to a third”.

### Mental model: circuits → wires → constraints
You can encode:
- **addition** as `(x + y) · 1 = s`
- **multiplication** as `x · y = z`

So a circuit becomes:
1) introduce intermediate wires for gate outputs
2) write one constraint per gate
3) a valid witness is just “all wire values computed correctly”

R1CS by itself is **not** zero-knowledge. It’s a *statement format* (“there exists a witness `w` satisfying these equations”). A proof system is what lets you prove that statement without revealing `w`.

## Build It
We’ll build a tiny, stdlib-only R1CS satisfiability checker over a prime field and use it to debug a small circuit.

### Step 1: Prime-field arithmetic (mod p)
R1CS lives over a field. We’ll use `F_p` with a small prime `p` and implement modular normalization plus modular inverse (via extended Euclid).

```python
def modp(x: int, p: int) -> int:
    return x % p


def inv_mod(a: int, p: int) -> int:
    a = a % p
    if a == 0:
        raise ValueError("0 has no inverse mod p")

    t, new_t = 0, 1
    r, new_r = p, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("a is not invertible mod p")
    return t % p
```

This is enough to demonstrate the most important fact: **every number you see is modulo `p`** (including negatives).

### Step 2: Linear combinations on a witness
R1CS uses linear combinations to talk about “x + y”, “x − y”, “3x + 5”, etc. A linear combination is a list of `(wire_index, coefficient)` pairs. We evaluate it by summing `coeff · witness[index]`.

```python
def normalize_witness(witness: list[int], p: int) -> list[int]:
    if not witness:
        raise ValueError("witness must have at least one element (w[0] == 1)")
    if witness[0] != 1:
        raise ValueError("witness[0] must be 1 (the constant wire)")
    return [w % p for w in witness]


def eval_lc(terms: list[tuple[int, int]], witness: list[int], p: int) -> int:
    acc = 0
    for idx, coeff in terms:
        if idx < 0 or idx >= len(witness):
            raise IndexError(f"witness index out of range: {idx}")
        acc = (acc + (coeff % p) * witness[idx]) % p
    return acc
```

With the `w[0] == 1` convention, constants are easy: `5` is just the term `(0, 5)`.

### Step 3: Check one constraint (A·B == C)
Now we can define what it means for a single R1CS constraint to be satisfied: compute `A(w)`, `B(w)`, `C(w)` and verify `A(w)·B(w) − C(w) == 0 (mod p)`.

```python
def check_constraint(constraint: dict, witness: list[int], p: int) -> bool:
    a = eval_lc(constraint["A"], witness, p)
    b = eval_lc(constraint["B"], witness, p)
    c = eval_lc(constraint["C"], witness, p)
    return (a * b - c) % p == 0


def first_unsatisfied(constraints: list[dict], witness: list[int], p: int) -> int | None:
    witness = normalize_witness(witness, p)
    for i, con in enumerate(constraints):
        if not check_constraint(con, witness, p):
            return i
    return None


def constraint_trace(constraint: dict, witness: list[int], p: int) -> tuple[int, int, int]:
    witness = normalize_witness(witness, p)
    a = eval_lc(constraint["A"], witness, p)
    b = eval_lc(constraint["B"], witness, p)
    c = eval_lc(constraint["C"], witness, p)
    return a, b, c
```

When a proof system says “constraint i failed”, these are the numbers you conceptually want to inspect.

### Step 4: Encode a tiny circuit as R1CS
We’ll encode the circuit:

`out = (x + y) · (x − y)`

using intermediate wires `s = x + y` and `d = x − y`, and three constraints:
1) `(x + y)·1 = s`
2) `(x − y)·1 = d`
3) `s·d = out`

```python
def check_r1cs(constraints: list[dict], witness: list[int], p: int) -> bool:
    witness = normalize_witness(witness, p)
    return all(check_constraint(con, witness, p) for con in constraints)


def r1cs_for_out_equals_xplusy_times_xminusy() -> tuple[int, list[dict], list[int]]:
    p = 101

    x = 9
    y = 4
    s = x + y
    d = x - y
    out = s * d

    # Wire layout (standard convention):
    # w[0] = 1 (constant)
    # w[1] = x
    # w[2] = y
    # w[3] = s = x + y
    # w[4] = d = x - y
    # w[5] = out = s * d
    w = [1, x, y, s, d, out]

    constraints = [
        # (x + y) * 1 = s
        {"A": [(1, 1), (2, 1)], "B": [(0, 1)], "C": [(3, 1)]},
        # (x - y) * 1 = d
        {"A": [(1, 1), (2, -1)], "B": [(0, 1)], "C": [(4, 1)]},
        # s * d = out
        {"A": [(3, 1)], "B": [(4, 1)], "C": [(5, 1)]},
    ]

    return p, constraints, w


def main():
    p, constraints, w = r1cs_for_out_equals_xplusy_times_xminusy()
    w = normalize_witness(w, p)

    print("=== Step 1: prime-field arithmetic (everything is mod p) ===")
    a = 42
    inv_a = inv_mod(a, p)
    print(f"  p = {p}")
    print(f"  a = {a}, inv(a) = {inv_a}, a*inv(a) mod p = {(a * inv_a) % p}")
    print(f"  (-3) mod p = {modp(-3, p)}")

    print()
    print("=== Step 2: linear combinations evaluate on a witness ===")
    lc_x_plus_y = [(1, 1), (2, 1)]
    lc_x_minus_y = [(1, 1), (2, -1)]
    print(f"  witness w = {w}")
    print(f"  (x + y)(w) = {eval_lc(lc_x_plus_y, w, p)}")
    print(f"  (x - y)(w) = {eval_lc(lc_x_minus_y, w, p)}")

    print()
    print("=== Step 3: an R1CS constraint is (A(w) * B(w) == C(w)) ===")
    con0 = constraints[0]
    a0, b0, c0 = constraint_trace(con0, w, p)
    print(f"  constraint 0: A(w)={a0}, B(w)={b0}, C(w)={c0} -> satisfied={check_constraint(con0, w, p)}")

    w_bad = w.copy()
    w_bad[3] = (w_bad[3] + 1) % p
    bad_idx = first_unsatisfied(constraints, w_bad, p)
    print(f"  tweak witness: set s = s+1 -> first_unsatisfied = {bad_idx}")
    if bad_idx is not None:
        a_bad, b_bad, c_bad = constraint_trace(constraints[bad_idx], w_bad, p)
        print(f"  failing trace: A(w)={a_bad}, B(w)={b_bad}, C(w)={c_bad}")

    print()
    print("=== Step 4: a whole circuit becomes a list of constraints ===")
    ok = check_r1cs(constraints, w, p)
    ok_bad = check_r1cs(constraints, w_bad, p)
    print(f"  constraints: {len(constraints)}")
    print(f"  satisfied (good witness) = {ok}")
    print(f"  satisfied (bad witness)  = {ok_bad}")
    print(f"  output wire out = w[5] = {w[5]} (for x=9, y=4, out=(x+y)*(x-y)=65)")
```

Run it:
`python3 code/main.py`

## Use It
R1CS is a *representation*; proof systems sit “below” it.

Practical places you’ll see the same ideas:
- **Circom/snarkjs (Groth16/PLONK backends):** compilers emit constraint systems and witness generators.
- **arkworks / bellman / gnark:** front-ends provide APIs to write constraints like “this is multiplication”.
- **Halo2-style systems:** not R1CS, but the *pattern* is similar: you encode program correctness as field equations.

When reading real code, look for:
- a “constraint system” builder that creates variables/wires
- a function that computes a witness from inputs
- a “satisfy / check” path used in tests

## Pitfalls
- **Forgetting `w[0] == 1`:** you’ll have no clean way to express constants and your constraints will look “off by one”.
- **Mixing integers and field elements:** `-1` means `p-1`; range checks require *extra* constraints, not wishful thinking.
- **Missing intermediate wires:** any non-linear computation needs wires for intermediate results; you can’t “reuse” an expression unless you allocated a wire for it.
- **No canonical wire ordering:** if prover and verifier disagree on variable indices, everything breaks while looking “almost right”.
- **Treating satisfiable as secure:** “constraints satisfied” only means “equations hold”; it does not give zero-knowledge or soundness guarantees by itself.

## Ship It
Save the checklist in `outputs/r1cs-constraint-review-checklist.md` and use it whenever you:
- translate a program into R1CS constraints
- debug “constraint not satisfied” errors
- review a PR that adds or changes constraints / witness generation

## Exercises
1. Easy. Run `python3 code/main.py`. Observe which constraint fails after the witness tweak and what `A(w)`, `B(w)`, `C(w)` look like.
2. Medium. Change the circuit to `out = (x + 3) · (y + 2)`. Add wires and constraints, then update the witness and confirm it satisfies the new system.
3. Hard. Pick a real circuit library (Circom, gnark, arkworks) and find where it encodes “addition gate” and “multiplication gate”. Write down the equivalent R1CS-style equations and explain how constants are represented.

## Key Terms
| Term | What people say | What it actually means |
|------|----------------|----------------------|
| Witness | “the secret inputs” | The full vector of all wire values (including intermediates) that makes every constraint true. |
| Linear combination | “a weighted sum” | An expression `Σ c_i·w[i] (mod p)` used as `A(w)`, `B(w)`, or `C(w)`. |
| Constraint | “a gate” | One equation `A(w)·B(w)=C(w)`; typically one per circuit gate (plus wiring constraints). |
| `w[0] = 1` | “the constant wire” | A convention that lets you represent constants as coefficients on `w[0]`. |
| Arithmetization | “turn code into math” | The process of converting a program/circuit into field equations (R1CS, PLONK-ish, AIR, …). |

## Further Reading
- Oded Goldreich, *Foundations of Cryptography: Volume 1* (2001) — for the mindset: “prove statements about computation”.
- Ben-Sasson et al., *Succinct Non-Interactive Zero Knowledge for a von Neumann Architecture* (2013) — a classic lens on compiling computation to constraints.
- Vitalik Buterin, *Quadratic Arithmetic Programs: from R1CS to QAP* (2016) — a friendly bridge to the next lesson.
