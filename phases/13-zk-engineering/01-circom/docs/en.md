# Writing Circom Circuits
> A circuit is a set of constraints; the witness is just an assignment that satisfies them.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** Phase 12 · 01 (Arithmetic Circuits), Phase 12 · 02 (R1CS)  
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- Explain why Circom is constraints-over-a-field, not “code that runs”.
- Distinguish circuit compilation (constraints) from witness generation (assignment).
- Implement a tiny R1CS checker (`A * B = C`) and validate a witness.
- Apply boolean and 4-bit range constraints to model “integers” safely.
- Compute a concrete witness for an arithmetic circuit and see cheating attempts rejected.

## The Problem

Circom looks like a programming language, so people read circuits like programs. That mental model is wrong in the way that matters most for security: the verifier is not executing your circuit. The verifier is checking that **some** witness exists that satisfies **constraints** derived from the circuit.

If you mix up “assignment” and “constraint”, you ship circuits that verify proofs for statements you didn’t intend. The most common bugs are soundness bugs: you treat field elements as integers without range checks, or you compute something in witness code without constraining it. A malicious prover can then pick a weird witness that still satisfies the constraints and produce a proof that verifies.

This lesson builds a runnable mental model for Circom using a tiny, stdlib-only Python “compiler” to R1CS-style constraints plus a checker. Once you can *run the checker*, it becomes obvious what must be constrained and what can be faked by the witness.

## The Concept

At a high level, Circom (and many SNARK circuit DSLs) compile to a constraint system over a finite field `F_p`. Conceptually, R1CS constraints look like:

`A(x) * B(x) = C(x)` in `F_p`,

where `A`, `B`, and `C` are **linear combinations** of variables:

`const + Σ (coeff_i * var_i)`.

A **witness** is just a map `{var_id -> value}`. The prover chooses witness values. The verifier checks whether every constraint holds. Two consequences:

- All arithmetic is modulo `p`. If you mean integers, you must add **range constraints**.
- There are no “types” like `bool` unless you constrain them. A boolean is enforced by `b * (b - 1) = 0`.

We’ll implement:

- Field arithmetic (just enough to evaluate constraints)
- Linear combinations and an R1CS constraint checker
- Two gadgets: boolean constraints and a 4-bit range check via bit decomposition
- A tiny arithmetic circuit that binds `d` to `a*b+c` and range-checks all inputs

## Build It

### Step 1: Field arithmetic (mod p)
```python
class Field:
    def __init__(self, p: int):
        if not isinstance(p, int) or p <= 2:
            raise ValueError("p must be an int > 2")
        self.p = p

    def __call__(self, x: int) -> "FieldElem":
        return FieldElem(self, x % self.p)
```

Everything lives in a field. This wrapper makes the “mod p” behavior explicit and keeps evaluation deterministic.

### Step 2: R1CS constraints (A*B=C) and checking
```python
@dataclass(frozen=True)
class LinearComb:
    """A linear combination over variables: const + sum_i (coeff_i * var_i).

    `terms` is a list of [coeff, var_id] pairs. var_id 0 is reserved for the
    constant-one wire (so assignment[0] must be 1).
    """

    F: Field
    const: int
    terms: List[List[int]]


def eval_lc(lc: LinearComb, assignment: Dict[int, int]) -> FieldElem:
    F = lc.F
    acc = F(lc.const)
    for coeff, var_id in lc.terms:
        if var_id not in assignment:
            raise KeyError(f"missing var {var_id} in assignment")
        acc = acc + F(coeff) * F(assignment[var_id])
    return acc


@dataclass(frozen=True)
class R1CSConstraint:
    A: LinearComb
    B: LinearComb
    C: LinearComb
    label: str = ""


def check_r1cs(constraints: Iterable[R1CSConstraint], assignment: Dict[int, int]) -> Tuple[bool, List[str]]:
    failures: List[str] = []
    for i, con in enumerate(constraints):
        try:
            a = eval_lc(con.A, assignment)
            b = eval_lc(con.B, assignment)
            c = eval_lc(con.C, assignment)
        except Exception as e:
            failures.append(f"constraint {i} {con.label}: eval error: {e}")
            continue
        if int(a * b - c) != 0:
            failures.append(
                f"constraint {i} {con.label}: (A*B-C) != 0 (A={int(a)}, B={int(b)}, C={int(c)})"
            )
    return (len(failures) == 0), failures
```

This is the verifier mental model: a witness is valid if every constraint evaluates to zero in the field.

### Step 3: Boolean and 4-bit range constraints
```python
def compile_assert_boolean(F: Field, b_var: int, label: str) -> R1CSConstraint:
    A = _lc_var(F, b_var)
    B = LinearComb(F, const=-1, terms=[[1, b_var]])
    return R1CSConstraint(A=A, B=B, C=_lc_const(F, 0), label=label)


def compile_range_check_4bit(F: Field, x_var: int, prefix: str) -> Tuple[List[R1CSConstraint], List[int]]:
    """Constrains x in [0, 15] by introducing 4 boolean bits b0..b3.

    Constraints:
      - each bi is boolean
      - x == b0 + 2*b1 + 4*b2 + 8*b3

    Returns (constraints, bit_var_ids). Bit ids are deterministic: [x_var+1..x_var+4].
    """

    bit_ids = [x_var + 1, x_var + 2, x_var + 3, x_var + 4]
    constraints: List[R1CSConstraint] = []

    for i, bid in enumerate(bit_ids):
        constraints.append(compile_assert_boolean(F, bid, label=f"{prefix}.bit{i}.boolean"))

    terms = [[1, x_var]]
    for i, bid in enumerate(bit_ids):
        terms.append([-(1 << i), bid])
    A = LinearComb(F, const=0, terms=terms)
    constraints.append(R1CSConstraint(A=A, B=_lc_const(F, 1), C=_lc_const(F, 0), label=f"{prefix}.recompose"))
    return constraints, bit_ids
```

In circuit land, “is a bit” and “is a 32-bit integer” are not types — they’re constraints you must add. Without them, a prover can choose any field element that makes constraints pass.

### Step 4: A tiny “Circom-like” circuit and witness
```python
def build_arith_and_range_circuit(F: Field) -> Dict[str, object]:
    """Circuit:
      - inputs: a, b, c (all 4-bit), d (unconstrained field element)
      - compute: t = a*b, out = t + c
      - enforce: out == d
      - range-check: a,b,c are 4-bit

    Variable layout is fixed for determinism:
      0: one
      1: a
      2..5: a bits
      6: b
      7..10: b bits
      11: c
      12..15: c bits
      16: d
      21: t
      22: out
    """

    one = 0
    a = 1
    b = 6
    c_in = 11
    d = 16
    t = 21
    out = 22

    constraints: List[R1CSConstraint] = []
    constraints.extend(compile_range_check_4bit(F, a, "a")[0])
    constraints.extend(compile_range_check_4bit(F, b, "b")[0])
    constraints.extend(compile_range_check_4bit(F, c_in, "c")[0])

    constraints.append(compile_mul(F, a, b, t, label="t=a*b"))

    A = LinearComb(F, const=0, terms=[[1, out], [-1, t], [-1, c_in]])
    constraints.append(R1CSConstraint(A=A, B=_lc_const(F, 1), C=_lc_const(F, 0), label="out=t+c"))

    constraints.append(compile_assert_equal(F, out, d, label="out==d"))

    return {
        "var_ids": {"one": one, "a": a, "b": b, "c": c_in, "d": d, "t": t, "out": out},
        "constraints": constraints,
    }
```

This is the full pipeline: define wires, add constraints, generate a witness, and check it. Circom does the same thing at a much larger scale, with nicer syntax and real proving/verification tooling.

Run it:
`python3 code/main.py`

## Use It

Real production equivalents for the concepts here:

- **Circom + snarkjs**: `.circom` → constraints (R1CS) + WASM witness generator → Groth16/Plonk proofs.
- **Noir**: similar “constraints + witness” model, different language and ecosystem.
- **Halo2 / Plonkish frameworks (Rust)**: you write constraints (gates) and explicitly assign witness values.
- **Gadget libraries**: circomlib and equivalents provide tested building blocks (hashes, Merkle proofs, comparisons, range checks).

## Pitfalls

1. Missing range checks: treating field elements as integers without constraining bit-width.
2. Missing boolean constraints: selectors must be constrained to `{0,1}` or they become arbitrary scalars.
3. Confusing assignment with proof: witness code can compute anything unless constraints bind it.
4. Modulo wraparound surprises: `a*b+c=d` is modulo `p`, not integer arithmetic.
5. No negative tests: without “cheating witness” tests, soundness bugs ship quietly.

## Ship It

Use `outputs/zk-circuit-review-checklist.md` as a PR review template for Circom/Noir/Halo2 circuits. Paste it into PRs, write the statement + ranges first, then add constraints and negative tests until every checkbox is satisfied.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe how a valid witness passes and a tampered (non-bit) witness is rejected.
2. Medium: Extend the circuit to also range-check `out` (e.g., as 5-bit) and add a deterministic vector test.
3. Hard: Pick a real Circom gadget (e.g., `Num2Bits` or `LessThan`) and write a cheating-witness test plan: what witness values would you try to forge and which constraints should reject them?

## Key Terms

| Term | What people say | What it actually means |
|---|---|---|
| Witness | “the private inputs” | Full assignment to all wires (including intermediates) that satisfies constraints |
| Constraint | “a line of Circom” | An equation over a field that must hold for the witness |
| R1CS | “rank-1 constraints” | Constraints of the form `(linear) * (linear) = (linear)` |
| Range check | “make it an int” | Constrain a field element to fit a chosen bit-width |
| Boolean constraint | “this is a bit” | Force a value to be 0 or 1 via `b*(b-1)=0` |

## Further Reading

- Vitalik Buterin, “Quadratic Arithmetic Programs: from Zero to Hero” (2016) — intuition for constraints → SNARK-friendly math.
- Circom Documentation, “Signals and Constraints” — how `signal`, assignments, and constraints relate in Circom.
- Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru, “PLONK” (2019) — a modern proving system built around polynomial constraints.
