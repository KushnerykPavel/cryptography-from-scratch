# Noir — Aztec's ZK Language (Without the Magic)

> A ZK DSL is just: program → constraints + witness.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 13 / `01-circom`, `02-snarkjs` (witness + constraints mental model)
**Time:** ~75 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives

- Explain the pipeline from high-level code to constraints + witness
- Compute a witness by evaluating a program over a finite field
- Implement a tiny compiler that lowers an AST to R1CS-ish constraints
- Distinguish `Field` arithmetic from `u32` (range-constrained) arithmetic
- Apply a checklist to spot underconstrained / unconstrained output bugs

## The Problem

Noir is “Rust-like code for ZK proofs”, but the proof system does not execute your program like a CPU. It checks a set of **constraints** over a finite field, and it accepts if there exists a **witness** (an assignment to all wires) that satisfies them.

If you don’t internalize this, you’ll write code that *looks right* but proves the wrong thing. The classic failure mode is **underconstraint**: the prover can supply a witness that passes the constraints while violating your intent. This is how “valid proofs for false statements” happen.

This lesson makes the pipeline concrete by building a tiny Noir-inspired front-end in Python: an AST, a compiler to constraints, and a satisfiability checker. No cryptography, no proving keys—just the engineering reality of “what are we actually proving?”

## The Concept

Think in two artifacts:

1. **Constraint System (what gets proved):** equations that must hold over field elements.
2. **Witness (how the prover convinces you):** concrete values for *every* intermediate wire that make the equations true.

In R1CS-style systems, each constraint is “one multiplication wide”:

```
(A · w) * (B · w) = (C · w)
```

where `w` is the witness vector (wire values), and `A`, `B`, `C` are *linear combinations* of wires.

Why this matters:

- Addition is “cheap”: it stays linear.
- Multiplication is “special”: you typically introduce an intermediate wire so each constraint has at most one multiplication.
- Fixed-width integers like `u32` are not “native”; they’re field elements **plus extra constraints** (range checks, overflow rules).
- Unconstrained computation can generate witness values without adding constraints; if you forget to constrain its outputs, you might prove nothing.

## Build It

### Step 1: A Tiny Noir-Like AST

We model a tiny subset of “Noir-like code” as an AST (expressions + statements) and interpret it to produce a witness environment. Everything lives in a finite field (a modulus), which is the only numeric domain the constraint system understands.

```python
DEFAULT_FIELD_MODULUS = 2**61 - 1


def field_normalize(value: int, modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    return value % modulus


def field_add(a: int, b: int, modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    return (a + b) % modulus


def field_sub(a: int, b: int, modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    return (a - b) % modulus


def field_mul(a: int, b: int, modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    return (a * b) % modulus


@dataclass(frozen=True)
class Expr:
    pass


@dataclass(frozen=True)
class Const(Expr):
    value: int


@dataclass(frozen=True)
class Var(Expr):
    name: str


@dataclass(frozen=True)
class Add(Expr):
    left: Expr
    right: Expr


@dataclass(frozen=True)
class Mul(Expr):
    left: Expr
    right: Expr


def eval_expr(expr: Expr, env: Dict[str, int], modulus: int = DEFAULT_FIELD_MODULUS) -> int:
    if isinstance(expr, Const):
        return field_normalize(expr.value, modulus)
    if isinstance(expr, Var):
        return field_normalize(env[expr.name], modulus)
    if isinstance(expr, Add):
        return field_add(eval_expr(expr.left, env, modulus), eval_expr(expr.right, env, modulus), modulus)
    if isinstance(expr, Mul):
        return field_mul(eval_expr(expr.left, env, modulus), eval_expr(expr.right, env, modulus), modulus)
    raise TypeError(f"unknown Expr: {type(expr).__name__}")


@dataclass(frozen=True)
class Stmt:
    pass


@dataclass(frozen=True)
class Let(Stmt):
    name: str
    expr: Expr
    constrained: bool = True


@dataclass(frozen=True)
class AssertEq(Stmt):
    left: Expr
    right: Expr


@dataclass(frozen=True)
class RangeCheck(Stmt):
    expr: Expr
    bits: int


def execute_program(
    statements: List[Stmt], inputs: Dict[str, int], modulus: int = DEFAULT_FIELD_MODULUS
) -> Dict[str, int]:
    env: Dict[str, int] = {k: field_normalize(v, modulus) for k, v in inputs.items()}
    for stmt in statements:
        if isinstance(stmt, Let):
            env[stmt.name] = eval_expr(stmt.expr, env, modulus)
        elif isinstance(stmt, AssertEq):
            pass
        elif isinstance(stmt, RangeCheck):
            pass
        else:
            raise TypeError(f"unknown Stmt: {type(stmt).__name__}")
    return env
```

### Step 2: Compile to Constraints (R1CS-ish)

Now we lower the AST to constraints. The key trick is representing expressions as **linear combinations**; when we hit multiplication, we create a fresh wire and emit a single `A*B=C` constraint. We also build a tiny witness generator for intermediate wires so the demo can produce a full witness vector.

```python
@dataclass(frozen=True)
class LinearCombination:
    terms: Dict[int, int]
    const: int = 0


@dataclass(frozen=True)
class R1CSConstraint:
    a: LinearCombination
    b: LinearCombination
    c: LinearCombination


@dataclass(frozen=True)
class WireGenerator:
    wire: int
    kind: str
    left: LinearCombination
    right: Optional[LinearCombination] = None


@dataclass(frozen=True)
class Circuit:
    modulus: int
    num_wires: int
    constraints: List[R1CSConstraint]
    range_constraints: List[Tuple[int, int]]
    name_to_wire: Dict[str, int]
    wire_to_name: Dict[int, str]
    generators: List["WireGenerator"]


def circuit_is_satisfied(circuit: Circuit, witness: List[int]) -> bool:
    if len(witness) != circuit.num_wires:
        return False
    if witness[0] % circuit.modulus != 1:
        return False

    w = [field_normalize(x, circuit.modulus) for x in witness]
    for wire, bits in circuit.range_constraints:
        if not range_check_bits(w[wire], bits):
            return False

    for con in circuit.constraints:
        left = eval_lc(con.a, w, circuit.modulus)
        right = eval_lc(con.b, w, circuit.modulus)
        out = eval_lc(con.c, w, circuit.modulus)
        if (left * right - out) % circuit.modulus != 0:
            return False
    return True
```

### Step 3: Add u32 Range Checks

In Noir, `u32` is conceptually “a field element + constraints that keep it within 32 bits”. We model that by adding explicit `RangeCheck(expr, 32)` statements and checking them during `circuit_is_satisfied`.

```python
def range_check_bits(value: int, bits: int) -> bool:
    if bits <= 0:
        return False
    if value < 0:
        return False
    return value < (1 << bits)


def demo_program_u32_add() -> List[Stmt]:
    a = Var("a")
    b = Var("b")
    s = Var("s")
    return [
        RangeCheck(a, 32),
        RangeCheck(b, 32),
        Let("s", Add(a, b)),
        RangeCheck(s, 32),
    ]
```

### Step 4: Spot Underconstrained Computation

The easiest way to ship a “valid proof of a false statement” is to compute something without constraints, then forget to assert what makes it true. We simulate this by letting `Let(..., constrained=False)` skip constraint emission. A malicious prover can then set `out` arbitrarily and still satisfy the circuit—until we add an explicit `AssertEq(out, x*y)`.

```python
def demo_program_unconstrained_product(also_constrain: bool) -> List[Stmt]:
    x = Var("x")
    y = Var("y")
    out = Var("out")
    stmts: List[Stmt] = [Let("out", Mul(x, y), constrained=False)]
    if also_constrain:
        stmts.append(AssertEq(out, Mul(x, y)))
    return stmts


def set_witness_value(circuit: Circuit, witness: List[int], name: str, value: int) -> None:
    wire = circuit.name_to_wire[name]
    witness[wire] = field_normalize(value, circuit.modulus)
```

Run it:

```bash
python3 code/main.py
```

## Use It

Real Noir workflow (high level):

- Write a circuit in `.nr` (Noir).
- Use `nargo` to typecheck/compile and to execute to a witness.
- Inspect constraints/opcodes (ACIR) to understand what is actually being proven.
- Use a proving backend (e.g. Barretenberg) to generate/verify proofs from the circuit + witness.

What maps to what:

- Our `Expr` / `Stmt` AST → Noir frontend AST / typechecked IR
- Our “R1CS-ish constraints” → ACIR opcodes / backend constraints
- Our `witness_from_env(...)` → witness generation (`nargo execute`) + solver logic

## Pitfalls

- Treating `Field` like an integer type: comparisons, bounds, and overflow don’t exist unless you add constraints.
- Forgetting to range-check fixed-width values (`u32`/`u64`) when the protocol assumes a bound.
- Computing a value “off-circuit” (unconstrained / oracle) and not asserting a relation that ties it back to inputs.
- Assuming “I computed it” implies “I proved it”: only constraints are proven.
- Underconstrained outputs: if outputs are not functionally determined by intended inputs, a prover can choose them.

## Ship It

Save a reusable review prompt to:

- `outputs/prompt-noir-circuit-review-checklist.md`

Use it when reviewing Noir PRs:

1. Paste the prompt into your assistant.
2. Paste the relevant `.nr` files (or link the diff).
3. Ask for “must-fix soundness issues first, then performance”.

## Exercises

1. Easy: Run `python3 code/main.py`. Observe that `u32` overflow makes `satisfied: False`.
2. Medium: Extend `demo_program_u32_add()` to include `RangeCheck(s, 32)` *and* an `AssertEq(s, Add(a, b))`. Re-run the demo and explain what changed (or didn’t).
3. Hard: Add a `Bool` type to the model (enforce `b * (b - 1) == 0`) and show how a missing boolean constraint creates an underconstraint.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Witness | “The secret input” | The full assignment to all wires (inputs + intermediates) |
| Constraint | “A check” | An equation that must hold over field elements |
| Field | “Big integer” | Arithmetic modulo a prime; wraps with no overflow unless constrained |
| Range check | “Make it a u32” | Extra constraints that force a field element into a bit-length range |
| Underconstrained | “Missing an assert” | Multiple distinct witnesses satisfy the same public instance |

## Further Reading

- Noir Documentation, Thinking in Circuits (n.d.) — practical advice for writing circuits and reasoning about gate costs
- Noir Documentation, Fields (n.d.) — what the native field type is and why overflow is not checked
- Noir Documentation, Integers (n.d.) — integers as range-constrained field elements and overflow expectations
- Noir Documentation, Unconstrained Functions (n.d.) — when unconstrained execution is safe and how to constrain results
