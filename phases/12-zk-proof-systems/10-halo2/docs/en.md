# Halo2 — A PLONKish “Circuit Builder” Mindset

> Halo2 is “write constraints over columns and rows”, plus ergonomics that make it hard to lie to yourself.

**Type:** Build
**Languages:** Python
**Prerequisites:** Phase 12 · 06 (PLONK Overview), Phase 12 · 09 (PLONKish Arithmetization)
**Time:** ~120 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** how Halo2 models a circuit as columns + rows with gate constraints.
- **Compute** constraint satisfaction by evaluating gate polynomials on each row.
- **Implement** a tiny Halo2-like DSL (columns, selectors, copy constraints, mock prover).
- **Distinguish** advice vs fixed vs instance columns and when each is appropriate.
- **Apply** these ideas to reason about “unconstrained witness” bugs in real circuits.

## The Problem

You can read PLONK papers and still ship circuits that are *formally invalid* because you accidentally left some witness value unconstrained. In a ZK system, “my tests pass” does not mean “my circuit enforces what I think it enforces” — it often means your witness assignment happened to satisfy your (incomplete) constraints for the test cases you tried.

Halo2 is widely used (Zcash, many research prototypes) because it gives you a practical circuit API: selectors, rotations, copy constraints, and a mock prover that helps catch mistakes early. But the API can feel like magic if you don’t internalize the mental model: **a circuit is just a table**, and every safety property you want must be forced by constraints on that table.

In this lesson you’ll build a minimal, dependency-free “Halo2-ish” system in Python so you can *see* the pieces move: which values are public, which are private, what a selector does, what a copy constraint does, and how a mock prover checks satisfiability.

## The Concept

### The Halo2 table model

Think in rows and columns:

- **Advice columns**: witness values (private inputs and intermediate values).
- **Fixed columns**: prover-independent constants and selectors (often 0/1).
- **Instance columns**: public inputs/outputs (what the verifier sees).

Constraints are written as expressions that must evaluate to zero. If you have a constraint like:

`a + b - c = 0`

that is really “for each row where this gate is enabled, plug the row’s cell values into the expression and check it becomes 0 in the field”.

### Selectors and “don’t accidentally constrain every row”

Most gates should only apply on some rows. Halo2 uses **selectors** (fixed 0/1 columns). The common pattern is:

`q * constraint = 0`

When `q=0`, the gate is off. When `q=1`, the constraint must be satisfied.

### Copy constraints (“same value, different place”)

If you assign `a` on row 0 and use `a` again on row 2, you need to force those cells to be equal. Halo2 models this with **copy constraints** (implemented in PLONKish systems via a permutation argument). In the mental model:

`cell_left == cell_right`

is just another constraint the prover must satisfy.

## Build It

### Step 1: Define a small finite field and expression AST

We need a field (mod prime arithmetic) and a way to write constraints as expressions over “cells”:

```python
GOLDILOCKS_PRIME = 2**64 - 2**32 + 1


@dataclass(frozen=True)
class F:
    v: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "v", int(self.v) % GOLDILOCKS_PRIME)

    @staticmethod
    def zero() -> "F":
        return F(0)

    @staticmethod
    def one() -> "F":
        return F(1)

    def __int__(self) -> int:
        return self.v

    def __add__(self, other: "F") -> "F":
        return F(self.v + other.v)

    def __sub__(self, other: "F") -> "F":
        return F(self.v - other.v)

    def __mul__(self, other: "F") -> "F":
        return F(self.v * other.v)

    def __neg__(self) -> "F":
        return F(-self.v)

    def __pow__(self, exponent: int) -> "F":
        if exponent < 0:
            return self.inv().__pow__(-exponent)
        return F(pow(self.v, exponent, GOLDILOCKS_PRIME))

    def inv(self) -> "F":
        if self.v == 0:
            raise ZeroDivisionError("0 has no multiplicative inverse")
        return F(pow(self.v, GOLDILOCKS_PRIME - 2, GOLDILOCKS_PRIME))

    def __truediv__(self, other: "F") -> "F":
        return self * other.inv()

    def __repr__(self) -> str:
        return f"F({self.v})"


class Expr:
    def eval(self, assignment: "Assignment", row: int) -> F:
        raise NotImplementedError

    def __add__(self, other: "Expr") -> "Expr":
        return Add(self, other)

    def __sub__(self, other: "Expr") -> "Expr":
        return Add(self, Neg(other))

    def __mul__(self, other: "Expr") -> "Expr":
        return Mul(self, other)

    def __neg__(self) -> "Expr":
        return Neg(self)


@dataclass(frozen=True)
class Const(Expr):
    value: F

    def eval(self, assignment: "Assignment", row: int) -> F:
        return self.value


@dataclass(frozen=True)
class Cell(Expr):
    column: "Column"
    rotation: int = 0

    def eval(self, assignment: "Assignment", row: int) -> F:
        return assignment.get(self.column, row + self.rotation)


@dataclass(frozen=True)
class Add(Expr):
    a: Expr
    b: Expr

    def eval(self, assignment: "Assignment", row: int) -> F:
        return self.a.eval(assignment, row) + self.b.eval(assignment, row)


@dataclass(frozen=True)
class Mul(Expr):
    a: Expr
    b: Expr

    def eval(self, assignment: "Assignment", row: int) -> F:
        return self.a.eval(assignment, row) * self.b.eval(assignment, row)


@dataclass(frozen=True)
class Neg(Expr):
    a: Expr

    def eval(self, assignment: "Assignment", row: int) -> F:
        return -self.a.eval(assignment, row)
```

This is the “polynomial constraint” core: a constraint is an `Expr` that must evaluate to zero row-by-row (often multiplied by a selector).

### Step 2: Add columns, selectors, copy constraints, and an assignment table

We model columns, gates, and an assignment table (the “circuit spreadsheet”):

```python
@dataclass(frozen=True)
class Column:
    kind: str  # "advice" | "fixed" | "instance"
    index: int

    def __repr__(self) -> str:
        return f"{self.kind}[{self.index}]"


@dataclass(frozen=True)
class Gate:
    name: str
    selector: "Column"
    constraints: Tuple[Expr, ...]


@dataclass(frozen=True)
class CopyConstraint:
    left: "CellRef"
    right: "CellRef"


@dataclass(frozen=True)
class CellRef:
    column: Column
    row: int

    def __repr__(self) -> str:
        return f"{self.column}@{self.row}"


class ConstraintSystem:
    def __init__(self) -> None:
        self._advice_columns: List[Column] = []
        self._fixed_columns: List[Column] = []
        self._instance_columns: List[Column] = []
        self._selectors: List[Column] = []
        self._gates: List[Gate] = []
        self._copies: List[CopyConstraint] = []

    def advice_column(self) -> Column:
        col = Column("advice", len(self._advice_columns))
        self._advice_columns.append(col)
        return col

    def fixed_column(self) -> Column:
        col = Column("fixed", len(self._fixed_columns))
        self._fixed_columns.append(col)
        return col

    def instance_column(self) -> Column:
        col = Column("instance", len(self._instance_columns))
        self._instance_columns.append(col)
        return col

    def selector(self) -> Column:
        col = Column("fixed", len(self._fixed_columns))
        self._fixed_columns.append(col)
        self._selectors.append(col)
        return col

    def create_gate(self, name: str, selector: Column, constraints: Sequence[Expr]) -> None:
        if selector.kind != "fixed":
            raise ValueError("selector must be a fixed column")
        self._gates.append(Gate(name=name, selector=selector, constraints=tuple(constraints)))

    def constrain_equal(self, left: CellRef, right: CellRef) -> None:
        self._copies.append(CopyConstraint(left=left, right=right))

    @property
    def gates(self) -> Sequence[Gate]:
        return self._gates

    @property
    def copy_constraints(self) -> Sequence[CopyConstraint]:
        return self._copies

    @property
    def columns(self) -> Sequence[Column]:
        return [*self._instance_columns, *self._advice_columns, *self._fixed_columns]


class Assignment:
    def __init__(self) -> None:
        self._cols: Dict[Tuple[str, int], Dict[int, F]] = {}
        self._n_rows: int = 0

    @property
    def n_rows(self) -> int:
        return self._n_rows

    def _set(self, column: Column, row: int, value: F) -> None:
        if row < 0:
            raise ValueError("row must be non-negative")
        key = (column.kind, column.index)
        self._cols.setdefault(key, {})
        self._cols[key][row] = value
        if row + 1 > self._n_rows:
            self._n_rows = row + 1

    def set_advice(self, column: Column, row: int, value: int | F) -> CellRef:
        if column.kind != "advice":
            raise ValueError("set_advice expects an advice column")
        v = value if isinstance(value, F) else F(value)
        self._set(column, row, v)
        return CellRef(column=column, row=row)

    def set_fixed(self, column: Column, row: int, value: int | F) -> None:
        if column.kind != "fixed":
            raise ValueError("set_fixed expects a fixed column")
        v = value if isinstance(value, F) else F(value)
        self._set(column, row, v)

    def set_instance(self, column: Column, row: int, value: int | F) -> None:
        if column.kind != "instance":
            raise ValueError("set_instance expects an instance column")
        v = value if isinstance(value, F) else F(value)
        self._set(column, row, v)

    def get(self, column: Column, row: int) -> F:
        if row < 0:
            raise IndexError("rotation underflow (row < 0)")
        key = (column.kind, column.index)
        try:
            return self._cols[key][row]
        except KeyError as exc:
            raise KeyError(f"missing assignment for {column}@{row}") from exc

    def clone(self) -> "Assignment":
        out = Assignment()
        out._n_rows = self._n_rows
        for key, row_map in self._cols.items():
            out._cols[key] = dict(row_map)
        return out
```

This is enough structure to define gates and fill a concrete witness table.

### Step 3: Configure a circuit (3-bit range check + addition) and assign a witness

We’ll prove: `a` and `b` are 3-bit values, and `c = a + b` is a public output.

```python
def const(x: int) -> Const:
    return Const(F(x))


def bit_constraint(bit: Expr) -> Expr:
    return bit * (bit - const(1))


def decompose_3bit(value: int) -> Tuple[int, int, int]:
    if value < 0 or value > 7:
        raise ValueError("value must be a 3-bit integer (0..7)")
    return value & 1, (value >> 1) & 1, (value >> 2) & 1


def recompose_3bit(d0: int, d1: int, d2: int) -> int:
    if d0 not in (0, 1) or d1 not in (0, 1) or d2 not in (0, 1):
        raise ValueError("bits must be 0 or 1")
    return d0 + 2 * d1 + 4 * d2


def configure_range_add_circuit() -> Tuple[ConstraintSystem, Dict[str, Column]]:
    cs = ConstraintSystem()

    q_decompose = cs.selector()
    q_add = cs.selector()

    a = cs.advice_column()
    b = cs.advice_column()
    c = cs.advice_column()

    d0 = cs.advice_column()
    d1 = cs.advice_column()
    d2 = cs.advice_column()

    cs.create_gate(
        "3-bit decomposition",
        selector=q_decompose,
        constraints=[
            Cell(d0) + Cell(d1) * const(2) + Cell(d2) * const(4) - Cell(a),
            bit_constraint(Cell(d0)),
            bit_constraint(Cell(d1)),
            bit_constraint(Cell(d2)),
        ],
    )

    cs.create_gate(
        "addition",
        selector=q_add,
        constraints=[Cell(a) + Cell(b) - Cell(c)],
    )

    return cs, {
        "q_decompose": q_decompose,
        "q_add": q_add,
        "a": a,
        "b": b,
        "c": c,
        "d0": d0,
        "d1": d1,
        "d2": d2,
    }


def assign_range_decomposition_row(
    assignment: Assignment,
    cols: Dict[str, Column],
    row: int,
    value: int,
) -> Tuple[CellRef, CellRef]:
    assignment.set_fixed(cols["q_decompose"], row, 1)
    assignment.set_fixed(cols["q_add"], row, 0)

    d0, d1, d2 = decompose_3bit(value)

    a_cell = assignment.set_advice(cols["a"], row, value)
    d0_cell = assignment.set_advice(cols["d0"], row, d0)
    assignment.set_advice(cols["d1"], row, d1)
    assignment.set_advice(cols["d2"], row, d2)
    assignment.set_advice(cols["b"], row, 0)
    assignment.set_advice(cols["c"], row, 0)

    return a_cell, d0_cell


def assign_add_row(
    assignment: Assignment,
    cols: Dict[str, Column],
    row: int,
    a_value: int,
    b_value: int,
) -> Tuple[CellRef, CellRef, CellRef]:
    assignment.set_fixed(cols["q_decompose"], row, 0)
    assignment.set_fixed(cols["q_add"], row, 1)

    assignment.set_advice(cols["d0"], row, 0)
    assignment.set_advice(cols["d1"], row, 0)
    assignment.set_advice(cols["d2"], row, 0)

    a_cell = assignment.set_advice(cols["a"], row, a_value)
    b_cell = assignment.set_advice(cols["b"], row, b_value)
    c_cell = assignment.set_advice(cols["c"], row, a_value + b_value)
    return a_cell, b_cell, c_cell


def build_witness_for_range_add(a_value: int, b_value: int) -> Tuple[ConstraintSystem, Assignment, Dict[str, Column]]:
    cs, cols = configure_range_add_circuit()
    assignment = Assignment()

    a_cell_row0, _ = assign_range_decomposition_row(assignment, cols, row=0, value=a_value)
    b_cell_row1, _ = assign_range_decomposition_row(assignment, cols, row=1, value=b_value)
    a_cell_row2, b_cell_row2, c_cell_row2 = assign_add_row(assignment, cols, row=2, a_value=a_value, b_value=b_value)

    cs.constrain_equal(a_cell_row0, a_cell_row2)
    cs.constrain_equal(b_cell_row1, b_cell_row2)

    instance = cs.instance_column()
    cols["instance_c"] = instance
    assignment.set_instance(instance, 0, a_value + b_value)
    cs.constrain_equal(CellRef(column=instance, row=0), c_cell_row2)

    return cs, assignment, cols
```

This is the critical “Halo2 feeling”: you assign witness values into a table, then separately declare which equalities and gate constraints must hold.

### Step 4: Build a mock prover to check satisfiability

Finally, we implement a deterministic checker that evaluates all enabled gates on all rows and checks all copy constraints:

```python
@dataclass(frozen=True)
class CheckFailure:
    kind: str  # "gate" | "copy"
    name: str
    row: Optional[int]
    left: Optional[F] = None
    right: Optional[F] = None
    value: Optional[F] = None

    def __repr__(self) -> str:
        if self.kind == "copy":
            return f"copy constraint failed: {self.name} (left={self.left}, right={self.right})"
        return f"gate failed: {self.name} at row={self.row} (value={self.value})"


class MockProver:
    def __init__(self, cs: ConstraintSystem, assignment: Assignment) -> None:
        self.cs = cs
        self.assignment = assignment

    def check(self) -> List[CheckFailure]:
        failures: List[CheckFailure] = []
        for row in range(self.assignment.n_rows):
            for gate in self.cs.gates:
                s = self.assignment.get(gate.selector, row)
                if int(s) not in (0, 1):
                    failures.append(CheckFailure(kind="gate", name=f"{gate.name} (selector not boolean)", row=row, value=s))
                for idx, expr in enumerate(gate.constraints):
                    val = (Cell(gate.selector) * expr).eval(self.assignment, row)
                    if int(val) != 0:
                        failures.append(
                            CheckFailure(
                                kind="gate",
                                name=f"{gate.name}[{idx}]",
                                row=row,
                                value=val,
                            )
                        )
        for idx, copy in enumerate(self.cs.copy_constraints):
            left = self.assignment.get(copy.left.column, copy.left.row)
            right = self.assignment.get(copy.right.column, copy.right.row)
            if left != right:
                failures.append(
                    CheckFailure(
                        kind="copy",
                        name=f"copy[{idx}]: {copy.left} == {copy.right}",
                        row=None,
                        left=left,
                        right=right,
                    )
                )
        return failures


def prove_range_add(a_value: int, b_value: int) -> List[CheckFailure]:
    cs, assignment, _ = build_witness_for_range_add(a_value, b_value)
    return MockProver(cs, assignment).check()
```

This plays the role of Halo2’s `MockProver`: it doesn’t prove anything cryptographic — it only checks that your constraints actually constrain the witness the way you think.

Run it:

`python3 code/main.py`

## Use It

In real Halo2 (Rust), you use the `halo2_proofs` crate and write a `Circuit` that has:

- `configure(meta: &mut ConstraintSystem<F>)` to declare columns, selectors, and gates
- `synthesize(&self, layouter: impl Layouter<F>)` to assign witness values and copy constraints

Concept mapping:

| This lesson | Real Halo2 (Rust) | Meaning |
|---|---|---|
| `Column("advice", i)` | `Column<Advice>` | Private witness cells |
| `Column("fixed", i)` | `Column<Fixed>` | Constants, selectors, fixed tables |
| `Column("instance", i)` | `Column<Instance>` | Public inputs/outputs |
| `selector()` | `Selector` / fixed selector column | Enable a gate on some rows |
| `Cell(col, rot)` | `meta.query_advice(col, rot)` | Query a cell at a rotation |
| `constrain_equal` | `layouter.constrain_equal` | Force two cells to be equal |
| `MockProver.check()` | `MockProver::run(...).verify()` | Debug constraint satisfaction |

## Pitfalls

1. **Unconstrained witness.** You assign a value but never relate it to anything. The prover can pick any value and still satisfy constraints.
2. **Selector mistakes.** Forgetting to enable a selector (or enabling it on the wrong rows) can silently disable a gate.
3. **Copy-constraint gaps.** You compute `a` in one place and use `a` elsewhere without a copy constraint, so the “same variable” becomes two unrelated cells.
4. **Rotation confusion.** Querying `Rotation::next()` when you meant `cur()` changes which row is being constrained, often breaking soundness in subtle ways.
5. **Non-boolean selectors.** If a selector can be 2 (or any non-0/1), you can accidentally scale constraints in unexpected ways.

## Ship It

Save as `outputs/skill-halo2-circuit-review.md`. Use it as a PR-review checklist when reading Halo2 circuits: it helps you look for unconstrained witnesses, selector bugs, missing copy constraints, and public input mismatches.

## Exercises

1. **Easy.** Run `python3 code/main.py`. Observe how the circuit is satisfied, then observe the failures after the single-bit flip.
2. **Medium.** Extend the circuit from 3-bit to 4-bit range checks by adding one more bit column and changing the reconstruction constraint.
3. **Hard.** Port the same circuit to real Halo2 in Rust and verify it with `MockProver`. Keep the same logic: bit constraints + reconstruction + `c = a + b` as a public instance.

## Key Terms

| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Advice column | “Witness column” | Prover-chosen values that must be constrained by gates/copies |
| Fixed column | “Constants / selectors” | Verifier-known values (often 0/1 selectors or lookup tables) |
| Instance column | “Public inputs” | Values fixed by the verifier (public inputs/outputs) |
| Selector | “Turns a gate on” | A fixed 0/1 multiplier that enables constraints on specific rows |
| Gate | “A constraint” | One or more expressions that must evaluate to 0 when enabled |
| Rotation | “Previous/next row” | Querying a cell at `row + k` inside an expression |
| Copy constraint | “Same variable” | Equality between two cells (implemented via a permutation argument) |
| Mock prover | “Unit test for circuits” | Deterministic satisfiability checker (not a cryptographic proof) |

## Further Reading

- Zcash Foundation, *The Halo2 Book* (ongoing) — The best practical guide to the Halo2 API and mental model.
- Gabizon, Williamson, Ciobotaru, *PLONK* (2019) — The core PLONK construction behind “PLONKish” systems like Halo2.
- Electric Coin Company, *Halo: Recursive Proof Composition without a Trusted Setup* (2019) — Context for the “Halo” family of ideas that influenced Halo2.
