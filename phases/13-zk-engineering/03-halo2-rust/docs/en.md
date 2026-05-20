# Halo2 in Rust — A Working Circuit
> Think in constraints, not code.

**Type:** Build  
**Languages:** Python  
**Prerequisites:** `../../01-circom/docs/en.md`, `../../02-snarkjs/docs/en.md`  
**Time:** ~90 minutes

> ⚠️ Educational implementation. Not constant-time. Not production-safe.

## Learning Objectives
- **Explain** Halo2’s “spreadsheet” mental model (columns, rows, cells).
- **Compute** whether a gate constraint evaluates to zero in a finite field.
- **Implement** a tiny constraint checker with selectors and equality constraints.
- **Distinguish** configuration-time constraints vs synthesis-time witness assignment.
- **Apply** a range-check as a set-membership constraint (a toy “lookup”).

## The Problem
You can understand SNARKs in theory and still ship a broken Halo2 circuit in practice. The failure mode is sneaky: the Rust code compiles, the witness assignment “looks right”, but the constraints you *thought* you enforced were never enabled (selector bug), or the values you *thought* you reused were not actually tied together (missing equality constraint).

Halo2’s API pushes you toward composable “chips” and flexible layout, but the mental model is different from the R1CS-style “one constraint = one line” world. If you can’t *see the table*, you’ll struggle to debug verification failures, reason about public inputs, or review a circuit PR safely.

This lesson builds a tiny, stdlib-only “Halo2-like” constraint system in Python so you can practice the core ideas (columns, selectors, gates, copy constraints, range checks) without fighting Rust lifetimes or the full proving system.

## The Concept
Halo2 circuits are easiest to picture as a **table**:

- **Advice columns** hold witness values (private inputs + intermediates).
- **Instance columns** hold public inputs/outputs.
- **Fixed columns** hold constants baked into the circuit shape (selectors are a special case: fixed 0/1).

Constraints are **identities that must hold on each row**. A gate is typically written as:

`q(row) * t(row) = 0`

Where:
- `q(row)` is a **selector** (0 or 1) that decides whether the gate is “on” at that row.
- `t(row)` is a low-degree expression in the row’s cells (e.g. `a*b - c`).

Two more engineering primitives matter constantly:
- **Copy/equality constraints** (“these two cells must contain the same value”) — in Halo2 this is enforced via a permutation argument.
- **Lookups / range checks** (“this cell must be one of these values”) — in Halo2 this is enforced via a lookup argument.

In this lesson we won’t implement a proof system. We’ll implement the *checker* for “does this filled-in table satisfy the constraints?”, which is the part your brain needs to debug circuits.

## Build It

### Step 1: Field arithmetic (mod p)
```python
MODULUS = 97


@dataclass(frozen=True)
class F:
    n: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "n", self.n % MODULUS)

    @staticmethod
    def from_int(x: int) -> "F":
        return F(x)

    def __int__(self) -> int:
        return self.n

    def __add__(self, other: "F") -> "F":
        return F(self.n + other.n)

    def __sub__(self, other: "F") -> "F":
        return F(self.n - other.n)

    def __mul__(self, other: "F") -> "F":
        return F(self.n * other.n)

    def __neg__(self) -> "F":
        return F(-self.n)

    def __pow__(self, exp: int) -> "F":
        return F(pow(self.n, exp, MODULUS))

    def inv(self) -> "F":
        if self.n == 0:
            raise ZeroDivisionError("0 has no inverse in a field")
        return self ** (MODULUS - 2)

    def __truediv__(self, other: "F") -> "F":
        return self * other.inv()


def fe(x: int) -> F:
    return F.from_int(x)
```
Halo2 arithmetic happens in a finite field. We’ll use a tiny prime field (mod 97) so you can compute examples by hand. Every constraint is “this expression equals 0 in the field”.

### Step 2: Constraint systems (columns, selectors, gates)
```python
class ColumnType(str, Enum):
    ADVICE = "advice"
    FIXED = "fixed"
    INSTANCE = "instance"


@dataclass(frozen=True)
class Column:
    col_type: ColumnType
    index: int


@dataclass(frozen=True)
class Selector:
    index: int


@dataclass(frozen=True)
class Cell:
    column: Column
    row: int


@dataclass(frozen=True)
class Gate:
    name: str
    selector: Selector | None
    constraints: Callable[["Assignment", int], Sequence[F]]


class Assignment:
    def __init__(self) -> None:
        self._values: dict[tuple[ColumnType, int], dict[int, F]] = {}
        self._selectors: dict[int, set[int]] = {}

    def assign(self, column: Column, row: int, value: int | F) -> Cell:
        if row < 0:
            raise ValueError("row must be non-negative")
        key = (column.col_type, column.index)
        col = self._values.setdefault(key, {})
        col[row] = value if isinstance(value, F) else fe(value)
        return Cell(column=column, row=row)

    def enable(self, selector: Selector, row: int) -> None:
        if row < 0:
            raise ValueError("row must be non-negative")
        self._selectors.setdefault(selector.index, set()).add(row)

    def selector_value(self, selector: Selector, row: int) -> F:
        enabled = row in self._selectors.get(selector.index, set())
        return fe(1 if enabled else 0)

    def query(self, column: Column, row: int) -> F:
        key = (column.col_type, column.index)
        if key not in self._values or row not in self._values[key]:
            raise KeyError(f"unassigned cell: {column.col_type}:{column.index} row={row}")
        return self._values[key][row]

    def max_row(self) -> int:
        rows: list[int] = []
        for col in self._values.values():
            rows.extend(col.keys())
        for enabled_rows in self._selectors.values():
            rows.extend(list(enabled_rows))
        return (max(rows) + 1) if rows else 0


class ConstraintSystem:
    def __init__(self) -> None:
        self._next_index: dict[ColumnType, int] = {t: 0 for t in ColumnType}
        self._next_selector: int = 0
        self.gates: list[Gate] = []
        self.equalities: list[tuple[Cell, Cell]] = []

    def new_column(self, col_type: ColumnType) -> Column:
        idx = self._next_index[col_type]
        self._next_index[col_type] = idx + 1
        return Column(col_type=col_type, index=idx)

    def new_selector(self) -> Selector:
        idx = self._next_selector
        self._next_selector = idx + 1
        return Selector(index=idx)

    def create_gate(
        self,
        name: str,
        selector: Selector | None,
        constraints: Callable[[Assignment, int], Sequence[F]],
    ) -> None:
        self.gates.append(Gate(name=name, selector=selector, constraints=constraints))

    def constrain_equal(self, left: Cell, right: Cell) -> None:
        self.equalities.append((left, right))

    def is_satisfied(self, assignment: Assignment) -> tuple[bool, list[str]]:
        failures: list[str] = []

        for (left, right) in self.equalities:
            lv = assignment.query(left.column, left.row)
            rv = assignment.query(right.column, right.row)
            if lv != rv:
                failures.append(
                    f"equality failed: ({left.column.col_type}:{left.column.index}, row {left.row}) "
                    f"!= ({right.column.col_type}:{right.column.index}, row {right.row})"
                )

        for gate in self.gates:
            for row in range(assignment.max_row()):
                if gate.selector is not None and int(assignment.selector_value(gate.selector, row)) == 0:
                    continue
                for i, c in enumerate(gate.constraints(assignment, row)):
                    if int(c) != 0:
                        failures.append(f"gate failed: {gate.name} row={row} constraint#{i} value={int(c)}")

        return (len(failures) == 0), failures
```
This is the “spreadsheet engine”: you declare columns and gates up front (configuration), then you assign witness values and enable selectors for specific rows (synthesis). `is_satisfied()` is your mental debugger: it tells you if the filled-in table actually satisfies the identities.

### Step 3: A worked circuit: prove `a*b=c` and expose `c` publicly
```python
def mul_residual(a: int, b: int, c: int) -> int:
    return int(fe(a) * fe(b) - fe(c))


def vanishing_product(x: int, allowed: Iterable[int]) -> int:
    acc = fe(1)
    fx = fe(x)
    for v in allowed:
        acc = acc * (fx - fe(v))
    return int(acc)


def build_mul_circuit() -> tuple[ConstraintSystem, dict[str, Column], Selector]:
    cs = ConstraintSystem()
    a = cs.new_column(ColumnType.ADVICE)
    b = cs.new_column(ColumnType.ADVICE)
    c = cs.new_column(ColumnType.ADVICE)
    out = cs.new_column(ColumnType.INSTANCE)
    q_mul = cs.new_selector()

    def mul_gate(assn: Assignment, row: int) -> Sequence[F]:
        q = assn.selector_value(q_mul, row)
        av = assn.query(a, row)
        bv = assn.query(b, row)
        cv = assn.query(c, row)
        return [q * (av * bv - cv)]

    cs.create_gate("mul: a*b=c", q_mul, mul_gate)
    return cs, {"a": a, "b": b, "c": c, "out": out}, q_mul


def assign_mul_witness(
    assignment: Assignment, cols: dict[str, Column], selector: Selector, a: int, b: int, row: int = 0
) -> None:
    assignment.enable(selector, row)
    assignment.assign(cols["a"], row, a)
    assignment.assign(cols["b"], row, b)
    assignment.assign(cols["c"], row, fe(a) * fe(b))


def expose_public_output(cs: ConstraintSystem, assignment: Assignment, cols: dict[str, Column], row: int = 0) -> None:
    c_cell = Cell(column=cols["c"], row=row)
    out_cell = assignment.assign(cols["out"], row, assignment.query(cols["c"], row))
    cs.constrain_equal(c_cell, out_cell)
```
This is the minimal Halo2 “shape”: a selector-enabled multiplication gate plus an equality constraint tying an advice cell to an instance (public) cell. In real Halo2, `configure()` builds this constraint system, and `synthesize()` assigns the witness and enables the selector.

### Step 4: Range checks via a vanishing polynomial (toy lookup)
```python
def add_range_gate(cs: ConstraintSystem, x_col: Column, selector: Selector, allowed: Sequence[int]) -> None:
    def range_gate(assn: Assignment, row: int) -> Sequence[F]:
        q = assn.selector_value(selector, row)
        x = assn.query(x_col, row)
        acc = fe(1)
        for v in allowed:
            acc = acc * (x - fe(v))
        return [q * acc]

    cs.create_gate(f"in-set: {allowed[0]}..{allowed[-1]}", selector, range_gate)
```
Lookups in Halo2 are how you do efficient range checks (and lots of other “x is in this table” constraints). Here we simulate the *idea* using a vanishing polynomial: the product is zero exactly when `x` is one of the allowed values. It’s not how you’d implement range checks in production, but it’s a great constraint-level mental model.

Run it:
`python3 code/main.py`

## Use It
Real Halo2 Rust code uses the same pieces, just with stronger types and a real proving system:

- **Columns:** `meta.advice_column()`, `meta.instance_column()`, `meta.fixed_column()`
- **Selectors:** `meta.selector()` / `meta.complex_selector()`; enable via `selector.enable(&mut region, offset)`
- **Custom gates:** `meta.create_gate("name", |meta| { ... })`
- **Equality/copy constraints:** enable equality on columns + `region.constrain_equal(a.cell(), b.cell())`
- **Public IO:** `layouter.constrain_instance(cell.cell(), instance_col, row)`
- **Lookups / range checks:** `meta.lookup(|meta| { ... })` with a table loaded in `layouter.assign_table(...)`

A good workflow is: (1) decide your table layout + constraints on paper, (2) implement `configure()` to match it, (3) implement `synthesize()` to fill it, (4) debug by printing the table (Halo2 has a dev feature for this), (5) only then optimize.

## Pitfalls
- **Selector never enabled:** the gate exists, but `q(row)=0` everywhere so the constraint is effectively off.
- **Values “copied” without equality:** you assign the same integer twice, but forget the constraint that forces them to stay equal.
- **Unassigned cells in enabled rows:** if a selector turns a gate on at a row, every queried cell in that gate must be assigned.
- **Range checks via high-degree polynomials:** the vanishing-product trick explodes degree; real circuits use lookup arguments and decomposition gadgets.
- **Public input indexing mismatch:** instance row numbers are absolute positions; off-by-one bugs here are common and painful.

## Ship It
Save and reuse this artifact: `outputs/skill-halo2-circuit-review-checklist.md`.

Use it as a PR review checklist for Halo2 circuits: selectors, equality constraints, public IO, range checks, and “configure vs synthesize” hazards. Paste it into a review, or into a model prompt, before approving a circuit change.

## Exercises
1. Easy. Run `python3 code/main.py`. Observe how a selector makes a constraint “do nothing” when disabled.
2. Medium. Add an `add: a+b=c` gate next to the multiplication gate, and update `main()` to show both gates working on different rows.
3. Hard. Extend the toy system to support “next-row” queries (a rotation), then build a 2-row gadget (e.g. `x_next = x + 1`) and test it.

## Key Terms
| Term | What people say | What it actually means |
|------|------------------|------------------------|
| Advice column | “Witness column” | Private values the prover commits to and proves constraints about |
| Instance column | “Public inputs” | Public values the verifier knows; tied to witness via constraints |
| Fixed column | “Constants / selectors” | Circuit-structure values known to both prover and verifier |
| Selector | “Turn a gate on/off” | A fixed 0/1 value multiplied into a constraint to conditionally enable it |
| Gate | “A constraint” | One or more identities evaluated per row (usually selector-gated) |
| Equality / copy constraint | “Copy a value” | Forces two arbitrary cells to be equal (implemented via a permutation argument) |
| Lookup | “Table membership” | Forces a value to appear in a table (implemented via a lookup argument) |
| Configure vs synthesize | “Two phases” | First declare constraints/columns; then assign witness and enable selectors |

## Further Reading
- Zcash Foundation, *The halo2 Book* — the canonical reference for Halo2 concepts and arguments.
- Zcash Foundation, *A simple example* — a minimal end-to-end circuit showing selectors, gates, and `constrain_instance`.
- Electric Coin Company / Zcash ecosystem blog posts on Halo2 engineering — practical lessons on debugging and circuit design.
