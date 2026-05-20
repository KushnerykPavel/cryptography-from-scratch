"""Toy Halo2-style PLONKish circuits in pure Python (stdlib only).

This lesson builds a minimal "Halo2-ish" constraint system:
- advice / fixed / instance columns
- selectors that enable gates on some rows
- rotations (query prev/cur/next row)
- copy constraints ("these two cells must be equal")
- a MockProver that checks satisfiability deterministically

Run:
  python3 code/main.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


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


def prove_range_add(a_value: int, b_value: int) -> List[CheckFailure]:
    cs, assignment, _ = build_witness_for_range_add(a_value, b_value)
    return MockProver(cs, assignment).check()


def main() -> None:
    print("=== Step 1: Field and expressions ===")
    x = F(10)
    y = F(3)
    print(f"  modulus: {GOLDILOCKS_PRIME}")
    print(f"  x={x}, y={y}")
    print(f"  x+y={x+y}, x*y={x*y}, x/y={x/y}")

    print()
    print("=== Step 2: Columns, selectors, and gates ===")
    cs, cols = configure_range_add_circuit()
    print(f"  columns: {len(cs.columns)} (advice+fixed+instance)")
    print(f"  gates:   {[g.name for g in cs.gates]}")
    print(f"  selectors: q_decompose={cols['q_decompose']}, q_add={cols['q_add']}")

    print()
    print("=== Step 3: Lay out a 3-bit range-check + addition circuit ===")
    a_value = 5
    b_value = 6
    cs2, assignment, _ = build_witness_for_range_add(a_value, b_value)
    print(f"  witness: a={a_value}, b={b_value}, public c={a_value + b_value}")
    print(f"  rows:    {assignment.n_rows}")

    print()
    print("=== Step 4: MockProver (constraint checking) ===")
    prover = MockProver(cs2, assignment)
    failures = prover.check()
    if not failures:
        print("  all constraints satisfied")
    else:
        print("  failures:")
        for f in failures:
            print(f"   - {f}")

    print()
    print("  now break the witness (flip one bit) ...")
    broken = assignment.clone()
    broken.set_advice(cols["d0"], 0, 0 if int(assignment.get(cols["d0"], 0)) == 1 else 1)

    broken_failures = MockProver(cs2, broken).check()
    print(f"  failures: {len(broken_failures)}")
    for f in broken_failures[:3]:
        print(f"   - {f}")
    if len(broken_failures) > 3:
        print("   - ...")


if __name__ == "__main__":
    main()
